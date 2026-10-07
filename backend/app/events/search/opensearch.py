import logging
import re
import uuid
from typing import Any

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError, OpenSearchException, RequestError

from app.core.config import Settings
from app.core.errors import UpstreamUnavailable
from app.events.fields import CUSTOM_ANALYSIS, FIELDS, FULL_TEXT_FIELDS, build_properties
from app.events.schema import SCHEMA_VERSION, Event, EventType
from app.events.search.base import IndexResult
from app.events.search.query import (
    AggregationResult,
    Bucket,
    EventQuery,
    Filter,
    SearchResult,
    TimeRange,
)

log = logging.getLogger("app.search")

FAMILIES = ("events", "network", "authentication", "endpoint", "dns")
_FAMILY_BY_TYPE = {
    EventType.NETWORK_CONNECTION: "network",
    EventType.DNS_QUERY: "dns",
    EventType.AUTHENTICATION: "authentication",
    EventType.PROCESS_CREATION: "endpoint",
    EventType.FILE_EVENT: "endpoint",
    EventType.REGISTRY_EVENT: "endpoint",
    EventType.SCHEDULED_TASK: "endpoint",
    EventType.SERVICE_INSTALL: "endpoint",
}
_HISTOGRAM_STEPS = [
    ("1m", 60),
    ("5m", 300),
    ("15m", 900),
    ("30m", 1800),
    ("1h", 3600),
    ("3h", 10800),
    ("6h", 21600),
    ("12h", 43200),
    ("1d", 86400),
    ("7d", 604800),
]
_EXCLUDE_FROM_LIST = ["raw"]


def _escape_wildcard(value: str) -> str:
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


_Q_TOKEN = re.compile(r'"[^"]*"?|\S+')


def translate_query(q: str) -> str:
    """Let analysts write `a AND b`, `a OR b`, `NOT a` (upper-case, outside quotes); the engine's
    simple_query_string dialect uses implicit-AND, `|` and `-` instead."""
    out: list[str] = []
    negate = False
    for tok in _Q_TOKEN.findall(q):
        if tok == "AND":
            continue
        if tok == "OR":
            out.append("|")
        elif tok == "NOT":
            negate = True
        else:
            out.append(("-" + tok) if negate else tok)
            negate = False
    return " ".join(out)


def pick_interval(tr: TimeRange, target_buckets: int = 60) -> str:
    seconds = (tr.end - tr.start).total_seconds()
    for label, step in _HISTOGRAM_STEPS:
        if seconds / step <= target_buckets:
            return label
    return "7d"


class OpenSearchBackend:
    def __init__(self, client: AsyncOpenSearch, settings: Settings) -> None:
        self.client = client
        self.prefix = settings.index_prefix
        self.settings = settings

    # ---- naming -----------------------------------------------------------------------------
    @property
    def pattern(self) -> str:
        return ",".join(f"{self.prefix}{f}-*" for f in FAMILIES)

    def index_for(self, event: Event) -> str:
        family = _FAMILY_BY_TYPE.get(event.event_type, "events")
        return f"{self.prefix}{family}-{event.timestamp:%Y.%m.%d}"

    # ---- schema -----------------------------------------------------------------------------
    async def ensure_schema(self) -> None:
        body = {
            "index_patterns": [f"{self.prefix}{f}-*" for f in FAMILIES],
            "priority": 100,
            "template": {
                "settings": {
                    "index": {
                        "number_of_shards": self.settings.index_shards,
                        "number_of_replicas": self.settings.index_replicas,
                        "refresh_interval": "1s",
                        "mapping.total_fields.limit": 500,
                    },
                    "analysis": CUSTOM_ANALYSIS,
                },
                "mappings": {
                    "dynamic": "strict",
                    "_meta": {"schema_version": SCHEMA_VERSION},
                    "properties": build_properties(),
                },
            },
            "_meta": {"schema_version": SCHEMA_VERSION},
        }
        await self.client.indices.put_index_template(name=f"{self.prefix}telemetry", body=body)

    # ---- write ------------------------------------------------------------------------------
    async def index_events(self, events: list[Event]) -> IndexResult:
        result = IndexResult()
        if not events:
            return result
        lines: list[dict[str, Any]] = []
        for event in events:
            lines.append({"create": {"_index": self.index_for(event), "_id": event.id}})
            lines.append(event.to_document())
        try:
            response = await self.client.bulk(body=lines)
        except OpenSearchException as exc:
            log.error("bulk indexing failed", extra={"error": type(exc).__name__})
            raise UpstreamUnavailable("Search backend unavailable") from exc
        for pos, item in enumerate(response["items"]):
            op = item["create"]
            if op["status"] < 300:
                result.accepted += 1
            elif op["status"] == 409:
                result.duplicates += 1
            else:
                reason = (op.get("error") or {}).get("type", "index_error")
                log.warning("event rejected by index", extra={"reason": reason, "detail": str(op.get("error"))[:300]})
                result.failed.append((pos, reason))
        return result

    # ---- read -------------------------------------------------------------------------------
    def compile(self, tenant_id: uuid.UUID, query: EventQuery) -> dict[str, Any]:
        """Build the request body. The tenant term is a top-level filter that user-supplied clauses
        can only narrow, never widen: user input lives entirely inside a nested bool."""
        tr = query.effective_range()
        user_filter: list[dict[str, Any]] = []
        user_must_not: list[dict[str, Any]] = []
        for f in query.filters:
            clause, negate = self._compile_filter(f)
            (user_must_not if negate else user_filter).append(clause)
        user_must: list[dict[str, Any]] = []
        if query.q and query.q.strip():
            user_must.append(
                {
                    "simple_query_string": {
                        "query": translate_query(query.q),
                        "fields": FULL_TEXT_FIELDS,
                        "default_operator": "and",
                        # No FUZZY/NEAR/SLOP/ESCAPE games; PREFIX allows `power*`.
                        "flags": "AND|OR|NOT|PHRASE|PREFIX|PRECEDENCE|WHITESPACE",
                        "lenient": True,
                        "analyze_wildcard": False,
                    }
                }
            )
        body: dict[str, Any] = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"tenant_id": str(tenant_id)}},
                        {"range": {"timestamp": {"gte": tr.start.isoformat(), "lt": tr.end.isoformat()}}},
                        {"bool": {"filter": user_filter, "must_not": user_must_not, "must": user_must}},
                    ]
                }
            },
            "from": query.offset,
            "size": query.limit,
            "track_total_hits": 10_000,
            "_source": {"excludes": _EXCLUDE_FROM_LIST},
            "sort": self._compile_sort(query),
        }
        if query.aggregations:
            body["aggs"] = {a.name: self._compile_agg(a, tr) for a in query.aggregations}
        return body

    @staticmethod
    def _compile_sort(query: EventQuery) -> list[dict[str, Any]]:
        sort = [{FIELDS[s.field].exact_path: {"order": s.order, "unmapped_type": "keyword"}} for s in query.sort]
        if not any(s.field == "timestamp" for s in query.sort):
            sort.append({"timestamp": {"order": "desc"}})
        sort.append({"id": {"order": "desc", "unmapped_type": "keyword"}})  # deterministic tie-breaker
        return sort

    @staticmethod
    def _compile_agg(agg: Any, tr: TimeRange) -> dict[str, Any]:
        if agg.type == "date_histogram":
            return {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": pick_interval(tr),
                    "min_doc_count": 0,
                    "extended_bounds": {"min": tr.start.isoformat(), "max": tr.end.isoformat()},
                }
            }
        return {"terms": {"field": FIELDS[agg.field].exact_path, "size": agg.size}}

    @staticmethod
    def _compile_filter(f: Filter) -> tuple[dict[str, Any], bool]:
        """Returns (clause, negated)."""
        spec = FIELDS[f.field]
        path = spec.exact_path
        match f.op:
            case "eq":
                return {"term": {path: f.value}}, False
            case "neq":
                return {"term": {path: f.value}}, True
            case "in":
                return {"terms": {path: f.value}}, False
            case "exists":
                return {"exists": {"field": spec.name}}, False
            case "not_exists":
                return {"exists": {"field": spec.name}}, True
            case "prefix":
                return {"prefix": {path: {"value": str(f.value), "case_insensitive": True}}}, False
            case "contains":
                if spec.kind == "text":  # analysed match on tokens, phrase-ordered
                    return {"match_phrase": {spec.name: str(f.value)}}, False
                return {
                    "wildcard": {path: {"value": f"*{_escape_wildcard(str(f.value))}*", "case_insensitive": True}}
                }, False
            case "gt" | "gte" | "lt" | "lte":
                return {"range": {path: {f.op: f.value}}}, False
        raise ValueError(f"unhandled operator {f.op}")  # pragma: no cover

    async def search(self, tenant_id: uuid.UUID, query: EventQuery) -> SearchResult:
        body = self.compile(tenant_id, query)
        try:
            resp = await self.client.search(
                index=self.pattern,
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
                request_timeout=20,
                params={"timeout": "15s"},
            )
        except RequestError as exc:
            log.warning("search rejected by backend", extra={"detail": str(exc)[:300]})
            from app.core.errors import AppError

            raise AppError("Query could not be executed") from None
        except OpenSearchException as exc:
            log.error("search failed", extra={"error": type(exc).__name__})
            raise UpstreamUnavailable("Search backend unavailable") from exc
        hits = [h["_source"] for h in resp["hits"]["hits"]]
        total = resp["hits"]["total"]
        aggs: dict[str, AggregationResult] = {}
        for name, agg in (resp.get("aggregations") or {}).items():
            aggs[name] = AggregationResult(
                buckets=[
                    Bucket(
                        key=b.get("key_as_string", b["key"]) if "key_as_string" in b else b["key"], count=b["doc_count"]
                    )
                    for b in agg["buckets"]
                ]
            )
        return SearchResult(
            total=total["value"],
            total_relation=total["relation"],
            took_ms=resp["took"],
            hits=hits,
            aggregations=aggs,
            time_range=query.effective_range(),
        )

    async def get_event(self, tenant_id: uuid.UUID, event_id: str) -> dict[str, Any] | None:
        body = {
            "size": 1,
            "query": {"bool": {"filter": [{"term": {"tenant_id": str(tenant_id)}}, {"ids": {"values": [event_id]}}]}},
        }
        try:
            resp = await self.client.search(
                index=self.pattern, body=body, ignore_unavailable=True, allow_no_indices=True
            )
        except NotFoundError:
            return None
        except OpenSearchException as exc:
            raise UpstreamUnavailable("Search backend unavailable") from exc
        hits = resp["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    async def delete_before(self, tenant_id: uuid.UUID, cutoff_iso: str) -> int:
        body = {
            "query": {
                "bool": {
                    "filter": [{"term": {"tenant_id": str(tenant_id)}}, {"range": {"timestamp": {"lt": cutoff_iso}}}]
                }
            }
        }
        try:
            resp = await self.client.delete_by_query(
                index=self.pattern,
                body=body,
                conflicts="proceed",
                ignore_unavailable=True,
                allow_no_indices=True,
                refresh=True,
            )
        except OpenSearchException as exc:
            raise UpstreamUnavailable("Search backend unavailable") from exc
        return int(resp.get("deleted", 0))

    async def health(self) -> dict[str, Any]:
        try:
            h = await self.client.cluster.health(request_timeout=3)
            return {"status": "ok" if h["status"] in ("green", "yellow") else "degraded", "cluster_status": h["status"]}
        except Exception:
            return {"status": "down"}


__all__ = ["FAMILIES", "OpenSearchBackend", "pick_interval", "translate_query"]
