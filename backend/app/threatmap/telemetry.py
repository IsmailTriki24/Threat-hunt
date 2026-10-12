"""Aggregations over the tenant's own telemetry for the threat map. OpenSearch-specific by design (it uses the backend's client and index
pattern); the domain logic that consumes these results lives in `service.py`.

Everything is aggregated server-side: the browser never receives raw events, only per-IP and per-flow summaries, bounded by `size`.
Every query is scoped by the tenant id of the caller's principal."""

import uuid
from dataclasses import dataclass, field
from typing import Any

from opensearchpy.exceptions import OpenSearchException

from app.core.errors import UpstreamUnavailable
from app.events.search.opensearch import OpenSearchBackend

SRC, DST, AUTH = "network.src_ip", "network.dst_ip", "auth.source_ip"
IP_FIELDS = (SRC, DST, AUTH)
_ROLE = {SRC: "src", DST: "dst", AUTH: "auth"}

# Never worth bucketing as "remote" endpoints; the authoritative public/private decision is still `geo.classify_ip` in Python.
NON_PUBLIC_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]  # fmt: skip

_TERMS_CHUNK = 4000


@dataclass
class IpActivity:
    ip: str
    src: int = 0
    dst: int = 0
    auth: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    max_severity: int = 0
    sources: dict[str, int] = field(default_factory=dict)
    ports: dict[int, int] = field(default_factory=dict)

    @property
    def events(self) -> int:
        return self.src + self.dst + self.auth


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    events: int
    first_seen: str | None
    last_seen: str | None
    max_severity: int
    ports: list[int]
    sources: list[str]
    protocols: list[str]


def _base_filter(
    tenant_id: uuid.UUID, start_iso: str, end_iso: str, sources: list[str] | None, min_sev: int
) -> list[dict[str, Any]]:
    f: list[dict[str, Any]] = [
        {"term": {"tenant_id": str(tenant_id)}},
        {"range": {"timestamp": {"gte": start_iso, "lt": end_iso}}},
    ]
    if sources:
        f.append({"terms": {"source": sources}})
    if min_sev > 0:
        f.append({"range": {"severity": {"gte": min_sev}}})
    return f


def _cidr_terms(field_name: str) -> dict[str, Any]:
    return {"bool": {"should": [{"term": {field_name: c}} for c in NON_PUBLIC_CIDRS], "minimum_should_match": 1}}


def _ip_terms(ips: list[str]) -> dict[str, Any]:
    return {"bool": {"should": [{"terms": {f: ips}} for f in IP_FIELDS], "minimum_should_match": 1}}


async def _search(search: OpenSearchBackend, body: dict[str, Any]) -> dict[str, Any]:
    try:
        resp: dict[str, Any] = await search.client.search(
            index=search.pattern, body=body, ignore_unavailable=True, allow_no_indices=True
        )
        return resp
    except OpenSearchException as exc:
        raise UpstreamUnavailable("Search backend unavailable") from exc


def _iso(agg: dict[str, Any]) -> str | None:
    return agg.get("value_as_string") if agg.get("value") is not None else None


async def ip_activity(
    search: OpenSearchBackend,
    tenant_id: uuid.UUID,
    start_iso: str,
    end_iso: str,
    *,
    sources: list[str] | None = None,
    min_severity: int = 0,
    ips: list[str] | None = None,
    include_internal: bool = False,
    size: int = 3000,
) -> tuple[dict[str, IpActivity], int]:
    """Per-IP activity over [start, end): how often each address appeared as a network source, destination or sign-in source.
    Returns ({ip: activity}, events_in_scope). `ips` restricts to those addresses (used to correlate against intelligence)."""
    chunks = [ips[i : i + _TERMS_CHUNK] for i in range(0, len(ips), _TERMS_CHUNK)] if ips is not None else [None]
    out: dict[str, IpActivity] = {}
    total = 0
    for chunk in chunks:
        flt = _base_filter(tenant_id, start_iso, end_iso, sources, min_severity)
        if chunk is not None:
            flt.append(_ip_terms(chunk))
        else:  # "events in scope" must mean events that carry an address at all
            flt.append({"bool": {"should": [{"exists": {"field": f}} for f in IP_FIELDS], "minimum_should_match": 1}})
        aggs: dict[str, Any] = {}
        for f in IP_FIELDS:
            terms: dict[str, Any] = {"field": f, "size": size, "order": {"_count": "desc"}}
            sub: dict[str, Any] = {
                "first": {"min": {"field": "timestamp"}},
                "last": {"max": {"field": "timestamp"}},
                "sev": {"max": {"field": "severity"}},
                "src": {"terms": {"field": "source", "size": 5}},
            }
            if f == DST:
                sub["ports"] = {"terms": {"field": "network.dst_port", "size": 5}}
            agg: dict[str, Any] = {"terms": terms, "aggs": sub}
            if not include_internal:
                agg = {"filter": {"bool": {"must_not": [_cidr_terms(f)]}}, "aggs": {"ips": agg}}
            else:
                agg = {"filter": {"match_all": {}}, "aggs": {"ips": agg}}
            aggs[f.replace(".", "_")] = agg
        body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": flt}}, "aggs": aggs}
        resp = await _search(search, body)
        total += int(resp["hits"]["total"]["value"])
        got = resp.get("aggregations") or {}  # absent when no index exists yet (a tenant that has never ingested)
        wanted = set(chunk) if chunk is not None else None
        for f in IP_FIELDS:
            for b in got.get(f.replace(".", "_"), {}).get("ips", {}).get("buckets", []):
                ip = str(b["key"])
                if wanted is not None and ip not in wanted:
                    continue
                a = out.setdefault(ip, IpActivity(ip))
                setattr(a, _ROLE[f], getattr(a, _ROLE[f]) + b["doc_count"])
                first, last = _iso(b["first"]), _iso(b["last"])
                if first and (a.first_seen is None or first < a.first_seen):
                    a.first_seen = first
                if last and (a.last_seen is None or last > a.last_seen):
                    a.last_seen = last
                a.max_severity = max(a.max_severity, int(b["sev"].get("value") or 0))
                for s in b["src"]["buckets"]:
                    a.sources[str(s["key"])] = a.sources.get(str(s["key"]), 0) + s["doc_count"]
                for p in b.get("ports", {}).get("buckets", []):
                    a.ports[int(p["key"])] = a.ports.get(int(p["key"]), 0) + p["doc_count"]
    return out, total


async def flows(
    search: OpenSearchBackend,
    tenant_id: uuid.UUID,
    start_iso: str,
    end_iso: str,
    *,
    sources: list[str] | None = None,
    min_severity: int = 0,
    ips: list[str] | None = None,
    limit: int = 1500,
) -> list[Flow]:
    """Source→destination pairs that the events themselves establish (both `network.src_ip` and `network.dst_ip` present).
    Internal↔internal pairs are excluded server-side; they can never be placed on a map."""
    flt = _base_filter(tenant_id, start_iso, end_iso, sources, min_severity)
    flt.append({"exists": {"field": SRC}})
    flt.append({"exists": {"field": DST}})
    if ips is not None:
        flt.append(
            {
                "bool": {
                    "should": [{"terms": {SRC: ips[:_TERMS_CHUNK]}}, {"terms": {DST: ips[:_TERMS_CHUNK]}}],
                    "minimum_should_match": 1,
                }
            }
        )
    must_not = [{"bool": {"filter": [_cidr_terms(SRC), _cidr_terms(DST)]}}]
    out: list[Flow] = []
    after: dict[str, Any] | None = None
    for _ in range(
        4
    ):  # bounded paging: at most 4 x 500 pairs, busiest-first is not guaranteed by composite, so cap and flag
        comp: dict[str, Any] = {
            "size": 500,
            "sources": [{"s": {"terms": {"field": SRC}}}, {"d": {"terms": {"field": DST}}}],
        }
        if after:
            comp["after"] = after
        body = {
            "size": 0,
            "query": {"bool": {"filter": flt, "must_not": must_not}},
            "aggs": {
                "f": {
                    "composite": comp,
                    "aggs": {
                        "first": {"min": {"field": "timestamp"}},
                        "last": {"max": {"field": "timestamp"}},
                        "sev": {"max": {"field": "severity"}},
                        "ports": {"terms": {"field": "network.dst_port", "size": 3}},
                        "src": {"terms": {"field": "source", "size": 3}},
                        "proto": {"terms": {"field": "network.protocol", "size": 2}},
                    },
                }
            },
        }
        agg = ((await _search(search, body)).get("aggregations") or {}).get("f", {"buckets": []})
        for b in agg["buckets"]:
            out.append(
                Flow(
                    src_ip=str(b["key"]["s"]),
                    dst_ip=str(b["key"]["d"]),
                    events=b["doc_count"],
                    first_seen=_iso(b["first"]),
                    last_seen=_iso(b["last"]),
                    max_severity=int(b["sev"].get("value") or 0),
                    ports=[int(p["key"]) for p in b["ports"]["buckets"]],
                    sources=[str(s["key"]) for s in b["src"]["buckets"]],
                    protocols=[str(p["key"]) for p in b["proto"]["buckets"]],
                )
            )
        after = agg.get("after_key")
        if not after or len(out) >= limit:
            break
    return out[:limit]


async def histogram(
    search: OpenSearchBackend,
    tenant_id: uuid.UUID,
    start_iso: str,
    end_iso: str,
    interval: str,
    *,
    sources: list[str] | None = None,
    min_severity: int = 0,
    ips: list[str] | None = None,
    only_ip_events: bool = True,
) -> list[tuple[str, int]]:
    """Events per time bucket. With `only_ip_events`, counts only events that carry at least one IP of interest."""
    flt = _base_filter(tenant_id, start_iso, end_iso, sources, min_severity)
    if ips is not None:
        flt.append(_ip_terms(ips[:_TERMS_CHUNK]))
    elif only_ip_events:
        flt.append({"bool": {"should": [{"exists": {"field": f}} for f in IP_FIELDS], "minimum_should_match": 1}})
    body = {
        "size": 0,
        "query": {"bool": {"filter": flt}},
        "aggs": {
            "h": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": start_iso, "max": end_iso},
                }
            }
        },
    }
    resp = await _search(search, body)
    return [
        (b["key_as_string"], b["doc_count"]) for b in (resp.get("aggregations") or {}).get("h", {}).get("buckets", [])
    ]


async def events_for_ip(
    search: OpenSearchBackend, tenant_id: uuid.UUID, ip: str, start_iso: str, end_iso: str, limit: int = 25
) -> tuple[list[dict[str, Any]], int]:
    flt = _base_filter(tenant_id, start_iso, end_iso, None, 0)
    flt.append(_ip_terms([ip]))
    body = {
        "size": limit,
        "track_total_hits": True,
        "sort": [{"timestamp": "desc"}],
        "_source": {"excludes": ["raw"]},
        "query": {"bool": {"filter": flt}},
    }
    resp = await _search(search, body)
    return [h["_source"] for h in resp["hits"]["hits"]], int(resp["hits"]["total"]["value"])


async def telemetry_sources(
    search: OpenSearchBackend, tenant_id: uuid.UUID, start_iso: str, end_iso: str
) -> tuple[list[dict[str, Any]], int]:
    """Which log sources contribute IP-bearing events in the window, and how many of those events carry a *mappable* (non-private) address.
    Drives the source filter and the honest empty state: a source whose events only carry private addresses can never put a marker on the map."""
    flt = _base_filter(tenant_id, start_iso, end_iso, None, 0)
    flt.append({"bool": {"should": [{"exists": {"field": f}} for f in IP_FIELDS], "minimum_should_match": 1}})
    mappable = {
        "filter": {
            "bool": {
                "should": [
                    {"bool": {"filter": [{"exists": {"field": f}}], "must_not": [_cidr_terms(f)]}} for f in IP_FIELDS
                ],
                "minimum_should_match": 1,
            }
        }
    }
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": flt}},
        "aggs": {"s": {"terms": {"field": "source", "size": 50}, "aggs": {"mappable": mappable}}},
    }
    resp = await _search(search, body)
    buckets = (resp.get("aggregations") or {}).get("s", {}).get("buckets", [])
    return [
        {"source": str(b["key"]), "events": b["doc_count"], "with_public_ip": int(b["mappable"]["doc_count"])}
        for b in buckets
    ], int(resp["hits"]["total"]["value"])


async def event_scope(
    search: OpenSearchBackend,
    tenant_id: uuid.UUID,
    start_iso: str,
    end_iso: str,
    *,
    sources: list[str] | None = None,
    min_severity: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Events carrying at least one IP address under the given filters (the "observed events" card), with a per-source breakdown."""
    flt = _base_filter(tenant_id, start_iso, end_iso, sources, min_severity)
    flt.append({"bool": {"should": [{"exists": {"field": f}} for f in IP_FIELDS], "minimum_should_match": 1}})
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": flt}},
        "aggs": {"s": {"terms": {"field": "source", "size": 50}}},
    }
    resp = await _search(search, body)
    buckets = (resp.get("aggregations") or {}).get("s", {}).get("buckets", [])
    return [{"source": str(b["key"]), "events": b["doc_count"]} for b in buckets], int(resp["hits"]["total"]["value"])
