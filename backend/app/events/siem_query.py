# ruff: noqa: E501
"""Live SIEM search: ask LogRhythm and Trend Vision One directly and show what they answer. Nothing is stored.

This is what the Events page is: the platform no longer copies the SIEMs' logs, so a search goes to the SIEMs themselves.
* The query is the same one the rest of the product speaks (free text, `field:value` language, filters, time range).
* Per source it is turned into the searches that source can really answer: LogRhythm with the filters verified on production (ADR 0020/0021),
  Trend Vision One with TMV1 queries. Whatever a source cannot express is reported ("can't be searched by ...") and applied to what comes back.
* EVERY returned record is normalised and checked locally against the whole query, so a loose vendor search can never show a false hit.
* Results are held server-side for 30 minutes under a `search_id`. Only when an analyst opens an event, or adds it to a case, is that one event
  imported into the platform (`import_events`); until then nothing is stored."""

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import registry as connectors
from app.connectors._http import SourceError
from app.connectors.base import NormalizationError
from app.connectors.logrhythm import ioa_searches, ioc_query_filter, text_searches
from app.core.config import Settings
from app.core.crypto import decrypt_json
from app.datasources.models import DataSource
from app.events import siem_search
from app.events.schema import Event
from app.events.search import local
from app.events.search.base import SearchBackend
from app.events.search.query import Condition, EventQuery, Filter, TimeRange
from app.iochunt import hunting

MAX_WINDOW = timedelta(days=14)
CAP_PER_SEARCH = 1500  # logs / events read per search
MAX_HITS = 500
BUDGET_S = 120
CACHE_TTL = 1800
MAX_TEXT_SEARCH_TOKENS = 1
TREND_DATASETS = ("endpoint_activity", "detections", "identity_activity")
_GATE = asyncio.Semaphore(3)


class SiemQuery(EventQuery):
    sources: list[uuid.UUID] = Field(
        default_factory=list, max_length=20
    )  # data sources to ask; empty = all searchable ones


# ---- the query ----------------------------------------------------------------------------------------
@dataclass
class Alt:
    pos: list[str] = field(default_factory=list)
    neg: list[str] = field(default_factory=list)


@dataclass
class Parsed:
    alts: list[Alt]
    filters: list[Filter]
    where: Condition | None
    terms: dict[str, list[str]]  # indicators (kind -> values) from filter fields and bare tokens
    words: list[str]  # positive free-text words, longest first


def parse_text(free: str) -> list[Alt]:
    """`a b` = both, `"a b"` = phrase, `-a` / `NOT a` = without, `x OR y` = alternatives (at most 4)."""
    alts, cur, neg_next = [Alt()], 0, False
    for tok in re.findall(r'"[^"]+"|\S+', free.replace("(", " ").replace(")", " ")):
        up = tok.upper()
        if up == "AND":
            continue
        if up == "OR":
            if len(alts) < 4:
                alts.append(Alt())
                cur += 1
            continue
        if up == "NOT":
            neg_next = True
            continue
        negated = neg_next or tok.startswith("-")
        neg_next = False
        word = tok.lstrip("-").strip('"').strip()
        if not word:
            continue
        (alts[cur].neg if negated else alts[cur].pos).append(word)
    return [a for a in alts if a.pos or a.neg]


def parse(query: EventQuery) -> Parsed:
    plan = siem_search.plan_for(query)
    free = " ".join(p for p in (query.q, query._parsed[0]) if p)
    alts = parse_text(free)
    words = sorted(
        {w for a in alts for w in a.pos if not siem_search.classify(w) and "*" not in w.strip("*")},
        key=len,
        reverse=True,
    )
    return Parsed(alts, query.effective_filters(), query.where, plan.terms, words)


# ---- local verification -------------------------------------------------------------------------------
def _blob(doc: dict[str, Any]) -> str:
    parts: list[str] = [str(doc.get("message") or ""), " ".join(doc.get("tags") or [])]
    for path in (
        "host.hostname", "user.name", "process.name", "process.command_line", "process.executable", "process.parent.name",
        "process.parent.command_line", "network.src_ip", "network.dst_ip", "network.dst_domain", "dns.question", "file.path",
        "file.name", "registry.key", "auth.source_ip",
    ):  # fmt: skip
        parts += [str(v) for v in local.values_at(doc, path)]
    parts += [str(v) for v in (doc.get("labels") or {}).values()]
    # the vendor's own scalar fields (a log carries more than the canonical schema keeps); an indicator still has to be a whole token in them
    parts += [str(v) for v in (doc.get("raw") or {}).values() if isinstance(v, str | int) and not isinstance(v, bool)]
    return " ".join(parts).lower()


def _has(word: str, blob: str) -> bool:
    w = word.lower()
    kind = siem_search.classify(w)
    if (
        kind
    ):  # an indicator is a whole token: 203.0.113.5 is not inside 203.0.113.50, a domain is not inside a longer one
        return bool(hunting._bounded(w, ip=kind == "ip").search(blob))  # noqa: SLF001
    return local.glob_match(f"*{w.strip('*')}*", blob) if "*" in w else w in blob


def accepts(parsed: Parsed, doc: dict[str, Any]) -> bool:
    """Does this record satisfy the whole query? The authority on what is shown, whatever the vendor returned."""
    if not all(local.matches_filter(f, doc) for f in parsed.filters):
        return False
    if parsed.where is not None and not local.matches(parsed.where, doc):
        return False
    if parsed.alts:
        blob = _blob(doc)
        if not any(all(_has(w, blob) for w in a.pos) and not any(_has(w, blob) for w in a.neg) for a in parsed.alts):
            return False
    return True


# ---- one source's answer ------------------------------------------------------------------------------
@dataclass
class SourceResult:
    id: str
    name: str
    kind: str
    status: str = "ok"  # ok | partial | error | not_applicable
    detail: str = ""
    searched: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    scanned: int = 0
    capped: bool = False
    ms: int = 0
    events: list[Event] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "kind": self.kind, "status": self.status, "detail": self.detail, "searched": self.searched,
            "skipped": self.skipped, "scanned": self.scanned, "matched": len(self.events), "capped": self.capped, "ms": self.ms,
        }  # fmt: skip


def _secrets(settings: Settings, ds: DataSource) -> dict[str, str]:
    return {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()} if ds.secrets_enc else {}


def _collect(res: SourceResult, conn: Any, raws: list[dict[str, Any]], parsed: Parsed, tenant_id: uuid.UUID) -> None:
    seen = {e.id for e in res.events}
    for raw in raws:
        try:
            evs = [Event.from_input(e, tenant_id) for e in conn.normalize(raw)]
        except NormalizationError:
            continue
        for ev in evs:
            if ev.id not in seen and accepts(parsed, ev.to_document()):
                seen.add(ev.id)
                res.events.append(ev)


def _lr_plan(parsed: Parsed) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """(label, search) pairs for LogRhythm, and notes on what it cannot be asked."""
    out: list[tuple[str, dict[str, Any]]] = []
    notes: list[str] = []
    batch = 100
    for kind, values in parsed.terms.items():
        for k in range(0, len(values), batch):
            vals = values[k : k + batch]
            out.append(
                (f"{kind}: {', '.join(vals[:3])}{' ...' if len(vals) > 3 else ''}", ioc_query_filter(kind, vals))
            )
    if out:
        return out, notes
    if parsed.filters:
        cond = Condition(all=[Condition(filter=f) for f in parsed.filters if not f.negate])
        if cond.all:
            searches, unsearchable = ioa_searches(cond)
            out += [("filters", s) for s in searches]
            if unsearchable or not searches:
                names = sorted({f.field for f in parsed.filters})
                notes.append(
                    "LogRhythm can't be searched by " + ", ".join(names) + "; they are applied to the logs it returns"
                )
    if out:
        return out, notes
    for w in parsed.words[:MAX_TEXT_SEARCH_TOKENS]:
        out += [(f"text: {w}", s) for s in text_searches(w)]
    if out:
        notes.append(
            "A bare word is looked for in process, command line, user, host, URL, reason and object; use field:value for anything else"
        )
    return out, notes


async def _run_lr(
    ds: DataSource, settings: Settings, parsed: Parsed, rng: TimeRange, tenant_id: uuid.UUID, deadline: float
) -> SourceResult:
    res = SourceResult(str(ds.id), ds.name, "logrhythm")
    searches, notes = _lr_plan(parsed)
    res.skipped += notes
    if not searches:
        res.status, res.detail = (
            "not_applicable",
            "Nothing here LogRhythm can be asked: search for an IP, domain, hash, e-mail, host, user, process, command line, or a word.",
        )
        return res
    secrets = _secrets(settings, ds)
    sem = asyncio.Semaphore(int((ds.config or {}).get("sweep_parallel", 2) or 2))
    raws: dict[Any, dict[str, Any]] = {}

    async def one(label: str, flt: dict[str, Any]) -> None:
        async with sem:
            if time.monotonic() > deadline:
                res.status = "partial"
                return
            conn: Any = connectors.build(
                "logrhythm", ds.config, secrets
            )  # own connector: the filter override is per instance
            conn._filter_override = flt
            logs = await conn._search_window(rng.start, rng.end, None, CAP_PER_SEARCH)
            res.searched.append(label)
            res.capped = res.capped or conn.capped
            for r in logs:
                raws[r.get("messageId")] = r

    try:
        await asyncio.gather(*(one(label, flt) for label, flt in searches))
        conn = connectors.build("logrhythm", ds.config, secrets)
        res.scanned = len(raws)
        _collect(res, conn, list(raws.values()), parsed, tenant_id)
        res.detail = f"{len(res.searched)} search(es) over the whole SIEM, {res.scanned} log(s) read, {len(res.events)} match the whole query"
    except (SourceError, ValueError) as exc:
        res.status, res.detail = "error", str(exc)[:240]
    return res


def _tq(field_: str, value: str, wildcard: bool = False) -> str:
    v = value.replace('"', " ")
    return f'{field_}:"*{v}*"' if wildcard else f'{field_}:"{v}"'


def _trend_queries(dataset: str, parsed: Parsed) -> tuple[list[str], list[str]]:
    """TMV1-Queries for a dataset, and notes on what it cannot be asked. Unknown fields fall back clause by clause (the local check decides)."""
    notes: list[str] = []
    out: list[str] = []
    iocs = [
        SimpleNamespace(type=k if k != "hostname" else "domain", value=v, id=f"{k}:{v}")
        for k, vs in parsed.terms.items()
        for v in vs
        if k != "hostname"
    ]
    for q, _chunk in hunting._trend_queries(dataset, iocs):  # type: ignore[arg-type]
        out.append(q)
    host_values = parsed.terms.get("hostname", [])
    if dataset == "endpoint_activity" and host_values:
        out.append(" OR ".join(_tq("endpointHostName", h) for h in host_values))
    if out:
        return out, notes
    if dataset == "endpoint_activity":
        clauses: list[str] = []
        for f in parsed.filters:
            vals = [str(v) for v in (f.value if isinstance(f.value, list) else [f.value]) if v is not None]
            if f.negate or not vals:
                continue
            wild = f.op in ("contains", "prefix", "wildcard")
            m = {
                "host.hostname": ["endpointHostName"], "user.name": ["logonUser", "processUser"], "process.name": ["objectName"],
                "process.command_line": ["objectCmd", "processCmd"], "network.dst_ip": ["dst"], "network.src_ip": ["src"],
                "dns.question": ["hostName"], "file.path": ["objectFilePath"],
            }.get(f.field)  # fmt: skip
            if not m:
                continue
            clauses.append(
                "("
                + " OR ".join(
                    _tq(fld, v if f.field != "process.name" else f"\\{v}", wild or f.field == "process.name")
                    for fld in m
                    for v in vals
                )
                + ")"
            )
        if clauses:
            out.append(" AND ".join(clauses))
            return out, notes
        for w in parsed.words[:MAX_TEXT_SEARCH_TOKENS]:
            out.append(
                " OR ".join(_tq(fld, w, True) for fld in ("objectCmd", "processCmd", "objectName", "endpointHostName"))
            )
        if out:
            notes.append(
                "A bare word is looked for in process, command line and host name; use field:value for anything else"
            )
    return out, notes


async def _run_trend(
    ds: DataSource, settings: Settings, parsed: Parsed, rng: TimeRange, tenant_id: uuid.UUID, deadline: float
) -> SourceResult:
    dataset = str((ds.config or {}).get("dataset", ""))
    res = SourceResult(str(ds.id), ds.name, f"trend:{dataset}")
    queries, notes = _trend_queries(dataset, parsed)
    res.skipped += notes
    if not queries:
        res.status, res.detail = (
            "not_applicable",
            f"Nothing in this search can be asked of Trend Vision One / {dataset}.",
        )
        return res
    try:
        conn: Any = connectors.build("trend_vision_one", ds.config, _secrets(settings, ds))
        raws: list[dict[str, Any]] = []
        for q in queries:
            if time.monotonic() > deadline:
                res.status = "partial"
                break
            try:
                got, cut = await conn.search_query(q, rng.start, rng.end, max_events=CAP_PER_SEARCH, deadline=deadline)
            except SourceError as exc:
                if "Unsupported query field" not in str(exc):
                    raise
                got, cut = [], False
                for single in hunting._split_clauses(q):  # drop the field this dataset does not know, keep the rest
                    try:
                        g, c = await conn.search_query(
                            single, rng.start, rng.end, max_events=CAP_PER_SEARCH, deadline=deadline
                        )
                        got += g
                        cut = cut or c
                    except SourceError as inner:
                        if "Unsupported query field" not in str(inner):
                            raise
            res.searched.append(q[:160])
            res.capped = res.capped or cut
            raws += got
        res.scanned = len(raws)
        _collect(res, conn, raws, parsed, tenant_id)
        res.detail = (
            f"{len(queries)} vendor query(ies), {res.scanned} event(s) read, {len(res.events)} match the whole query"
        )
    except (SourceError, ValueError) as exc:
        res.status, res.detail = "error", str(exc)[:240]
    return res


# ---- public API -----------------------------------------------------------------------------------------
async def searchable_sources(session: AsyncSession, tenant_id: uuid.UUID) -> list[DataSource]:
    rows = (
        await session.execute(
            select(DataSource).where(
                DataSource.tenant_id == tenant_id, DataSource.connector_type.in_(("logrhythm", "trend_vision_one"))
            ).order_by(DataSource.name)
        )
    ).scalars().all()  # fmt: skip
    out = []
    for ds in rows:
        cfg = ds.config or {}
        lr = ds.connector_type == "logrhythm" and cfg.get("siem_search") is not False
        trend = ds.connector_type == "trend_vision_one" and cfg.get("dataset") in TREND_DATASETS
        if lr or trend:
            out.append(ds)
    return out


def cache_key(tenant_id: uuid.UUID, search_id: str) -> str:
    return f"siemq:{tenant_id}:{search_id}"


async def search(
    session: AsyncSession,
    redis: Any | None,
    settings: Settings,
    tenant_id: uuid.UUID,
    query: SiemQuery,
    budget_s: int = BUDGET_S,
) -> dict[str, Any]:
    t0 = time.monotonic()
    parsed = parse(query)
    rng = query.effective_range()
    note = ""
    if rng.end - rng.start > MAX_WINDOW:
        rng = TimeRange(start=rng.end - MAX_WINDOW, end=rng.end)
        note = f"The SIEMs are searched over at most the last {MAX_WINDOW.days} days of your range."
    sources = await searchable_sources(session, tenant_id)
    if query.sources:
        sources = [d for d in sources if d.id in set(query.sources)]
    empty = not (parsed.alts or parsed.filters or parsed.where is not None or parsed.terms)
    results: list[SourceResult] = []
    if sources and not empty:
        deadline = time.monotonic() + budget_s

        async def go(ds: DataSource) -> SourceResult:
            async with _GATE:
                fn = _run_lr if ds.connector_type == "logrhythm" else _run_trend
                started = time.monotonic()
                r = await fn(ds, settings, parsed, rng, tenant_id, deadline)
                r.ms = int((time.monotonic() - started) * 1000)
                return r

        results = list(await asyncio.gather(*(go(d) for d in sources)))
    events: dict[str, Event] = {}
    origin: dict[str, str] = {}  # event id -> the data source that returned it (the first one, if several did)
    for r in results:
        for e in r.events:
            events.setdefault(e.id, e)
            origin.setdefault(e.id, r.id)
    ordered = sorted(events.values(), key=lambda e: e.timestamp, reverse=True)
    truncated = len(ordered) > MAX_HITS
    ordered = ordered[:MAX_HITS]
    search_id = uuid.uuid4().hex
    docs = [e.to_document() for e in ordered]
    if docs and redis is not None:
        await redis.set(cache_key(tenant_id, search_id), json.dumps(docs), ex=CACHE_TTL)
    return {
        "search_id": search_id,
        "hits": docs,
        "origins": {d["id"]: origin[d["id"]] for d in docs},
        "total": len(docs),
        "truncated": truncated or any(r.capped for r in results),
        "sources": [r.public() for r in results],
        "empty_query": empty,
        "no_sources": not sources,
        "note": note,
        "time_range": {"start": rng.start.isoformat(), "end": rng.end.isoformat()},
        "took_ms": int((time.monotonic() - t0) * 1000),
    }


async def store_docs(backend: SearchBackend, tenant_id: uuid.UUID, docs: list[dict[str, Any]]) -> int:
    """Store these result documents (server-produced, so trusted) as events. Returns how many were new."""
    events = [Event.model_validate(d) for d in docs if str(d.get("tenant_id")) == str(tenant_id)]
    res = await backend.index_events(events) if events else None
    if events:
        await backend.refresh()
    return res.accepted if res else 0


# What each kind of SIEM source CAN hold, as event types of the canonical schema. This is the connector's capability, not a claim that the
# data is present: it tells an investigator which questions can be put to a source at all.
LIVE_TYPES: dict[str, list[str]] = {
    "logrhythm": ["authentication", "network_connection", "alert", "other"],
    "trend:endpoint_activity": ["process_creation", "network_connection", "dns_query", "file_event"],
    "trend:detections": ["alert"],
    "trend:identity_activity": ["authentication"],
}


def kind_of(ds: DataSource) -> str:
    return "logrhythm" if ds.connector_type == "logrhythm" else f"trend:{(ds.config or {}).get('dataset', '')}"


async def live_sources(session: AsyncSession, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    return [
        {"name": d.name, "kind": kind_of(d), "event_types": LIVE_TYPES.get(kind_of(d), [])}
        for d in await searchable_sources(session, tenant_id)
    ]


async def import_events(
    redis: Any, backend: SearchBackend, tenant_id: uuid.UUID, search_id: str, ids: list[str]
) -> dict[str, int]:
    """Store the chosen events of a held result so they can be opened, pivoted on and added to cases. Only what was asked for."""
    raw = await redis.get(cache_key(tenant_id, search_id))
    if raw is None:
        return {"requested": len(ids), "imported": 0, "expired": 1}
    wanted = set(ids)
    docs = [d for d in json.loads(raw) if d.get("id") in wanted]
    events = [Event.model_validate(d) for d in docs if str(d.get("tenant_id")) == str(tenant_id)]
    res = await backend.index_events(events) if events else None
    if events:
        await backend.refresh()
    return {
        "requested": len(ids),
        "imported": res.accepted if res else 0,
        "duplicates": res.duplicates if res else 0,
        "expired": 0,
    }
