"""The automatic IOC hunt: search every available data source for a batch of validated indicators.

Adapters
* local      - the tenant's own OpenSearch index (everything already ingested, from every connector).
* trend      - Trend Vision One *upstream* search (full vendor retention, not just what we ingested). A data source that is disabled for
               ingestion (e.g. endpoint telemetry paused for capacity) is still searchable here.
* logrhythm  - LogRhythm upstream search, when the source carries console-captured filter templates; otherwise only ingested LR data
               (via the local adapter) is covered, and the coverage report says so.

Every candidate event is *attributed*: we re-check which indicator it really contains, so a loose vendor query can never create a false
match. Matched upstream events are indexed so cases can cite them as evidence."""

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import registry as connectors
from app.connectors._http import SourceError
from app.connectors.base import NormalizationError
from app.core.config import Settings
from app.core.crypto import decrypt_json
from app.datasources.models import DataSource
from app.events.schema import Event
from app.events.search.base import SearchBackend
from app.events.search.local import values_at
from app.events.search.query import EventQuery, Filter, Sort, TimeRange
from app.events.summary import summarize
from app.iochunt.models import Ioc, IocHunt, IocMatch

log = logging.getLogger("app.iochunt")

ADAPTER_BUDGET_S = 240
LOCAL_PAGE = 200
MAX_TEXT_QUERIES = 150
TREND_CHUNK_IOCS = 12
TREND_CHUNK_CHARS = 900
MAX_UPSTREAM_EVENTS = 3000

# ---- attribution ---------------------------------------------------------------------------------------
_EXACT: dict[str, list[str]] = {
    "ip": ["network.dst_ip", "network.src_ip", "auth.source_ip", "dns.answers"],
    "domain": ["dns.question", "network.dst_domain"],
    "md5": ["process.hash.md5", "file.hash.md5", "process.parent.hash.md5"],
    "sha1": ["process.hash.sha1", "file.hash.sha1"],
    "sha256": ["process.hash.sha256", "file.hash.sha256"],
}
_TEXT = [
    "process.command_line",
    "process.parent.command_line",
    "message",
    "file.path",
    "registry.value",
    "dns.question",
    "network.dst_domain",
    "user.name",
]


def _text_blobs(doc: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for path in _TEXT:
        for v in values_at(doc, path):
            if isinstance(v, str):
                out.append(v.lower())
    return out


def _bounded(needle: str, *, ip: bool = False) -> re.Pattern[str]:
    """Whole-token match. A domain matches as a host suffix (subdomains count) but never inside a longer name, and an IPv4
    address never inside a longer dotted number: 'evil.example' is not in 'notevil.example' or 'evil.example.org'."""
    if ip:
        return re.compile(r"(?<![0-9.])" + re.escape(needle) + r"(?![0-9]|\.[0-9])")
    return re.compile(r"(?<![a-z0-9_-])" + re.escape(needle) + r"(?![a-z0-9_-]|\.[a-z0-9])")


def attribute(doc: dict[str, Any], iocs: list[Ioc]) -> list[tuple[Ioc, str]]:
    """Which of these indicators does this event genuinely contain, and in which field?"""
    found: list[tuple[Ioc, str]] = []
    blobs: list[str] | None = None
    for ioc in iocs:
        val = ioc.value.lower()
        hit = ""
        for path in _EXACT.get(ioc.type, []):
            if any(isinstance(v, str) and v.lower() == val for v in values_at(doc, path)):
                hit = path
                break
        if not hit and ioc.type in ("domain", "ip", "url", "email"):
            blobs = blobs if blobs is not None else _text_blobs(doc)
            if ioc.type == "url":
                needle = val.rstrip("/")
                if any(needle in b for b in blobs):
                    hit = "text"
            elif ioc.type == "email":
                if any(val in b for b in blobs):
                    hit = "text"
            else:
                pat = _bounded(val, ip=ioc.type == "ip")
                if any(pat.search(b) for b in blobs):
                    hit = "text"
        if hit:
            found.append((ioc, hit))
    return found


@dataclass
class Hit:
    ioc: Ioc
    doc: dict[str, Any]
    field: str
    source: str


@dataclass
class Coverage:
    source: str
    kind: str
    status: str = "ok"  # ok | truncated | error | skipped
    detail: str = ""
    iocs_searched: int = 0
    hits: int = 0
    ms: int = 0

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class AdapterResult:
    hits: list[Hit] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)


def _host_of(value: str) -> str:
    from urllib.parse import urlsplit

    try:
        return (urlsplit(value).hostname or "").lower()
    except ValueError:
        return ""


# ---- local index -----------------------------------------------------------------------------------
async def search_local(
    backend: SearchBackend, tenant_id: uuid.UUID, iocs: list[Ioc], start: datetime, end: datetime
) -> AdapterResult:
    t0 = time.monotonic()
    tr = TimeRange(start=start, end=end)
    cov = Coverage("Ingested telemetry", "local", iocs_searched=len(iocs))
    docs: dict[str, dict[str, Any]] = {}
    truncated = False

    async def run(filters: list[Filter] | None = None, q: str | None = None) -> None:
        nonlocal truncated
        res = await backend.search(
            tenant_id,
            EventQuery(
                time_range=tr,
                limit=LOCAL_PAGE,
                filters=filters or [],
                q=q,
                sort=[Sort(field="timestamp", order="desc")],
            ),
        )
        truncated = truncated or res.total > LOCAL_PAGE
        docs.update({h["id"]: h for h in res.hits})

    by_type: dict[str, list[Ioc]] = {}
    for i in iocs:
        by_type.setdefault(i.type, []).append(i)
    for typ, group in by_type.items():
        for fld in _EXACT.get(typ, []):
            for k in range(0, len(group), 100):
                await run(filters=[Filter(field=fld, op="in", value=[g.value for g in group[k : k + 100]])])
    text_iocs = [i for i in iocs if i.type in ("domain", "url", "email", "ip")][:MAX_TEXT_QUERIES]
    for i in text_iocs:
        needle = _host_of(i.value) if i.type == "url" else i.value
        if needle and i.type != "email":
            await run(filters=[Filter(field="process.command_line", op="contains", value=needle[:128])])
        if i.type in ("url", "email"):
            await run(q='"' + i.value.replace('"', " ")[:200] + '"')
    hits: list[Hit] = []
    for doc in docs.values():
        for ioc, fld in attribute(doc, iocs):
            hits.append(Hit(ioc, doc, fld, str(doc.get("source", "local"))))
    cov.hits = len(hits)
    cov.ms = int((time.monotonic() - t0) * 1000)
    cov.status = "truncated" if truncated else "ok"
    srcs = sorted({h.source for h in hits})
    cov.detail = (f"matches in: {', '.join(srcs)}" if srcs else "no matches in ingested events") + (
        "; result window was capped, narrow the lookback to see all" if truncated else ""
    )
    return AdapterResult(hits, [cov])


# ---- Trend Vision One upstream -----------------------------------------------------------------------------
def _q(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"')


def _clause(field_: str, value: str, wildcard: bool) -> str:
    return f'{field_}:"*{_q(value)}*"' if wildcard else f'{field_}:"{_q(value)}"'


# dataset -> IOC type -> [(vendor field, wildcard?)]
TREND_FIELDS: dict[str, dict[str, list[tuple[str, bool]]]] = {
    "endpoint_activity": {
        "ip": [("dst", False), ("src", False), ("objectIps", False)],
        "domain": [("hostName", False), ("processCmd", True), ("objectCmd", True)],
        "url": [("processCmd", True), ("objectCmd", True)],
        "sha256": [("objectFileHashSha256", False), ("processFileHashSha256", False), ("parentFileHashSha256", False)],
        "sha1": [("objectFileHashSha1", False), ("processFileHashSha1", False)],
        "md5": [("objectFileHashMd5", False), ("processFileHashMd5", False)],
    },
    "detections": {
        "domain": [("processCmd", True)],
        "url": [("processCmd", True)],
        "sha256": [("fileHashSha256", False)],
    },
    "identity_activity": {"ip": [("ipAddress", False)], "email": [("principalName", False)]},
}


# Hosts that serve huge amounts of benign content: a host-only search would drown in noise, so a URL on one of these is only
# searched upstream when it has a distinctive path segment.
SHARED_HOSTS = (
    "github.com",
    "githubusercontent.com",
    "gist.github.com",
    "pastebin.com",
    "paste.ee",
    "discord.com",
    "discordapp.com",
    "dropbox.com",
    "dropboxusercontent.com",
    "drive.google.com",
    "docs.google.com",
    "storage.googleapis.com",
    "onedrive.live.com",
    "sharepoint.com",
    "blob.core.windows.net",
    "amazonaws.com",
    "cloudfront.net",
    "t.me",
    "telegram.org",
    "bit.ly",
    "tinyurl.com",
    "gitlab.com",
    "bitbucket.org",
    "mediafire.com",
    "mega.nz",
    "ipfs.io",
    "workers.dev",
    "pages.dev",
)
_SEGMENT = re.compile(r"[A-Za-z0-9._-]{6,}")


def _distinctive_segment(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    segs = [s for s in path.split("/") if _SEGMENT.fullmatch(s)]
    return max(segs, key=len) if segs else None


def _url_clause(ioc: Ioc, fields: list[tuple[str, bool]]) -> str | None:
    host = _host_of(ioc.value)
    if not host:
        return None
    seg = _distinctive_segment(ioc.value)
    shared = any(host == h or host.endswith("." + h) for h in SHARED_HOSTS)
    if shared and not seg:
        return None  # cannot be searched selectively
    parts = []
    for fld, wild in fields:
        if not wild:
            continue
        parts.append(f"({_clause(fld, host, True)} AND {_clause(fld, seg, True)})" if seg else _clause(fld, host, True))
    return " OR ".join(parts) or None


def _trend_queries(dataset: str, iocs: list[Ioc]) -> list[tuple[str, list[Ioc]]]:
    """(query, iocs it covers) chunks, each short enough for the vendor's query limit."""
    spec = TREND_FIELDS.get(dataset, {})
    pairs: list[tuple[Ioc, str]] = []
    for i in iocs:
        fields = spec.get(i.type)
        if not fields:
            continue
        if i.type == "url":
            clause = _url_clause(i, fields)
            if clause:
                pairs.append((i, clause))
            continue
        if not i.value:
            continue
        pairs.append((i, " OR ".join(_clause(f, i.value, w) for f, w in fields)))
    chunks: list[tuple[str, list[Ioc]]] = []
    cur: list[str] = []
    cur_iocs: list[Ioc] = []
    size = 0
    for ioc, clause in pairs:
        if cur and (size + len(clause) + 4 > TREND_CHUNK_CHARS or len(cur_iocs) >= TREND_CHUNK_IOCS):
            chunks.append((" OR ".join(cur), cur_iocs))
            cur, cur_iocs, size = [], [], 0
        cur.append(clause)
        cur_iocs.append(ioc)
        size += len(clause) + 4
    if cur:
        chunks.append((" OR ".join(cur), cur_iocs))
    return chunks


async def search_trend(
    session: AsyncSession,
    backend: SearchBackend,
    settings: Settings,
    tenant_id: uuid.UUID,
    iocs: list[Ioc],
    start: datetime,
    end: datetime,
) -> AdapterResult:
    result = AdapterResult()
    sources = (
        (
            await session.execute(
                select(DataSource).where(
                    DataSource.tenant_id == tenant_id, DataSource.connector_type == "trend_vision_one"
                )
            )
        )
        .scalars()
        .all()
    )
    for ds in sources:
        dataset = str((ds.config or {}).get("dataset", ""))
        name = f"Trend Vision One / {dataset}"
        if dataset not in TREND_FIELDS:
            continue  # alerts/OAT/audit... have no IOC query surface; their ingested events are covered by the local adapter
        cov = Coverage(name, f"trend:{dataset}")
        t0 = time.monotonic()
        try:
            secrets = {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()} if ds.secrets_enc else {}
            conn: Any = connectors.build("trend_vision_one", ds.config, secrets)
            queries = _trend_queries(dataset, iocs)
            if not queries:
                cov.status, cov.detail = "skipped", "no searchable indicator types for this dataset"
                result.coverage.append(cov)
                continue
            cov.iocs_searched = sum(len(c[1]) for c in queries)
            skipped_urls = [
                i
                for i in iocs
                if i.type == "url"
                and "url" in TREND_FIELDS[dataset]
                and _url_clause(i, TREND_FIELDS[dataset]["url"]) is None
            ]
            deadline = time.monotonic() + ADAPTER_BUDGET_S
            hits: dict[tuple[str, str], Hit] = {}
            truncated = False
            for query, chunk in queries:
                try:
                    raws, cut = await conn.search_query(
                        query, start, end, max_events=MAX_UPSTREAM_EVENTS, deadline=deadline
                    )
                except SourceError as exc:
                    if "Unsupported query field" not in str(exc):
                        raise
                    raws, cut = [], False
                    for single in _split_clauses(query):  # drop the field this dataset does not know, keep the rest
                        try:
                            r, c = await conn.search_query(
                                single, start, end, max_events=MAX_UPSTREAM_EVENTS, deadline=deadline
                            )
                            raws += r
                            cut = cut or c
                        except SourceError as inner:
                            if "Unsupported query field" not in str(inner):
                                raise
                truncated = truncated or cut
                events: list[Event] = []
                for raw in raws:
                    try:
                        events += [Event.from_input(e, tenant_id) for e in conn.normalize(raw)]
                    except NormalizationError:
                        continue
                docs = [e.to_document() for e in events]
                matched: list[tuple[Event, dict[str, Any], list[tuple[Ioc, str]]]] = []
                for ev, doc in zip(events, docs, strict=True):
                    attrib = attribute(doc, chunk)
                    if attrib:
                        matched.append((ev, doc, attrib))
                if matched:
                    await backend.index_events([m[0] for m in matched])  # matched events become citable evidence
                for _ev, doc, attrib in matched:
                    for ioc, fld in attrib:
                        hits.setdefault((str(ioc.id), doc["id"]), Hit(ioc, doc, fld, "trend_vision_one"))
            if hits:
                await backend.refresh()  # imported events must be readable before a case cites them
            result.hits += list(hits.values())
            cov.hits = len(hits)
            cov.status = "truncated" if truncated else "ok"
            cov.detail = (
                f"{len(queries)} vendor queries over the last {(end - start).days or 1} day(s)"
                + ("; result cap reached" if truncated else "")
                + (
                    f"; {len(skipped_urls)} URL(s) on shared hosting (e.g. GitHub) without a distinctive path were not searched upstream"
                    if skipped_urls
                    else ""
                )
            )
        except (SourceError, ValueError) as exc:
            cov.status, cov.detail = "error", str(exc)[:240]
        cov.ms = int((time.monotonic() - t0) * 1000)
        result.coverage.append(cov)
    return result


def _split_clauses(query: str) -> list[str]:
    return [c for c in re.split(r"\s+OR\s+(?=[A-Za-z]+:\")", query) if c]


# ---- LogRhythm upstream (template based) ---------------------------------------------------------------------
async def search_logrhythm(
    session: AsyncSession,
    backend: SearchBackend,
    settings: Settings,
    tenant_id: uuid.UUID,
    iocs: list[Ioc],
    start: datetime,
    end: datetime,
) -> AdapterResult:
    from app.connectors.logrhythm import search_ioc

    result = AdapterResult()
    sources = (
        (
            await session.execute(
                select(DataSource).where(DataSource.tenant_id == tenant_id, DataSource.connector_type == "logrhythm")
            )
        )
        .scalars()
        .all()
    )
    for ds in sources:
        cov = Coverage("LogRhythm SIEM", "logrhythm")
        templates = (ds.config or {}).get("ioc_filter_templates") or {}
        if not templates:
            cov.status = "skipped"
            cov.detail = "no ioc_filter_templates configured: only already-ingested LogRhythm events were searched (see 'Ingested telemetry')"
            result.coverage.append(cov)
            continue
        t0 = time.monotonic()
        try:
            secrets = {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()} if ds.secrets_enc else {}
            conn: Any = connectors.build("logrhythm", ds.config, secrets)
            searchable = [i for i in iocs if i.type in templates][:25]  # bound the load on the SIEM
            cov.iocs_searched = len(searchable)
            hits: dict[tuple[str, str], Hit] = {}
            deadline = time.monotonic() + ADAPTER_BUDGET_S
            for ioc in searchable:
                if time.monotonic() > deadline:
                    cov.status = "truncated"
                    break
                logs = await search_ioc(conn, ioc.type, ioc.value, start, end)
                events: list[Event] = []
                for raw in logs[:2000]:
                    try:
                        events += [Event.from_input(e, tenant_id) for e in conn.normalize(raw)]
                    except NormalizationError:
                        continue
                matched = [(ev, ev.to_document()) for ev in events]
                matched = [(ev, d) for ev, d in matched if attribute(d, [ioc])]
                if matched:
                    await backend.index_events([m[0] for m in matched])
                for _ev, doc in matched:
                    hits.setdefault((str(ioc.id), doc["id"]), Hit(ioc, doc, "logrhythm", "logrhythm"))
            if hits:
                await backend.refresh()
            result.hits += list(hits.values())
            cov.hits = len(hits)
            if len([i for i in iocs if i.type in templates]) > 25:
                cov.status, cov.detail = "truncated", "only the first 25 indicators were sent to LogRhythm"
            elif not cov.detail:
                cov.detail = f"{cov.iocs_searched} filtered searches"
        except (SourceError, ValueError) as exc:
            cov.status, cov.detail = "error", str(exc)[:240]
        cov.ms = int((time.monotonic() - t0) * 1000)
        result.coverage.append(cov)
    return result


# ---- orchestration -------------------------------------------------------------------------------------
async def execute(
    session: AsyncSession, backend: SearchBackend, settings: Settings, hunt: IocHunt, iocs: list[Ioc]
) -> tuple[list[Hit], list[Coverage]]:
    end = hunt.window_end or datetime.now(UTC)
    start = hunt.window_start or end - timedelta(days=hunt.lookback_days)
    results = await asyncio.gather(
        search_local(backend, hunt.tenant_id, iocs, start, end),
        search_trend(session, backend, settings, hunt.tenant_id, iocs, start, end),
        search_logrhythm(session, backend, settings, hunt.tenant_id, iocs, start, end),
        return_exceptions=True,
    )
    hits: list[Hit] = []
    coverage: list[Coverage] = []
    for name, r in zip(("Ingested telemetry", "Trend Vision One", "LogRhythm SIEM"), results, strict=True):
        if isinstance(r, BaseException):
            log.warning("hunt adapter failed", extra={"adapter": name, "error": type(r).__name__})
            coverage.append(Coverage(name, "error", "error", f"{type(r).__name__}: {str(r)[:200]}"))
            continue
        hits += r.hits
        coverage += r.coverage
    # one match per (ioc, event); keep the strongest field label
    uniq: dict[tuple[str, str], Hit] = {}
    for h in hits:
        uniq.setdefault((str(h.ioc.id), h.doc["id"]), h)
    return list(uniq.values()), coverage


async def persist_matches(session: AsyncSession, hunt: IocHunt, hits: list[Hit]) -> set[tuple[str, str]]:
    """Store matches; returns the (ioc_id, event_id) pairs that were not known before (what a re-hunt reports as new)."""
    new: set[tuple[str, str]] = set()
    for h in hits:
        doc = h.doc
        host = (doc.get("host") or {}).get("hostname") or ""
        user = (doc.get("user") or {}).get("name") or ""
        ts = datetime.fromisoformat(str(doc["timestamp"]).replace("Z", "+00:00"))
        res = await session.execute(
            insert(IocMatch)
            .values(
                id=uuid.uuid4(),
                tenant_id=hunt.tenant_id,
                hunt_id=hunt.id,
                ioc_id=h.ioc.id,
                event_id=doc["id"],
                event_timestamp=ts,
                source=h.source[:64],
                matched_field=h.field[:64],
                host=str(host)[:256],
                user=str(user)[:256],
                summary=summarize(doc)[:500],
            )
            .on_conflict_do_nothing(constraint="uq_ioc_match")
            .returning(IocMatch.id)
        )
        if res.first():
            new.add((str(h.ioc.id), doc["id"]))
    return new
