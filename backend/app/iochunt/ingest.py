"""Feed ingestion: normalise -> guard-rails -> age/confidence/cap -> idempotent upsert -> expiry -> prescreen.

Guard-rails follow MISP warning-lists / RFC 9424 practice: indicators that would only create false positives (private addresses, public
resolvers, empty-file hashes, big benign domains, the tenant's own allow-list) never enter the database, and old indicators leave it."""

import ipaddress
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import literal_column, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors._http import SourceError
from app.core.config import Settings
from app.core.crypto import decrypt_json
from app.events.search.base import SearchBackend
from app.events.search.query import Aggregation, EventQuery, Filter, TimeRange
from app.intel import types as intel_types
from app.investigations import iocs as ioc_rules
from app.iochunt.feeds import registry
from app.iochunt.feeds.base import RawIoc
from app.iochunt.models import Ioc, IocAllow, IocFeed

log = logging.getLogger("app.iochunt")

MANUAL_MAX_AGE_DAYS = 30
VALIDATED_WATCH_DAYS = 30  # a validated IOC is re-hunted for this long, then retired
BATCH = 500

# Never useful as indicators: they match enormous amounts of benign traffic.
BENIGN_IPS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "4.2.2.2",
    "0.0.0.0",  # noqa: S104  # nosec B104 (a value we refuse to import, not a bind address)
    "255.255.255.255",
}
BENIGN_DOMAINS = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "office.com",
    "office365.com",
    "live.com",
    "msftconnecttest.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "amazon.com",
    "facebook.com",
    "youtube.com",
    "wikipedia.org",
    "mozilla.org",
    "digicert.com",
    "letsencrypt.org",
    "localhost",
}
EMPTY_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\(at\)"), "@"),
]


def refang(value: str) -> str:
    v = value.strip()
    for pattern, repl in _REFANG:
        v = pattern.sub(repl, v)
    return v


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _domain_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def rejected_reason(typ: str, value: str, allow: list[tuple[str, str]]) -> str | None:
    """Why this (already normalised) value must not be imported, or None."""
    if typ == "ip":
        if ioc_rules.is_internal_ip(value) or value in BENIGN_IPS:
            return "private or well-known benign address"
        host_candidates = [value]
    elif typ == "domain":
        if value.endswith(ioc_rules._INTERNAL_SUFFIXES) or any(_domain_matches(value, d) for d in BENIGN_DOMAINS):
            return "internal or well-known benign domain"
        host_candidates = [value]
    elif typ == "url":
        host = _host_of(value)
        if host.endswith(ioc_rules._INTERNAL_SUFFIXES) or (host and _is_ip(host) and ioc_rules.is_internal_ip(host)):
            return "internal URL"
        host_candidates = [host] if host else []
    elif typ in ("md5", "sha1", "sha256"):
        if value in EMPTY_HASHES:
            return "hash of an empty file"
        host_candidates = []
    elif typ == "email":
        host_candidates = [value.rsplit("@", 1)[-1]]
    else:
        host_candidates = []
    for a_type, a_value in allow:
        if a_type == typ and a_value == value:
            return "allow-listed"
        if a_type == "domain" and any(_domain_matches(h, a_value) for h in host_candidates):
            return "allow-listed domain"
        if a_type == "ip" and typ == "url" and _host_of(value) == a_value:
            return "allow-listed host"
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@dataclass
class Prepared:
    type: str
    value: str
    raw: RawIoc
    first_seen: datetime
    last_seen: datetime


@dataclass
class FeedRunResult:
    fetched: int = 0
    accepted: int = 0
    new: int = 0
    updated: int = 0
    dropped: dict[str, int] = field(default_factory=dict)

    def drop(self, why: str) -> None:
        self.dropped[why] = self.dropped.get(why, 0) + 1

    def detail(self) -> str:
        parts = [f"{self.fetched} fetched", f"{self.new} new", f"{self.updated} refreshed"]
        if self.dropped:
            parts.append(
                "dropped: " + ", ".join(f"{n} {w}" for w, n in sorted(self.dropped.items(), key=lambda kv: -kv[1])[:4])
            )
        return "; ".join(parts)[:300]


def prepare(
    raws: list[RawIoc],
    *,
    max_age_days: int,
    min_confidence: int,
    max_items: int,
    allow: list[tuple[str, str]],
    now: datetime,
) -> tuple[list[Prepared], FeedRunResult]:
    res = FeedRunResult(fetched=len(raws))
    floor = now - timedelta(days=max_age_days)
    best: dict[tuple[str, str], Prepared] = {}
    for r in raws:
        value = refang(r.value)
        typ = r.type or intel_types.detect_type(value)
        if typ is None or typ not in intel_types.INDICATOR_TYPES or typ == "certificate":
            res.drop("unrecognised")
            continue
        norm = intel_types.normalize(typ, value)
        if norm is None:
            res.drop("invalid")
            continue
        seen_basis = r.last_seen or r.first_seen or now
        first = r.first_seen or seen_basis
        if max(seen_basis, first) < floor:
            res.drop("too old")
            continue
        if r.valid_until is not None and r.valid_until < now:
            res.drop("expired")
            continue
        if r.confidence < min_confidence:
            res.drop("low confidence")
            continue
        why = rejected_reason(typ, norm, allow)
        if why:
            res.drop(why.split(" ")[0] if "allow" not in why else "allow-listed")
            continue
        prep = Prepared(typ, norm, r, min(first, seen_basis), max(first, seen_basis))
        cur = best.get((typ, norm))
        if cur is None or prep.raw.confidence > cur.raw.confidence or prep.last_seen > cur.last_seen:
            best[(typ, norm)] = prep
    ordered = sorted(best.values(), key=lambda p: (p.raw.confidence, p.last_seen), reverse=True)
    if len(ordered) > max_items:
        res.dropped["over item cap"] = len(ordered) - max_items
        ordered = ordered[:max_items]
    res.accepted = len(ordered)
    return ordered, res


async def allow_pairs(session: AsyncSession, tenant_id: uuid.UUID) -> list[tuple[str, str]]:
    rows = (await session.execute(select(IocAllow.type, IocAllow.value).where(IocAllow.tenant_id == tenant_id))).all()
    return [(t, v) for t, v in rows]


async def store(
    session: AsyncSession,
    feed: IocFeed | None,
    tenant_id: uuid.UUID,
    items: list[Prepared],
    res: FeedRunResult,
    source: str,
) -> None:
    for i in range(0, len(items), BATCH):
        chunk = items[i : i + BATCH]
        ins = insert(Ioc).values(
            [
                dict(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    feed_id=feed.id if feed else None,
                    source=source[:64],
                    type=p.type,
                    value=p.value,
                    confidence=max(0, min(100, p.raw.confidence)),
                    first_seen=p.first_seen,
                    last_seen=p.last_seen,
                    valid_until=p.raw.valid_until,
                    threat_type=p.raw.threat_type[:64],
                    malware=p.raw.malware[:120],
                    description=p.raw.description[:1000],
                    reference=p.raw.reference[:500],
                    tags=list(dict.fromkeys(p.raw.tags))[:15],
                    techniques=p.raw.techniques[:10],
                    status="NEW",
                )
                for p in chunk
            ]
        )
        stmt: Any = ins.on_conflict_do_update(
            constraint="uq_ioc",
            set_={
                "last_seen": ins.excluded.last_seen,
                "valid_until": ins.excluded.valid_until,
                "confidence": ins.excluded.confidence,
                # a re-sighted expired indicator is live again; validated/rejected decisions are never overridden
                "status": Ioc.status,
            },
            where=(Ioc.last_seen < ins.excluded.last_seen) | (Ioc.confidence < ins.excluded.confidence),
        ).returning(Ioc.id, literal_column("(xmax = 0)").label("fresh"))
        rows = (await session.execute(stmt)).all()
        res.new += sum(1 for r in rows if r.fresh)
        res.updated += sum(1 for r in rows if not r.fresh)
    await session.execute(
        update(Ioc)
        .where(
            Ioc.tenant_id == tenant_id, Ioc.status == "EXPIRED", Ioc.last_seen >= datetime.now(UTC) - timedelta(days=1)
        )
        .values(status="NEW", status_reason="re-sighted by feed")
    )


async def run_feed(
    session: AsyncSession, settings: Settings, feed: IocFeed, *, now: datetime | None = None
) -> FeedRunResult:
    """Fetch one feed and persist. Never raises: failures are recorded on the feed."""
    now = now or datetime.now(UTC)
    result = FeedRunResult()
    try:
        secrets = {k: str(v) for k, v in decrypt_json(settings, feed.secrets_enc).items()} if feed.secrets_enc else {}
        impl = registry.build(feed.feed_type, feed.config, secrets)
        raws = await impl.fetch(feed.last_run_at, feed.max_age_days)
        items, result = prepare(
            raws,
            max_age_days=feed.max_age_days,
            min_confidence=feed.min_confidence,
            max_items=feed.max_items,
            allow=await allow_pairs(session, feed.tenant_id),
            now=now,
        )
        await store(session, feed, feed.tenant_id, items, result, feed.name)
        feed.last_status, feed.last_detail = "ok", result.detail()
        feed.last_new, feed.last_seen_total = result.new, result.accepted
    except SourceError as exc:
        feed.last_status, feed.last_detail = "error", str(exc)[:300]
    except Exception as exc:
        log.warning("ioc feed failed", extra={"feed": str(feed.id), "error": type(exc).__name__})
        feed.last_status, feed.last_detail = "error", f"{type(exc).__name__}: {str(exc)[:200]}"
    feed.last_run_at = now
    return result


def _rc(result: Any) -> int:
    return int(result.rowcount or 0) if isinstance(result, CursorResult) else 0


async def expire(
    session: AsyncSession, tenant_id: uuid.UUID | None = None, *, now: datetime | None = None
) -> dict[str, int]:
    """Retire stale indicators: unreviewed ones past the feed's age limit, anything past its own valid_until, and validated ones
    after the watch period. Rejected indicators are kept so they are not re-queued as new."""
    now = now or datetime.now(UTC)
    counts = {"aged": 0, "invalid": 0, "unwatched": 0}
    scope = [Ioc.tenant_id == tenant_id] if tenant_id else []
    feeds = (await session.execute(select(IocFeed.id, IocFeed.max_age_days))).all()
    for fid, days in [*feeds, (None, MANUAL_MAX_AGE_DAYS)]:
        cond = [Ioc.status == "NEW", Ioc.last_seen < now - timedelta(days=days), *scope]
        cond.append(Ioc.feed_id == fid if fid else Ioc.feed_id.is_(None))
        r = await session.execute(update(Ioc).where(*cond).values(status="EXPIRED", status_reason="aged out"))
        counts["aged"] += _rc(r)
    r = await session.execute(
        update(Ioc)
        .where(Ioc.status.in_(("NEW", "VALIDATED")), Ioc.valid_until.is_not(None), Ioc.valid_until < now, *scope)
        .values(status="EXPIRED", status_reason="past its valid-until date")
    )
    counts["invalid"] = _rc(r)
    r = await session.execute(
        update(Ioc)
        .where(Ioc.status == "VALIDATED", Ioc.validated_at < now - timedelta(days=VALIDATED_WATCH_DAYS), *scope)
        .values(status="EXPIRED", status_reason="watch period ended")
    )
    counts["unwatched"] = _rc(r)
    return counts


_SEEN_FIELDS: dict[str, list[str]] = {
    "ip": ["network.dst_ip", "network.src_ip", "auth.source_ip", "dns.answers"],
    "domain": ["dns.question", "network.dst_domain"],
    "md5": ["process.hash.md5", "file.hash.md5"],
    "sha1": ["process.hash.sha1", "file.hash.sha1"],
    "sha256": ["process.hash.sha256", "file.hash.sha256"],
}


def _screen_key(ioc: Ioc) -> tuple[str, str] | None:
    """(type, value) to look for in our own telemetry. A URL is screened by its host: only a prioritisation hint, never a match."""
    if ioc.type in _SEEN_FIELDS:
        return ioc.type, ioc.value
    if ioc.type == "url":
        host = _host_of(ioc.value)
        if host:
            return ("ip" if _is_ip(host) else "domain"), host
    return None


async def prescreen(
    session: AsyncSession, backend: SearchBackend, tenant_id: uuid.UUID, *, days: int = 3, limit: int = 3000
) -> int:
    """Flag NEW indicators already present in the tenant's own telemetry (cheap batched `in` queries). These rise to the top of the
    triage queue: an indicator that is *already seen* in the environment is worth far more than one that is merely published."""
    rows = (
        (
            await session.execute(
                select(Ioc)
                .where(
                    Ioc.tenant_id == tenant_id,
                    Ioc.status == "NEW",
                    Ioc.type.in_([*_SEEN_FIELDS, "url"]),
                    Ioc.seen_at.is_(None),
                )
                .order_by(Ioc.confidence.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    end = datetime.now(UTC)
    tr = TimeRange(start=end - timedelta(days=days), end=end)
    flagged = 0
    by_key: dict[str, dict[str, list[Ioc]]] = {}
    for r in rows:
        key = _screen_key(r)
        if key:
            by_key.setdefault(key[0], {}).setdefault(key[1], []).append(r)
    for typ, values in by_key.items():
        names = list(values)
        for i in range(
            0, len(names), 50
        ):  # a terms aggregation returns at most 50 buckets, so 50 values can never be undercounted
            chunk = names[i : i + 50]
            counts: dict[str, int] = {}
            for fld in _SEEN_FIELDS[typ]:
                q = EventQuery(
                    time_range=tr,
                    limit=1,
                    filters=[Filter(field=fld, op="in", value=chunk)],
                    aggregations=[Aggregation(name="v", type="terms", field=fld, size=50)]
                    if fld in ioc_agg_fields
                    else [],
                )
                res = await backend.search(tenant_id, q)
                agg = res.aggregations.get("v")
                for b in agg.buckets if agg is not None else []:
                    counts[str(b.key)] = counts.get(str(b.key), 0) + b.count
            for name in chunk:
                for ioc in values[name]:
                    ioc.seen_count = counts.get(name, 0)
                    ioc.seen_at = end
                    flagged += 1 if ioc.seen_count else 0
    return flagged


ioc_agg_fields = {
    "network.dst_ip",
    "network.src_ip",
    "auth.source_ip",
    "dns.question",
    "network.dst_domain",
    "process.hash.sha256",
    "file.hash.sha256",
    "process.hash.sha1",
    "file.hash.sha1",
    "process.hash.md5",
    "file.hash.md5",
}
