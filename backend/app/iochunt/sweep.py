"""Continuous sweep: look for indicators AND behaviours inside the SIEMs instead of copying their logs.

Every few minutes, for every LogRhythm source and every searchable Trend Vision One dataset, the validated indicators (IOCs) and the behaviours
(IOAs) of validated threats are sent to the SIEM as searches over the time since the last sweep. Only logs that really contain an indicator, or
satisfy a behaviour's full condition (both are re-checked locally on what comes back), are imported, so the platform stores evidence, not the stream.

Progress is exact, never assumed. `IocSweep.cursor` is the instant up to which every swept item has been searched. A window is searched
chunk by chunk; if the tick runs out of time or the SIEM errors, the unsearched items stay in `queue` and the cursor does not move, so nothing is
skipped silently and a slow SIEM only makes the sweep lag (which the status shows). Items that become sweepable while a window is in flight are
searched over that same window before it is closed. Queue entries are bare ids for indicators and `ioa:<id>` for behaviours.

A hit lands in the existing case of its indicator / threat (evidence, activity note, severity, reopen), exactly like a watch-list re-hunt, but does
not count as a full re-hunt: it covers SIEM logs only, so the 6-hourly re-hunt (local index, techniques) still runs."""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import takewhile
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import registry as connectors
from app.core.config import Settings
from app.datasources.models import DataSource
from app.events.search.base import SearchBackend
from app.events.search.query import Condition
from app.iochunt import casebuild, hunting
from app.iochunt import siem_behaviours as sb
from app.iochunt.hunting import TREND_FIELDS, AdapterResult, Coverage, Hit, IoaSearch, SignalHit
from app.iochunt.models import Ioc, IocHunt, IocSweep, Threat, ThreatIoa

log = logging.getLogger("app.iochunt.sweep")

LOCK_FOR = timedelta(minutes=12)  # a worker that dies mid-sweep frees the source after this
MAX_WINDOWS_PER_TICK = 6
MIN_SPAN = timedelta(minutes=1)
TREND_CHUNK = 120
IOA_CHUNK = 6
IOA = "ioa:"
SB = "sb:"  # built-in SIEM behaviour (no threat attached): alerts, not case notes
SB_CHUNK = 3
LR_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "email")
CONCURRENT_SOURCES = 3
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Plan:
    """What one data source is swept with."""

    kind: str  # logrhythm | trend
    dataset: str
    cfg: Any
    chunk: int

    def supports(self, ioc: Ioc) -> bool:
        if self.kind == "logrhythm":
            return ioc.type in LR_TYPES or ioc.type in (self.cfg.ioc_filter_templates or {})
        return ioc.type in TREND_FIELDS.get(self.dataset, {})

    def supports_ioa(self, ioa: ThreatIoa, cond: Condition | None) -> bool:
        if self.kind == "logrhythm":
            return hunting.lr_searchable(cond)
        return self.dataset == "endpoint_activity" and bool(ioa.trend_query)

    def supports_sb(self, b: sb.Behaviour) -> bool:
        return self.kind == "logrhythm" and self.cfg.siem_behaviours and b.key not in self.cfg.siem_behaviours_disabled


def plan_for(ds: DataSource) -> Plan | None:
    """The sweep plan of a source, or None when this source is not swept (other connectors, switched off, or a dataset with no query surface)."""
    if ds.connector_type not in ("logrhythm", "trend_vision_one"):
        return None
    cfg: Any = connectors.build(ds.connector_type, ds.config, {}).config
    if not cfg.ioc_sweep:
        return None
    if ds.connector_type == "logrhythm":
        return Plan("logrhythm", "", cfg, cfg.ioc_search_max) if cfg.ioc_search else None
    dataset = str(cfg.dataset)
    return Plan("trend", dataset, cfg, TREND_CHUNK) if dataset in TREND_FIELDS else None


async def sweepable(session: AsyncSession, tenant_id: uuid.UUID, plan: Plan, now: datetime) -> list[Ioc]:
    """Validated indicators that already have a case to report into, most valuable first."""
    rows = (
        (
            await session.execute(
                select(Ioc)
                .where(
                    Ioc.tenant_id == tenant_id,
                    Ioc.status == "VALIDATED",
                    Ioc.case_id.is_not(None),
                    or_(Ioc.valid_until.is_(None), Ioc.valid_until > now),
                )
                .order_by(Ioc.seen_count.desc(), Ioc.confidence.desc(), Ioc.id)
            )
        )
        .scalars()
        .all()
    )
    return [i for i in rows if plan.supports(i)]


async def sweepable_ioas(session: AsyncSession, tenant_id: uuid.UUID, plan: Plan) -> list[ThreatIoa]:
    """Behaviours of validated threats (that have a case) which this SIEM can search, most severe first."""
    rows = (
        await session.execute(
            select(ThreatIoa)
            .join(Threat, Threat.id == ThreatIoa.threat_id)
            .where(ThreatIoa.tenant_id == tenant_id, Threat.status == "VALIDATED", Threat.case_id.is_not(None))
        )
    ).scalars()
    out: list[ThreatIoa] = []
    for ioa in rows:
        if plan.supports_ioa(ioa, await hunting.ioa_cond(session, ioa)):
            out.append(ioa)
    return sorted(out, key=lambda i: (SEVERITY_ORDER.get(i.severity, 5), i.name, str(i.id)))


OWN_INTEL = ("manual", "Trend Vision One")  # indicators the organisation itself supplied
LIVE_ROLES = ("botnet_cc", "c2", "ransomware")


def hot_score(ioc: Ioc, now: datetime) -> int:
    """How urgent an indicator is to search for. Confidence is deliberately NOT used: feeds report it saturated (969 of 1,241 validated
    indicators here are at 80+). What separates indicators is: already seen in our telemetry, supplied by the organisation, a role that means
    live attacker infrastructure, and freshness."""
    score = 0
    if ioc.seen_count > 0:
        score += 1000
    if ioc.source.startswith(OWN_INTEL):
        score += 600
    if (ioc.threat_type or "") in LIVE_ROLES:
        score += 300
    age_h = max(0.0, (now - ioc.last_seen).total_seconds() / 3600)
    score += 200 if age_h <= 24 else 100 if age_h <= 72 else 0
    return score + (
        50 if ioc.type in ("ip", "domain", "url") else 0
    )  # hosts match in network logs; hashes only where files are logged


async def queue_ids(
    session: AsyncSession, tenant_id: uuid.UUID, plan: Plan, now: datetime, lane: str = "full"
) -> tuple[list[str], int, int]:
    """Everything to search in one window of a lane. The full lane has every item; the fast lane only the hottest indicators (score >= 300:
    seen, own intel or live infrastructure) and the most severe behaviours, and no built-in behaviours."""
    cfg = plan.cfg
    iocs = await sweepable(session, tenant_id, plan, now)
    ioas = await sweepable_ioas(session, tenant_id, plan)
    if lane == "fast":
        ranked = sorted(iocs, key=lambda i: (-hot_score(i, now), str(i.id)))
        hot = [i for i in ranked if hot_score(i, now) >= 300][: cfg.sweep_hot_size]
        hot_ioas = ioas[: cfg.sweep_hot_ioas]  # already ordered by severity
        return [*(str(i.id) for i in hot), *(IOA + str(i.id) for i in hot_ioas)], len(hot), len(hot_ioas)
    builtin = [SB + b.key for b in sb.CATALOG if plan.supports_sb(b)]
    return [*(str(i.id) for i in iocs), *(IOA + str(i.id) for i in ioas), *builtin], len(iocs), len(ioas) + len(builtin)


@dataclass
class Tick:
    hits: dict[tuple[str, str], Hit]
    signals: dict[tuple[str, str], SignalHit] = field(default_factory=dict)
    ioa_case: dict[str, uuid.UUID] = field(default_factory=dict)  # behaviour id -> case of its threat
    detections: list[sb.Detection] = field(default_factory=list)
    overflow: int = 0
    searches: int = 0
    covered: int = 0
    url_left: int = 0  # exact-URL pattern searches this tick may still spend
    error: str = ""
    cap_hit: bool = False


async def _claim(session: AsyncSession, state: IocSweep, now: datetime) -> bool:
    res = await session.execute(
        update(IocSweep)
        .where(IocSweep.id == state.id, or_(IocSweep.lock_until.is_(None), IocSweep.lock_until < now))
        .values(lock_until=now + LOCK_FOR)
        .returning(IocSweep.id)
    )
    got = res.first() is not None
    await session.commit()
    return got


async def sweep_source(
    session: AsyncSession, backend: SearchBackend, settings: Settings, ds: DataSource, now: datetime | None = None
) -> dict[str, Any] | None:
    """Run one tick for one source: the fast lane first (it is small and must stay close to real time), then the full lane with the rest of the
    budget. Never raises: failures are written to the lane's sweep status. Returns a small summary (None if not swept)."""
    now = now or datetime.now(UTC)
    try:
        plan = plan_for(ds)
    except Exception as exc:  # an invalid source configuration
        await _fail(session, ds, now, f"invalid configuration: {str(exc)[:200]}")
        return None
    if plan is None:
        off = (await session.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id))).scalars().all()
        for row in off:
            if row.status != "off":
                row.status, row.detail, row.queue, row.members, row.window_end = (
                    "off",
                    "indicator sweep is switched off for this source",
                    [],
                    [],
                    None,
                )
        await session.commit()
        return None
    cfg = plan.cfg
    t_end = time.monotonic() + cfg.sweep_budget_s
    lanes = ["fast", "full"] if cfg.sweep_hot_size > 0 or cfg.sweep_hot_ioas > 0 else ["full"]
    total: dict[str, Any] | None = None
    for lane in lanes:
        left = t_end - time.monotonic()
        # the fast lane never takes more than a third of the tick; the full lane gets whatever is left
        deadline = time.monotonic() + (min(left, cfg.sweep_budget_s / 3) if lane == "fast" else left)
        out = await _sweep_lane(session, backend, settings, ds, plan, lane, now, deadline)
        if out is None:
            continue
        if total is None:
            total = out
        else:
            total = {
                "hits": total["hits"] + out["hits"],
                "windows": total["windows"] + out["windows"],
                "pending": out["pending"]
                if out["pending"] < 0 or total["pending"] < 0
                else total["pending"] + out["pending"],
                "error": total["error"] or out["error"],
            }
    return total


async def _sweep_lane(
    session: AsyncSession,
    backend: SearchBackend,
    settings: Settings,
    ds: DataSource,
    plan: Plan,
    lane: str,
    now: datetime,
    deadline: float,
) -> dict[str, Any] | None:
    cfg = plan.cfg
    lag = timedelta(minutes=cfg.sweep_lag_minutes)
    state = (
        await session.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id, IocSweep.lane == lane))
    ).scalar_one_or_none()
    if state is None:
        state = IocSweep(
            tenant_id=ds.tenant_id, data_source_id=ds.id, lane=lane, cursor=now - lag, queue=[], members=[]
        )
        session.add(state)
        await session.flush()
    if not await _claim(session, state, now):
        return None  # another worker is sweeping this lane
    await session.refresh(state)
    tick = Tick(hits={}, url_left=getattr(cfg, "sweep_url_patterns", 0))
    first_start = state.cursor
    try:
        queue_left, windows = await _run_windows(session, backend, settings, ds, plan, state, tick, now, deadline)
        new_hits = await _record_hits(session, backend, ds, tick, first_start, state.cursor)
        new_hits += await sb.emit_alerts(session, backend, settings, ds, tick.detections)
        state.hits_total += new_hits
        state.searches_total += tick.searches
        state.windows_done += windows
        state.status = "error" if tick.error else ("partial" if queue_left else "ok")
        behind = max(timedelta(0), now - lag - state.cursor)
        state.detail = (
            (
                f"{tick.error[:200]}; "
                if tick.error
                else f"{queue_left} item(s) of the current window still to search; "
                if queue_left
                else ""
            )
            + f"swept up to {state.cursor:%Y-%m-%d %H:%M}Z, {int(behind.total_seconds() // 60)} min behind"
            + ("; a vendor result cap was reached, some events of a busy window may be missing" if tick.cap_hit else "")
            + (f"; {tick.overflow} more matches than the alert limit were not alerted" if tick.overflow else "")
        )[:300]
        state.last_run_at = now
        if not tick.error:
            state.last_ok_at = now
        state.lock_until = None
        await session.commit()
        return {"hits": new_hits, "windows": windows, "pending": queue_left, "error": tick.error}
    except Exception as exc:
        log.warning("ioc sweep failed", extra={"data_source": str(ds.id), "lane": lane, "error": type(exc).__name__})
        await session.rollback()
        await _fail(session, ds, now, f"{type(exc).__name__}: {str(exc)[:200]}", release=True, lane=lane)
        return {"hits": 0, "windows": 0, "pending": -1, "error": type(exc).__name__}


async def _fail(
    session: AsyncSession, ds: DataSource, now: datetime, detail: str, release: bool = False, lane: str | None = None
) -> None:
    values: dict[str, Any] = {"status": "error", "detail": detail[:300], "last_run_at": now}
    if release:
        values["lock_until"] = None
    q = update(IocSweep).where(IocSweep.data_source_id == ds.id)
    if lane:
        q = q.where(IocSweep.lane == lane)
    await session.execute(q.values(**values))
    await session.commit()


async def _run_windows(
    session: AsyncSession,
    backend: SearchBackend,
    settings: Settings,
    ds: DataSource,
    plan: Plan,
    state: IocSweep,
    tick: Tick,
    now: datetime,
    deadline: float,
) -> tuple[int, int]:
    """Advance the cursor as far as the budget allows. Returns (items still queued in the window in flight, windows completed)."""
    cfg = plan.cfg
    lag = timedelta(minutes=cfg.sweep_lag_minutes)
    overlap = timedelta(minutes=cfg.sweep_overlap_minutes)
    max_span = timedelta(minutes=cfg.sweep_max_window_minutes)
    done_windows = 0
    for _ in range(MAX_WINDOWS_PER_TICK):
        if state.window_end is None:
            end = min(state.cursor + max_span, now - lag)
            if end - state.cursor < MIN_SPAN:
                break  # caught up: nothing new old enough to search yet
            ids, n_iocs, n_ioas = await queue_ids(session, ds.tenant_id, plan, now, state.lane)
            state.window_end, state.queue, state.members = end, ids, ids
            state.iocs_total, state.ioas_total = n_iocs, n_ioas
        start, end = state.cursor - overlap, state.window_end
        assert end is not None
        while state.queue:
            budget = int(deadline - time.monotonic())
            if budget < 10:
                return len(state.queue), done_windows
            if state.queue[0].startswith(SB):
                progressed = await _sb_round(settings, ds, plan, state, tick, start, end, budget)
            elif state.queue[0].startswith(IOA):
                progressed = await _ioa_round(session, backend, settings, ds, plan, state, tick, start, end, budget)
            else:
                progressed = await _ioc_round(session, backend, settings, ds, plan, state, tick, start, end, budget)
            if tick.error or not progressed:
                return len(state.queue), done_windows  # nothing progressed (error or out of time): retry next tick
        # everything in the window is searched; anything that became sweepable meanwhile is searched over the same window first
        members = set(state.members)
        ids, _n, _m = await queue_ids(session, ds.tenant_id, plan, now, state.lane)
        late = [i for i in ids if i not in members]
        if late:
            state.queue, state.members = late, [*state.members, *late]
            continue
        state.cursor, state.window_end, state.queue, state.members = end, None, [], []
        done_windows += 1
        await session.commit()  # the cursor moves only with its window fully searched
    return len(state.queue), done_windows


async def _ioc_round(
    session: AsyncSession,
    backend: SearchBackend,
    settings: Settings,
    ds: DataSource,
    plan: Plan,
    state: IocSweep,
    tick: Tick,
    start: datetime,
    end: datetime,
    budget: int,
) -> bool:
    """Search the next `sweep_parallel` chunks of indicators at once. True if any item was settled."""
    wanted = list(takewhile(lambda q: not q.startswith((IOA, SB)), state.queue))[: plan.chunk * plan.cfg.sweep_parallel]
    rows = {
        str(i.id): i
        for i in (
            await session.execute(
                select(Ioc).where(Ioc.id.in_([uuid.UUID(c) for c in wanted]), Ioc.status == "VALIDATED")
            )
        ).scalars()
    }
    done = set(wanted) - set(rows)  # an indicator retired meanwhile has nothing left to search
    parts = [[rows[c] for c in wanted[k : k + plan.chunk] if c in rows] for k in range(0, len(wanted), plan.chunk)]
    outs: list[AdapterResult]
    if plan.kind == "logrhythm":
        # the URL-pattern allowance is shared by the whole tick, not repeated for every chunk of a pass
        n_parts = max(1, len([p for p in parts if p]))
        shares = [tick.url_left // n_parts + (1 if k < tick.url_left % n_parts else 0) for k in range(len(parts))]
        outs = await asyncio.gather(
            *(
                hunting.search_logrhythm(
                    session,
                    backend,
                    settings,
                    ds.tenant_id,
                    part,
                    start,
                    end,
                    only=[ds],
                    budget_s=budget,
                    url_patterns=share,
                )
                for part, share in zip(parts, shares, strict=True)
                if part
            )
        )
        tick.url_left = max(0, tick.url_left - sum(o.url_searches for o in outs))
    else:
        outs = await asyncio.gather(
            *(
                hunting.search_trend(
                    session, backend, settings, ds.tenant_id, part, start, end, only=[ds], budget_s=budget
                )
                for part in parts
                if part
            )
        )
    for res in outs:
        tick.searches += 1
        for h in res.hits:
            tick.hits.setdefault((str(h.ioc.id), h.doc["id"]), h)
        done |= {str(i) for i in res.covered}
        errors = [c for c in res.coverage if c.status == "error"]
        if errors:
            tick.error = "; ".join(c.detail for c in errors)[:240]
        if any(c.status == "truncated" and "result cap" in c.detail for c in res.coverage):
            tick.cap_hit = True
    tick.covered += len(done & set(wanted))
    state.queue = [q for q in state.queue if q not in done]
    return bool(done & set(wanted))


async def _ioa_round(
    session: AsyncSession,
    backend: SearchBackend,
    settings: Settings,
    ds: DataSource,
    plan: Plan,
    state: IocSweep,
    tick: Tick,
    start: datetime,
    end: datetime,
    budget: int,
) -> bool:
    """Search the next few behaviours. True if any item was settled."""
    wanted = list(takewhile(lambda q: q.startswith(IOA), state.queue))[:IOA_CHUNK]
    ids = [uuid.UUID(w[len(IOA) :]) for w in wanted]
    pairs = (
        await session.execute(
            select(ThreatIoa, Threat.case_id)
            .join(Threat, Threat.id == ThreatIoa.threat_id)
            .where(ThreatIoa.id.in_(ids), Threat.status == "VALIDATED", Threat.case_id.is_not(None))
        )
    ).all()
    ioas = [p[0] for p in pairs]
    for ioa, ioa_case in pairs:
        if ioa_case is not None:
            tick.ioa_case[str(ioa.id)] = ioa_case
    done = {IOA + str(i) for i in ids} - {
        IOA + str(i.id) for i in ioas
    }  # a retired behaviour has nothing left to search
    if ioas:
        fn = hunting.search_ioas_logrhythm if plan.kind == "logrhythm" else hunting.search_ioas_trend
        res: IoaSearch = await fn(
            session, backend, settings, ds.tenant_id, ioas, start, end, only=[ds], budget_s=budget
        )
        tick.searches += 1
        for h in res.hits:
            tick.signals.setdefault((h.ref, h.doc["id"]), h)
        done |= {IOA + str(i) for i in res.covered}
        errors = [c for c in res.coverage if c.status == "error"]
        if errors:
            tick.error = "; ".join(c.detail for c in errors)[:240]
    tick.covered += len(done & set(wanted))
    state.queue = [q for q in state.queue if q not in done]
    return bool(done & set(wanted))


async def _sb_round(
    settings: Settings,
    ds: DataSource,
    plan: Plan,
    state: IocSweep,
    tick: Tick,
    start: datetime,
    end: datetime,
    budget: int,
) -> bool:
    """Run the next few built-in behaviours in the SIEM. True if any was settled."""
    wanted = list(takewhile(lambda q: q.startswith(SB), state.queue))[:SB_CHUNK]
    behaviours = [sb.BY_KEY[w[len(SB) :]] for w in wanted if w[len(SB) :] in sb.BY_KEY]
    done = {w for w in wanted if w[len(SB) :] not in sb.BY_KEY}  # a behaviour removed from the catalogue
    if behaviours:
        run = await sb.run_behaviours(settings, ds, behaviours, start, end, budget, plan.cfg.sweep_parallel)
        tick.searches += run.searches
        tick.detections += run.detections
        tick.overflow += run.overflow
        done |= {SB + k for k in run.covered}
        if run.error:
            tick.error = run.error
    tick.covered += len(done & set(wanted))
    state.queue = [q for q in state.queue if q not in done]
    return bool(done & set(wanted))


async def _record_hits(
    session: AsyncSession, backend: SearchBackend, ds: DataSource, tick: Tick, start: datetime, end: datetime
) -> int:
    """File the new matches in the cases of the indicators / threats that matched (one sweep note per case). Returns how many were new."""
    if not tick.hits and not tick.signals:
        return 0
    by_case: dict[uuid.UUID, tuple[list[Hit], list[SignalHit]]] = {}
    for h in tick.hits.values():
        if h.ioc.case_id:
            by_case.setdefault(h.ioc.case_id, ([], []))[0].append(h)
    for sh in tick.signals.values():
        sig_case = tick.ioa_case.get(sh.ref)
        if sig_case:
            by_case.setdefault(sig_case, ([], []))[1].append(sh)
    cov = Coverage(
        ds.name,
        "logrhythm" if ds.connector_type == "logrhythm" else f"trend:{(ds.config or {}).get('dataset', '')}",
        iocs_searched=tick.covered,
        hits=len(tick.hits) + len(tick.signals),
        detail=f"sweep, {tick.searches} search round(s)",
    )
    now = datetime.now(UTC)
    new_total = 0
    for case_id, (hits, sigs) in by_case.items():
        requester = (
            (
                await session.execute(
                    select(IocHunt.requested_by).where(IocHunt.case_id == case_id, IocHunt.mode == "initial")
                )
            )
            .scalars()
            .first()
        )
        iocs = list({h.ioc.id: h.ioc for h in hits}.values())
        hunt = IocHunt(
            tenant_id=ds.tenant_id,
            name=f"Sweep: {ds.name}"[:200],
            mode="rehunt",
            status="COMPLETED",
            ioc_ids=[str(i.id) for i in iocs],
            lookback_days=1,
            window_start=start,
            window_end=end,
            requested_by=requester,
            case_id=case_id,
            signals={"sweep": True, "data_source": str(ds.id), "ioa_ids": sorted({s.ref for s in sigs})},
            hypothesis="Continuous sweep of the SIEM for validated indicators and behaviours.",
            coverage=[cov.as_dict()],
            started_at=now,
            finished_at=now,
        )
        session.add(hunt)
        await session.flush()
        new_keys = await hunting.persist_matches(session, hunt, hits) if hits else set()
        new_sig_keys = await hunting.persist_signals(session, hunt, sigs) if sigs else set()
        if not new_keys and not new_sig_keys:  # every event was already known: no record worth keeping
            await session.delete(hunt)
            await session.flush()
            continue
        new_hits = [h for h in hits if (str(h.ioc.id), h.doc["id"]) in new_keys]
        new_sigs = [s for s in sigs if (s.kind, s.ref, s.doc["id"]) in new_sig_keys]
        hunt.match_count, hunt.new_match_count = len(hits), len(new_hits) + len(new_sigs)
        hunt.signal_count = len(sigs)
        new_total += len(new_hits) + len(new_sigs)
        await casebuild.finalize(session, backend, hunt, iocs, hits, new_hits, sigs, new_sigs, [cov])
    return new_total


async def release_locks(sessionmaker: Any) -> int:
    """At worker start: free the sources a previous (dead) worker was sweeping. Safe because progress is only saved together with its window
    and everything a sweep imports is idempotent, so the worst case of two workers overlapping is searching a window twice."""
    async with sessionmaker() as session:
        res = await session.execute(update(IocSweep).where(IocSweep.lock_until.is_not(None)).values(lock_until=None))
        await session.commit()
        return int(getattr(res, "rowcount", 0) or 0)


async def run_sweeps(
    sessionmaker: Any, backend: SearchBackend, settings: Settings, tenant_id: uuid.UUID | None = None
) -> dict[str, int]:
    """One tick over every SIEM source. Sources run concurrently (own session each); a failing source only marks its own status."""
    async with sessionmaker() as session:
        ids = list(
            (
                await session.execute(
                    select(DataSource.id).where(
                        DataSource.connector_type.in_(("logrhythm", "trend_vision_one")),
                        *([DataSource.tenant_id == tenant_id] if tenant_id else []),
                    )
                )
            ).scalars()
        )
    sem = asyncio.Semaphore(CONCURRENT_SOURCES)
    summary = {"sources": 0, "hits": 0, "errors": 0}

    async def one(ds_id: uuid.UUID) -> None:
        async with sem, sessionmaker() as session:
            ds = await session.get(DataSource, ds_id)
            if ds is None:
                return
            out = await sweep_source(session, backend, settings, ds)
            if out is not None:
                summary["sources"] += 1
                summary["hits"] += out["hits"]
                summary["errors"] += bool(out["error"])

    await asyncio.gather(*(one(i) for i in ids), return_exceptions=True)
    return summary
