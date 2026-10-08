"""Orchestration: feed refresh, hunt execution, and the watch-list re-hunt loop. Everything here is idempotent and safe to run
concurrently from several workers (hunts are claimed with an atomic status change)."""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.events.search.base import SearchBackend
from app.iochunt import casebuild, hunting, ingest
from app.iochunt.models import Ioc, IocFeed, IocHunt
from app.tenants.models import Tenant

log = logging.getLogger("app.iochunt")

REHUNT_EVERY = timedelta(hours=6)
REHUNT_OVERLAP = timedelta(minutes=15)
MAX_IOCS_PER_HUNT = 200


def hypothesis_for(tenant: str, iocs: list[Ioc], days: int) -> str:
    feeds = sorted({i.source for i in iocs if i.source}) or ["manual entry"]
    kinds = sorted({i.type for i in iocs})
    malware = sorted({i.malware for i in iocs if i.malware})[:4]
    threat = f" associated with {', '.join(malware)}" if malware else ""
    return (
        f"If the {len(iocs)} validated indicator(s) ({', '.join(kinds)}; from {', '.join(feeds)}){threat} are relevant to {tenant}, then telemetry from its "
        f"endpoints, network, identity and security products will show communication with, resolution of, or execution of them within the last {days} day(s). "
        "Absence in every searched source supports the conclusion that the organisation was not exposed; presence is treated as a potential intrusion."
    )


async def create_hunt(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID | None,
    iocs: list[Ioc],
    *,
    name: str | None,
    lookback_days: int,
) -> IocHunt:
    tenant = await session.get(Tenant, tenant_id)
    now = datetime.now(UTC)
    hunt = IocHunt(
        tenant_id=tenant_id,
        name=(name or f"IOC hunt {now:%Y-%m-%d %H:%M} ({len(iocs)} IOCs)")[:200],
        mode="initial",
        status="PENDING",
        ioc_ids=[str(i.id) for i in iocs],
        lookback_days=lookback_days,
        requested_by=user_id,
        hypothesis=hypothesis_for(tenant.name if tenant else "the organisation", iocs, lookback_days),
    )
    session.add(hunt)
    await session.flush()
    return hunt


async def run_hunt(session: AsyncSession, backend: SearchBackend, settings: Settings, hunt: IocHunt) -> None:
    iocs = list(
        (
            await session.execute(
                select(Ioc).where(Ioc.tenant_id == hunt.tenant_id, Ioc.id.in_([uuid.UUID(i) for i in hunt.ioc_ids]))
            )
        ).scalars()
    )
    if not iocs:
        hunt.status, hunt.error, hunt.finished_at = "FAILED", "the indicators no longer exist", datetime.now(UTC)
        return
    now = datetime.now(UTC)
    hunt.window_end = now
    if hunt.mode == "rehunt":
        last = min((i.last_hunted_at for i in iocs if i.last_hunted_at), default=None)
        hunt.window_start = (last - REHUNT_OVERLAP) if last else now - timedelta(days=hunt.lookback_days)
    else:
        hunt.window_start = now - timedelta(days=hunt.lookback_days)
    try:
        hits, coverage = await hunting.execute(session, backend, settings, hunt, iocs)
    except Exception as exc:
        log.warning("ioc hunt failed", extra={"hunt": str(hunt.id), "error": type(exc).__name__})
        hunt.status, hunt.error, hunt.finished_at = (
            "FAILED",
            f"{type(exc).__name__}: {str(exc)[:200]}",
            datetime.now(UTC),
        )
        return
    new_keys = await hunting.persist_matches(session, hunt, hits)
    new_hits = [h for h in hits if (str(h.ioc.id), h.doc["id"]) in new_keys]
    hunt.match_count, hunt.new_match_count = len(hits), len(new_hits)
    hunt.coverage = [c.as_dict() for c in coverage]
    errors = [c for c in coverage if c.status == "error"]
    searched = [c for c in coverage if c.status != "skipped"]
    if searched and len(errors) == len(searched):
        hunt.status, hunt.error = "FAILED", "; ".join(f"{c.source}: {c.detail}" for c in errors)[:300]
    else:
        hunt.status = "PARTIAL" if errors else "COMPLETED"
        case = await casebuild.finalize(session, backend, hunt, iocs, hits, new_hits, coverage)
        if case is not None:
            hunt.case_id = case.id
    hunt.finished_at = datetime.now(UTC)


async def process_pending(sessionmaker: Any, backend: SearchBackend, settings: Settings, limit: int = 3) -> int:
    """Claim and run pending hunts. A hunt is claimed by flipping PENDING->RUNNING in one atomic UPDATE."""
    done = 0
    async with sessionmaker() as session:
        ids = list(
            (
                await session.execute(
                    select(IocHunt.id).where(IocHunt.status == "PENDING").order_by(IocHunt.created_at).limit(limit)
                )
            ).scalars()
        )
    for hid in ids:
        async with sessionmaker() as session:
            claimed = await session.execute(
                update(IocHunt)
                .where(IocHunt.id == hid, IocHunt.status == "PENDING")
                .values(status="RUNNING", started_at=datetime.now(UTC))
                .returning(IocHunt.id)
            )
            if claimed.first() is None:
                await session.rollback()
                continue
            await session.commit()
        async with sessionmaker() as session:
            hunt = await session.get(IocHunt, hid)
            if hunt is None:
                continue
            await run_hunt(session, backend, settings, hunt)
            await session.commit()
            done += 1
    return done


async def recover_stuck(sessionmaker: Any, max_minutes: int = 30) -> int:
    """A worker that died mid-hunt leaves it RUNNING: put it back in the queue."""
    async with sessionmaker() as session:
        r = await session.execute(
            update(IocHunt)
            .where(IocHunt.status == "RUNNING", IocHunt.started_at < datetime.now(UTC) - timedelta(minutes=max_minutes))
            .values(status="PENDING")
        )
        await session.commit()
        return int(getattr(r, "rowcount", 0) or 0)


async def schedule_rehunts(sessionmaker: Any) -> int:
    """Validated indicators stay on the watch list: re-hunt each case's indicators every few hours over the new window only."""
    created = 0
    async with sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(Ioc).where(
                        Ioc.status == "VALIDATED",
                        Ioc.case_id.is_not(None),
                        (Ioc.last_hunted_at.is_(None)) | (Ioc.last_hunted_at < datetime.now(UTC) - REHUNT_EVERY),
                    )
                )
            )
            .scalars()
            .all()
        )
        by_case: dict[uuid.UUID, list[Ioc]] = {}
        for r in rows:
            if r.case_id:
                by_case.setdefault(r.case_id, []).append(r)
        for case_id, group in by_case.items():
            open_run = (
                await session.execute(
                    select(IocHunt.id).where(
                        IocHunt.case_id == case_id, IocHunt.mode == "rehunt", IocHunt.status.in_(("PENDING", "RUNNING"))
                    )
                )
            ).first()
            if open_run:
                continue
            first = group[0]
            requester = (
                await session.execute(
                    select(IocHunt.requested_by).where(IocHunt.case_id == case_id, IocHunt.mode == "initial")
                )
            ).scalar_one_or_none()
            session.add(
                IocHunt(
                    tenant_id=first.tenant_id,
                    name=f"Watch-list re-hunt ({len(group)} IOCs)",
                    mode="rehunt",
                    status="PENDING",
                    ioc_ids=[str(i.id) for i in group[:MAX_IOCS_PER_HUNT]],
                    lookback_days=2,
                    requested_by=requester,
                    case_id=case_id,
                    hypothesis="Scheduled re-check of validated indicators against newly available telemetry.",
                )
            )
            created += 1
        await session.commit()
    return created


async def run_due_feeds(sessionmaker: Any, backend: SearchBackend, settings: Settings) -> dict[str, int]:
    now = datetime.now(UTC)
    summary = {"feeds": 0, "new": 0, "errors": 0}
    async with sessionmaker() as session:
        feeds = list((await session.execute(select(IocFeed.id).where(IocFeed.enabled.is_(True)))).scalars())
    tenants: set[uuid.UUID] = set()
    for fid in feeds:
        async with sessionmaker() as session:
            feed = await session.get(IocFeed, fid)
            if feed is None or (feed.last_run_at and feed.last_run_at > now - timedelta(minutes=feed.interval_minutes)):
                continue
            res = await ingest.run_feed(session, settings, feed)
            summary["feeds"] += 1
            summary["new"] += res.new
            summary["errors"] += feed.last_status == "error"
            tenants.add(feed.tenant_id)
            await session.commit()
    for tid in tenants:
        async with sessionmaker() as session:
            await ingest.expire(session, tid)
            await ingest.prescreen(session, backend, tid)
            await session.commit()
    return summary
