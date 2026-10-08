import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from arq import cron
from arq.connections import RedisSettings
from sqlalchemy import select

from app.api.health import WORKER_HEARTBEAT_KEY
from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.logging import configure_logging
from app.events.search.opensearch import OpenSearchBackend
from app.main import make_opensearch
from app.tenants.models import Tenant

log = logging.getLogger("app.worker")


async def startup(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    ctx["engine"] = create_engine(settings)
    ctx["sessionmaker"] = create_sessionmaker(ctx["engine"])
    ctx["os"] = make_opensearch(settings)
    ctx["search"] = OpenSearchBackend(ctx["os"], settings)
    log.info("worker started")


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["os"].close()
    await ctx["engine"].dispose()


async def heartbeat(ctx: dict[str, Any]) -> None:
    await ctx["redis"].set(WORKER_HEARTBEAT_KEY, datetime.now(UTC).isoformat(), ex=90)


async def enforce_retention(ctx: dict[str, Any]) -> None:
    """Delete telemetry older than each tenant's retention window. This is the `delete` phase of the
    lifecycle; hot/warm/cold tier transitions plug in beside it (see ARCHITECTURE.md)."""
    backend: OpenSearchBackend = ctx["search"]
    async with ctx["sessionmaker"]() as session:
        tenants = (await session.execute(select(Tenant.id, Tenant.retention_days))).all()
    for tenant_id, days in tenants:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        deleted = await backend.delete_before(tenant_id, cutoff)
        if deleted:
            log.info("retention applied", extra={"tenant_id": str(tenant_id), "deleted": deleted})


async def collect_datasources(ctx: dict[str, Any]) -> None:
    """Pull from every enabled, pull-capable data source. Sources run concurrently (each in its own session and
    transaction) so one slow upstream cannot starve the others; errors only mark that source's health."""
    import asyncio

    from app.datasources import service as ds_service
    from app.datasources.models import DataSource

    settings = get_settings()
    async with ctx["sessionmaker"]() as session:
        ids = list((await session.execute(select(DataSource.id).where(DataSource.enabled.is_(True)))).scalars())
    sem = asyncio.Semaphore(4)

    async def one(ds_id: Any) -> None:
        async with sem, ctx["sessionmaker"]() as session:
            ds = await session.get(DataSource, ds_id)
            if ds is None or not ds.enabled:
                return
            try:
                if not ds_service.build_connector(ds, settings).supports_collect:
                    return
            except Exception:
                log.warning("invalid data source configuration", extra={"data_source": str(ds.id)})
                return
            await ds_service.collect_source(session, ctx["search"], settings, ds)
            await session.commit()

    await asyncio.gather(*(one(i) for i in ids), return_exceptions=True)


async def run_detections(ctx: dict[str, Any]) -> None:
    """Evaluate ACTIVE detection rules against newly ingested telemetry and raise (deduplicated) alerts."""
    from app.detections import service as det_service

    summary = await det_service.run_scheduled(ctx["sessionmaker"], ctx["search"])
    if summary["alerts"] or summary["errors"]:
        log.info("detections evaluated", extra=summary)


async def refresh_ioc_feeds(ctx: dict[str, Any]) -> None:
    """Fetch every due IOC feed, then retire stale indicators and flag ones already seen in our own telemetry."""
    from app.iochunt import runner

    summary = await runner.run_due_feeds(ctx["sessionmaker"], ctx["search"], get_settings())
    if summary["feeds"]:
        log.info("ioc feeds refreshed", extra=summary)


async def process_ioc_hunts(ctx: dict[str, Any]) -> None:
    """Run validated-IOC hunts: search all data sources and open/update the case, automatically."""
    from app.iochunt import runner

    done = await runner.process_pending(ctx["sessionmaker"], ctx["search"], get_settings())
    if done:
        log.info("ioc hunts processed", extra={"hunts": done})


async def ioc_maintenance(ctx: dict[str, Any]) -> None:
    """Hourly: requeue hunts a dead worker left RUNNING and schedule re-hunts of the watch list."""
    from app.iochunt import runner

    stuck = await runner.recover_stuck(ctx["sessionmaker"])
    scheduled = await runner.schedule_rehunts(ctx["sessionmaker"])
    if stuck or scheduled:
        log.info("ioc maintenance", extra={"requeued": stuck, "rehunts": scheduled})


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    on_startup = startup
    on_shutdown = shutdown
    functions = [
        enforce_retention,
        collect_datasources,
        run_detections,
        refresh_ioc_feeds,
        process_ioc_hunts,
        ioc_maintenance,
    ]
    cron_jobs = [
        cron(heartbeat, second={0, 30}, run_at_startup=True),
        cron(enforce_retention, hour={3}, minute={15}),
        cron(run_detections, minute={2, 7, 12, 17, 22, 27, 32, 37, 42, 47, 52, 57}, timeout=240),
        cron(refresh_ioc_feeds, minute={1, 11, 21, 31, 41, 51}, timeout=280),
        cron(process_ioc_hunts, minute=set(range(60)), timeout=900),
        cron(ioc_maintenance, minute={20}, timeout=120),
        cron(collect_datasources, minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55}, timeout=280),
    ]
    redis_settings = _redis_settings()
