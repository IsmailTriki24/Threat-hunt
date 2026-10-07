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


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    on_startup = startup
    on_shutdown = shutdown
    functions = [enforce_retention]
    cron_jobs = [
        cron(heartbeat, second={0, 30}, run_at_startup=True),
        cron(enforce_retention, hour={3}, minute={15}),
    ]
    redis_settings = _redis_settings()
