import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import Principal
from app.events.search.query import EventQuery, Filter, SearchResult
from app.hunts.models import Hunt, QueryHistory

HISTORY_KEEP = 200


def apply_hunt_scope(hunt: Hunt, query: EventQuery) -> EventQuery:
    """Hunt defaults fill gaps; they never override what the analyst explicitly set."""
    data = query.model_dump(mode="json", exclude_none=True)
    if query.time_range is None and hunt.time_start and hunt.time_end:
        data["time_range"] = {"start": hunt.time_start.isoformat(), "end": hunt.time_end.isoformat()}
    if hunt.data_sources:
        scope = Filter(field="source", op="in", value=list(hunt.data_sources)).model_dump(mode="json")
        data["filters"] = [*data.get("filters", []), scope]
    return EventQuery.model_validate(data)


async def record_history(
    session: AsyncSession,
    principal: Principal,
    query: EventQuery,
    result: SearchResult,
    hunt_id: uuid.UUID | None = None,
) -> None:
    session.add(
        QueryHistory(
            tenant_id=principal.tid,
            user_id=principal.user_id,
            hunt_id=hunt_id,
            text=query.text or "",
            query=query.model_dump(mode="json", exclude_none=True),
            total=result.total,
            took_ms=result.took_ms,
        )
    )
    await session.flush()
    stale = (
        select(QueryHistory.id)
        .where(QueryHistory.user_id == principal.user_id, QueryHistory.tenant_id == principal.tid)
        .order_by(QueryHistory.executed_at.desc())
        .offset(HISTORY_KEEP)
    )
    await session.execute(delete(QueryHistory).where(QueryHistory.id.in_(stale)))


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection (CSV injection) in attacker-controlled telemetry."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
