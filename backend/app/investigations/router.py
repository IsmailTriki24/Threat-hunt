import re
from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.core.errors import NotFound
from app.core.ratelimit import enforce
from app.events.search.base import SearchBackend
from app.events.search.query import EventQuery, Filter, Sort, TimeRange
from app.investigations import timeline

router = APIRouter(prefix="/timeline", tags=["investigations"])
PAGE = 200


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TimelineRequest(_In):
    query: EventQuery
    limit: int = Field(default=500, ge=1, le=1000)
    collapse: bool = True


class AroundRequest(_In):
    event_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    window_minutes: int = Field(default=30, ge=1, le=1440)
    scope: Literal["host", "user", "host_user"] = "host"
    collapse: bool = True


async def _collect(
    backend: SearchBackend, principal: Principal, query: EventQuery, limit: int
) -> tuple[list[dict[str, Any]], bool]:
    base = query.model_copy(update={"sort": [Sort(field="timestamp", order="asc")], "aggregations": []})
    docs: list[dict[str, Any]] = []
    truncated = False
    while len(docs) < limit:
        page = base.model_copy(update={"offset": len(docs), "limit": min(PAGE, limit - len(docs))})
        result = await backend.search(principal.tid, page)
        docs.extend(result.hits)
        if len(result.hits) < page.limit:
            break
        if len(docs) >= limit and result.total > limit:
            truncated = True
    return docs, truncated


@router.post("", response_model=timeline.Timeline)
async def build_timeline(
    body: TimelineRequest, request: Request, principal: Principal = Depends(require(Permission.EVENTS_READ))
) -> timeline.Timeline:
    await enforce(request, f"timeline:{principal.user_id}", 30, 60)
    docs, truncated = await _collect(request.app.state.search, principal, body.query, body.limit)
    await audit.record(request, "timeline.build", principal=principal, details={"events": len(docs)})
    return timeline.build(docs, truncated=truncated, collapse=body.collapse)


@router.post("/around", response_model=timeline.Timeline)
async def timeline_around_event(
    body: AroundRequest, request: Request, principal: Principal = Depends(require(Permission.EVENTS_READ))
) -> timeline.Timeline:
    await enforce(request, f"timeline:{principal.user_id}", 30, 60)
    backend: SearchBackend = request.app.state.search
    doc = await backend.get_event(principal.tid, body.event_id)
    if doc is None or not re.match(r"^[a-f0-9]{32}$", doc["id"]):
        raise NotFound("Event not found")
    from datetime import datetime

    center = datetime.fromisoformat(doc["timestamp"].replace("Z", "+00:00"))
    filters: list[Filter] = []
    host = (doc.get("host") or {}).get("hostname")
    user = (doc.get("user") or {}).get("name")
    if body.scope in ("host", "host_user") and host:
        filters.append(Filter(field="host.hostname", op="eq", value=host))
    if body.scope in ("user", "host_user") and user:
        filters.append(Filter(field="user.name", op="eq", value=user))
    if not filters:
        raise NotFound("Event has no host/user to build a timeline around")
    delta = timedelta(minutes=body.window_minutes)
    query = EventQuery(
        filters=filters, time_range=TimeRange(start=center - delta, end=center + delta + timedelta(seconds=1))
    )
    docs, truncated = await _collect(backend, principal, query, 1000)
    await audit.record(
        request,
        "timeline.build",
        principal=principal,
        resource_type="event",
        resource_id=body.event_id,
        details={"events": len(docs), "scope": body.scope},
    )
    return timeline.build(docs, truncated=truncated, collapse=body.collapse)
