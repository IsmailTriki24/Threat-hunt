import re
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.connectors import registry
from app.core.errors import AppError, NotFound
from app.core.metrics import SEARCHES
from app.core.ratelimit import enforce
from app.events import service
from app.events.fields import FIELDS
from app.events.pivots import Pivot, pivots_for
from app.events.search.base import SearchBackend
from app.events.search.query import EventQuery, SearchResult

router = APIRouter(prefix="/events", tags=["events"])

_ID_RE = re.compile(r"^[a-f0-9]{32}$")


def backend_of(request: Request) -> SearchBackend:
    backend: SearchBackend = request.app.state.search
    return backend


class FieldInfo(BaseModel):
    name: str
    kind: str
    sortable: bool
    aggregatable: bool


class EventDetail(BaseModel):
    event: dict[str, Any]
    pivots: list[Pivot]


@router.post("/search", response_model=SearchResult)
async def search_events(
    query: EventQuery,
    request: Request,
    principal: Principal = Depends(require(Permission.EVENTS_READ)),
) -> SearchResult:
    await enforce(request, f"search:{principal.user_id}", 120, 60)
    result = await backend_of(request).search(principal.tid, query)
    SEARCHES.inc()
    await audit.record(
        request,
        "event.search",
        principal=principal,
        details={
            "q": (query.q or "")[:200],
            "filters": [f.model_dump(mode="json") for f in query.filters],
            "total": result.total,
        },
    )
    return result


@router.get("/fields", response_model=list[FieldInfo])
async def list_fields(_: Principal = Depends(require(Permission.EVENTS_READ))) -> list[FieldInfo]:
    return [
        FieldInfo(name=f.name, kind=f.kind, sortable=f.sortable, aggregatable=f.aggregatable)
        for f in FIELDS.values()
        if f.name != "tenant_id"
    ]


@router.get("/{event_id}", response_model=EventDetail)
async def get_event(
    event_id: str,
    request: Request,
    principal: Principal = Depends(require(Permission.EVENTS_READ)),
) -> EventDetail:
    if not _ID_RE.match(event_id):
        raise NotFound("Event not found")
    doc = await backend_of(request).get_event(principal.tid, event_id)
    if doc is None:
        raise NotFound("Event not found")
    await audit.record(request, "event.view", principal=principal, resource_type="event", resource_id=event_id)
    return EventDetail(event=doc, pivots=pivots_for(doc))


@router.post("/ingest", response_model=service.IngestResponse)
async def ingest_events(
    body: service.IngestRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.EVENTS_INGEST)),
) -> service.IngestResponse:
    from app.core.config import get_settings

    if len(body.events) > get_settings().ingest_max_batch:
        raise AppError(f"Batch too large (max {get_settings().ingest_max_batch})")
    if body.source_type not in registry.available():
        raise AppError(f"Unknown source_type; available: {', '.join(registry.available())}")
    await enforce(request, f"ingest:{principal.tid}", 120, 60)
    try:
        response = await service.ingest(backend_of(request), principal.tid, body)
    except ValueError as exc:  # invalid connector config
        raise AppError(f"Invalid connector config: {str(exc)[:200]}") from None
    await audit.record(
        request,
        "event.ingest",
        principal=principal,
        details={
            "source_type": body.source_type,
            "accepted": response.accepted,
            "duplicates": response.duplicates,
            "rejected": len(response.rejected),
        },
    )
    return response
