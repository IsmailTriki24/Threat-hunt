import uuid
from typing import Any

from pydantic import BaseModel, Field

from app.connectors import registry
from app.connectors.base import NormalizationError
from app.core.metrics import EVENTS_INGESTED, EVENTS_REJECTED
from app.events.schema import Event, EventIn
from app.events.search.base import SearchBackend


class IngestRequest(BaseModel):
    source_type: str = Field(default="canonical", max_length=64)
    # Connector configuration, e.g. field_map for generic_json. Validated by the connector's config model.
    config: dict[str, Any] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(min_length=1)


class Rejection(BaseModel):
    index: int
    reason: str


class IngestResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: list[Rejection]


async def ingest(backend: SearchBackend, tenant_id: uuid.UUID, req: IngestRequest) -> IngestResponse:
    connector = registry.build(req.source_type, req.config)
    rejected: list[Rejection] = []
    staged: list[tuple[int, Event]] = []
    for i, raw in enumerate(req.events):
        try:
            normalized: list[EventIn] = connector.normalize(raw)
        except NormalizationError as exc:
            rejected.append(Rejection(index=i, reason=str(exc)))
            EVENTS_REJECTED.labels("normalization").inc()
            continue
        # tenant_id is stamped here from the authenticated principal; any value in the payload is
        # rejected earlier (extra="forbid") or ignored by connectors.
        staged.extend((i, Event.from_input(e, tenant_id)) for e in normalized)

    result = await backend.index_events([e for _, e in staged])
    for pos, reason in result.failed:
        rejected.append(Rejection(index=staged[pos][0], reason=f"index_error:{reason}"))
        EVENTS_REJECTED.labels("index").inc()
    if result.accepted:
        EVENTS_INGESTED.labels(str(tenant_id)).inc(result.accepted)
    return IngestResponse(accepted=result.accepted, duplicates=result.duplicates, rejected=rejected)
