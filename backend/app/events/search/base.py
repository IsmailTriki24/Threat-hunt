import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.events.schema import Event
from app.events.search.query import EventQuery, SearchResult


@dataclass
class IndexResult:
    accepted: int = 0
    duplicates: int = 0
    failed: list[tuple[int, str]] = field(default_factory=list)  # (position in batch, reason)


class SearchBackend(Protocol):
    """Storage/search engine for telemetry. OpenSearch is the first implementation; any engine
    that can honour these contracts (tenant-scoped, field-registry-validated) can be swapped in.

    Every method takes a tenant id explicitly; implementations MUST scope all reads/writes by it."""

    async def ensure_schema(self) -> None: ...

    async def index_events(self, events: list[Event]) -> IndexResult: ...

    async def search(self, tenant_id: uuid.UUID, query: EventQuery) -> SearchResult: ...

    async def get_event(self, tenant_id: uuid.UUID, event_id: str) -> dict[str, Any] | None: ...

    async def delete_before(self, tenant_id: uuid.UUID, cutoff_iso: str) -> int: ...

    async def health(self) -> dict[str, Any]: ...
