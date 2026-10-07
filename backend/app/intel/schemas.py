import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.intel.types import EntityType

WatchVerdict = Literal["malicious", "suspicious", "benign"]
Tag = Annotated[str, StringConstraints(min_length=1, max_length=40)]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LookupRequest(_In):
    value: str = Field(min_length=1, max_length=2048)
    type: EntityType | None = None  # auto-detected when omitted
    refresh: bool = False
    providers: list[str] | None = Field(default=None, max_length=10)


class EntityCreate(_In):
    type: EntityType
    value: str = Field(min_length=1, max_length=2048)
    watch_verdict: WatchVerdict | None = None
    watch_confidence: int = Field(default=70, ge=0, le=100)
    notes: str = Field(default="", max_length=10000)
    tags: list[Tag] = Field(default_factory=list, max_length=20)


class EntityUpdate(_In):
    watch_verdict: WatchVerdict | None = None
    clear_watch: bool = False
    watch_confidence: int | None = Field(default=None, ge=0, le=100)
    notes: str | None = Field(default=None, max_length=10000)
    tags: list[Tag] | None = Field(default=None, max_length=20)


class ObservationOut(BaseModel):
    provider: str
    status: str
    verdict: str
    confidence: int
    summary: str
    data: dict[str, Any]
    fetched_at: datetime


class EntityOut(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    verdict: str
    score: int
    watch_verdict: str | None
    watch_confidence: int
    notes: str
    tags: list[str]
    source: str
    last_enriched_at: datetime | None
    created_at: datetime
    updated_at: datetime


class RelationOut(BaseModel):
    id: uuid.UUID
    kind: str
    direction: Literal["out", "in"]
    other: EntityOut
    source: str


class Coverage(BaseModel):
    answered: int
    failed: int
    not_found: int
    skipped: list[dict[str, str]]  # providers that did not run and why (e.g. not configured)


class EntityDetail(BaseModel):
    entity: EntityOut
    score_breakdown: list[dict[str, Any]]
    observations: list[ObservationOut]
    relations: list[RelationOut]
    coverage: Coverage | None = None


class RelationCreate(_In):
    dst_id: uuid.UUID
    kind: Literal["indicates", "uses", "attributed-to", "part-of"]


class BatchItem(_In):
    type: EntityType
    value: str = Field(min_length=1, max_length=2048)


class BatchRequest(_In):
    items: list[BatchItem] = Field(min_length=1, max_length=100)


class ProviderIn(_In):
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] | None = None  # omitted => keep existing secrets


class ProviderOut(BaseModel):
    key: str
    display_name: str
    description: str
    supported_types: list[str]
    offline: bool
    secret_keys: list[str]
    config_schema: dict[str, Any]
    config: dict[str, Any] = Field(default_factory=dict)  # non-secret settings only
    configured: bool
    enabled: bool
    last_status: str
    last_detail: str
    last_checked_at: datetime | None
