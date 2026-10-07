import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.events.search.query import EventQuery

HuntStatus = Literal["DRAFT", "ACTIVE", "COMPLETED", "ARCHIVED"]
Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Source = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{1,64}$")]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HuntCreate(_In):
    title: str = Field(min_length=1, max_length=200)
    hypothesis: str = Field(default="", max_length=5000)
    status: HuntStatus = "DRAFT"
    time_start: datetime | None = None
    time_end: datetime | None = None
    data_sources: list[Source] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def _window(self) -> "HuntCreate":
        if (self.time_start is None) != (self.time_end is None):
            raise ValueError("time_start and time_end must be set together")
        if self.time_start and self.time_end and self.time_start >= self.time_end:
            raise ValueError("time_start must be before time_end")
        return self


class HuntUpdate(_In):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    hypothesis: str | None = Field(default=None, max_length=5000)
    status: HuntStatus | None = None
    conclusion: str | None = Field(default=None, max_length=10000)
    time_start: datetime | None = None
    time_end: datetime | None = None
    data_sources: list[Source] | None = Field(default=None, max_length=20)


class HuntOut(BaseModel):
    id: uuid.UUID
    title: str
    hypothesis: str
    status: str
    time_start: datetime | None
    time_end: datetime | None
    data_sources: list[str]
    conclusion: str
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    finding_count: int = 0
    query_count: int = 0


class HuntRunRequest(_In):
    query: EventQuery


class SavedQueryCreate(_In):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    hunt_id: uuid.UUID | None = None
    query: EventQuery


class SavedQueryOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    hunt_id: uuid.UUID | None
    query: dict[str, Any]
    created_by: uuid.UUID | None
    created_at: datetime


class HistoryOut(BaseModel):
    id: uuid.UUID
    hunt_id: uuid.UUID | None
    query: dict[str, Any]
    total: int
    took_ms: int
    executed_at: datetime


class FindingCreate(_In):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    severity: Severity = "MEDIUM"
    event_ids: list[Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]] = Field(max_length=50)


class FindingOut(BaseModel):
    id: uuid.UUID
    hunt_id: uuid.UUID
    title: str
    description: str
    severity: str
    evidence: list[dict[str, Any]]
    created_by: uuid.UUID | None
    created_at: datetime


class NoteCreate(_In):
    body: str = Field(min_length=1, max_length=10000)


class NoteOut(BaseModel):
    id: uuid.UUID
    hunt_id: uuid.UUID
    body: str
    author_id: uuid.UUID | None
    created_at: datetime


class ParseRequest(_In):
    text: str = Field(max_length=2000)


class ExportRequest(_In):
    query: EventQuery
    format: Literal["csv", "json"] = "csv"
    max_rows: int = Field(default=1000, ge=1, le=5000)
