import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Priority = Literal["P1", "P2", "P3", "P4"]
Status = Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"]
EventId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CaseCreate(_In):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20000)
    severity: Severity = "MEDIUM"
    priority: Priority = "P3"
    assignee_id: uuid.UUID | None = None
    hunt_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None  # promote a hunt finding: its evidence events seed the case
    event_ids: list[EventId] = Field(default_factory=list, max_length=100)


class CaseUpdate(_In):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=20000)
    severity: Severity | None = None
    priority: Priority | None = None
    assignee_id: uuid.UUID | None = None
    unassign: bool = False


class TransitionRequest(_In):
    status: Status
    comment: str = Field(default="", max_length=10000)


class NoteIn(_In):
    body: str = Field(min_length=1, max_length=20000)


class EvidenceAdd(_In):
    event_ids: list[EventId] = Field(min_length=1, max_length=100)
    comment: str = Field(default="", max_length=2000)


class IocAdd(_In):
    type: Literal["ip", "domain", "url", "sha256", "sha1", "md5", "email"]
    value: str = Field(min_length=1, max_length=2048)


class AssetLink(_In):
    asset_id: uuid.UUID


class PersonRef(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str


class CaseOut(BaseModel):
    id: uuid.UUID
    case_id: str  # human id, CASE-0001
    number: int
    title: str
    description: str
    severity: str
    priority: str
    status: str
    resolution: str
    assignee: PersonRef | None
    hunt_id: uuid.UUID | None
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    evidence_count: int = 0
    ioc_count: int = 0
    asset_count: int = 0
    allowed_transitions: list[str] = Field(default_factory=list)


class EvidenceOut(BaseModel):
    id: uuid.UUID
    event_id: str
    comment: str
    snapshot: dict[str, Any]
    summary: str
    added_by: uuid.UUID | None
    created_at: datetime


class IocOut(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    source: str
    occurrences: int
    context: str
    created_at: datetime


class ActivityOut(BaseModel):
    id: uuid.UUID
    kind: str
    body: str
    details: dict[str, Any]
    actor_id: uuid.UUID | None
    actor_email: str | None = None
    created_at: datetime


class ReportOut(BaseModel):
    id: uuid.UUID
    version: int
    content: str
    created_by: uuid.UUID | None
    created_at: datetime
