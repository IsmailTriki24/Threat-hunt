import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.events.search.query import EventQuery
from app.mitre.suggest import Suggestion

TechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
EventId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]
ObjectType = Literal["hunt", "case", "finding", "detection"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SuggestRequest(_In):
    event_ids: list[EventId] | None = Field(default=None, max_length=200)
    query: EventQuery | None = None
    case_id: uuid.UUID | None = None
    hunt_id: uuid.UUID | None = None
    limit: int = Field(default=300, ge=1, le=500)


class SuggestionOut(Suggestion):
    mapped: bool = False  # already accepted for the case/hunt the suggestions were computed for


class SuggestResponse(BaseModel):
    analyzed_events: int
    suggestions: list[SuggestionOut]


class MappingCreate(_In):
    technique_id: TechniqueId
    object_type: ObjectType
    object_id: uuid.UUID
    confidence: Confidence
    reasoning: str = Field(min_length=10, max_length=5000)
    evidence_event_ids: list[EventId] = Field(default_factory=list, max_length=100)
    source: Literal["analyst", "suggestion"] = "analyst"


class MappingOut(BaseModel):
    id: uuid.UUID
    technique_id: str
    technique_name: str
    tactics: list[str]
    object_type: str
    object_id: uuid.UUID
    confidence: str
    reasoning: str
    evidence_event_ids: list[str]
    evidence_count: int
    source: str
    created_by: uuid.UUID | None
    created_at: datetime


class TacticOut(BaseModel):
    id: str
    shortname: str
    name: str
    position: int


class TechniqueOut(BaseModel):
    id: str
    name: str
    parent_id: str | None
    is_subtechnique: bool
    tactics: list[str]
    description: str
    url: str
    source: str


class TechniqueDetail(TechniqueOut):
    subtechniques: list[TechniqueOut] = Field(default_factory=list)


class MatrixTechnique(BaseModel):
    id: str
    name: str
    mapping_count: int
    top_confidence: str | None
    subtechniques: list["MatrixTechnique"] = Field(default_factory=list)


class MatrixColumn(BaseModel):
    tactic: TacticOut
    techniques: list[MatrixTechnique]


class MappedObject(BaseModel):
    object_type: str
    object_id: uuid.UUID
    title: str
    confidence: str


class NameCount(BaseModel):
    count: int
    names: list[str]


class TechniqueSummary(BaseModel):
    technique: TechniqueOut
    mappings: int
    objects: list[MappedObject]
    evidence_events: int
    hosts: NameCount
    users: NameCount
    risk: Literal["HIGH", "MEDIUM", "LOW"]
    risk_reasons: list[str]
