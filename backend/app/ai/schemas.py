import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunCreate(_In):
    goal: str = Field(min_length=5, max_length=2000)
    hunt_id: uuid.UUID | None = None
    hours_back: int = Field(default=24, ge=1, le=720)
    mode: Literal["quick", "standard", "deep"] = "standard"
    open_case: bool = False  # when the run finishes, open a case holding the hunt report (needs cases:write)


class ResumeIn(_In):
    mode: Literal["quick", "standard", "deep"] | None = None  # defaults to the run's own mode
    open_case: bool = False


class TranslateIn(_In):
    question: str = Field(min_length=3, max_length=1000)


class SaveIn(_In):
    hunt_id: uuid.UUID | None = None  # defaults to the run's hunt
    finding_indexes: list[int] = Field(min_length=1, max_length=20)


class Status(BaseModel):
    enabled: bool
    provider: str
    model: str
    max_steps: int
    web_search: bool = False
    intel_providers: list[str] = []
    modes: dict[str, dict[str, int]] = {}


class CaseLinkOut(BaseModel):
    case_id: uuid.UUID
    number: int
    created: bool  # False when the run already had a case and its report was refreshed


class TranslateOut(BaseModel):
    query: str | None
    note: str


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hunt_id: uuid.UUID | None
    case_id: uuid.UUID | None = None
    case_number: int | None = None  # set when this response opened or refreshed the run's case
    goal: str
    status: str
    provider: str
    model: str
    hours_back: int
    mode: str = "standard"
    resumable: bool = False
    steps: list[dict[str, Any]]
    conclusion: dict[str, Any] | None
    saved_findings: list[str]
    input_tokens: int
    output_tokens: int
    error: str
    created_at: datetime


class LessonOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cue: str
    lesson: str
    evidence: str
    confidence: str
    origin: str
    status: str
    times_shown: int
    run_id: uuid.UUID | None
    created_at: datetime


class LessonIn(_In):
    cue: str = Field(min_length=8, max_length=200)
    lesson: str = Field(min_length=20, max_length=400)
    evidence: str = Field(default="", max_length=300)


class LessonPatch(_In):
    status: Literal["active", "disabled"]
