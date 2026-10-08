import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.events.schema import EventIn
from app.events.search.query import Condition, TimeRange

RuleStatus = Literal["DRAFT", "TESTING", "ACTIVE", "DISABLED", "ARCHIVED"]
AlertStatus = Literal["OPEN", "ACKNOWLEDGED", "CLOSED"]
Content = Field(min_length=1, max_length=65_000)


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RuleCreate(_In):
    format: str = Field(pattern=r"^[a-z_]{1,16}$")
    content: str = Content
    hunt_id: uuid.UUID | None = None


class RuleUpdate(_In):
    content: str = Content
    note: str = Field(default="", max_length=300)


class FromQuery(_In):
    """Promote a hunt query to a detection."""

    title: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=2000)
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    description: str = Field(default="", max_length=2000)
    hunt_id: uuid.UUID | None = None


class Transition(_In):
    to: RuleStatus


class ValidateRequest(_In):
    format: str = Field(pattern=r"^[a-z_]{1,16}$")
    content: str = Content
    events: list[EventIn] = Field(default_factory=list, max_length=20)


class TestCaseIn(_In):
    name: str = Field(min_length=1, max_length=200)
    event: EventIn
    expect_match: bool


class BacktestRequest(_In):
    time_range: TimeRange | None = None  # default: last 24 hours
    limit: int = Field(default=50, ge=1, le=200)


class AlertUpdate(_In):
    status: AlertStatus


class AlertToCase(_In):
    title: str | None = Field(default=None, max_length=200)


class FormatOut(BaseModel):
    id: str
    name: str
    description: str


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    description: str
    format: str
    content: str
    version: int
    status: str
    severity: str
    executable: bool = False
    compiled: dict[str, Any] | None
    unsupported: list[str]
    warnings: list[str]
    techniques: list[str]
    tactics: list[str]
    tags: list[str]
    hunt_id: uuid.UUID | None
    tests_passed: bool | None
    tests_run_at: datetime | None
    activated_at: datetime | None
    last_evaluated_at: datetime | None
    last_run_status: str
    last_run_error: str
    created_at: datetime
    updated_at: datetime
    test_count: int = 0
    open_alerts: int = 0


class VersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: int
    format: str
    content: str
    note: str
    changed_by: uuid.UUID | None
    created_at: datetime


class TestCaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    event: dict[str, Any]
    expect_match: bool
    created_at: datetime


class TestResult(BaseModel):
    case_id: uuid.UUID | None = None
    name: str
    expect_match: bool
    matched: bool
    passed: bool
    explanation: list[str] = Field(default_factory=list)  # which named Sigma selections matched


class TestRunOut(BaseModel):
    passed: bool
    results: list[TestResult]


class ValidateOut(BaseModel):
    ok: bool
    error: str | None = None
    title: str = ""
    severity: str = ""
    executable: bool = False
    unsupported: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    condition: Condition | None = None
    results: list[TestResult] = Field(default_factory=list)


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: uuid.UUID
    rule_version: int
    kind: str
    window_start: datetime
    window_end: datetime
    status: str
    error: str
    matches: int
    new_alerts: int
    took_ms: int
    sample_event_ids: list[str]
    created_at: datetime


class BacktestOut(BaseModel):
    run: RunOut
    hits: list[dict[str, Any]]
    total: int


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: uuid.UUID
    rule_version: int
    rule_title: str
    severity: str
    event_id: str
    event_timestamp: datetime
    snapshot: dict[str, Any]
    status: str
    case_id: uuid.UUID | None
    created_at: datetime


class Overview(BaseModel):
    rules_by_status: dict[str, int]
    open_alerts: int
    alerts_by_severity: dict[str, int]
    coverage: list[str]  # ATT&CK techniques covered by ACTIVE rules
