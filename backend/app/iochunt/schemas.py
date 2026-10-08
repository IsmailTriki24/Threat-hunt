import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IocType = Literal["ip", "domain", "url", "sha256", "sha1", "md5", "email"]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FeedCreate(_In):
    name: str = Field(min_length=1, max_length=120)
    feed_type: str = Field(min_length=1, max_length=32)
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict, max_length=5)
    enabled: bool = True
    interval_minutes: int = Field(default=60, ge=5, le=1440)
    max_age_days: int = Field(default=14, ge=1, le=90)
    min_confidence: int = Field(default=0, ge=0, le=100)
    max_items: int = Field(default=2000, ge=1, le=20000)


class FeedUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=5, le=1440)
    max_age_days: int | None = Field(default=None, ge=1, le=90)
    min_confidence: int | None = Field(default=None, ge=0, le=100)
    max_items: int | None = Field(default=None, ge=1, le=20000)


class SecretValue(_In):
    value: str = Field(min_length=1, max_length=8192)


class FeedOut(BaseModel):
    id: uuid.UUID
    name: str
    feed_type: str
    config: dict[str, Any]
    has_secrets: bool
    secret_keys: list[str]
    enabled: bool
    interval_minutes: int
    max_age_days: int
    min_confidence: int
    max_items: int
    last_run_at: datetime | None
    last_status: str
    last_detail: str
    last_new: int
    last_seen_total: int
    ioc_count: int = 0


class FeedTypeOut(BaseModel):
    type: str
    name: str
    description: str
    needs_secret: bool
    secret_names: list[str]
    config_schema: dict[str, Any]


class IocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    type: str
    value: str
    confidence: int
    first_seen: datetime
    last_seen: datetime
    valid_until: datetime | None
    threat_type: str
    malware: str
    description: str
    reference: str
    tags: list[str]
    techniques: list[str]
    status: str
    status_reason: str
    seen_count: int
    validated_at: datetime | None
    case_id: uuid.UUID | None
    last_hunted_at: datetime | None


class IocPage(BaseModel):
    total: int
    items: list[IocOut]
    facets: dict[str, dict[str, int]]


class ManualIoc(_In):
    type: IocType
    value: str = Field(min_length=1, max_length=2048)
    confidence: int = Field(default=70, ge=0, le=100)
    description: str = Field(default="", max_length=1000)
    threat_type: str = Field(default="", max_length=64)
    tags: list[str] = Field(default_factory=list, max_length=10)
    valid_days: int = Field(default=30, ge=1, le=365)


class ValidateIn(_In):
    ioc_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    name: str | None = Field(default=None, max_length=200)
    lookback_days: int = Field(default=7, ge=1, le=30)


class RejectIn(_In):
    ioc_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    reason: str = Field(default="", max_length=300)


class AllowIn(_In):
    type: IocType
    value: str = Field(min_length=1, max_length=2048)
    reason: str = Field(default="", max_length=300)


class AllowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    type: str
    value: str
    reason: str
    created_at: datetime


class HuntOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    threat_id: uuid.UUID | None = None
    threat_name: str | None = None
    signal_count: int = 0

    id: uuid.UUID
    name: str
    hypothesis: str
    mode: str
    status: str
    lookback_days: int
    window_start: datetime | None
    window_end: datetime | None
    ioc_count: int = 0
    case_id: uuid.UUID | None
    case_number: int | None = None
    case_status: str | None = None
    hunt_id: uuid.UUID | None
    match_count: int
    new_match_count: int
    coverage: list[dict[str, Any]]
    error: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class MatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ioc_id: uuid.UUID
    ioc_value: str = ""
    ioc_type: str = ""
    event_id: str
    event_timestamp: datetime
    source: str
    matched_field: str
    host: str
    user: str
    summary: str


class SignalMatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    ref: str
    label: str
    event_id: str
    event_timestamp: datetime
    source: str
    host: str
    user: str
    summary: str


class HuntDetail(HuntOut):
    matches: list[MatchOut] = Field(default_factory=list)
    signal_matches: list[SignalMatchOut] = Field(default_factory=list)


class Overview(BaseModel):
    threats_by_status: dict[str, int] = Field(default_factory=dict)
    new_threats_24h: int = 0
    iocs_by_status: dict[str, int]
    new_last_24h: int
    seen_in_environment: int
    feeds: int
    feeds_failing: int
    hunts_by_status: dict[str, int]
    open_ioc_cases: int


class TtpOut(BaseModel):
    technique_id: str
    name: str = ""
    tactics: list[str] = Field(default_factory=list)
    url: str = ""
    source: str
    confidence: str
    note: str = ""


class IoaOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    technique_id: str
    severity: str
    source: str
    query_text: str
    trend_query: str
    rule_id: uuid.UUID | None = None


class ThreatRow(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    aliases: list[str]
    mitre_id: str
    severity: str
    confidence: int
    status: str
    first_seen: datetime | None
    last_updated: datetime | None
    ioc_count: int
    ioc_types: dict[str, int]
    new_ioc_count: int = 0
    ioa_count: int = 0
    ttp_count: int = 0
    seen_count: int
    sources: list[str]
    case_id: uuid.UUID | None
    case_number: int | None = None
    case_status: str | None = None
    last_hunted_at: datetime | None


class ThreatPage(BaseModel):
    total: int
    items: list[ThreatRow]
    facets: dict[str, dict[str, int]]


class Bulletin(ThreatRow):
    description: str
    references: list[str]
    status_reason: str
    ttps: list[TtpOut]
    ioas: list[IoaOut]
    iocs: list[IocOut]
    hunts: list[HuntOut]


class ThreatValidate(_In):
    lookback_days: int = Field(default=7, ge=1, le=30)
    name: str | None = Field(default=None, max_length=200)
    exclude_ioc_ids: list[uuid.UUID] = Field(default_factory=list, max_length=2000)
    exclude_ioa_ids: list[uuid.UUID] = Field(default_factory=list, max_length=200)
    include_signals: bool = True  # also hunt the threat's behaviours (IOAs) and techniques (TTPs)


class ThreatReject(_In):
    reason: str = Field(default="", max_length=300)


class IoaCreate(_In):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=500)
    technique_id: str = Field(default="", pattern=r"^(T\d{4}(\.\d{3})?)?$")
    query_text: str = Field(min_length=1, max_length=1000, description="Hunt query language")
    trend_query: str = Field(default="", max_length=1000)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"


class TtpCreate(_In):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    note: str = Field(default="", max_length=300)
