import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DataSourceCreate(_In):
    name: str = Field(min_length=1, max_length=120)
    connector_type: str = Field(min_length=1, max_length=64)
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict, max_length=10)
    enabled: bool = True


class DataSourceUpdate(_In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    config: dict[str, Any] | None = None
    secrets: dict[str, str] | None = Field(default=None, max_length=10)
    enabled: bool | None = None


class FastLaneOut(BaseModel):
    """The fast lane of a sweep: the hottest indicators only, kept close to real time."""

    status: str
    detail: str = ""
    cursor: datetime | None = None
    last_run_at: datetime | None = None
    iocs_total: int = 0
    ioas_total: int = 0
    pending: int = 0
    hits_total: int = 0


class SweepOut(BaseModel):
    """Progress of the continuous indicator sweep of a SIEM source."""

    status: str  # pending (not run yet) | idle | ok | partial | error | off
    detail: str = ""
    cursor: datetime | None = None  # everything before this instant has been searched for every swept indicator
    last_run_at: datetime | None = None
    last_ok_at: datetime | None = None
    iocs_total: int = 0
    ioas_total: int = 0  # behaviours swept alongside the indicators
    pending: int = 0  # indicators of the window in flight still to search
    hits_total: int = 0
    windows_done: int = 0
    fast: FastLaneOut | None = None  # None: no fast lane on this source


class DataSourceOut(BaseModel):
    id: uuid.UUID
    name: str
    connector_type: str
    config: dict[str, Any]
    has_secrets: bool
    secret_keys: list[str]
    enabled: bool
    supports_collect: bool
    health_status: str
    health_detail: str
    health_checked_at: datetime | None
    last_ingest_at: datetime | None
    events_total: int
    created_at: datetime
    ingest_key: str | None = None  # returned exactly once, at creation / rotation
    sweep: SweepOut | None = None  # None: this source is not swept (push sources, datasets with no query surface)


class ConnectorInfo(BaseModel):
    type: str
    display_name: str
    supports_collect: bool
    config_schema: dict[str, Any]


class SecretValue(_In):
    value: str = Field(min_length=1, max_length=8192)
