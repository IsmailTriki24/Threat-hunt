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


class ConnectorInfo(BaseModel):
    type: str
    display_name: str
    supports_collect: bool
    config_schema: dict[str, Any]


class SecretValue(_In):
    value: str = Field(min_length=1, max_length=8192)
