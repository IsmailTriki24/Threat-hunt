import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

AssetType = Literal["host", "server", "user", "ip", "domain", "application", "cloud"]
Criticality = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Tag = Annotated[str, StringConstraints(min_length=1, max_length=40)]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssetCreate(_In):
    type: AssetType
    key: str = Field(min_length=1, max_length=320)
    display_name: str | None = Field(default=None, max_length=320)
    criticality: Criticality = "MEDIUM"
    owner: str = Field(default="", max_length=200)
    tags: list[Tag] = Field(default_factory=list, max_length=20)
    attributes: dict[str, str | int | bool] = Field(default_factory=dict, max_length=30)


class AssetUpdate(_In):
    display_name: str | None = Field(default=None, max_length=320)
    criticality: Criticality | None = None
    owner: str | None = Field(default=None, max_length=200)
    tags: list[Tag] | None = Field(default=None, max_length=20)
    attributes: dict[str, str | int | bool] | None = Field(default=None, max_length=30)


class AssetOut(BaseModel):
    id: uuid.UUID
    type: str
    key: str
    display_name: str
    criticality: str
    owner: str
    tags: list[str]
    attributes: dict[str, Any]
    event_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime


class DiscoverRequest(_In):
    days: int = Field(default=7, ge=1, le=30)


class DiscoverResult(BaseModel):
    created: int
    updated: int
