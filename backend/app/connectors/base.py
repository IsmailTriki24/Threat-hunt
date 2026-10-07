"""Connector contract. The core never imports a concrete connector; it only sees this interface
via the registry. Improvements over the sketch in the brief:
  * `normalize` is synchronous and pure (CPU-bound, no I/O) so it is trivially testable.
  * Push-only sources declare `supports_collect = False`.
  * Config is a typed pydantic model validated before use.
"""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from app.events.schema import EventIn


class EmptyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectionResult(BaseModel):
    ok: bool
    detail: str = ""


class ConnectorHealth(BaseModel):
    status: str  # ok | degraded | down | unknown
    detail: str = ""


class NormalizationError(ValueError):
    """A raw record cannot be mapped to the canonical schema."""


class Connector(ABC):
    connector_type: ClassVar[str]
    display_name: ClassVar[str]
    supports_collect: ClassVar[bool] = False
    config_model: ClassVar[type[BaseModel]] = EmptyConfig

    def __init__(self, config: BaseModel | None = None, secrets: dict[str, str] | None = None) -> None:
        self.config = config if config is not None else self.config_model()
        self.secrets: dict[str, str] = secrets or {}

    async def test_connection(self) -> ConnectionResult:
        return ConnectionResult(ok=True, detail="push-based source; nothing to connect to")

    async def collect(self, since: datetime | None = None, limit: int = 1000) -> AsyncIterator[dict[str, Any]]:
        raise NotImplementedError(f"{self.connector_type} is push-based and does not support collect()")
        yield {}  # pragma: no cover  (makes this an async generator)

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        """Map one raw record to zero or more canonical events. Raise NormalizationError if invalid."""

    async def health(self) -> ConnectorHealth:
        return ConnectorHealth(status="unknown", detail="no health probe for push-based source")
