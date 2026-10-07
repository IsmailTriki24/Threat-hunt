# ruff: noqa: E501
"""Enrichment provider contract. Providers are adapters: they translate an indicator into a normalised `ProviderResult`.
All remote responses are untrusted data — providers extract allow-listed, size-capped fields and never act on content."""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal

import httpx
from pydantic import BaseModel, ConfigDict

from app.core import ssrf

# Test seam (same pattern as connectors.generic_rest).
HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None
RESOLVER: ssrf.Resolver = ssrf.default_resolver
MAX_DATA_BYTES = 8 * 1024
TIMEOUT_S = 10.0


class EmptyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass
class RelationHint:
    kind: str  # indicates | attributed-to | uses
    type: str  # target entity type (malware | threat_actor | campaign)
    value: str


@dataclass
class ProviderResult:
    status: Literal["ok", "not_found", "error", "unavailable"]
    verdict: str = "unknown"
    confidence: int = 0
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    relations: list[RelationHint] = field(default_factory=list)


@dataclass
class Context:
    config: dict[str, Any]
    secrets: dict[str, str]
    watch_verdict: str | None = None  # entity-level analyst verdict (watchlist provider)
    watch_confidence: int = 0


def trim(data: dict[str, Any]) -> dict[str, Any]:
    """Cap stored provider data; drop it entirely rather than store something huge."""
    blob = json.dumps(data, default=str)
    if len(blob) <= MAX_DATA_BYTES:
        return data
    return {"truncated": True, "note": "provider data exceeded storage cap"}


def clip(value: Any, n: int = 200) -> str:
    return str(value)[:n]


def clip_list(values: Any, n: int = 10, width: int = 100) -> list[str]:
    return [clip(v, width) for v in values[:n]] if isinstance(values, list) else []


class Provider(ABC):
    key: ClassVar[str]
    display_name: ClassVar[str]
    description: ClassVar[str] = ""
    supported_types: ClassVar[set[str]] = set()
    offline: ClassVar[bool] = False
    secret_keys: ClassVar[list[str]] = []  # all required unless listed in optional_secrets
    optional_secrets: ClassVar[list[str]] = []
    config_model: ClassVar[type[BaseModel]] = EmptyConfig

    def configured(self, ctx: Context) -> bool:
        return all(k in ctx.secrets and ctx.secrets[k] for k in self.secret_keys)

    @abstractmethod
    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult: ...

    async def test(self, ctx: Context) -> tuple[bool, str]:
        return (
            (True, "offline provider")
            if self.offline
            else (self.configured(ctx), "credentials present" if self.configured(ctx) else "not configured")
        )

    # ---- helpers for HTTP providers ----------------------------------------------------------------
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        form: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await ssrf.fetch(
            method,
            url,
            headers=headers,
            params=params,
            json_body=json_body,
            form=form,
            timeout_s=TIMEOUT_S,
            transport=HTTP_TRANSPORT,
            resolver=RESOLVER,
        )

    @staticmethod
    def parse_json(resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except ValueError:
            raise ValueError("provider returned non-JSON content") from None

    @staticmethod
    def http_error(resp: httpx.Response) -> ProviderResult | None:
        if resp.status_code in (401, 403):
            return ProviderResult("error", summary=f"authentication rejected (HTTP {resp.status_code})")
        if resp.status_code == 429:
            return ProviderResult("error", summary="rate limited by provider (HTTP 429)")
        if resp.status_code >= 400:
            return ProviderResult("error", summary=f"provider error (HTTP {resp.status_code})")
        return None
