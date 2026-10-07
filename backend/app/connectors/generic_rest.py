"""Pull connector for JSON REST APIs. All requests go through the SSRF guard."""

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.connectors.base import ConnectionResult, Connector, ConnectorHealth, NormalizationError
from app.connectors.generic_json import GenericJsonConfig, GenericJsonConnector
from app.core import ssrf

# Test seam: tests inject a MockTransport / fake resolver here.
HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None
RESOLVER: ssrf.Resolver = ssrf.default_resolver


class GenericRestConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: HttpUrl
    records_path: str = Field(default="", max_length=200, description="dotted path to the list of records")
    since_param: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    limit_param: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    mapping: GenericJsonConfig = Field(default_factory=GenericJsonConfig)
    # Which secret becomes the Authorization header value (secrets: {"authorization": "Bearer …"}).
    timeout_s: float = Field(default=15.0, gt=0, le=60)


def _dig(obj: Any, path: str) -> Any:
    for part in [p for p in path.split(".") if p]:
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


class GenericRestConnector(Connector):
    connector_type = "generic_rest"
    display_name = "Generic REST API"
    supports_collect = True
    config_model = GenericRestConfig

    def _headers(self) -> dict[str, str]:
        auth = self.secrets.get("authorization")
        return {"Authorization": auth, "Accept": "application/json"} if auth else {"Accept": "application/json"}

    async def test_connection(self) -> ConnectionResult:
        cfg: GenericRestConfig = self.config  # type: ignore[assignment]
        try:
            resp = await ssrf.fetch(
                "GET",
                str(cfg.url),
                headers=self._headers(),
                timeout=cfg.timeout_s,
                transport=HTTP_TRANSPORT,
                resolver=RESOLVER,
            )
        except (ssrf.SsrfError, httpx.HTTPError) as exc:
            return ConnectionResult(ok=False, detail=f"{type(exc).__name__}: {str(exc)[:150]}")
        return ConnectionResult(ok=resp.status_code < 400, detail=f"HTTP {resp.status_code}")

    async def health(self) -> ConnectorHealth:
        res = await self.test_connection()
        return ConnectorHealth(status="ok" if res.ok else "down", detail=res.detail)

    async def collect(self, since: datetime | None = None, limit: int = 1000) -> AsyncIterator[dict[str, Any]]:
        cfg: GenericRestConfig = self.config  # type: ignore[assignment]
        params: dict[str, Any] = {}
        if since and cfg.since_param:
            params[cfg.since_param] = since.isoformat()
        if cfg.limit_param:
            params[cfg.limit_param] = limit
        resp = await ssrf.fetch(
            "GET",
            str(cfg.url),
            headers=self._headers(),
            params=params,
            timeout=cfg.timeout_s,
            transport=HTTP_TRANSPORT,
            resolver=RESOLVER,
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            raise NormalizationError("response is not valid JSON") from None
        records = _dig(payload, cfg.records_path) if cfg.records_path else payload
        if not isinstance(records, list):
            raise NormalizationError("records_path does not point at a list")
        for record in records[:limit]:
            if isinstance(record, dict):
                yield record

    def normalize(self, raw: dict[str, Any]) -> list[Any]:
        cfg: GenericRestConfig = self.config  # type: ignore[assignment]
        return GenericJsonConnector(cfg.mapping).normalize(raw)
