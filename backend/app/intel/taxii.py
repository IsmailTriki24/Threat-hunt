"""Minimal TAXII 2.1 client (collection object pull) built on the SSRF-safe fetcher."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.core import ssrf
from app.intel.providers import base as provider_base

MAX_PAGES = 10
MAX_OBJECTS = 5000
ACCEPT = "application/taxii+json;version=2.1"


class TaxiiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: HttpUrl  # API root, e.g. https://taxii.example.org/taxii2/root/
    collection_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")


async def pull(config: dict[str, Any], secrets: dict[str, str], added_after: str | None = None) -> list[dict[str, Any]]:
    cfg = TaxiiConfig.model_validate(config)
    headers = {"Accept": ACCEPT}
    if secrets.get("bearer"):
        headers["Authorization"] = f"Bearer {secrets['bearer']}"
    elif secrets.get("username") and secrets.get("password"):
        import base64

        headers["Authorization"] = (
            "Basic " + base64.b64encode(f"{secrets['username']}:{secrets['password']}".encode()).decode()
        )
    url = f"{str(cfg.url).rstrip('/')}/collections/{cfg.collection_id}/objects/"
    params: dict[str, Any] = {"limit": 500}
    if added_after:
        params["added_after"] = added_after
    objects: list[dict[str, Any]] = []
    for _ in range(MAX_PAGES):
        resp = await ssrf.fetch(
            "GET",
            url,
            headers=headers,
            params=params,
            timeout_s=provider_base.TIMEOUT_S,
            transport=provider_base.HTTP_TRANSPORT,
            resolver=provider_base.RESOLVER,
        )
        if resp.status_code >= 400:
            raise ValueError(f"TAXII server returned HTTP {resp.status_code}")
        body = resp.json()
        if not isinstance(body, dict):
            raise ValueError("unexpected TAXII response")
        objects.extend(o for o in (body.get("objects") or []) if isinstance(o, dict))
        if not body.get("more") or not body.get("next") or len(objects) >= MAX_OBJECTS:
            break
        params = {"limit": 500, "next": str(body["next"])[:200]}
        if added_after:
            params["added_after"] = added_after
    return objects[:MAX_OBJECTS]
