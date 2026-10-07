from typing import Any

from pydantic import BaseModel, ConfigDict, HttpUrl

from app.intel.providers.base import Context, Provider, ProviderResult, clip, trim


class MispConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: HttpUrl  # base URL of the MISP instance, e.g. https://misp.example.org


class MispProvider(Provider):
    key = "misp"
    display_name = "MISP"
    description = "Your MISP instance (attributes search). Requires its URL and an automation API key."
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256", "email"}
    secret_keys = ["api_key"]
    config_model = MispConfig

    def configured(self, ctx: Context) -> bool:
        return bool(ctx.config.get("url")) and super().configured(ctx)

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        base = str(ctx.config["url"]).rstrip("/")
        resp = await self.request(
            "POST",
            f"{base}/attributes/restSearch",
            headers={"Authorization": ctx.secrets["api_key"], "Accept": "application/json"},
            json_body={
                "returnFormat": "json",
                "value": value,
                "limit": 20,
                "includeEventTags": True,
                "enforceWarninglist": True,
            },
        )
        if err := self.http_error(resp):
            return err
        body: Any = self.parse_json(resp)
        attrs = ((body.get("response") or {}).get("Attribute") if isinstance(body, dict) else None) or []
        if not isinstance(attrs, list):
            return ProviderResult("error", summary="unexpected MISP response")
        attrs = [a for a in attrs if isinstance(a, dict)][:20]
        if not attrs:
            return ProviderResult("not_found", summary="No MISP attribute")
        to_ids = any(a.get("to_ids") is True for a in attrs)
        events = sorted(
            {clip((a.get("Event") or {}).get("info"), 120) for a in attrs if isinstance(a.get("Event"), dict)}
        )[:5]
        tags = sorted({clip(t.get("name"), 60) for a in attrs for t in (a.get("Tag") or []) if isinstance(t, dict)})[
            :10
        ]
        data = trim(
            {
                "attributes": len(attrs),
                "to_ids": to_ids,
                "events": events,
                "tags": tags,
                "categories": sorted({clip(a.get("category"), 40) for a in attrs})[:5],
            }
        )
        if to_ids:
            return ProviderResult("ok", "malicious", 75, f"MISP: {len(attrs)} attribute(s) flagged for detection", data)
        return ProviderResult("ok", "suspicious", 40, f"MISP: {len(attrs)} attribute(s), not flagged to_ids", data)
