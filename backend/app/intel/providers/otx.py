from typing import Any
from urllib.parse import quote

from app.intel.providers.base import Context, Provider, ProviderResult, RelationHint, clip, clip_list, trim

_SECTION = {"ip": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}


class OtxProvider(Provider):
    key = "otx"
    display_name = "AlienVault OTX"
    description = "Open Threat Exchange pulses. Requires a free OTX API key."
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    secret_keys = ["api_key"]
    BASE = "https://otx.alienvault.com/api/v1/indicators"

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        section = "IPv6" if type_ == "ip" and ":" in value else _SECTION[type_]
        resp = await self.request(
            "GET",
            f"{self.BASE}/{section}/{quote(value, safe='')}/general",
            headers={"X-OTX-API-KEY": ctx.secrets["api_key"]},
        )
        if resp.status_code == 404:
            return ProviderResult("not_found", summary="No OTX record")
        if err := self.http_error(resp):
            return err
        body: Any = self.parse_json(resp)
        info = body.get("pulse_info") if isinstance(body, dict) else None
        if not isinstance(info, dict):
            return ProviderResult("error", summary="unexpected OTX response")
        raw_count = info.get("count")
        count: int = raw_count if isinstance(raw_count, int) else 0
        pulses = [p for p in (info.get("pulses") or []) if isinstance(p, dict)][:10]
        if count == 0:
            return ProviderResult("not_found", summary="Not in any OTX pulse")
        adversaries = sorted({clip(p.get("adversary"), 80) for p in pulses if p.get("adversary")})[:3]
        names = [clip(p.get("name"), 100) for p in pulses[:5]]
        verdict, conf = ("malicious", 70) if count >= 3 else ("suspicious", 50)
        return ProviderResult(
            "ok",
            verdict,
            conf,
            f"Referenced by {count} OTX pulse(s)",
            trim(
                {
                    "pulse_count": count,
                    "pulses": names,
                    "adversaries": adversaries,
                    "tags": sorted({t for p in pulses for t in clip_list(p.get("tags") or [], 10, 40)})[:10],
                }
            ),
            [RelationHint("attributed-to", "threat_actor", a) for a in adversaries],
        )
