import base64
from typing import Any

from app.intel.providers.base import Context, Provider, ProviderResult, clip, clip_list, trim

_PATH = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "md5": "files", "sha1": "files", "sha256": "files"}


class VirusTotalProvider(Provider):
    key = "virustotal"
    display_name = "VirusTotal"
    description = (
        "Multi-engine reputation (API v3). Requires a VirusTotal API key; the public tier is heavily rate limited."
    )
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    secret_keys = ["api_key"]
    BASE = "https://www.virustotal.com/api/v3"

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if type_ == "url" else value
        resp = await self.request(
            "GET", f"{self.BASE}/{_PATH[type_]}/{ident}", headers={"x-apikey": ctx.secrets["api_key"]}
        )
        if resp.status_code == 404:
            return ProviderResult("not_found", summary="Unknown to VirusTotal")
        if err := self.http_error(resp):
            return err
        body: Any = self.parse_json(resp)
        attrs = ((body.get("data") or {}).get("attributes") if isinstance(body, dict) else None) or {}
        stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
        if not isinstance(stats, dict):
            return ProviderResult("error", summary="unexpected VirusTotal response")
        m, sus, harmless = (int(stats.get(k) or 0) for k in ("malicious", "suspicious", "harmless"))
        total = sum(int(v or 0) for v in stats.values() if isinstance(v, int))
        data = trim(
            {
                "malicious": m,
                "suspicious": sus,
                "harmless": harmless,
                "engines": total,
                "reputation": attrs.get("reputation") if isinstance(attrs.get("reputation"), int) else None,
                "tags": clip_list(attrs.get("tags") or [], 10, 40),
                "name": clip(attrs.get("meaningful_name"), 120),
                "threat_label": clip(
                    ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")), 80
                ),
            }
        )
        summary = f"{m}/{total} engines flag as malicious" + (f", {sus} suspicious" if sus else "")
        if m >= 5:
            return ProviderResult("ok", "malicious", min(95, 55 + 3 * m), summary, data)
        if m >= 1 or sus >= 3:
            return ProviderResult("ok", "suspicious", 45 + 5 * min(m, 4), summary, data)
        if harmless >= 5:
            return ProviderResult("ok", "benign", 40, summary, data)
        return ProviderResult("ok", "unknown", 0, summary, data)
