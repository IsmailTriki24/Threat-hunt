from typing import Any

from app.intel.providers.base import Context, Provider, ProviderResult, clip, clip_list, trim


class UrlhausProvider(Provider):
    key = "urlhaus"
    display_name = "URLhaus (abuse.ch)"
    description = "Malware-distribution URLs, hosts and payload hashes. Requires a free abuse.ch Auth-Key."
    supported_types = {"url", "domain", "ip", "md5", "sha256"}
    secret_keys = ["auth_key"]
    BASE = "https://urlhaus-api.abuse.ch/v1"

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        endpoint, form = {
            "url": ("url", {"url": value}),
            "domain": ("host", {"host": value}),
            "ip": ("host", {"host": value}),
            "md5": ("payload", {"md5_hash": value}),
            "sha256": ("payload", {"sha256_hash": value}),
        }[type_]
        resp = await self.request(
            "POST", f"{self.BASE}/{endpoint}/", headers={"Auth-Key": ctx.secrets["auth_key"]}, form=form
        )
        if err := self.http_error(resp):
            return err
        body: Any = self.parse_json(resp)
        status = body.get("query_status") if isinstance(body, dict) else None
        if status in ("no_results", "invalid_url", "invalid_host", "invalid_md5_hash", "invalid_sha256_hash"):
            return ProviderResult("not_found", summary="No URLhaus record")
        if status != "ok":
            return ProviderResult("error", summary=f"unexpected URLhaus response ({clip(status, 40)})")
        data: dict[str, Any] = {
            "threat": clip(body.get("threat"), 60),
            "url_status": clip(body.get("url_status"), 20),
            "tags": clip_list(body.get("tags") or [], 10, 40),
            "signature": clip(body.get("signature"), 80),
            "url_count": clip(body.get("url_count"), 12),
            "urls_online": clip(body.get("urls_online"), 12),
        }
        data = {k: v for k, v in data.items() if v not in ("", [], "None")}
        online = data.get("url_status") == "online" or str(data.get("urls_online", "0")) not in ("0", "")
        return ProviderResult(
            "ok",
            "malicious",
            90 if online else 75,
            "URLhaus: known malware distribution" + (" (online)" if online else ""),
            trim(data),
        )
