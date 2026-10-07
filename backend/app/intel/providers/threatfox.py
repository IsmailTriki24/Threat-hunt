from typing import Any

from app.intel.providers.base import Context, Provider, ProviderResult, RelationHint, clip, clip_list, trim


class ThreatFoxProvider(Provider):
    key = "threatfox"
    display_name = "ThreatFox (abuse.ch)"
    description = "Community IOC database of malware C2s and payloads. Requires a free abuse.ch Auth-Key."
    supported_types = {"ip", "domain", "url", "md5", "sha256"}
    secret_keys = ["auth_key"]
    URL = "https://threatfox-api.abuse.ch/api/v1/"

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        resp = await self.request(
            "POST",
            self.URL,
            headers={"Auth-Key": ctx.secrets["auth_key"]},
            json_body={"query": "search_ioc", "search_term": value, "exact_match": type_ != "ip"},
        )
        if err := self.http_error(resp):
            return err
        body: Any = self.parse_json(resp)
        status = body.get("query_status") if isinstance(body, dict) else None
        if status in ("no_result", "illegal_search_term"):
            return ProviderResult("not_found", summary="No ThreatFox record")
        rows = body.get("data") if isinstance(body, dict) else None
        if status != "ok" or not isinstance(rows, list) or not rows:
            return ProviderResult("error", summary=f"unexpected ThreatFox response ({clip(status, 40)})")
        rows = [r for r in rows if isinstance(r, dict)][:20]
        confidence = max(
            (int(r.get("confidence_level") or 50) for r in rows if str(r.get("confidence_level", "0")).isdigit()),
            default=50,
        )
        malware = sorted({clip(r.get("malware_printable"), 80) for r in rows if r.get("malware_printable")})[:5]
        tags = sorted({t for r in rows for t in clip_list(r.get("tags") or [], 10, 40)})[:10]
        return ProviderResult(
            "ok",
            "malicious",
            min(95, max(confidence, 50)),
            f"ThreatFox: {len(rows)} report(s)" + (f"; malware: {', '.join(malware)}" if malware else ""),
            trim(
                {
                    "reports": len(rows),
                    "malware": malware,
                    "tags": tags,
                    "threat_types": sorted({clip(r.get("threat_type"), 40) for r in rows if r.get("threat_type")})[:5],
                    "first_seen": clip(rows[0].get("first_seen_utc"), 40),
                }
            ),
            [RelationHint("indicates", "malware", m) for m in malware[:3]],
        )
