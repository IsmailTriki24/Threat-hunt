"""Threat-intel platforms: AlienVault OTX, MISP, and Trend Vision One's Suspicious Object List."""

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.connectors._http import SourceError, request_json
from app.iochunt.feeds.base import Feed, RawIoc, parse_dt, techniques_in


# ---- AlienVault OTX -----------------------------------------------------------------------------------
class OtxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_pages: int = Field(default=5, ge=1, le=20)


_OTX_TYPES = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-SHA256": "sha256",
    "FileHash-SHA1": "sha1",
    "FileHash-MD5": "md5",
    "email": "email",
}


class OtxFeed(Feed):
    feed_type = "otx"
    display_name = "AlienVault OTX (subscribed pulses)"
    description = "Indicators from the pulses your OTX account subscribes to, with ATT&CK ids and adversary names where the pulse has them."
    config_model = OtxConfig
    secret_names = ["api_key"]
    needs_secret = True

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        key = self.secrets.get("api_key")
        if not key:
            raise SourceError("no OTX API key configured for this feed")
        cfg: OtxConfig = self.config  # type: ignore[assignment]
        floor = datetime.now(UTC) - timedelta(days=max_age_days)
        modified_since = max(since - timedelta(hours=1), floor) if since else floor
        url: str | None = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        params: dict[str, Any] | None = {"modified_since": modified_since.strftime("%Y-%m-%dT%H:%M:%S"), "limit": 50}
        out: list[RawIoc] = []
        for _ in range(cfg.max_pages):
            if not url:
                break
            page = await request_json(
                "GET", url, headers={"X-OTX-API-KEY": key, "Accept": "application/json"}, params=params
            )
            params = None
            if not isinstance(page, dict):
                raise SourceError("unexpected OTX response shape")
            for pulse in page.get("results") or []:
                if not isinstance(pulse, dict):
                    continue
                attack = [
                    str(a.get("id")) for a in pulse.get("attack_ids") or [] if isinstance(a, dict) and a.get("id")
                ]
                tags = [str(t) for t in pulse.get("tags") or []][:10]
                adversary = str(pulse.get("adversary") or "")
                refs = pulse.get("references") or []
                for ind in pulse.get("indicators") or []:
                    if not isinstance(ind, dict) or ind.get("is_active") is False:
                        continue
                    typ = _OTX_TYPES.get(str(ind.get("type")))
                    if typ is None:
                        continue
                    created = parse_dt(ind.get("created")) or parse_dt(pulse.get("created"))
                    out.append(
                        RawIoc(
                            value=str(ind.get("indicator") or ""),
                            type=typ,
                            first_seen=created,
                            last_seen=parse_dt(pulse.get("modified")) or created,
                            valid_until=parse_dt(ind.get("expiration")),
                            confidence=60,
                            threat_type="",
                            malware=adversary,
                            description=(
                                str(pulse.get("name") or "")
                                + (": " + str(ind.get("description")) if ind.get("description") else "")
                            )[:900],
                            reference=(
                                f"https://otx.alienvault.com/pulse/{pulse.get('id')}"
                                if pulse.get("id")
                                else (str(refs[0]) if refs else "")
                            )[:500],
                            tags=["otx", *tags],
                            techniques=techniques_in(*attack),
                        )
                    )
            nxt = page.get("next")
            url = nxt if isinstance(nxt, str) and nxt else None
        return out


# ---- MISP ---------------------------------------------------------------------------------------------
class MispConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url: HttpUrl
    verify_tls: bool = True
    ca_pem: str | None = Field(default=None, max_length=20_000)
    tls_server_name: str | None = Field(default=None, max_length=255, pattern=r"^[A-Za-z0-9.-]+$")
    only_to_ids: bool = Field(default=True, description="Only attributes flagged for detection (to_ids)")
    limit: int = Field(default=2000, ge=1, le=20000)


_MISP_TYPES = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
}


class MispFeed(Feed):
    feed_type = "misp"
    display_name = "MISP"
    description = "Detection-flagged attributes updated within the age window; ATT&CK ids are taken from mitre-attack galaxy tags."
    config_model = MispConfig
    secret_names = ["api_key"]
    needs_secret = True

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        key = self.secrets.get("api_key")
        if not key:
            raise SourceError("no MISP API key configured for this feed")
        cfg: MispConfig = self.config  # type: ignore[assignment]
        body = {
            "returnFormat": "json",
            "last": f"{max(1, max_age_days)}d",
            "limit": cfg.limit,
            "includeEventTags": True,
            "deleted": False,
        }
        if cfg.only_to_ids:
            body["to_ids"] = 1
        data = await request_json(
            "POST",
            f"{str(cfg.base_url).rstrip('/')}/attributes/restSearch",
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            json_body=body,
            verify_tls=cfg.verify_tls,
            ca_pem=cfg.ca_pem,
            tls_server_name=cfg.tls_server_name,
        )
        attrs = (data.get("response") or {}).get("Attribute") if isinstance(data, dict) else None
        if attrs is None:
            raise SourceError("unexpected MISP response shape")
        out: list[RawIoc] = []
        for a in attrs:
            if not isinstance(a, dict):
                continue
            typ = _MISP_TYPES.get(str(a.get("type")))
            if typ is None:
                continue
            tag_names = [
                str(t.get("name"))
                for t in (a.get("Tag") or []) + (a.get("EventTag") or [])
                if isinstance(t, dict) and t.get("name")
            ]
            when = parse_dt(a.get("timestamp"))
            out.append(
                RawIoc(
                    value=str(a.get("value") or ""),
                    type=typ,
                    first_seen=when,
                    last_seen=when,
                    confidence=70 if a.get("to_ids") else 40,
                    threat_type=str(a.get("category") or ""),
                    description=(
                        str((a.get("Event") or {}).get("info") or "")
                        + (f": {a.get('comment')}" if a.get("comment") else "")
                    )[:900],
                    reference=f"{str(cfg.base_url).rstrip('/')}/events/view/{a.get('event_id')}"
                    if a.get("event_id")
                    else "",
                    tags=["misp", *[t for t in tag_names if not t.startswith("misp-galaxy")][:8]],
                    techniques=techniques_in(*[t for t in tag_names if "mitre-attack" in t.lower()]),
                )
            )
        return out


# ---- Trend Vision One Suspicious Object List --------------------------------------------------------------
class TrendSoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    region: Literal["us", "eu", "jp", "sg", "au", "in", "mea"] = "eu"
    max_pages: int = Field(default=20, ge=1, le=100)


_TREND_SO_TYPES = {
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "fileSha1": "sha1",
    "fileSha256": "sha256",
    "senderMailAddress": "email",
}
_RISK_CONF = {"high": 90, "medium": 60, "low": 35}


class TrendSuspiciousObjectsFeed(Feed):
    feed_type = "trend_suspicious_objects"
    display_name = "Trend Vision One - Suspicious Object List"
    description = "Objects your Vision One tenant has flagged (block / log), with their risk level and expiry. Uses the same API key as a Trend data source."
    config_model = TrendSoConfig
    secret_names = ["api_key"]
    needs_secret = True

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        from app.connectors.trend_vision_one import REGIONS

        key = self.secrets.get("api_key")
        if not key:
            raise SourceError("no Vision One API key configured for this feed")
        cfg: TrendSoConfig = self.config  # type: ignore[assignment]
        url: str | None = REGIONS[cfg.region] + "/v3.0/threatintel/suspiciousObjects"
        params: dict[str, Any] | None = {"top": 200}
        out: list[RawIoc] = []
        for _ in range(cfg.max_pages):
            if not url:
                break
            page = await request_json(
                "GET", url, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"}, params=params
            )
            params = None
            if not isinstance(page, dict):
                raise SourceError("unexpected Vision One response shape")
            for item in page.get("items") or []:
                if not isinstance(item, dict) or item.get("inExceptionList"):
                    continue
                kind = str(item.get("type") or "")
                typ = _TREND_SO_TYPES.get(kind)
                value = item.get(kind)
                if typ is None or not isinstance(value, str):
                    continue
                risk = str(item.get("riskLevel") or "").lower()
                modified = parse_dt(item.get("lastModifiedDateTime"))
                out.append(
                    RawIoc(
                        value=value,
                        type=typ,
                        first_seen=modified,
                        last_seen=modified,
                        valid_until=parse_dt(item.get("expiredDateTime")),
                        confidence=_RISK_CONF.get(risk, 50),
                        description=f"Vision One Suspicious Object ({risk or 'unrated'} risk, action: {item.get('scanAction') or 'n/a'})",
                        reference="",
                        tags=["trend-suspicious-object", risk] if risk else ["trend-suspicious-object"],
                    )
                )
            nxt = page.get("nextLink")
            url = nxt if isinstance(nxt, str) and nxt else None
        return out
