"""abuse.ch feeds. URLhaus' CSV and Feodo's JSON need no key; ThreatFox needs the free abuse.ch Auth-Key."""

import csv
import io
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.connectors._http import SourceError, request_json, request_text
from app.iochunt.feeds.base import Feed, RawIoc, parse_dt

MAX_FEED_BYTES = 40 * 1024 * 1024


# URLhaus tags that describe a file type, host or sensor rather than a threat
GENERIC_TAGS = {
    "github",
    "gitlab",
    "zip",
    "rar",
    "7z",
    "iso",
    "elf",
    "exe",
    "dll",
    "msi",
    "bat",
    "ps1",
    "powershell",
    "js",
    "vbs",
    "lnk",
    "jar",
    "apk",
    "sh",
    "doc",
    "pdf",
    "ascii",
    "32-bit",
    "64-bit",
    "arm",
    "arm64",
    "mips",
    "mipsel",
    "x86",
    "x64",
    "ua-wget",
    "opendir",
    "honeypot",
    "cowrie",
    "censys",
    "rat",
    "stealer",
    "botnetdomain",
    "downloader",
    "malware",
    "url",
    "none",
}


def urlhaus_threat(tags: list[str]) -> str:
    """The first tag that names a threat; 'dropped-by-amadey' names Amadey."""
    for t in tags:
        low = t.lower()
        if low.startswith("dropped-by-"):
            return t[len("dropped-by-") :]
        if low not in GENERIC_TAGS:
            return t
    return ""


class UrlhausConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    only_online: bool = Field(default=True, description="Skip URLs that are no longer serving payloads")


class UrlhausCsvFeed(Feed):
    feed_type = "urlhaus_csv"
    display_name = "abuse.ch URLhaus (recent URLs, CSV)"
    description = "Malware-distribution URLs from the last ~30 days. No key needed. Very high volume: use the item cap and min confidence."
    config_model = UrlhausConfig

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        text = await request_text(
            "GET",
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            headers={"Accept": "text/csv"},
            max_bytes=MAX_FEED_BYTES,
        )
        cfg: UrlhausConfig = self.config  # type: ignore[assignment]
        floor = datetime.now(UTC) - timedelta(days=max_age_days)
        out: list[RawIoc] = []
        rows = csv.reader(line for line in io.StringIO(text) if line.strip() and not line.startswith("#"))
        for row in rows:
            if len(row) < 8:
                continue
            _id, added, url, status, last_online, threat, tags, link = row[:8]
            added_dt, online_dt = parse_dt(added), parse_dt(last_online)
            if added_dt is None or max(added_dt, online_dt or added_dt) < floor:
                continue
            online = status.strip().lower() == "online"
            if cfg.only_online and not online:
                continue
            tag_list = [t.strip() for t in tags.split(",") if t.strip() and t.strip().lower() != "none"][:12]
            out.append(
                RawIoc(
                    value=url,
                    type="url",
                    first_seen=added_dt,
                    last_seen=online_dt or added_dt,
                    confidence=75 if online else 35,
                    threat_type="payload_delivery" if "malware" in threat else threat.strip(),
                    malware=urlhaus_threat(tag_list),
                    threat=urlhaus_threat(tag_list),
                    threat_kind="malware",
                    description=f"URLhaus: {threat.strip()} URL ({status.strip()})",
                    reference=link.strip(),
                    tags=["urlhaus", *tag_list],
                )
            )
        return out


class FeodoFeed(Feed):
    feed_type = "feodo"
    display_name = "abuse.ch Feodo Tracker (botnet C2 IPs)"
    description = "Active botnet command-and-control servers. No key needed. Small and high-signal; often empty if no C2 is active."

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        data = await request_json(
            "GET", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers={"Accept": "application/json"}
        )
        if not isinstance(data, list):
            raise SourceError("unexpected Feodo response shape")
        out: list[RawIoc] = []
        for row in data:
            if not isinstance(row, dict) or not row.get("ip_address"):
                continue
            first, last = parse_dt(row.get("first_seen")), parse_dt(row.get("last_online"))
            online = str(row.get("status", "")).lower() == "online"
            malware = str(row.get("malware") or "")
            out.append(
                RawIoc(
                    value=str(row["ip_address"]),
                    type="ip",
                    first_seen=first,
                    last_seen=last or first,
                    confidence=90 if online else 55,
                    threat_type="botnet_cc",
                    malware=malware,
                    threat=malware,
                    threat_kind="malware",
                    description=f"{malware} botnet C2 on port {row.get('port')} ({row.get('status')}, AS{row.get('as_number')} {row.get('as_name')})",
                    reference="https://feodotracker.abuse.ch/browse/",
                    tags=["feodo", "c2", *([malware.lower()] if malware else [])],
                )
            )
        return out


class ThreatFoxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: int = Field(default=7, ge=1, le=7, description="ThreatFox serves at most the last 7 days")
    min_feed_confidence: int = Field(default=0, ge=0, le=100)


class ThreatFoxFeed(Feed):
    feed_type = "threatfox"
    display_name = "abuse.ch ThreatFox"
    description = (
        "Community IOCs (C2, payload delivery, malware hashes) from the last 7 days. Needs the free abuse.ch Auth-Key."
    )
    config_model = ThreatFoxConfig
    secret_names = ["auth_key"]
    needs_secret = True

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        key = self.secrets.get("auth_key")
        if not key:
            raise SourceError("no abuse.ch Auth-Key configured for this feed")
        cfg: ThreatFoxConfig = self.config  # type: ignore[assignment]
        body = await request_json(
            "POST",
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key, "Accept": "application/json"},
            json_body={"query": "get_iocs", "days": min(cfg.days, max(1, max_age_days))},
            max_bytes=MAX_FEED_BYTES,
        )
        if not isinstance(body, dict) or body.get("query_status") not in ("ok", "no_result"):
            raise SourceError(f"ThreatFox: {str(body.get('query_status') if isinstance(body, dict) else body)[:100]}")
        out: list[RawIoc] = []
        for row in body.get("data") or []:
            if not isinstance(row, dict):
                continue
            kind = str(row.get("ioc_type") or "")
            value = str(row.get("ioc") or "")
            typ = {
                "ip:port": "ip",
                "domain": "domain",
                "url": "url",
                "md5_hash": "md5",
                "sha256_hash": "sha256",
                "sha1_hash": "sha1",
            }.get(kind)
            if typ == "ip":
                value = value.rsplit(":", 1)[0]
            conf = int(row.get("confidence_level") or 50)
            if typ is None or conf < cfg.min_feed_confidence:
                continue
            tags: Any = row.get("tags") or []
            out.append(
                RawIoc(
                    value=value,
                    type=typ,
                    first_seen=parse_dt(row.get("first_seen")),
                    last_seen=parse_dt(row.get("last_seen")) or parse_dt(row.get("first_seen")),
                    confidence=conf,
                    threat_type=str(row.get("threat_type") or ""),
                    malware=str(row.get("malware_printable") or row.get("malware") or ""),
                    threat=str(row.get("malware_printable") or row.get("malware") or ""),
                    threat_kind="malware",
                    description=str(row.get("threat_type_desc") or "")[:400],
                    reference=str(row.get("reference") or "")[:500],
                    tags=["threatfox", *[str(t) for t in tags if t][:10]],
                )
            )
        return out
