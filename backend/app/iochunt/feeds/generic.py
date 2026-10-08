"""Generic feeds: a plain-text / CSV list at a URL, and a STIX 2.1 bundle at a URL."""

import csv
import io
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.connectors._http import SourceError, request_json, request_text
from app.iochunt.feeds.abusech import MAX_FEED_BYTES
from app.iochunt.feeds.base import Feed, RawIoc


class TextListConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: HttpUrl
    ioc_type: str | None = Field(
        default=None,
        pattern=r"^(ip|domain|url|sha256|sha1|md5|email)$",
        description="Force a type; default auto-detect",
    )
    csv_column: int | None = Field(
        default=None, ge=0, le=50, description="If set, treat lines as CSV and take this 0-based column"
    )
    delimiter: str = Field(default=",", min_length=1, max_length=1)
    confidence: int = Field(default=50, ge=0, le=100)
    threat_type: str = Field(default="", max_length=64)
    verify_tls: bool = True
    ca_pem: str | None = Field(default=None, max_length=20_000)


class TextListFeed(Feed):
    feed_type = "text_list"
    display_name = "Plain-text / CSV list (URL)"
    description = "One indicator per line (# comments ignored), or a CSV column. The list carries no dates, so indicators are timestamped when first imported."
    config_model = TextListConfig
    secret_names = ["authorization"]

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        cfg: TextListConfig = self.config  # type: ignore[assignment]
        headers = {"Accept": "text/plain"}
        if self.secrets.get("authorization"):
            headers["Authorization"] = self.secrets["authorization"]
        text = await request_text(
            "GET", str(cfg.url), headers=headers, verify_tls=cfg.verify_tls, ca_pem=cfg.ca_pem, max_bytes=MAX_FEED_BYTES
        )
        now = datetime.now(UTC)
        values: list[str] = []
        lines = (ln for ln in io.StringIO(text) if ln.strip() and not ln.lstrip().startswith("#"))
        if cfg.csv_column is not None:
            for row in csv.reader(lines, delimiter=cfg.delimiter):
                if len(row) > cfg.csv_column:
                    values.append(row[cfg.csv_column].strip())
        else:
            values = [ln.strip().split()[0] for ln in lines]
        return [
            RawIoc(
                value=v,
                type=cfg.ioc_type,
                first_seen=now,
                last_seen=now,
                confidence=cfg.confidence,
                threat_type=cfg.threat_type,
                tags=["list"],
                reference=str(cfg.url)[:500],
            )
            for v in values
            if v
        ]


class StixBundleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: HttpUrl
    verify_tls: bool = True
    ca_pem: str | None = Field(default=None, max_length=20_000)


class StixBundleFeed(Feed):
    feed_type = "stix_bundle"
    display_name = "STIX 2.1 bundle (URL)"
    description = "A STIX bundle served over HTTPS (indicators with patterns). TAXII collections can be added through Threat Intelligence."
    config_model = StixBundleConfig
    secret_names = ["authorization"]

    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        from app.intel import stix

        cfg: StixBundleConfig = self.config  # type: ignore[assignment]
        headers = {"Accept": "application/stix+json, application/json"}
        if self.secrets.get("authorization"):
            headers["Authorization"] = self.secrets["authorization"]
        data: Any = await request_json(
            "GET", str(cfg.url), headers=headers, verify_tls=cfg.verify_tls, ca_pem=cfg.ca_pem, max_bytes=MAX_FEED_BYTES
        )
        objects = data.get("objects") if isinstance(data, dict) else None
        if not isinstance(objects, list):
            raise SourceError("response is not a STIX bundle")
        now = datetime.now(UTC)
        parsed = stix.parse(objects)
        return [
            RawIoc(
                value=i.value,
                type=i.type,
                first_seen=now,
                last_seen=now,
                confidence=i.confidence,
                tags=["stix", *i.labels][:12],
            )
            for i in parsed.indicators
        ]
