"""IOC feed contract. A feed returns *raw* indicators; normalisation, guard-rails (private/benign/allow-listed values, age, duplicates)
and persistence are shared in `ingest.py`, so a new feed only has to parse its source."""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict


class EmptyFeedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass
class RawIoc:
    value: str
    type: str | None = None  # ip|domain|url|sha256|sha1|md5|email; None => auto-detect
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_until: datetime | None = None
    confidence: int = 50
    threat_type: str = ""
    malware: str = ""
    description: str = ""
    reference: str = ""
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    threat: str = ""  # which named threat (family / actor / campaign / report) this indicator belongs to
    threat_kind: str = ""  # malware | actor | campaign | report | other


class Feed(ABC):
    feed_type: ClassVar[str]
    display_name: ClassVar[str]
    description: ClassVar[str] = ""
    config_model: ClassVar[type[BaseModel]] = EmptyFeedConfig
    secret_names: ClassVar[list[str]] = []  # required credential names (set write-only)
    needs_secret: ClassVar[bool] = False

    def __init__(self, config: BaseModel | None = None, secrets: dict[str, str] | None = None) -> None:
        self.config = config if config is not None else self.config_model()
        self.secrets = secrets or {}

    @abstractmethod
    async def fetch(self, since: datetime | None, max_age_days: int) -> list[RawIoc]:
        """Return recent indicators. `since` is the previous successful run (None on the first run)."""


_DT_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def parse_dt(value: object) -> datetime | None:
    """Tolerant timestamp parser for feed fields: ISO-8601, 'YYYY-MM-DD HH:MM:SS[ UTC]', dates, epoch seconds/milliseconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        v = float(value)
        v = v / 1000 if v > 1e11 else v
        try:
            return datetime.fromtimestamp(v, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    s = value.strip().removesuffix(" UTC").removesuffix("Z").strip()
    if not s or s.lower() in ("none", "null", "n/a"):
        return None
    if s.isdigit():
        return parse_dt(int(s))
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(s.replace(" ", "T"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def techniques_in(*texts: object) -> list[str]:
    found: list[str] = []
    for t in texts:
        if isinstance(t, str):
            found += _TECHNIQUE.findall(t.upper())
    return list(dict.fromkeys(found))[:10]
