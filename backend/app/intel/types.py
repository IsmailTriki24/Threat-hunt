"""Entity types and normalisation. Indicator validation is shared with IOC extraction (investigations/iocs.py)."""

import re
from typing import Literal

from app.investigations import iocs

EntityType = Literal[
    "ip", "domain", "url", "sha256", "sha1", "md5", "email", "certificate", "malware", "threat_actor", "campaign"
]
INDICATOR_TYPES = {"ip", "domain", "url", "sha256", "sha1", "md5", "email", "certificate"}
NAMED_TYPES = {"malware", "threat_actor", "campaign"}
Verdict = Literal["unknown", "benign", "suspicious", "malicious"]

_NAME = re.compile(r"^[\w][\w .:/+@()'-]{0,198}$", re.U)


def normalize(type_: str, value: str) -> str | None:
    v = value.strip()
    if type_ in NAMED_TYPES:
        return v.lower() if _NAME.match(v) else None
    if type_ == "certificate":  # SHA-256 fingerprint, with or without colons
        v = v.replace(":", "")
        return v.lower() if re.fullmatch(r"[A-Fa-f0-9]{64}", v) else None
    return iocs.normalize(type_, v)


def detect_type(value: str) -> str | None:
    """Best-effort classification of a pasted indicator."""
    v = value.strip()
    for t in ("ip", "sha256", "sha1", "md5", "url", "email", "domain"):
        if normalize(t, v) is not None:
            return t
    return None
