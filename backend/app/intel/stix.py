# ruff: noqa: E501
"""STIX 2.x import (bundle or TAXII object list) → indicators, named objects and relationships.

Only simple, single-observable indicator patterns are imported; compound patterns joined by AND are skipped because they do not
denote one indicator. Everything is validated through `intel.types.normalize`; nothing from the feed is executed or trusted."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.intel import types

MAX_OBJECTS = 5000
_STR = r"'((?:[^'\\]|\\.)*)'"
_SIMPLE = re.compile(rf"(ipv4-addr|ipv6-addr|domain-name|url|email-addr):value\s*=\s*{_STR}")
_HASH = re.compile(rf"file:hashes\.(?:'([^']{{1,16}})'|\"([^\"]{{1,16}})\"|(\w{{1,16}}))\s*=\s*{_STR}")
_HASH_TYPES = {"md5": "md5", "sha-1": "sha1", "sha1": "sha1", "sha-256": "sha256", "sha256": "sha256"}
_TYPE_BY_STIX = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url", "email-addr": "email"}
_NAMED = {"malware": "malware", "threat-actor": "threat_actor", "campaign": "campaign", "intrusion-set": "threat_actor"}
_REL_KINDS = {"indicates", "uses", "attributed-to"}


@dataclass
class ParsedIndicator:
    stix_id: str
    type: str
    value: str
    confidence: int
    verdict: str
    labels: list[str]


@dataclass
class ParsedStix:
    indicators: list[ParsedIndicator] = field(default_factory=list)
    named: list[tuple[str, str, str]] = field(default_factory=list)  # (stix_id, type, name)
    relations: list[tuple[str, str, str]] = field(default_factory=list)  # (src stix id, dst stix id, kind)
    skipped: int = 0


def _unescape(s: str) -> str:
    return s.replace("\\'", "'").replace("\\\\", "\\")


def patterns(pattern: str) -> list[tuple[str, str]]:
    """Extract (entity_type, value) pairs from a simple STIX pattern; [] when it is compound/unsupported."""
    if len(pattern) > 2000 or re.search(r"\bAND\b|\bFOLLOWEDBY\b", pattern):
        return []
    out: list[tuple[str, str]] = []
    for m in _SIMPLE.finditer(pattern):
        out.append((_TYPE_BY_STIX[m.group(1)], _unescape(m.group(2))))
    for m in _HASH.finditer(pattern):
        algo = _HASH_TYPES.get((m.group(1) or m.group(2) or m.group(3)).lower())
        if algo:
            out.append((algo, _unescape(m.group(4))))
    return out


def parse(objects: list[Any], now: datetime | None = None) -> ParsedStix:
    now = now or datetime.now(UTC)
    result = ParsedStix()
    for obj in objects[:MAX_OBJECTS]:
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            result.skipped += 1
            continue
        kind, sid = obj.get("type"), obj["id"]
        if kind == "indicator" and isinstance(obj.get("pattern"), str):
            valid_until = obj.get("valid_until")
            if isinstance(valid_until, str):
                try:
                    if datetime.fromisoformat(valid_until.replace("Z", "+00:00")) < now:
                        result.skipped += 1
                        continue
                except ValueError:
                    pass
            labels = [str(label)[:60] for label in (obj.get("labels") or []) if isinstance(label, str)][:10]
            conf = obj.get("confidence")
            confidence = conf if isinstance(conf, int) and 0 <= conf <= 100 else 60
            verdict = (
                "benign" if "benign" in labels else "suspicious" if "anomalous-activity" in labels else "malicious"
            )
            found = patterns(obj["pattern"])
            if not found:
                result.skipped += 1
            for t, v in found:
                norm = types.normalize(t, v)
                if norm is None:
                    result.skipped += 1
                    continue
                result.indicators.append(ParsedIndicator(sid, t, norm, confidence, verdict, labels))
        elif kind in _NAMED and isinstance(obj.get("name"), str):
            name = types.normalize(_NAMED[kind], obj["name"])
            if name:
                result.named.append((sid, _NAMED[kind], name))
        elif kind == "relationship" and obj.get("relationship_type") in _REL_KINDS:
            if isinstance(obj.get("source_ref"), str) and isinstance(obj.get("target_ref"), str):
                result.relations.append((obj["source_ref"], obj["target_ref"], obj["relationship_type"]))
    return result
