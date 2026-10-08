"""Shared defensive helpers for normalizers. Raw telemetry is attacker-influenced: never assume types."""

import re
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from app.connectors.base import NormalizationError
from app.connectors.canonical import _summarize
from app.events.schema import EventIn

_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def obj(value: Any) -> dict[str, Any]:
    """Nested value as a dict; anything else (str, list, None, ...) is treated as empty."""
    return value if isinstance(value, dict) else {}


def text(value: Any) -> str | None:
    """Scalar → str. Containers/None/bool/empty → None (so they are simply absent)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, int | float):
        return str(value)
    return None


def integer(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        v = value.strip()
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        except ValueError:
            return None
    return None


def str_list(value: Any, limit: int = 32) -> list[str]:
    if not isinstance(value, list):
        return []
    return [s for s in (text(v) for v in value[:limit]) if s]


def epoch_to_iso(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise NormalizationError("timestamp: expected epoch seconds")
    try:
        return datetime.fromtimestamp(value, UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        raise NormalizationError("timestamp: epoch out of range") from None


def iso_timestamp(value: Any) -> str:
    """ISO-8601 with `+0000`-style offsets normalised; raises NormalizationError if unusable."""
    if not isinstance(value, str) or not value:
        raise NormalizationError("timestamp: missing")
    return _TZ_NO_COLON.sub(r"\1:\2", value.strip().replace("Z", "+00:00") if value.endswith("Z") else value.strip())


def drop_none(doc: dict[str, Any]) -> dict[str, Any]:
    """Recursively remove None values and empty sub-objects so optional sections stay absent."""
    out: dict[str, Any] = {}
    for k, v in doc.items():
        if isinstance(v, dict):
            v = drop_none(v)
            if not v:
                continue
        if v is None:
            continue
        out[k] = v
    return out


# (path, schema maximum). Attacker-controlled values routinely exceed these (a 20 KB base64 PowerShell command is what
# a hunter wants to see): truncated, never allowed to make the whole event disappear.
_LIMITS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("process", "command_line"), 8192),
    (("process", "parent", "command_line"), 8192),
    (("process", "executable"), 1024),
    (("file", "path"), 1024),
    (("registry", "key"), 1024),
    (("registry", "value"), 1024),
    (("message",), 1024),
    (("process", "name"), 256),
    (("process", "parent", "name"), 256),
    (("host", "hostname"), 256),
    (("user", "name"), 256),
)


def clip_oversized(doc: dict[str, Any]) -> list[str]:
    """Truncate over-long string fields in place (keeping the head); returns the dotted names that were cut."""
    cut: list[str] = []
    for path, limit in _LIMITS:
        parent: Any = doc
        for key in path[:-1]:
            parent = parent.get(key) if isinstance(parent, dict) else None
        if isinstance(parent, dict) and isinstance(parent.get(path[-1]), str) and len(parent[path[-1]]) > limit:
            parent[path[-1]] = parent[path[-1]][:limit]
            cut.append(".".join(path))
    return cut


def finish(doc: dict[str, Any]) -> list[EventIn]:
    cut = clip_oversized(doc)
    if cut:
        labels = dict(doc.get("labels") or {})
        labels["truncated"] = ",".join(cut)[:256]
        doc["labels"] = dict(list(labels.items())[:20])
    try:
        return [EventIn.model_validate(drop_none(doc))]
    except ValidationError as exc:
        raise NormalizationError(_summarize(exc)) from None
    except (ValueError, TypeError) as exc:
        raise NormalizationError(str(exc)[:200]) from None


def strict_int(value: Any, name: str) -> int | None:
    """Like `integer` but a present-yet-unparsable value is an error rather than silently dropped."""
    result = integer(value)
    if value is not None and result is None:
        raise NormalizationError(f"{name}: expected an integer")
    return result


def valid_ip(value: Any) -> str | None:
    """A clean IP string (IPv4-mapped IPv6 unwrapped) or None; never raises."""
    import ipaddress

    v = text(value)
    if not v:
        return None
    try:
        ip = ipaddress.ip_address(v.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def ip_list(value: Any, limit: int = 16) -> list[str]:
    items = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(ip for ip in (valid_ip(v) for v in items[:limit]) if ip))


def hashes(md5: Any = None, sha1: Any = None, sha256: Any = None) -> dict[str, str] | None:
    """Only well-formed hex digests of the right length; anything else is dropped rather than failing the event."""
    out: dict[str, str] = {}
    for key, value, size in (("md5", md5, 32), ("sha1", sha1, 40), ("sha256", sha256, 64)):
        v = text(value)
        if v and len(v) == size and all(c in "0123456789abcdefABCDEF" for c in v):
            out[key] = v
    return out or None


def clip(value: Any, n: int = 256) -> str | None:
    v = text(value)
    return v[:n].strip() or None if v else None


def labels(**pairs: Any) -> dict[str, str]:
    """Label map with every value clipped to the schema limit; empty values omitted; at most 20 keys."""
    out = {k: c for k, v in pairs.items() if (c := clip(v))}
    return dict(list(out.items())[:20])
