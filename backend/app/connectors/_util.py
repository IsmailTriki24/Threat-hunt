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


def finish(doc: dict[str, Any]) -> list[EventIn]:
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
