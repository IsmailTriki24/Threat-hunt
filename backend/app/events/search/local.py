"""Reference evaluator for Filter / Condition against a stored event document.

It mirrors the semantics the OpenSearch backend gets from the mapping (lower-casing normalizers, `ignore_above`, analysed
command-line tokens, CIDR matching on ip fields). The detection engine uses it for rule unit tests and for evaluating
explicit sample events; a differential test keeps it in lock-step with OpenSearch."""

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from app.events.fields import FIELDS, FieldSpec
from app.events.search.query import Condition, Filter

_TOKEN = re.compile(r"[^A-Za-z0-9_]+")


def values_at(doc: dict[str, Any], path: str) -> list[Any]:
    cur: list[Any] = [doc]
    for part in path.split("."):
        nxt: list[Any] = []
        for c in cur:
            v = c.get(part) if isinstance(c, dict) else None
            if isinstance(v, list):
                nxt.extend(v)
            elif v is not None:
                nxt.append(v)
        cur = nxt
    return cur


def glob_match(pattern: str, text: str) -> bool:
    """Case-insensitive `*` / `?` wildcard match. A backslash escapes only `*`, `?` and `\\` (Sigma semantics); any other
    backslash is literal, so Windows paths work unescaped. Iterative O(n*m); no regex, no backtracking blow-up."""
    toks: list[tuple[str, str]] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            toks.append(("lit", pattern[i + 1].lower()))
            i += 2
            continue
        toks.append(("star", "") if c == "*" else ("any", "") if c == "?" else ("lit", c.lower()))
        i += 1
    t = text.lower()
    p = ti = 0
    star = -1
    mark = 0
    while ti < len(t):
        if p < len(toks) and (toks[p][0] == "any" or (toks[p][0] == "lit" and toks[p][1] == t[ti])):
            p += 1
            ti += 1
        elif p < len(toks) and toks[p][0] == "star":
            star, mark = p, ti
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            ti = mark
        else:
            return False
    while p < len(toks) and toks[p][0] == "star":
        p += 1
    return p == len(toks)


def _strings(spec: FieldSpec, vals: list[Any]) -> list[str]:
    """Values as they exist in the exact-match (keyword) index representation."""
    limit = 2048 if spec.kind == "text" else 1024
    out = [str(v) for v in vals if not isinstance(v, dict | list) and len(str(v)) <= limit]
    return out


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.split(text.lower()) if t]


def _phrase_in(want: list[str], texts: list[str]) -> bool:
    if not want:
        return False
    for text in texts:
        toks = _tokens(text)
        if any(toks[i : i + len(want)] == want for i in range(len(toks) - len(want) + 1)):
            return True
    return False


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _ts(v: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _ip_eq(candidate: Any, wanted: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(candidate))
        if "/" in str(wanted):
            return ip in ipaddress.ip_network(str(wanted), strict=False)
        return ip == ipaddress.ip_address(str(wanted))
    except ValueError:
        return False


def _positive(f: Filter, doc: dict[str, Any]) -> bool:
    """Evaluate the filter's operator ignoring `neq`/`not_exists`/`negate` inversion (handled by the caller)."""
    spec = FIELDS[f.field]
    vals = values_at(doc, f.field)
    op = f.op
    if op in ("exists", "not_exists"):
        return bool(vals)
    if spec.kind in ("keyword", "text"):
        lowered = spec.lowercase or spec.kind == "text"
        strs = _strings(spec, vals)

        def norm(x: str) -> str:
            return x.lower() if lowered else x

        if op in ("eq", "neq"):
            return any(norm(s) == norm(str(f.value)) for s in strs)
        if op == "in":
            return any(norm(s) in {norm(str(w)) for w in (f.value or [])} for s in strs)  # type: ignore[union-attr]
        if op == "prefix":
            return any(s.lower().startswith(str(f.value).lower()) for s in strs)
        if op == "wildcard":
            return any(glob_match(str(f.value), s) for s in strs)
        if op == "contains":
            if spec.kind == "text":
                return _phrase_in(_tokens(str(f.value)), [str(v) for v in vals if isinstance(v, str)])
            return any(str(f.value).lower() in s.lower() for s in strs)
        return False
    if spec.kind == "ip":
        if op in ("eq", "neq"):
            return any(_ip_eq(v, f.value) for v in vals)
        if op == "in":
            return any(_ip_eq(v, w) for v in vals for w in (f.value or []))  # type: ignore[union-attr]
        return False
    if spec.kind in ("integer", "long"):
        nums = [n for n in (_num(v) for v in vals) if n is not None]
        if op in ("eq", "neq"):
            return any(n == _num(f.value) for n in nums)
        if op == "in":
            return any(n in {_num(w) for w in (f.value or [])} for n in nums)  # type: ignore[union-attr]
        want = _num(f.value)
        if want is None:
            return False
        return any({"gt": n > want, "gte": n >= want, "lt": n < want, "lte": n <= want}[op] for n in nums)
    if spec.kind == "date":
        want_ts = _ts(f.value)
        stamps = [t for t in (_ts(v) for v in vals) if t is not None]
        if want_ts is None:
            return False
        return any({"gt": t > want_ts, "gte": t >= want_ts, "lt": t < want_ts, "lte": t <= want_ts}[op] for t in stamps)
    return False


def matches_filter(f: Filter, doc: dict[str, Any]) -> bool:
    result = _positive(f, doc)
    if f.op in ("neq", "not_exists"):
        result = not result
    return result != f.negate


def matches(cond: Condition, doc: dict[str, Any]) -> bool:
    if cond.filter is not None:
        return matches_filter(cond.filter, doc)
    if cond.all is not None:
        return all(matches(c, doc) for c in cond.all)
    if cond.any is not None:
        return any(matches(c, doc) for c in cond.any)
    if cond.not_ is None:
        raise ValueError("empty condition node")
    return not matches(cond.not_, doc)
