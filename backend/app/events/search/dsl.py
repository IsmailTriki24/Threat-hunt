"""Hunt query language → (free text, filters). A deliberately small, total grammar:

    process.parent.name:WINWORD.EXE  -user.name:svc_*  network.dst_port>=1024
    process.name:(cmd.exe|powershell.exe)  has:network.dst_domain  "encoded command" enc*

* `field:value` equality (keyword/ip/number); on analysed text fields (command lines, paths) it means *contains*.
* `value*` prefix, `*value*` contains, `field:(a|b|c)` any-of, quotes for spaces.
* `>`, `>=`, `<`, `<=` for numbers/dates; `has:field` field exists; a leading `-` or `NOT` negates.
* Anything else is free text (simple_query_string) and may use AND / OR / NOT / "phrases" / prefix*.
Everything is validated by the same `Filter` model as structured queries, so this adds no new attack surface.
"""

import re
from typing import TYPE_CHECKING, Any

from app.events.fields import FIELDS, NON_QUERYABLE

if TYPE_CHECKING:
    from app.events.search.query import Filter

MAX_TEXT = 2000
_TOKEN = re.compile(r'(?:-?[A-Za-z_][\w.]*(?:>=|<=|:|>|<)(?:"[^"]*"|\([^)]*\)|\S*))|"[^"]*"|\S+')
_FIELD_EXPR = re.compile(r"^(-?)([A-Za-z_][\w.]*)(>=|<=|:|>|<)(.*)$", re.S)
_OPS = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}


class QueryParseError(ValueError):
    pass


def _unquote(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v


def _filter(neg: bool, field: str, sym: str, raw: str) -> "Filter":
    from app.events.search.query import Filter

    spec = FIELDS.get(field)
    if spec is None or field in NON_QUERYABLE:
        raise QueryParseError(f"unknown field {field[:64]!r}")
    kwargs: dict[str, Any] = {"field": field, "negate": neg}
    if field == "has" or (sym == ":" and raw == ""):
        raise QueryParseError(f"missing value for {field}")
    if sym in _OPS:
        kwargs.update(op=_OPS[sym], value=_unquote(raw))
    elif raw.startswith("(") and raw.endswith(")"):
        items = [_unquote(i.strip()) for i in raw[1:-1].split("|") if i.strip()]
        kwargs.update(op="in", value=items)
    else:
        quoted = raw.startswith('"')
        value = _unquote(raw)
        if not quoted and value.startswith("*") and value.endswith("*") and len(value) > 2:
            kwargs.update(op="contains", value=value[1:-1])
        elif not quoted and value.endswith("*") and len(value) > 1:
            kwargs.update(op="prefix", value=value[:-1])
        elif not quoted and value.startswith("*"):
            raise QueryParseError(
                f"leading wildcard requires a trailing one too: write {field}:{value}* (contains {value[1:]!r})"
            )
        elif spec.kind == "text":
            kwargs.update(op="contains", value=value)
        else:
            kwargs.update(op="eq", value=value)
    try:
        return Filter(**kwargs)
    except ValueError as exc:
        msg = str(exc).splitlines()[-1] if str(exc) else "invalid filter"
        raise QueryParseError(f"{field}: {msg}"[:200]) from None


def _make_filter(**kw: Any) -> "Filter":
    from app.events.search.query import Filter

    return Filter(**kw)


def parse(text: str) -> tuple[str | None, list["Filter"]]:
    if len(text) > MAX_TEXT:
        raise QueryParseError(f"query text longer than {MAX_TEXT} characters")
    tokens = _merge_same_field_or(_TOKEN.findall(text))
    free: list[str] = []
    filters: list[Filter] = []
    pending_not = False
    last_was_filter = False
    for i, tok in enumerate(tokens):
        if tok == "NOT":
            pending_not = True
            continue
        m = _FIELD_EXPR.match(tok)
        if m and not m.group(4).startswith("//"):  # `https://…` is text, not a field
            neg, field, sym, raw = m.groups()
            if field == "has":
                value = _unquote(raw)
                spec = FIELDS.get(value)
                if spec is None or value in NON_QUERYABLE:
                    raise QueryParseError(f"unknown field {value[:64]!r}")
                filters.append(_make_filter(field=value, op="exists", negate=bool(neg) != pending_not))
            else:
                filters.append(_filter(bool(neg) != pending_not, field, sym, raw))
            pending_not = False
            last_was_filter = True
            continue
        if tok == "OR" and (last_was_filter or _next_is_filter(tokens, i)):
            raise QueryParseError(
                "OR works between free-text terms only. Exact alternatives of ONE field: field:(a|b). "
                "Patterns (with *) or different "
                "fields cannot be OR-ed: run one query per condition"
            )
        if pending_not:
            free.append("NOT")
            pending_not = False
        if tok == "AND" and (last_was_filter or _next_is_filter(tokens, i)):
            continue  # filters are implicitly ANDed
        free.append(tok)
        last_was_filter = False
    if pending_not:
        raise QueryParseError("dangling NOT")
    return (" ".join(free) or None), filters


def _exact_values(raw: str) -> list[str] | None:
    """The values of `x` or `(x|y)` if all are plain exact values (no wildcard, quote or space); otherwise None."""
    items = raw[1:-1].split("|") if raw.startswith("(") and raw.endswith(")") else [raw]
    return items if items and all(i and not re.search(r'[*?"\s()|]', i) for i in items) else None


def _merge_same_field_or(tokens: list[str]) -> list[str]:
    """`f:a OR f:b` is exactly `f:(a|b)`: whoever writes the first gets the second instead of an error."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        out.append(tokens[i])
        i += 1
        while i + 1 < len(tokens) and tokens[i] == "OR" and (len(out) < 2 or out[-2] != "NOT"):
            a, b = _FIELD_EXPR.match(out[-1]), _FIELD_EXPR.match(tokens[i + 1])
            if not (
                a
                and b
                and a.group(1) == b.group(1) == ""
                and a.group(3) == b.group(3) == ":"
                and a.group(2) == b.group(2)
            ):
                break
            va, vb = _exact_values(a.group(4)), _exact_values(b.group(4))
            if va is None or vb is None:
                break
            out[-1] = f"{a.group(2)}:({'|'.join([*va, *vb])})"
            i += 2
    return out


def _next_is_filter(tokens: list[str], i: int) -> bool:
    return i + 1 < len(tokens) and bool(_FIELD_EXPR.match(tokens[i + 1]))
