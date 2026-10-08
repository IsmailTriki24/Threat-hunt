"""Sigma → Condition compiler.

Supported: selections (maps, lists of maps, keyword lists), field modifiers contains / startswith / endswith / all / cidr / exists /
gt / gte / lt / lte, wildcards in values, `null` (field absent), condition expressions with and / or / not / parentheses and
`1 of` / `all of` over `them` or `name*`. Logsource categories and Windows EventIDs are mapped to canonical event types.
Anything we cannot execute faithfully (regex, base64, aggregations/near, unmapped fields or logsources) is reported in
`ParsedRule.unsupported` rather than silently approximated: a rule with unsupported parts is never deployable."""

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from app.detections import safeyaml
from app.detections.formats.base import DetectionFormat, ParsedRule, RuleError
from app.events.fields import FIELDS, NON_QUERYABLE
from app.events.search.query import Condition, Filter, validate_condition_size

LEVELS = {"informational": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
MAX_SELECTIONS = 50
MAX_VALUES = 200

CATEGORY_EVENT_TYPE = {
    "process_creation": "process_creation",
    "network_connection": "network_connection",
    "dns_query": "dns_query",
    "dns": "dns_query",
    "file_event": "file_event",
    "file_change": "file_event",
    "file_access": "file_event",
    "file_rename": "file_event",
    "registry_add": "registry_event",
    "registry_set": "registry_event",
    "registry_event": "registry_event",
    "registry_delete": "registry_event",
    "registry_rename": "registry_event",
}
# Windows / Sysmon EventID -> condition parts
EVENT_ID: dict[int, list[tuple[str, str]]] = {
    1: [("event_type", "process_creation")],
    3: [("event_type", "network_connection")],
    11: [("event_type", "file_event")],
    22: [("event_type", "dns_query")],
    12: [("event_type", "registry_event")],
    13: [("event_type", "registry_event")],
    14: [("event_type", "registry_event")],
    4688: [("event_type", "process_creation")],
    4624: [("event_type", "authentication"), ("outcome", "success")],
    4625: [("event_type", "authentication"), ("outcome", "failure")],
    7045: [("event_type", "service_install")],
    4698: [("event_type", "scheduled_task")],
}
LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "10": "remote_interactive",
    "11": "cached_interactive",
}

# Sigma field -> canonical field, per category ("*" = any). A tuple (field, transform) for special handling.
COMMON = {
    "Computer": "host.hostname",
    "ComputerName": "host.hostname",
    "Hostname": "host.hostname",
    "User": "user.name",
    "ProcessId": "process.pid",
    "Image": "@image",
    "md5": "@hash:md5",
    "sha1": "@hash:sha1",
    "sha256": "@hash:sha256",
    "Hashes": "@hashes",
}
BY_CATEGORY: dict[str, dict[str, str]] = {
    "process_creation": {
        "CommandLine": "process.command_line",
        "ParentImage": "@parent_image",
        "ParentCommandLine": "process.parent.command_line",
        "ParentProcessId": "process.parent.pid",
    },
    "network_connection": {
        "DestinationIp": "network.dst_ip",
        "DestinationPort": "network.dst_port",
        "DestinationHostname": "network.dst_domain",
        "SourceIp": "network.src_ip",
        "SourcePort": "network.src_port",
        "Protocol": "network.protocol",
        "Initiated": "@initiated",
    },
    "dns_query": {"QueryName": "dns.question", "QueryResults": "dns.answers"},
    "file_event": {"TargetFilename": "file.path"},
    "registry_event": {"TargetObject": "registry.key", "Details": "registry.value"},
    "authentication": {
        "LogonType": "@logon_type",
        "IpAddress": "auth.source_ip",
        "SourceNetworkAddress": "auth.source_ip",
        "TargetUserName": "user.name",
        "AccountName": "user.name",
    },
    "scheduled_task": {"TaskName": "message"},
}
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "cidr", "exists", "gt", "gte", "lt", "lte"}
_HASH_RE = re.compile(r"(MD5|SHA1|SHA256)=([A-Fa-f0-9]+)", re.I)


class SigmaError(RuleError):
    pass


@dataclass
class _Ctx:
    category: str  # canonical category used for field mapping
    unsupported: list[str]
    warnings: list[str]


def _flt(field: str, op: str, value: Any = None, negate: bool = False) -> Condition:
    try:
        return Condition(filter=Filter(field=field, op=op, value=value, negate=negate))
    except ValueError as exc:
        raise SigmaError(f"{field} {op}: {str(exc).splitlines()[-1][:160]}") from None


def _and(parts: list[Condition]) -> Condition:
    return parts[0] if len(parts) == 1 else Condition(all=parts)


def _or(parts: list[Condition]) -> Condition:
    return parts[0] if len(parts) == 1 else Condition(any=parts)


def _escape_literal(v: str) -> str:
    return v.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _has_wildcard(v: str) -> bool:
    return bool(re.search(r"(?<!\\)[*?]", v))


def _pattern(value: str, mods: set[str]) -> tuple[str, bool]:
    """Return (pattern, is_wildcard). Sigma wildcards in values stay active; modifiers add anchors."""
    if "contains" in mods:
        return f"*{value}*", True
    if "startswith" in mods:
        return f"{value}*", True
    if "endswith" in mods:
        return f"*{value}", True
    return value, _has_wildcard(value)


def _basename(v: str) -> str:
    return re.split(r"[\\/]", v)[-1]


def _leaf(canon: str, value: Any, mods: set[str], ctx: _Ctx, sigma_field: str) -> Condition | None:
    """One value of one field -> Condition (or None if unsupported, with a note recorded)."""
    kind = FIELDS[canon].kind if canon in FIELDS else "keyword"
    if value is None:
        return _flt(canon, "not_exists")
    if isinstance(value, bool):
        value = "true" if value else "false"
    if kind in ("integer", "long"):
        if (
            "contains" in mods
            or "startswith" in mods
            or "endswith" in mods
            or (isinstance(value, str) and _has_wildcard(value))
        ):
            ctx.unsupported.append(f"{sigma_field}: string modifiers on numeric field")
            return None
        for op in ("gte", "gt", "lte", "lt"):
            if op in mods:
                return _flt(canon, op, value)
        return _flt(canon, "eq", value)
    if kind == "ip":
        return _flt(canon, "eq", str(value))  # exact or CIDR
    if kind == "date":
        for op in ("gte", "gt", "lte", "lt"):
            if op in mods:
                return _flt(canon, op, str(value))
        ctx.unsupported.append(f"{sigma_field}: date equality")
        return None
    text = str(value)
    pat, wild = _pattern(text, mods)
    if wild:
        return _flt(canon, "wildcard", pat)
    return _flt(canon, "eq", text.replace("\\*", "*").replace("\\?", "?"))


def _special(token: str, sigma_field: str, values: list[Any], mods: set[str], ctx: _Ctx) -> Condition | None:
    all_mode = "all" in mods

    def combine(parts: list[Condition | None]) -> Condition | None:
        if any(p is None for p in parts):
            return None
        return _and(parts) if all_mode else _or(parts)  # type: ignore[arg-type]

    if token == "@image":  # nosec B105 (field alias, not a credential)
        parts: list[Condition | None] = []
        for v in values:
            s = str(v)
            if "endswith" in mods and not _has_wildcard(s) and re.match(r"^[\\/]?[^\\/]+$", s):
                parts.append(_flt("process.name", "eq", _basename(s)))  # most robust: the name is always present
            else:
                parts.append(_leaf("process.executable", v, mods, ctx, sigma_field))
        return combine(parts)
    if token == "@parent_image":  # nosec B105 (field alias, not a credential)
        parts = []
        for v in values:
            s = str(v)
            if "endswith" in mods and not _has_wildcard(s) and re.match(r"^[\\/]?[^\\/]+$", s):
                parts.append(_flt("process.parent.name", "eq", _basename(s)))
            elif not mods and not _has_wildcard(s) and re.search(r"[\\/]", s):
                parts.append(_flt("process.parent.name", "eq", _basename(s)))
                ctx.warnings.append(
                    "ParentImage: only the parent process name is stored; the directory part was ignored"
                )
            elif "contains" in mods and not re.search(r"[\\/]", s.strip("\\/")):
                parts.append(_flt("process.parent.name", "wildcard", f"*{s.strip(chr(92) + '/')}*"))
            else:
                ctx.unsupported.append(
                    f"{sigma_field}: only the parent process name is stored, path conditions cannot be evaluated"
                )
                return None
        return combine(parts)
    if token == "@hashes" or token.startswith("@hash:"):  # nosec B105 (field alias, not a credential)
        prefix = "process" if ctx.category != "file_event" else "file"
        parts = []
        for v in values:
            m = _HASH_RE.search(str(v))
            algo = token.split(":")[1] if token.startswith("@hash:") else (m.group(1).lower() if m else "")
            digest = m.group(2) if m else str(v).strip("*")
            if algo not in ("md5", "sha1", "sha256") or not re.fullmatch(r"[A-Fa-f0-9]+", digest):
                ctx.unsupported.append(f"{sigma_field}: unsupported hash value (only MD5/SHA1/SHA256)")
                return None
            parts.append(_flt(f"{prefix}.hash.{algo}", "eq", digest.lower()))
        return combine(parts)
    if token == "@initiated":  # nosec B105 (field alias, not a credential)
        return combine(
            [_flt("network.direction", "eq", "outbound" if str(v).lower() == "true" else "inbound") for v in values]
        )
    if token == "@logon_type":  # nosec B105 (field alias, not a credential)
        return combine([_flt("auth.logon_type", "eq", LOGON_TYPES.get(str(v), str(v).lower())) for v in values])
    ctx.unsupported.append(f"{sigma_field}: unmapped special field")
    return None


def _event_id(values: list[Any], ctx: _Ctx) -> Condition | None:
    parts: list[Condition] = []
    for v in values:
        try:
            ids = EVENT_ID[int(v)]
        except (KeyError, ValueError, TypeError):
            ctx.unsupported.append(f"EventID {v}: no canonical mapping")
            return None
        parts.append(_and([_flt(f, "eq", val) for f, val in ids]))
    return _or(parts)


def _map_field(name: str, ctx: _Ctx) -> str | None:
    if "." in name and name in FIELDS and name not in NON_QUERYABLE:
        return name  # canonical field used directly (e.g. rules generated from hunts)
    return BY_CATEGORY.get(ctx.category, {}).get(name) or COMMON.get(name)


def _field_entry(key: str, raw: Any, ctx: _Ctx) -> Condition | None:
    name, *mod_list = key.split("|")
    mods = set(mod_list)
    bad = mods - SUPPORTED_MODIFIERS
    if bad:
        ctx.unsupported.append(f"{key}: unsupported modifier(s) {', '.join(sorted(bad))}")
        return None
    values = raw if isinstance(raw, list) else [raw]
    if len(values) > MAX_VALUES:
        raise SigmaError(f"{name}: more than {MAX_VALUES} values")
    if any(isinstance(v, dict | list) for v in values):
        raise SigmaError(f"{key}: values must be scalars")
    if "exists" in mods:
        target = _map_field(name, ctx)
        if target is None or target.startswith("@"):
            ctx.unsupported.append(f"{name}: unmapped field")
            return None
        return _flt(target, "exists" if str(raw).lower() == "true" else "not_exists")
    if name == "EventID":
        return _event_id(values, ctx)
    canon = _map_field(name, ctx)
    if canon is None:
        ctx.unsupported.append(f"{name}: no canonical field for logsource '{ctx.category}'")
        return None
    if canon.startswith("@"):
        return _special(canon, name, values, mods, ctx)
    parts: list[Condition | None] = []
    for v in values:
        if name == "User" and isinstance(v, str) and "\\" in v and not mods:
            v = v.rsplit("\\", 1)[-1]  # telemetry stores the domain separately
        parts.append(_leaf(canon, v, mods, ctx, name))
    if any(p is None for p in parts):
        return None
    return _and(parts) if "all" in mods else _or(parts)  # type: ignore[arg-type]


def _selection(name: str, body: Any, ctx: _Ctx) -> Condition | None:
    if isinstance(body, dict):
        parts = [_field_entry(k, v, ctx) for k, v in body.items()]
        if not parts:
            raise SigmaError(f"selection '{name}' is empty")
        return None if any(p is None for p in parts) else _and([p for p in parts if p])
    if isinstance(body, list):
        if all(isinstance(x, dict) for x in body):
            alts = [_selection(name, x, ctx) for x in body]
            return None if any(a is None for a in alts) or not alts else _or([a for a in alts if a])
        if all(not isinstance(x, dict | list) for x in body):  # keyword list
            kw = [_keyword(str(x), ctx) for x in body]
            return _or(kw) if kw else None
        raise SigmaError(f"selection '{name}' mixes maps and values")
    if isinstance(body, str):
        return _keyword(body, ctx)
    raise SigmaError(f"selection '{name}' has an unsupported shape")


def _keyword(word: str, ctx: _Ctx) -> Condition:
    pat = word if _has_wildcard(word) else f"*{_escape_literal(word)}*"
    return (
        _or([_flt("process.command_line", "wildcard", pat), _flt("message", "contains", word)])
        if len(word) < 128
        else _flt("process.command_line", "wildcard", pat)
    )


# ---- condition expression ------------------------------------------------------------------------------------
_TOK = re.compile(r"\(|\)|[^\s()]+")


class _Expr:
    def __init__(self, text: str, sels: dict[str, Condition | None], ctx: _Ctx) -> None:
        self.toks = _TOK.findall(text)
        self.i = 0
        self.sels = sels
        self.ctx = ctx

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        t = self.toks[self.i]
        self.i += 1
        return str(t)

    def parse(self) -> Condition | None:
        node = self.or_()
        if self.peek() is not None:
            raise SigmaError(f"unexpected '{self.peek()}' in condition")
        return node

    def or_(self) -> Condition | None:
        parts = [self.and_()]
        while (self.peek() or "").lower() == "or":
            self.take()
            parts.append(self.and_())
        return None if any(p is None for p in parts) else _or([p for p in parts if p])

    def and_(self) -> Condition | None:
        parts = [self.not_()]
        while (self.peek() or "").lower() == "and":
            self.take()
            parts.append(self.not_())
        return None if any(p is None for p in parts) else _and([p for p in parts if p])

    def not_(self) -> Condition | None:
        if (self.peek() or "").lower() == "not":
            self.take()
            inner = self.not_()
            return None if inner is None else Condition(not_=inner)
        return self.atom()

    def atom(self) -> Condition | None:
        t = self.peek()
        if t is None:
            raise SigmaError("condition ends unexpectedly")
        if t == "(":
            self.take()
            node = self.or_()
            if self.peek() != ")":
                raise SigmaError("missing ')' in condition")
            self.take()
            return node
        if t.lower() in ("1", "all") and self.i + 1 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()
            if self.peek() is None:
                raise SigmaError("'of' needs a target")
            target = self.take()
            names = list(self.sels) if target.lower() == "them" else [n for n in self.sels if fnmatchcase(n, target)]
            if not names:
                raise SigmaError(f"'{quant} of {target}' matches no selection")
            parts = [self.sels[n] for n in names]
            if any(p is None for p in parts):
                return None
            return _or([p for p in parts if p]) if quant == "1" else _and([p for p in parts if p])
        if t in (")", "|") or t.lower() in ("and", "or"):
            raise SigmaError(f"unexpected '{t}' in condition")
        self.take()
        if t not in self.sels:
            raise SigmaError(f"condition references unknown selection '{t}'")
        return self.sels[t]


# ---- logsource -----------------------------------------------------------------------------------------------
def _logsource(ls: Any, ctx_unsup: list[str]) -> tuple[str, Condition | None]:
    """Returns (category for field mapping, event_type constraint)."""
    if not isinstance(ls, dict):
        return "*", None
    category = str(ls.get("category") or "").lower()
    service = str(ls.get("service") or "").lower()
    if category:
        et = CATEGORY_EVENT_TYPE.get(category)
        if et is None:
            ctx_unsup.append(f"logsource category '{category}' has no canonical mapping")
            return "*", None
        field_cat = "registry_event" if et == "registry_event" else et
        return field_cat, _flt("event_type", "eq", et)
    if service in ("security", "system"):
        return (
            "authentication" if service == "security" else "*",
            None,
        )  # EventID in the detection selects the event type
    if service == "sysmon":
        return "*", None
    return "*", None


def _category_for_event_ids(sels: dict[str, Any]) -> str | None:
    ids: set[int] = set()

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k.split("|")[0] == "EventID":
                    ids.update(int(x) for x in (v if isinstance(v, list) else [v]) if str(x).isdigit())
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(sels)
    mapped = {EVENT_ID[i][0][1] for i in ids if i in EVENT_ID}
    return str(mapped.pop()) if len(mapped) == 1 else None


class SigmaFormat(DetectionFormat):
    format_id = "sigma"
    display_name = "Sigma"
    description = "Sigma YAML rules (single-event detections). Aggregations, regex and base64 modifiers are reported as unsupported."

    def parse(self, content: str) -> ParsedRule:
        try:
            doc = safeyaml.load(content)
        except safeyaml.YamlError as exc:
            raise SigmaError(str(exc)) from None
        title = doc.get("title")
        if not isinstance(title, str) or not title.strip():
            raise SigmaError("'title' is required")
        detection = doc.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise SigmaError("'detection' with a 'condition' is required")
        level = str(doc.get("level") or "medium").lower()
        tags = [str(t)[:100] for t in (doc.get("tags") or []) if isinstance(t, str)][:50]
        rule = ParsedRule(
            title=title.strip()[:200],
            description=str(doc.get("description") or "")[:5000],
            severity=LEVELS.get(level, "MEDIUM"),
            status=str(doc.get("status") or "")[:30],
            tags=tags,
            author=str(doc.get("author") or "")[:200],
            references=[str(r)[:300] for r in (doc.get("references") or []) if isinstance(r, str)][:20],
            false_positives=[str(r)[:300] for r in (doc.get("falsepositives") or []) if isinstance(r, str)][:20],
        )
        for t in tags:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", t.lower())
            if m:
                rule.techniques.append(m.group(1).upper())
            elif t.lower().startswith("attack.") and not re.fullmatch(r"attack\.[ts]\d+.*", t.lower()):
                rule.tactics.append(t.lower().removeprefix("attack.").replace("_", "-"))
        if level not in LEVELS and "level" in doc:
            rule.warnings.append(f"unknown level '{level}', using MEDIUM")

        names = [k for k in detection if k not in ("condition", "timeframe")]
        if len(names) > MAX_SELECTIONS:
            raise SigmaError(f"more than {MAX_SELECTIONS} selections")
        category, ls_cond = _logsource(doc.get("logsource"), rule.unsupported)
        if category == "authentication" or category == "*":
            inferred = _category_for_event_ids({n: detection[n] for n in names})
            if inferred:
                category = inferred
        ctx = _Ctx(category, rule.unsupported, rule.warnings)
        compiled: dict[str, Condition | None] = {n: _selection(n, detection[n], ctx) for n in names}
        rule.selections = {n: c for n, c in compiled.items() if c is not None}

        cond_text = detection["condition"]
        texts = cond_text if isinstance(cond_text, list) else [cond_text]
        if not all(isinstance(t, str) for t in texts):
            raise SigmaError("'condition' must be a string or list of strings")
        exprs: list[Condition | None] = []
        for text in texts:
            if "|" in text:
                rule.unsupported.append("aggregation / near conditions (count, sum, near, ...) are not supported")
                exprs.append(None)
                continue
            exprs.append(_Expr(text, compiled, ctx).parse())
        if rule.unsupported or any(e is None for e in exprs):
            rule.where = None
            return rule
        expr = _or([e for e in exprs if e])
        try:
            rule.where = _and([ls_cond, expr]) if ls_cond else expr
            validate_condition_size(rule.where)
        except ValueError as exc:
            rule.where = None
            rule.unsupported.append(str(exc)[:200])
        return rule
