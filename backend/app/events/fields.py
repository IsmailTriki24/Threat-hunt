"""Field registry: single source of truth for the OpenSearch mapping *and* for what the query layer
accepts. A field that is not listed here can neither be indexed (mapping is `strict`) nor queried,
which is the foundation of query-injection resistance."""

from dataclasses import dataclass
from typing import Any, Literal

FieldKind = Literal["keyword", "text", "ip", "integer", "long", "date"]


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: FieldKind
    lowercase: bool = False  # keyword with a lowercase normalizer (case-insensitive matching)
    keyword_sub: bool = False  # text field that also has a `.keyword` sub-field for exact match/agg
    aggregatable: bool = False
    sortable: bool = False
    full_text: bool = False  # included in free-text (`q`) search

    @property
    def exact_path(self) -> str:
        """Path for term-level queries, sorting and aggregations."""
        return f"{self.name}.keyword" if self.kind == "text" and self.keyword_sub else self.name


def _kw(name: str, lc: bool = False, agg: bool = True, sort: bool = False) -> FieldSpec:
    return FieldSpec(name, "keyword", lowercase=lc, aggregatable=agg, sortable=sort)


def _txt(name: str, full_text: bool = True) -> FieldSpec:
    return FieldSpec(name, "text", keyword_sub=True, aggregatable=False, full_text=full_text)


_SPECS: list[FieldSpec] = [
    _kw("id", agg=False),
    FieldSpec("schema_version", "integer"),
    FieldSpec("timestamp", "date", sortable=True),
    FieldSpec("ingested_at", "date", sortable=True),
    _kw("tenant_id", agg=False),
    _kw("source", sort=True),
    _kw("event_type", sort=True),
    _kw("action", sort=True),
    _kw("outcome"),
    FieldSpec("severity", "integer", sortable=True, aggregatable=True),
    _kw("original_id", agg=False),
    FieldSpec("message", "text", full_text=True),
    _kw("tags", lc=True),
    # host
    _kw("host.id"),
    _kw("host.hostname", lc=True, sort=True),
    FieldSpec("host.ip", "ip", aggregatable=True),
    _kw("host.os"),
    # user
    _kw("user.id"),
    _kw("user.name", lc=True, sort=True),
    _kw("user.domain", lc=True),
    # process
    _kw("process.name", lc=True, sort=True),
    FieldSpec("process.pid", "integer"),
    _txt("process.executable"),
    _txt("process.command_line"),
    _kw("process.hash.md5", lc=True),
    _kw("process.hash.sha1", lc=True),
    _kw("process.hash.sha256", lc=True),
    _kw("process.parent.name", lc=True),
    FieldSpec("process.parent.pid", "integer"),
    _txt("process.parent.command_line"),
    # network
    _kw("network.protocol", lc=True),
    _kw("network.direction", lc=True),
    FieldSpec("network.src_ip", "ip", aggregatable=True),
    FieldSpec("network.src_port", "integer"),
    FieldSpec("network.dst_ip", "ip", aggregatable=True),
    FieldSpec("network.dst_port", "integer", aggregatable=True),
    _kw("network.dst_domain", lc=True),
    FieldSpec("network.bytes", "long", sortable=True),
    # dns
    _kw("dns.question", lc=True),
    _kw("dns.query_type"),
    _kw("dns.answers", lc=True),
    # file
    _kw("file.name", lc=True),
    _txt("file.path"),
    _kw("file.hash.md5", lc=True),
    _kw("file.hash.sha1", lc=True),
    _kw("file.hash.sha256", lc=True),
    # authentication
    _kw("auth.logon_type"),
    _kw("auth.method"),
    FieldSpec("auth.source_ip", "ip", aggregatable=True),
    # registry
    _txt("registry.key"),
    _kw("registry.value", agg=False),
]

FIELDS: dict[str, FieldSpec] = {f.name: f for f in _SPECS}
FULL_TEXT_FIELDS: list[str] = [f.name for f in _SPECS if f.full_text]
# Stored for isolation/bookkeeping but never exposed to user queries.
NON_QUERYABLE: set[str] = {"tenant_id"}
SORTABLE: set[str] = {f.name for f in _SPECS if f.sortable}
AGGREGATABLE: set[str] = {f.name for f in _SPECS if f.aggregatable}

CUSTOM_ANALYSIS: dict[str, Any] = {
    "normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}},
    # Tokenises command lines / paths on anything that is not alphanumeric so that
    # `powershell`, `enc` and `downloadstring` are individually searchable.
    "tokenizer": {"cmd_tok": {"type": "pattern", "pattern": "[^A-Za-z0-9_]+"}},
    "analyzer": {"cmd": {"type": "custom", "tokenizer": "cmd_tok", "filter": ["lowercase"]}},
}


def _property(spec: FieldSpec) -> dict[str, Any]:
    if spec.kind == "keyword":
        prop: dict[str, Any] = {"type": "keyword", "ignore_above": 1024}
        if spec.lowercase:
            prop["normalizer"] = "lc"
        return prop
    if spec.kind == "text":
        prop = {"type": "text", "analyzer": "cmd" if spec.name != "message" else "standard"}
        if spec.keyword_sub:
            prop["fields"] = {"keyword": {"type": "keyword", "ignore_above": 2048, "normalizer": "lc"}}
        return prop
    return {"type": spec.kind}


def build_properties() -> dict[str, Any]:
    root: dict[str, Any] = {}
    for spec in _SPECS:
        node = root
        *parents, leaf = spec.name.split(".")
        for part in parents:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[leaf] = _property(spec)
    root["labels"] = {"type": "flat_object"}
    root["raw"] = {"type": "object", "enabled": False}
    return root
