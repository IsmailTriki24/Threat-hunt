"""Engine-neutral event query model. This is the only thing API callers can express; each
SearchBackend compiles it into its own dialect. Everything is validated against the field registry."""

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, StringConstraints, model_validator

from app.events.fields import AGGREGATABLE, FIELDS, NON_QUERYABLE, SORTABLE

MAX_WINDOW = 10_000
MAX_Q_LEN = 512

Scalar = str | int | float | bool
Op = Literal["eq", "neq", "in", "exists", "not_exists", "prefix", "contains", "wildcard", "gt", "gte", "lt", "lte"]

_OPS_BY_KIND: dict[str, set[str]] = {
    "keyword": {"eq", "neq", "in", "exists", "not_exists", "prefix", "contains", "wildcard"},
    "text": {"eq", "neq", "in", "exists", "not_exists", "prefix", "contains", "wildcard"},
    "ip": {"eq", "neq", "in", "exists", "not_exists"},
    "integer": {"eq", "neq", "in", "exists", "not_exists", "gt", "gte", "lt", "lte"},
    "long": {"eq", "neq", "in", "exists", "not_exists", "gt", "gte", "lt", "lte"},
    "date": {"exists", "not_exists", "gt", "gte", "lt", "lte"},
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TimeRange(_Strict):
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _check(self) -> "TimeRange":
        for attr in ("start", "end"):
            v = getattr(self, attr)
            setattr(self, attr, v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC))
        if self.start >= self.end:
            raise ValueError("start must be before end")
        return self

    @classmethod
    def last(cls, delta: timedelta) -> "TimeRange":
        now = datetime.now(UTC)
        return cls(start=now - delta, end=now)


def _coerce(kind: str, value: Scalar) -> Scalar:
    """Coerce/validate a filter value for a field kind. Raises ValueError on mismatch."""
    if kind in ("keyword", "text"):
        if not isinstance(value, str) or len(value) > 1024:
            raise ValueError("expected a string up to 1024 chars")
        return value
    if kind == "ip":
        if not isinstance(value, str):
            raise ValueError("expected an IP address or CIDR")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            ipaddress.ip_network(value, strict=False)  # CIDR; raises ValueError if invalid
        return value
    if kind in ("integer", "long"):
        if (
            isinstance(value, bool)
            or not isinstance(value, int | str)
            or (isinstance(value, str) and not re.fullmatch(r"-?\d{1,18}", value))
        ):
            raise ValueError("expected an integer")
        return int(value)
    if kind == "date":
        if not isinstance(value, str):
            raise ValueError("expected an ISO-8601 timestamp")
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).isoformat()
    raise ValueError("unsupported field kind")  # pragma: no cover


class Filter(_Strict):
    field: str
    op: Op = "eq"
    negate: bool = False
    value: Scalar | list[Scalar] | None = None

    @model_validator(mode="after")
    def _check(self) -> "Filter":
        spec = FIELDS.get(self.field)
        if spec is None or spec.name in NON_QUERYABLE:
            raise ValueError(f"unknown field: {self.field[:64]!r}")
        if self.op not in _OPS_BY_KIND[spec.kind]:
            raise ValueError(f"operator {self.op!r} not supported for field {self.field!r}")
        if self.op in ("exists", "not_exists"):
            self.value = None
            return self
        if self.op == "in":
            if not isinstance(self.value, list) or not 1 <= len(self.value) <= 100:
                raise ValueError("'in' requires a list of 1-100 values")
            self.value = [_coerce(spec.kind, v) for v in self.value]
            return self
        if self.value is None or isinstance(self.value, list):
            raise ValueError(f"operator {self.op!r} requires a single value")
        self.value = _coerce(spec.kind, self.value)
        if self.op in ("prefix", "contains") and not 1 <= len(str(self.value)) <= 128:
            raise ValueError("pattern must be 1-128 characters")
        if self.op == "wildcard":
            pattern = str(self.value)
            wild = sum(1 for i, c in enumerate(pattern) if c in "*?" and (i == 0 or pattern[i - 1] != "\\"))
            if not 1 <= len(pattern) <= 512 or wild > 10 or not pattern.replace("*", "").replace("?", ""):
                raise ValueError(
                    "wildcard pattern must be 1-512 chars, have at most 10 wildcards and some literal text"
                )
        return self


MAX_COND_DEPTH = 8
MAX_COND_NODES = 300


class Condition(_Strict):
    """Boolean tree over validated Filters: exactly one of all (AND) / any (OR) / not / filter.
    Detections (Sigma) compile to this, and it is evaluated identically by OpenSearch and by the local evaluator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    all: "list[Condition] | None" = Field(default=None, max_length=100)
    any: "list[Condition] | None" = Field(default=None, max_length=100)
    not_: "Condition | None" = Field(default=None, alias="not")
    filter: Filter | None = None

    @model_validator(mode="after")
    def _one_kind(self) -> "Condition":
        set_ = [x for x in (self.all, self.any, self.not_, self.filter) if x is not None]
        if len(set_) != 1:
            raise ValueError("a condition node needs exactly one of: all, any, not, filter")
        if (self.all is not None and not self.all) or (self.any is not None and not self.any):
            raise ValueError("all/any need at least one child")
        return self

    def children(self) -> "list[Condition]":
        return [*(self.all or []), *(self.any or []), *([self.not_] if self.not_ else [])]

    def stats(self) -> tuple[int, int]:
        """(depth, node count)"""
        depth, nodes = 1, 1
        for c in self.children():
            d, n = c.stats()
            depth, nodes = max(depth, d + 1), nodes + n
        return depth, nodes

    def filters(self) -> list[Filter]:
        out = [self.filter] if self.filter else []
        for c in self.children():
            out.extend(c.filters())
        return out


def validate_condition_size(cond: Condition) -> None:
    depth, nodes = cond.stats()
    if depth > MAX_COND_DEPTH or nodes > MAX_COND_NODES:
        raise ValueError(f"condition too large (depth<={MAX_COND_DEPTH}, nodes<={MAX_COND_NODES})")


class Sort(_Strict):
    field: str
    order: Literal["asc", "desc"] = "desc"

    @model_validator(mode="after")
    def _check(self) -> "Sort":
        if self.field not in SORTABLE:
            raise ValueError(f"field {self.field!r} is not sortable")
        return self


AggName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]


class Aggregation(_Strict):
    name: AggName
    type: Literal["terms", "date_histogram"] = "terms"
    field: str | None = None
    size: int = Field(default=10, ge=1, le=50)

    @model_validator(mode="after")
    def _check(self) -> "Aggregation":
        if self.type == "terms":
            if self.field not in AGGREGATABLE:
                raise ValueError(f"field {self.field!r} is not aggregatable")
        else:
            self.field = "timestamp"
        return self


class EventQuery(_Strict):
    q: Annotated[str, StringConstraints(max_length=MAX_Q_LEN)] | None = None
    # Hunt query language source (see dsl.py); parsed and validated here, merged at execution time.
    text: Annotated[str, StringConstraints(max_length=2000)] | None = None
    time_range: TimeRange | None = None  # defaults to the last 24 hours
    filters: list[Filter] = Field(default_factory=list, max_length=25)
    where: Condition | None = None  # boolean tree (used by detections); ANDed with q / text / filters
    sort: list[Sort] = Field(default_factory=list, max_length=3)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=200)
    aggregations: list[Aggregation] = Field(default_factory=list, max_length=6)

    _parsed: tuple[str | None, list[Filter]] = PrivateAttr(default=(None, []))

    @model_validator(mode="after")
    def _check(self) -> "EventQuery":
        if self.text and self.text.strip():
            from app.events.search.dsl import QueryParseError, parse

            try:
                self._parsed = parse(self.text)
            except QueryParseError as exc:
                raise ValueError(f"query text: {exc}") from None
        if self.where is not None:
            validate_condition_size(self.where)
        if len(self.filters) + len(self._parsed[1]) > 25:
            raise ValueError("too many filters (max 25)")
        if self.offset + self.limit > MAX_WINDOW:
            raise ValueError(f"offset + limit must not exceed {MAX_WINDOW}")
        if len({a.name for a in self.aggregations}) != len(self.aggregations):
            raise ValueError("aggregation names must be unique")
        return self

    def effective_filters(self) -> list[Filter]:
        return [*self.filters, *self._parsed[1]]

    def effective_q(self) -> str | None:
        parts = [p for p in (self.q, self._parsed[0]) if p and p.strip()]
        if len(parts) > 1:
            return " ".join(f"({p})" for p in parts)
        return parts[0] if parts else None

    def effective_range(self) -> TimeRange:
        return self.time_range or TimeRange.last(timedelta(hours=24))


class Bucket(BaseModel):
    key: str | int | float
    count: int


class AggregationResult(BaseModel):
    buckets: list[Bucket]


class SearchResult(BaseModel):
    total: int
    total_relation: Literal["eq", "gte"]
    took_ms: int
    hits: list[dict[str, Any]]
    aggregations: dict[str, AggregationResult] = Field(default_factory=dict)
    time_range: TimeRange


Condition.model_rebuild()
EventQuery.model_rebuild()
