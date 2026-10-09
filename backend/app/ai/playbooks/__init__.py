"""Hunt playbooks: curated, validated threat-hunting knowledge for the agent.

Each playbook is distilled from public hunting procedures (see NOTICE.md) and re-expressed for THIS platform: its queries are written in
the platform's hunt query language and checked by the real parser in tests, its telemetry needs are checked against what the tenant
actually has, and its steps only use the agent's read-only tools. A playbook is guidance - a hypothesis, where to look, which benign
explanations to rule out - never an instruction that can widen what the agent is allowed to do, and never evidence by itself."""

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.events.fields import AGGREGATABLE, FIELDS
from app.events.schema import EventType
from app.events.search import dsl

log = logging.getLogger("hunt.playbooks")

DATA = Path(__file__).parent / "data"
MAX_TEXT = 420
MAX_PLAYBOOK_CHARS = 7000

# Triage signals the agent derives from events (ai/state.py event_signals); a playbook may declare which ones make it relevant.
SIGNALS = (
    "encoded_command",
    "download_cradle",
    "office_spawn_shell",
    "cred_access",
    "persistence",
    "lateral_movement",
    "lolbin",
    "suspicious_path",
    "external_connection",
    "failed_auth",
)
PATH_FIELDS = {"process.name", "process.parent.name"}  # sensors report either a bare name or a full path in these
Purpose = Literal["test", "refute", "follow_up", "scope"]
StepTool = Literal["search_events", "aggregate_events", "pivot_entity", "process_lineage", "events_around"]
_ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,60}$")
_SOURCE = re.compile(r"^[a-z0-9][a-z0-9-]{2,100}$")

Text = Field(min_length=3, max_length=MAX_TEXT)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Step(_Strict):
    purpose: Purpose
    goal: str = Text  # what this step tells you
    tool: StepTool
    query: str | None = Field(default=None, max_length=500)  # hunt query language (search_events / aggregate_events)
    field: str | None = None  # aggregate_events: the field to group by
    look_for: str = Text  # what in the result is suspicious, and what is benign

    @model_validator(mode="after")
    def _check(self) -> "Step":
        if self.tool in ("search_events", "aggregate_events"):
            if not self.query:
                raise ValueError(f"{self.tool} step needs a query")
            try:
                _, filters = dsl.parse(self.query)
            except dsl.QueryParseError as exc:
                raise ValueError(f"query does not parse: {exc}") from None
            for f in filters:
                spec = FIELDS[f.field]
                if f.op == "in" and f.field in PATH_FIELDS:
                    # `(a|b)` is an exact match: it finds `cmd.exe` but misses `c:\\windows\\system32\\cmd.exe`, which EDR sensors report
                    raise ValueError(
                        f"{f.field} may be a full path: use one *name* pattern per step, not an alternation ({self.query!r})"
                    )
                if spec.kind == "text" and f.op in ("in", "prefix", "wildcard"):
                    # analysed text fields (command lines, paths) match on tokens; these operators act on the whole stored value
                    raise ValueError(
                        f"{f.field} is analysed text: use one token/phrase per query, not {f.op} ({self.query!r})"
                    )
        elif self.query:
            raise ValueError(f"{self.tool} takes no query; describe the pivot in look_for")
        if self.tool == "aggregate_events":
            if self.field not in AGGREGATABLE:
                raise ValueError(f"aggregate_events needs an aggregatable field, got {self.field!r}")
        elif self.field:
            raise ValueError("field is only for aggregate_events")
        return self


class Playbook(_Strict):
    id: str
    title: str = Field(min_length=5, max_length=120)
    summary: str = Text
    tactics: list[str] = Field(min_length=1, max_length=4)
    attack: list[str] = Field(min_length=1, max_length=8)
    sources: list[str] = Field(min_length=1, max_length=12)  # upstream procedures this was distilled from (provenance)
    keywords: list[str] = Field(min_length=2, max_length=24)
    signals: list[str] = Field(default_factory=list, max_length=6)
    needs: list[str] = Field(min_length=1, max_length=4)  # event types that must exist in the tenant's telemetry
    helps: list[str] = Field(default_factory=list, max_length=4)  # event types that make it better but are not required
    hypothesis: str = Text
    steps: list[Step] = Field(min_length=2, max_length=8)
    benign: list[str] = Field(
        min_length=1, max_length=8
    )  # legitimate explanations to rule out before calling it malicious
    escalate: list[str] = Field(min_length=1, max_length=6)  # what to pivot on when the hunt hits
    confirm: str = Text  # what makes it "confirmed" rather than "suspicious"
    gaps: list[str] = Field(
        default_factory=list, max_length=6
    )  # what the source procedure used that this platform's telemetry lacks

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _ID.match(v):
            raise ValueError("id must be lowercase letters, digits and dashes")
        return v

    @field_validator("attack")
    @classmethod
    def _attack(cls, v: list[str]) -> list[str]:
        bad = [a for a in v if not _ATTACK_ID.match(a)]
        if bad:
            raise ValueError(f"not ATT&CK technique ids: {bad}")
        return v

    @field_validator("sources")
    @classmethod
    def _sources(cls, v: list[str]) -> list[str]:
        bad = [s for s in v if not _SOURCE.match(s)]
        if bad:
            raise ValueError(f"bad source names: {bad}")
        return v

    @field_validator("signals")
    @classmethod
    def _signals(cls, v: list[str]) -> list[str]:
        bad = [s for s in v if s not in SIGNALS]
        if bad:
            raise ValueError(f"unknown signals {bad}; known: {list(SIGNALS)}")
        return v

    @field_validator("needs", "helps")
    @classmethod
    def _types(cls, v: list[str]) -> list[str]:
        valid = {e.value for e in EventType}
        bad = [t for t in v if t not in valid]
        if bad:
            raise ValueError(f"unknown event types {bad}")
        return v

    @field_validator("tactics", "keywords", "benign", "escalate", "gaps")
    @classmethod
    def _short(cls, v: list[str]) -> list[str]:
        if any(not (3 <= len(x) <= MAX_TEXT) for x in v):
            raise ValueError(f"entries must be 3-{MAX_TEXT} characters")
        return v

    @model_validator(mode="after")
    def _size(self) -> "Playbook":
        for s in self.steps:
            for f in (s.field,):
                if f is not None and f not in FIELDS:
                    raise ValueError(f"unknown field {f!r}")
        if len(self.model_dump_json()) > MAX_PLAYBOOK_CHARS:
            raise ValueError(f"playbook larger than {MAX_PLAYBOOK_CHARS} characters; split it")
        return self


@lru_cache(maxsize=1)
def catalog() -> dict[str, Playbook]:
    """All playbooks, keyed by id. A broken file is logged and skipped (tests make sure none is) so a bad edit cannot take the app down."""
    out: dict[str, Playbook] = {}
    for f in sorted(DATA.glob("*.yaml")):
        try:
            pb = Playbook.model_validate(yaml.safe_load(f.read_text(encoding="utf-8")))
            if pb.id != f.stem:
                raise ValueError(f"id {pb.id!r} does not match file name {f.stem!r}")
            if pb.id in out:
                raise ValueError("duplicate id")
            out[pb.id] = pb
        except (ValidationError, ValueError, yaml.YAMLError, OSError):
            log.exception("invalid hunt playbook skipped: %s", f.name)
    return out


# ---- relevance -----------------------------------------------------------------------------------------------------------------


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9][a-z0-9.+-]{2,}", text.lower())}


def score(pb: Playbook, text: str = "", *, attack: tuple[str, ...] = (), signals: tuple[str, ...] = ()) -> int:
    """How well a playbook fits an objective, ATT&CK ids and triage signals seen so far. 0 = unrelated."""
    low = text.lower()
    words = _words(low)
    s = 0
    ids = {a.upper() for a in attack}
    pb_ids = set(pb.attack)
    exact = ids & pb_ids
    s += 6 * len(exact)
    shared_parents = {i.split(".")[0] for i in ids} & {a.split(".")[0] for a in pb_ids}
    s += 2 * len(
        shared_parents - {i.split(".")[0] for i in exact}
    )  # T1059 finds the T1059.001 playbook; an exact hit counts once
    s += 3 * len(set(signals) & set(pb.signals))
    for kw in pb.keywords:
        k = kw.lower()
        if k in low:
            s += 3 if " " in k or len(k) > 8 else 2
    s += len(words & _words(f"{pb.title} {pb.summary}"))
    return s


def search(
    text: str = "", *, attack: tuple[str, ...] = (), signals: tuple[str, ...] = (), limit: int = 6, min_score: int = 2
) -> list[tuple[Playbook, int]]:
    ranked = [(pb, score(pb, text, attack=attack, signals=signals)) for pb in catalog().values()]
    ranked = [r for r in ranked if r[1] >= min_score]
    return sorted(ranked, key=lambda r: (-r[1], r[0].id))[:limit]


def feasibility(pb: Playbook, event_types: dict[str, Any] | None) -> dict[str, Any]:
    """Can this tenant's telemetry answer the playbook? `event_types` is the coverage map from data_coverage (None = not yet known)."""
    if not event_types:
        return {"status": "unknown", "missing": [], "note": "run data_coverage to learn what telemetry exists"}
    missing = [t for t in pb.needs if t not in event_types]
    if not missing:
        return {"status": "ready", "missing": [], "optional_missing": [t for t in pb.helps if t not in event_types]}
    status = "blocked" if len(missing) == len(pb.needs) else "partial"
    return {
        "status": status,
        "missing": missing,
        "note": f"telemetry for {', '.join(missing)} is not in the window: record it with declare_gap instead of reporting a clean result",
    }


def brief(pb: Playbook, event_types: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": pb.id,
        "title": pb.title,
        "attack": pb.attack,
        "tactics": pb.tactics,
        "summary": pb.summary,
        "feasibility": feasibility(pb, event_types),
    }


def detail(pb: Playbook, event_types: dict[str, Any] | None = None) -> dict[str, Any]:
    d = pb.model_dump(exclude={"sources", "keywords"})
    d["feasibility"] = feasibility(pb, event_types)
    d["how_to_use"] = (
        "Run the steps with the named tools (adapt the time window and add host/user filters from what you have seen). Each query is "
        "a starting point, not a verdict: record a hypothesis first, rule out the benign explanations, and confirm in telemetry."
    )
    return d
