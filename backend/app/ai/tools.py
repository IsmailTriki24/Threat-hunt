"""The only things the model can do. Every tool: typed (pydantic) input, read-only, runs as the *invoking user's* Principal
(tenant scope from the Principal, permission checked per call), bounded output. Model-written queries go through the same
`EventQuery` validation as human ones."""

import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import Principal
from app.auth.rbac import Permission
from app.events.search.base import SearchBackend
from app.events.search.query import Aggregation, EventQuery, TimeRange
from app.events.summary import summarize
from app.intel import types as intel_types
from app.intel.models import IntelEntity
from app.mitre.models import MitreTechnique

MAX_RESULT_CHARS = 12_000
MAX_HITS = 25


class ToolError(Exception):
    """Returned to the model as an error result (never raised to the user)."""


@dataclass
class Ledger:
    """Every event the model has actually been shown in this run. Conclusions may only cite these."""

    events: dict[str, dict[str, Any]] = field(default_factory=dict)

    def see(self, docs: list[dict[str, Any]]) -> None:
        for d in docs:
            if isinstance(d.get("id"), str):
                self.events[d["id"]] = d


@dataclass
class ToolContext:
    session: AsyncSession
    backend: SearchBackend
    principal: Principal
    ledger: Ledger


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchIn(_In):
    query: str = Field(
        max_length=500, description="Hunt query language, e.g. process.name:powershell.exe -user.name:svc_*"
    )
    hours_back: int = Field(default=24, ge=1, le=720)
    limit: int = Field(default=10, ge=1, le=MAX_HITS)


class AggIn(_In):
    query: str = Field(default="", max_length=500)
    field: str = Field(
        max_length=64, description="An aggregatable field, e.g. host.hostname, process.name, network.dst_ip"
    )
    hours_back: int = Field(default=24, ge=1, le=720)
    size: int = Field(default=10, ge=1, le=25)


class EventIdIn(_In):
    event_id: str = Field(pattern=r"^[a-f0-9]{32}$")


class IocIn(_In):
    value: str = Field(min_length=1, max_length=2048)


class TechniqueIn(_In):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")


def _compact(doc: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "timestamp", "source", "event_type", "action", "outcome")
    out: dict[str, Any] = {k: doc[k] for k in keys if k in doc}
    out["summary"] = summarize(doc)
    for part in ("host", "user", "process", "network", "dns", "file", "auth", "registry"):
        if isinstance(doc.get(part), dict):
            out[part] = doc[part]
    return out


class Tool:
    name: ClassVar[str]
    description: ClassVar[str]
    input_model: ClassVar[type[BaseModel]]
    permission: ClassVar[Permission]

    async def run(self, ctx: ToolContext, args: Any) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def schema(self) -> dict[str, Any]:
        js = self.input_model.model_json_schema()
        js.pop("title", None)
        return {"name": self.name, "description": self.description, "input_schema": js}


class SearchEvents(Tool):
    name = "search_events"
    description = (
        "Search this tenant's telemetry. Returns the total match count and up to `limit` newest events (compact)."
    )
    input_model = SearchIn
    permission = Permission.EVENTS_READ

    async def run(self, ctx: ToolContext, args: SearchIn) -> dict[str, Any]:
        try:
            q = EventQuery(
                text=args.query or None,
                time_range=TimeRange.last(timedelta(hours=args.hours_back)),
                limit=args.limit,
            )
        except ValidationError as exc:
            raise ToolError(f"invalid query: {exc.errors()[0]['msg']}") from None
        res = await ctx.backend.search(ctx.principal.tid, q)
        ctx.ledger.see(res.hits)
        return {"total": res.total, "returned": len(res.hits), "events": [_compact(h) for h in res.hits]}


class AggregateEvents(Tool):
    name = "aggregate_events"
    description = "Top values of one field over events matching a query (counts per value). Use to spot outliers."
    input_model = AggIn
    permission = Permission.EVENTS_READ

    async def run(self, ctx: ToolContext, args: AggIn) -> dict[str, Any]:
        try:
            q = EventQuery(
                text=args.query or None,
                time_range=TimeRange.last(timedelta(hours=args.hours_back)),
                limit=1,
                aggregations=[Aggregation(name="top", type="terms", field=args.field, size=args.size)],
            )
        except ValidationError as exc:
            raise ToolError(f"invalid request: {exc.errors()[0]['msg']}") from None
        res = await ctx.backend.search(ctx.principal.tid, q)
        buckets = res.aggregations["top"].buckets if "top" in res.aggregations else []
        return {"total_matching": res.total, "field": args.field, "values": [b.model_dump() for b in buckets]}


class GetEvent(Tool):
    name = "get_event"
    description = "Fetch one event by id (as returned by search_events) with all normalized fields."
    input_model = EventIdIn
    permission = Permission.EVENTS_READ

    async def run(self, ctx: ToolContext, args: EventIdIn) -> dict[str, Any]:
        doc = await ctx.backend.get_event(ctx.principal.tid, args.event_id)
        if doc is None:
            raise ToolError("event not found")
        ctx.ledger.see([doc])
        doc = {k: v for k, v in doc.items() if k not in ("raw", "tenant_id")}
        return {"event": doc}


class LookupIoc(Tool):
    name = "lookup_ioc"
    description = "Look up an indicator (ip, domain, url, hash, email) in this tenant's already-collected threat intelligence. Never calls external services."
    input_model = IocIn
    permission = Permission.INTEL_READ

    async def run(self, ctx: ToolContext, args: IocIn) -> dict[str, Any]:
        t = intel_types.detect_type(args.value.strip())
        norm = intel_types.normalize(t, args.value.strip()) if t else None
        if not t or not norm:
            raise ToolError("not a recognizable indicator")
        ent = (
            await ctx.session.execute(
                select(IntelEntity).where(
                    IntelEntity.tenant_id == ctx.principal.tid, IntelEntity.type == t, IntelEntity.value == norm
                )
            )
        ).scalar_one_or_none()
        if ent is None:
            return {
                "known": False,
                "type": t,
                "note": "no intelligence collected for this indicator; that is not evidence it is benign",
            }
        return {
            "known": True,
            "type": t,
            "verdict": ent.verdict,
            "score": ent.score,
            "signals": ent.score_breakdown[:8],
            "tags": ent.tags[:10],
        }


class MitreLookup(Tool):
    name = "mitre_technique"
    description = "Look up an ATT&CK technique by id (e.g. T1059.001): name, tactics, description."
    input_model = TechniqueIn
    permission = Permission.MITRE_READ

    async def run(self, ctx: ToolContext, args: TechniqueIn) -> dict[str, Any]:
        t = await ctx.session.get(MitreTechnique, args.technique_id)
        if t is None:
            raise ToolError("unknown technique")
        return {"id": t.id, "name": t.name, "tactics": t.tactics, "description": t.description[:600]}


TOOLS: dict[str, Tool] = {
    t.name: t for t in (SearchEvents(), AggregateEvents(), GetEvent(), LookupIoc(), MitreLookup())
}


def schemas_for(principal: Principal) -> list[dict[str, Any]]:
    """The model is only offered tools its user may use."""
    return [t.schema() for t in TOOLS.values() if principal.has(t.permission)]


async def execute(ctx: ToolContext, name: str, raw: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Returns (result, error). Never raises for model mistakes."""
    tool = TOOLS.get(name)
    if tool is None:
        return {}, f"unknown tool '{name}'"
    if not ctx.principal.has(tool.permission):
        return {}, "you are not permitted to use this tool"
    try:
        args = tool.input_model.model_validate(raw)
    except ValidationError as exc:
        e = exc.errors()[0]
        return {}, f"invalid arguments: {'.'.join(str(x) for x in e['loc'])}: {e['msg']}"
    try:
        result = await tool.run(ctx, args)
    except ToolError as exc:
        return {}, str(exc)
    text = json.dumps(result, default=str)
    if len(text) > MAX_RESULT_CHARS:
        result = {
            "truncated": True,
            "note": "result too large; narrow the query",
            "preview": text[: MAX_RESULT_CHARS // 2],
        }
    return result, None
