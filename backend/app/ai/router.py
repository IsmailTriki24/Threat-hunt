import asyncio
import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import state as st
from app.ai import translate as translator
from app.ai.agent import Outcome, run_agent
from app.ai.models import AiRun
from app.ai.providers import LLMProvider, ProviderUnavailable, build_provider
from app.ai.schemas import ResumeIn, RunCreate, RunOut, SaveIn, Status, TranslateIn, TranslateOut
from app.ai.tools import Ledger, ToolContext
from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.core.config import Settings, get_settings
from app.core.db import get_session
from app.core.errors import AppError, Conflict, Forbidden, NotFound, UpstreamUnavailable
from app.core.ratelimit import enforce
from app.events.search.base import SearchBackend
from app.events.summary import summarize
from app.hunts.models import Finding, Hunt

router = APIRouter(prefix="/ai", tags=["ai"])
USE = Depends(require(Permission.AI_USE))


def _provider(request: Request) -> LLMProvider | None:
    injected: LLMProvider | None = getattr(request.app.state, "llm", None)  # tests / alternative wiring
    return injected or build_provider(get_settings())


def _need_provider(request: Request) -> LLMProvider:
    p = _provider(request)
    if p is None:
        raise UpstreamUnavailable("AI hunting is not configured for this deployment")
    return p


@router.get("/status", response_model=Status)
async def status(request: Request, _: Principal = USE, settings: Settings = Depends(get_settings)) -> Status:
    p = _provider(request)
    return Status(
        enabled=p is not None,
        provider=p.name if p else "none",
        model=p.model if p else "",
        max_steps=settings.ai_max_steps,
        modes={
            name: {
                "max_steps": min(m.max_steps, settings.ai_max_steps),
                "max_tool_calls": min(m.max_tool_calls, settings.ai_max_tool_calls),
                "wall_s": min(m.wall_s, settings.ai_run_timeout_s),
            }
            for name, m in st.MODES.items()
        },
    )


@router.post("/translate", response_model=TranslateOut)
async def translate(body: TranslateIn, request: Request, principal: Principal = USE) -> TranslateOut:
    provider = _need_provider(request)
    await enforce(request, f"ai-translate:{principal.user_id}", 30, 60)
    try:
        query, note, _usage = await translator.translate(provider, body.question)
    except ProviderUnavailable as exc:
        raise UpstreamUnavailable(str(exc)) from None
    await audit.record(request, "ai.translate", principal=principal, details={"ok": query is not None})
    return TranslateOut(query=query, note=note)


async def _hunt(session: AsyncSession, principal: Principal, hunt_id: uuid.UUID) -> Hunt:
    hunt = (
        await session.execute(select(Hunt).where(Hunt.id == hunt_id, Hunt.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if hunt is None:
        raise NotFound("Hunt not found")
    return hunt


def _limits(mode: str, settings: Settings) -> st.Limits:
    return st.Limits.resolve(
        st.MODES[mode],
        steps=settings.ai_max_steps,
        calls=settings.ai_max_tool_calls,
        tokens=settings.ai_token_budget,
        wall_s=settings.ai_run_timeout_s,
    )


async def _drive(
    request: Request,
    principal: Principal,
    session: AsyncSession,
    provider: LLMProvider,
    settings: Settings,
    *,
    goal: str,
    hours_back: int,
    mode: str,
    state: st.Investigation | None = None,
) -> Outcome:
    backend: SearchBackend = request.app.state.search
    ctx = ToolContext(session=session, backend=backend, principal=principal, ledger=Ledger())
    lim = _limits(mode, settings)
    holder: list[st.Investigation] = []
    outcome = Outcome(mode=mode)
    try:
        # the agent enforces its own wall-clock budget; this is only the backstop for a stuck provider/tool call
        await asyncio.wait_for(
            run_agent(
                ctx,
                provider,
                goal,
                hours_back=hours_back,
                mode=mode,
                limits=lim,
                state=state,
                holder=holder,
                outcome=outcome,
            ),
            timeout=lim.wall_s + 45,
        )
    except TimeoutError:
        outcome.status, outcome.error = "INCOMPLETE", "The investigation hit its time limit"
        if holder:
            outcome.state = holder[0].to_dict()
            outcome.conclusion = holder[0].interim_report("budget_time (hard timeout)")
    return outcome


@router.post("/runs", response_model=RunOut, status_code=201)
async def create_run(
    body: RunCreate,
    request: Request,
    principal: Principal = USE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AiRun:
    provider = _need_provider(request)
    if body.hunt_id:
        await _hunt(session, principal, body.hunt_id)
    await enforce(request, f"ai-run:{principal.user_id}", 6, 60)
    outcome = await _drive(
        request, principal, session, provider, settings, goal=body.goal, hours_back=body.hours_back, mode=body.mode
    )
    run = AiRun(
        tenant_id=principal.tid,
        user_id=principal.user_id,
        hunt_id=body.hunt_id,
        goal=body.goal,
        status=outcome.status,
        provider=provider.name,
        model=provider.model,
        hours_back=body.hours_back,
        mode=body.mode,
        steps=outcome.steps,
        conclusion=outcome.conclusion,
        state=outcome.state,
        input_tokens=outcome.input_tokens,
        output_tokens=outcome.output_tokens,
        error=outcome.error[:300],
    )
    session.add(run)
    await session.flush()
    await session.refresh(run)
    await _audit_run(request, principal, run, "ai.run")
    return run


async def _audit_run(request: Request, principal: Principal, run: AiRun, action: str) -> None:
    await audit.record(
        request,
        action,
        principal=principal,
        resource_type="ai_run",
        resource_id=str(run.id),
        details={
            "status": run.status,
            "mode": run.mode,
            "tool_calls": sum(1 for s in run.steps if s.get("type") == "tool" and not s.get("cached")),
            "tokens": run.input_tokens + run.output_tokens,
        },
    )


@router.post("/runs/{run_id}/resume", response_model=RunOut)
async def resume_run(
    run_id: uuid.UUID,
    body: ResumeIn,
    request: Request,
    principal: Principal = USE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AiRun:
    """Continue an interrupted (INCOMPLETE/FAILED) investigation from its persisted state - hypotheses, query log, entities and
    evidence are restored (evidence is re-read from telemetry, tenant-scoped); the transcript is not needed. Gets a fresh budget."""
    provider = _need_provider(request)
    run = await _run(session, principal, run_id)
    if run.status == "COMPLETED" or not run.state:
        raise Conflict("Only an interrupted investigation with saved state can be resumed")
    await enforce(request, f"ai-run:{principal.user_id}", 6, 60)
    mode = body.mode or (run.mode if run.mode in st.MODES else "standard")
    outcome = await _drive(
        request,
        principal,
        session,
        provider,
        settings,
        goal=run.goal,
        hours_back=run.hours_back,
        mode=mode,
        state=st.Investigation.from_dict(run.state),
    )
    run.status, run.mode = outcome.status, mode
    run.steps = [*run.steps, {"type": "resume", "mode": mode}, *outcome.steps]
    run.conclusion = outcome.conclusion
    run.state = outcome.state
    run.input_tokens += outcome.input_tokens
    run.output_tokens += outcome.output_tokens
    run.error = outcome.error[:300]
    await session.flush()
    await session.refresh(run)
    await _audit_run(request, principal, run, "ai.resume")
    return run


@router.get("/runs", response_model=list[RunOut])
async def list_runs(principal: Principal = USE, session: AsyncSession = Depends(get_session)) -> list[AiRun]:
    stmt = select(AiRun).where(AiRun.tenant_id == principal.tid)
    if not principal.has(Permission.USERS_MANAGE):  # users see their own runs; tenant admins see all
        stmt = stmt.where(AiRun.user_id == principal.user_id)
    return list((await session.execute(stmt.order_by(AiRun.created_at.desc()).limit(50))).scalars())


async def _run(session: AsyncSession, principal: Principal, run_id: uuid.UUID) -> AiRun:
    run = (
        await session.execute(select(AiRun).where(AiRun.id == run_id, AiRun.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if run is None or (run.user_id != principal.user_id and not principal.has(Permission.USERS_MANAGE)):
        raise NotFound("Run not found")
    return run


@router.get("/runs/{run_id}", response_model=RunOut)
async def get_run(run_id: uuid.UUID, principal: Principal = USE, session: AsyncSession = Depends(get_session)) -> AiRun:
    return await _run(session, principal, run_id)


@router.post("/runs/{run_id}/save", response_model=RunOut)
async def save_findings(
    run_id: uuid.UUID,
    body: SaveIn,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> AiRun:
    """Promote validated findings to hunt findings. Evidence is re-read from telemetry (tenant-scoped); unsupported findings are refused."""
    if not principal.has(Permission.AI_USE):
        raise Forbidden("Missing permission: ai:use")
    run = await _run(session, principal, run_id)
    hunt_id = body.hunt_id or run.hunt_id
    if hunt_id is None:
        raise AppError("Choose a hunt to save the findings into")
    await _hunt(session, principal, hunt_id)
    findings = (run.conclusion or {}).get("findings", [])
    backend: SearchBackend = request.app.state.search
    created: list[str] = []
    for idx in dict.fromkeys(body.finding_indexes):
        if not 0 <= idx < len(findings):
            raise AppError(f"No finding at index {idx}")
        f = findings[idx]
        if not f.get("supported") or not f.get("event_ids"):
            raise Conflict(f"Finding {idx} cites no verified evidence and cannot be saved")
        docs = {d["id"]: d for d in await backend.get_events(principal.tid, f["event_ids"])}
        evidence = [
            {
                "id": i,
                "timestamp": docs[i]["timestamp"],
                "summary": summarize(docs[i]),
                "host": (docs[i].get("host") or {}).get("hostname"),
            }
            for i in f["event_ids"]
            if i in docs
        ]
        if not evidence:
            raise Conflict(f"The evidence for finding {idx} is no longer available")
        finding = Finding(
            tenant_id=principal.tid,
            hunt_id=hunt_id,
            created_by=principal.user_id,
            title=f"[AI] {f['title']}"[:200],
            description=(
                f"{f['description']}\n\nAssessment: {f.get('classification', 'unverified')} "
                f"(queries {', '.join(f.get('queries') or []) or 'n/a'}).\n(Generated by AI run {run.id}; verify before acting.)"
            )[:10000],
            severity=f["severity"],
            evidence=evidence,
        )
        session.add(finding)
        await session.flush()
        created.append(str(finding.id))
    run.saved_findings = [*run.saved_findings, *created]
    await session.flush()
    await session.refresh(run)
    await audit.record(
        request,
        "ai.save_findings",
        principal=principal,
        resource_type="ai_run",
        resource_id=str(run.id),
        details={"findings": created},
    )
    return run
