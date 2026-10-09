import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import state as st
from app.ai import translate as translator
from app.ai.agent import Outcome, Sink, run_agent
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

log = logging.getLogger("hunt.ai")
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
    sink: Sink | None = None,
    stop: asyncio.Event | None = None,
) -> Outcome:
    backend: SearchBackend = request.app.state.search
    ctx = ToolContext(session=session, backend=backend, principal=principal, ledger=Ledger())
    lim = _limits(mode, settings)
    holder: list[st.Investigation] = []
    outcome = Outcome(mode=mode, sink=sink)
    agent = asyncio.create_task(
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
        )
    )
    waiters: set[asyncio.Task[Any]] = {agent}
    if stop is not None:
        waiters.add(asyncio.create_task(stop.wait()))
    try:
        # the agent enforces its own wall-clock budget; the timeout is only the backstop for a stuck provider/tool call
        await asyncio.wait(waiters, timeout=lim.wall_s + 45, return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        agent.cancel()
        raise
    finally:
        for w in waiters - {agent}:
            w.cancel()
    if not agent.done():
        stopped = stop is not None and stop.is_set()
        agent.cancel()
        await asyncio.gather(agent, return_exceptions=True)
        outcome.status = "INCOMPLETE"
        outcome.error = "Stopped by the analyst" if stopped else "The investigation hit its time limit"
        if holder:
            outcome.state = holder[0].to_dict()
            outcome.conclusion = holder[0].interim_report(
                "stopped_by_analyst" if stopped else "budget_time (hard timeout)"
            )
    else:
        agent.result()  # run_agent reports its own failures through the outcome; anything else propagates
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


def _sse(event: str, data: Any) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n".encode()


def _active(request: Request) -> dict[str, tuple[uuid.UUID, uuid.UUID | None, asyncio.Event]]:
    """Running streamed investigations: run id -> (tenant, owner, stop flag)."""
    return request.app.state.__dict__.setdefault("ai_active", {})


async def _stream(
    request: Request,
    principal: Principal,
    settings: Settings,
    provider: LLMProvider,
    *,
    goal: str,
    hours_back: int,
    mode: str,
    run_id: uuid.UUID,
    persist: Callable[[AsyncSession, Outcome], Awaitable[AiRun]],
    state: st.Investigation | None = None,
    start_extra: dict[str, Any] | None = None,
) -> StreamingResponse:
    """Run an investigation in its own task (own DB session) and narrate it as Server-Sent Events. Shared by new runs and resumes."""
    maker = request.app.state.sessionmaker
    queue: asyncio.Queue[tuple[str, Any] | None] = asyncio.Queue()
    stop = asyncio.Event()
    active = _active(request)
    active[run_id] = (principal.tid, principal.user_id, stop)

    def sink(kind: str, data: dict[str, Any]) -> None:
        queue.put_nowait((kind, data))

    async def worker() -> None:
        try:
            async with maker() as session:
                try:
                    outcome = await _drive(
                        request, principal, session, provider, settings,
                        goal=goal, hours_back=hours_back, mode=mode, state=state, sink=sink, stop=stop,
                    )  # fmt: skip
                    run = await persist(session, outcome)
                    await session.commit()
                    queue.put_nowait(("done", RunOut.model_validate(run).model_dump(mode="json")))
                except Exception:
                    await session.rollback()
                    raise
        except Exception:  # noqa: BLE001 - internals never reach the client
            log.exception("ai stream run failed")
            queue.put_nowait(("error", {"message": "The investigation failed unexpectedly"}))
        finally:
            active.pop(run_id, None)
            queue.put_nowait(None)

    tasks: set[asyncio.Task[None]] = request.app.state.__dict__.setdefault("ai_tasks", set())
    task = asyncio.create_task(worker())
    tasks.add(task)  # strong reference: a closed browser tab must not garbage-collect a running investigation
    task.add_done_callback(tasks.discard)

    async def events() -> AsyncIterator[bytes]:
        lim = _limits(mode, settings)
        yield _sse(
            "start",
            {
                "run_id": str(run_id),
                "goal": goal,
                "mode": mode,
                "hours_back": hours_back,
                "provider": provider.name,
                "model": provider.model,
                "limits": {"steps": lim.max_steps, "tool_calls": lim.max_tool_calls, "seconds": lim.wall_s},
                **(start_extra or {}),
            },
        )
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=15)
            except TimeoutError:
                yield b": keep-alive\n\n"  # keeps proxies from closing a quiet connection
                continue
            if item is None:
                return
            yield _sse(*item)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.post("/runs/stream")
async def stream_run(
    body: RunCreate,
    request: Request,
    principal: Principal = USE,
    settings: Settings = Depends(get_settings),
) -> StreamingResponse:
    """Same investigation as `POST /runs`, narrated live over Server-Sent Events: `start`, then `thinking` / `step` / `tool_start`
    / `evidence` / `progress` as the agent works, and finally `done` (the saved run) or `error`. The investigation runs in its own
    task with its own DB session, so a closed tab does not lose it - the run is still saved and appears in the run list."""
    provider = _need_provider(request)
    if body.hunt_id:
        async with request.app.state.sessionmaker() as check:
            await _hunt(check, principal, body.hunt_id)
    await enforce(request, f"ai-run:{principal.user_id}", 6, 60)
    run_id = uuid.uuid4()

    async def persist(session: AsyncSession, outcome: Outcome) -> AiRun:
        run = AiRun(
            id=run_id,
            tenant_id=principal.tid,
            user_id=principal.user_id,
            hunt_id=body.hunt_id,
            goal=body.goal,
            status=outcome.status,
            provider=provider.name,
            model=provider.model,
            hours_back=body.hours_back,
            mode=body.mode,
            steps=list(outcome.steps),
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

    return await _stream(
        request, principal, settings, provider,
        goal=body.goal, hours_back=body.hours_back, mode=body.mode, run_id=run_id, persist=persist,
    )  # fmt: skip


@router.post("/runs/{run_id}/resume/stream")
async def stream_resume(
    run_id: uuid.UUID,
    body: ResumeIn,
    request: Request,
    principal: Principal = USE,
    settings: Settings = Depends(get_settings),
) -> StreamingResponse:
    """Continue an interrupted investigation, narrated live (see `resume_run`). The same run row is updated when it finishes."""
    provider = _need_provider(request)
    async with request.app.state.sessionmaker() as check:
        run = await _run(check, principal, run_id)
        if run.status == "COMPLETED" or not run.state:
            raise Conflict("Only an interrupted investigation with saved state can be resumed")
        goal, hours_back, saved_state = run.goal, run.hours_back, run.state
        mode = body.mode or (run.mode if run.mode in st.MODES else "standard")
        offset = len(run.steps) + 1  # the resume marker is step `len(run.steps)`
    if run_id in _active(request):
        raise Conflict("This investigation is already running")
    await enforce(request, f"ai-run:{principal.user_id}", 6, 60)

    async def persist(session: AsyncSession, outcome: Outcome) -> AiRun:
        run = await _run(session, principal, run_id)
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

    return await _stream(
        request, principal, settings, provider,
        goal=goal, hours_back=hours_back, mode=mode, run_id=run_id, persist=persist,
        state=st.Investigation.from_dict(saved_state), start_extra={"resumed": True, "step_offset": offset},
    )  # fmt: skip


@router.post("/runs/{run_id}/stop", status_code=202)
async def stop_run(run_id: uuid.UUID, request: Request, principal: Principal = USE) -> dict[str, str]:
    """Ask a running streamed investigation to stop. Whatever it found so far is saved as an INCOMPLETE, resumable run."""
    entry = _active(request).get(run_id)
    if (
        entry is None
        or entry[0] != principal.tid
        or (entry[1] != principal.user_id and not principal.has(Permission.USERS_MANAGE))
    ):
        raise NotFound("No such running investigation")
    entry[2].set()
    return {"status": "stopping"}


@router.get("/runs/{run_id}/evidence")
async def run_evidence(
    run_id: uuid.UUID, principal: Principal = USE, session: AsyncSession = Depends(get_session)
) -> list[dict[str, Any]]:
    """Every event the investigation reviewed (compact), for the evidence timeline. Time-ordered."""
    run = await _run(session, principal, run_id)
    ev = ((run.state or {}).get("evidence") or {}).values()
    keep = ("id", "timestamp", "host", "user", "event_type", "summary")
    return sorted(({k: e.get(k) for k in keep} for e in ev), key=lambda e: str(e.get("timestamp") or ""))


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
