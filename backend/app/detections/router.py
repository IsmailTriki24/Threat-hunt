import contextlib
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission, permissions_for
from app.cases import service as case_service
from app.cases.models import Case
from app.core.db import get_session
from app.core.errors import AppError, Forbidden, NotFound
from app.core.ratelimit import enforce
from app.detections import service
from app.detections.formats import registry
from app.detections.formats.base import RuleError
from app.detections.models import Alert, DetectionRule, DetectionRun, RuleTestCase, RuleVersion
from app.detections.schemas import (
    AlertOut,
    AlertToCase,
    AlertUpdate,
    BacktestOut,
    BacktestRequest,
    FormatOut,
    FromQuery,
    Overview,
    RuleCreate,
    RuleOut,
    RuleUpdate,
    RunOut,
    TestCaseIn,
    TestCaseOut,
    TestRunOut,
    Transition,
    ValidateOut,
    ValidateRequest,
    VersionOut,
)
from app.events.search.base import SearchBackend
from app.hunts.models import Hunt

router = APIRouter(prefix="/detections", tags=["detections"])
READ = Depends(require(Permission.DETECTIONS_READ))
WRITE = Depends(require(Permission.DETECTIONS_WRITE))
MANAGE = Depends(require(Permission.DETECTIONS_MANAGE))


def _backend(request: Request) -> SearchBackend:
    backend: SearchBackend = request.app.state.search
    return backend


async def _rule(session: AsyncSession, principal: Principal, rule_id: uuid.UUID) -> DetectionRule:
    rule = (
        await session.execute(
            select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == principal.tid)
        )
    ).scalar_one_or_none()
    if rule is None:
        raise NotFound("Rule not found")
    return rule


async def _out(session: AsyncSession, rule: DetectionRule) -> RuleOut:
    await session.flush()
    await session.refresh(rule)
    out = RuleOut.model_validate(rule)
    out.executable = bool(rule.compiled)
    out.test_count = await service.counts(session, RuleTestCase, RuleTestCase.rule_id == rule.id)
    out.open_alerts = await service.counts(session, Alert, Alert.rule_id == rule.id, Alert.status == "OPEN")
    return out


async def _check_hunt(session: AsyncSession, principal: Principal, hunt_id: uuid.UUID | None) -> None:
    if hunt_id is None:
        return
    found = (await session.execute(select(Hunt.id).where(Hunt.id == hunt_id, Hunt.tenant_id == principal.tid))).first()
    if found is None:
        raise NotFound("Hunt not found")


@router.get("/formats", response_model=list[FormatOut])
async def formats(_: Principal = READ) -> list[FormatOut]:
    return [
        FormatOut(id=f.format_id, name=f.display_name, description=f.description) for f in registry.FORMATS.values()
    ]


@router.get("/overview", response_model=Overview)
async def overview(principal: Principal = READ, session: AsyncSession = Depends(get_session)) -> Overview:
    by_status = dict(
        (
            await session.execute(
                select(DetectionRule.status, func.count())
                .where(DetectionRule.tenant_id == principal.tid)
                .group_by(DetectionRule.status)
            )
        ).all()
    )
    by_sev = dict(
        (
            await session.execute(
                select(Alert.severity, func.count())
                .where(Alert.tenant_id == principal.tid, Alert.status == "OPEN")
                .group_by(Alert.severity)
            )
        ).all()
    )
    active = (
        await session.execute(
            select(DetectionRule.techniques).where(
                DetectionRule.tenant_id == principal.tid, DetectionRule.status == "ACTIVE"
            )
        )
    ).scalars()
    return Overview(
        rules_by_status=by_status,
        open_alerts=sum(by_sev.values()),
        alerts_by_severity=by_sev,
        coverage=sorted({t for ts in active for t in ts}),
    )


@router.post("/validate", response_model=ValidateOut)
async def validate(body: ValidateRequest, request: Request, principal: Principal = WRITE) -> ValidateOut:
    """Stateless: compile a rule and run optional sample events through it. Nothing is stored."""
    await enforce(request, f"det-validate:{principal.user_id}", 120, 60)
    try:
        fmt = registry.get(body.format)
    except KeyError:
        raise AppError(f"Unknown detection format '{body.format}'") from None
    try:
        parsed = fmt.parse(body.content)
    except RuleError as exc:
        return ValidateOut(ok=False, error=str(exc))
    results = []
    if parsed.executable and parsed.where is not None and body.events:
        cases = [(None, f"sample {i + 1}", ev.model_dump(mode="json"), True) for i, ev in enumerate(body.events)]
        results = service.run_cases(parsed.where, parsed.selections, cases)
    return ValidateOut(
        ok=True,
        title=parsed.title,
        severity=parsed.severity,
        executable=parsed.executable,
        unsupported=parsed.unsupported,
        warnings=parsed.warnings,
        techniques=parsed.techniques,
        tactics=parsed.tactics,
        condition=parsed.where if parsed.executable else None,
        results=results,
    )


# ---- rules -------------------------------------------------------------------------------------
@router.get("/rules", response_model=list[RuleOut])
async def list_rules(
    status: str | None = None,
    technique: str | None = None,
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> list[RuleOut]:
    stmt = select(DetectionRule).where(DetectionRule.tenant_id == principal.tid)
    if status:
        stmt = stmt.where(DetectionRule.status == status.upper())
    if technique:
        stmt = stmt.where(DetectionRule.techniques.contains([technique.upper()]))
    rules = (await session.execute(stmt.order_by(DetectionRule.updated_at.desc()).limit(500))).scalars().all()
    return [await _out(session, r) for r in rules]


async def _create(
    session: AsyncSession, principal: Principal, format_id: str, content: str, hunt_id: uuid.UUID | None
) -> DetectionRule:
    parsed = service.parse(format_id, content)
    rule = DetectionRule(
        tenant_id=principal.tid, format=format_id, content=content, hunt_id=hunt_id, created_by=principal.user_id
    )
    service.apply_parsed(rule, parsed)
    rule.status = "DRAFT"
    session.add(rule)
    await session.flush()
    await service.snapshot_version(session, rule, principal.user_id, "created")
    await service.sync_mitre(session, rule, principal.user_id)
    return rule


@router.post("/rules", response_model=RuleOut, status_code=201)
async def create_rule(
    body: RuleCreate, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> RuleOut:
    await _check_hunt(session, principal, body.hunt_id)
    rule = await _create(session, principal, body.format, body.content, body.hunt_id)
    await audit.record(
        request, "detection.create", principal=principal, resource_type="detection", resource_id=str(rule.id)
    )
    return await _out(session, rule)


def _one_line(s: str) -> str:
    return " ".join(s.split())


@router.post("/rules/from-query", response_model=RuleOut, status_code=201)
async def rule_from_query(
    body: FromQuery, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> RuleOut:
    """Hunt -> detection: wrap a hunt query in the `hunt_query` format. The result is a DRAFT like any other rule."""
    await _check_hunt(session, principal, body.hunt_id)
    header = f"# title: {_one_line(body.title)}\n# level: {body.severity.lower()}\n"
    if body.description:
        header += f"# description: {_one_line(body.description)}\n"
    rule = await _create(session, principal, "hunt_query", header + body.text, body.hunt_id)
    await audit.record(
        request,
        "detection.create",
        principal=principal,
        resource_type="detection",
        resource_id=str(rule.id),
        details={"from_hunt": str(body.hunt_id) if body.hunt_id else None},
    )
    return await _out(session, rule)


@router.get("/rules/{rule_id}", response_model=RuleOut)
async def get_rule(
    rule_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> RuleOut:
    return await _out(session, await _rule(session, principal, rule_id))


@router.put("/rules/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: uuid.UUID,
    body: RuleUpdate,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> RuleOut:
    rule = await _rule(session, principal, rule_id)
    parsed = service.parse(rule.format, body.content)
    was_active = rule.status == "ACTIVE"
    rule.content = body.content
    rule.version += 1
    service.apply_parsed(rule, parsed)
    rule.tests_passed, rule.tests_run_at = None, None
    if rule.status in ("ACTIVE", "TESTING", "DISABLED"):
        rule.status = "DRAFT"  # every new version re-earns its way to ACTIVE
        rule.activated_at = None
    await session.flush()
    await service.snapshot_version(session, rule, principal.user_id, body.note)
    await service.sync_mitre(session, rule, principal.user_id)
    await audit.record(
        request,
        "detection.update",
        principal=principal,
        resource_type="detection",
        resource_id=str(rule.id),
        details={"version": rule.version, "deactivated": was_active},
    )
    return await _out(session, rule)


@router.post("/rules/{rule_id}/transition", response_model=RuleOut)
async def transition(
    rule_id: uuid.UUID,
    body: Transition,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> RuleOut:
    rule = await _rule(session, principal, rule_id)
    # Only MANAGE may put a rule into (or take it out of) production; WRITE may move it between DRAFT/TESTING/ARCHIVED.
    production = {"ACTIVE", "DISABLED"}
    if (body.to in production or rule.status in production) and Permission.DETECTIONS_MANAGE not in permissions_for(
        principal.role
    ):
        raise Forbidden("Activating or disabling rules requires the detections:manage permission")
    cases = await service.load_cases(session, rule)
    service.check_transition(rule, body.to, len(cases), any(c.expect_match for c in cases))
    previous = rule.status
    rule.status = body.to
    if body.to == "ACTIVE":
        rule.activated_at = datetime.now(UTC)
        rule.last_evaluated_at = rule.activated_at  # no historical alert flood; use a backtest to look back
        rule.last_run_status, rule.last_run_error = "", ""
    await audit.record(
        request,
        "detection.transition",
        principal=principal,
        resource_type="detection",
        resource_id=str(rule.id),
        details={"from": previous, "to": body.to, "version": rule.version},
    )
    return await _out(session, rule)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: uuid.UUID, request: Request, principal: Principal = MANAGE, session: AsyncSession = Depends(get_session)
) -> Response:
    rule = await _rule(session, principal, rule_id)
    await service.remove_mitre(session, rule)
    await session.delete(rule)
    await audit.record(
        request,
        "detection.delete",
        principal=principal,
        resource_type="detection",
        resource_id=str(rule_id),
        details={"title": rule.title},
    )
    return Response(status_code=204)


@router.get("/rules/{rule_id}/versions", response_model=list[VersionOut])
async def versions(
    rule_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[VersionOut]:
    rule = await _rule(session, principal, rule_id)
    rows = (
        (
            await session.execute(
                select(RuleVersion).where(RuleVersion.rule_id == rule.id).order_by(RuleVersion.version.desc())
            )
        )
        .scalars()
        .all()
    )
    return [VersionOut.model_validate(r) for r in rows]


# ---- tests -------------------------------------------------------------------------------------
@router.get("/rules/{rule_id}/tests", response_model=list[TestCaseOut])
async def list_tests(
    rule_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[TestCaseOut]:
    rule = await _rule(session, principal, rule_id)
    return [TestCaseOut.model_validate(c) for c in await service.load_cases(session, rule)]


@router.post("/rules/{rule_id}/tests", response_model=TestCaseOut, status_code=201)
async def add_test(
    rule_id: uuid.UUID, body: TestCaseIn, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> TestCaseOut:
    rule = await _rule(session, principal, rule_id)
    if await service.counts(session, RuleTestCase, RuleTestCase.rule_id == rule.id) >= 50:
        raise AppError("A rule can have at most 50 test cases")
    case = RuleTestCase(
        tenant_id=principal.tid,
        rule_id=rule.id,
        name=body.name,
        event=body.event.model_dump(mode="json", exclude_none=True),
        expect_match=body.expect_match,
        created_by=principal.user_id,
    )
    session.add(case)
    await service.invalidate_tests(session, rule)
    await session.flush()
    await session.refresh(case)
    return TestCaseOut.model_validate(case)


@router.delete("/rules/{rule_id}/tests/{case_id}", status_code=204)
async def delete_test(
    rule_id: uuid.UUID, case_id: uuid.UUID, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> Response:
    rule = await _rule(session, principal, rule_id)
    case = (
        await session.execute(select(RuleTestCase).where(RuleTestCase.id == case_id, RuleTestCase.rule_id == rule.id))
    ).scalar_one_or_none()
    if case is None:
        raise NotFound("Test case not found")
    await session.delete(case)
    await service.invalidate_tests(session, rule)
    return Response(status_code=204)


@router.post("/rules/{rule_id}/tests/run", response_model=TestRunOut)
async def run_rule_tests(
    rule_id: uuid.UUID, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> TestRunOut:
    rule = await _rule(session, principal, rule_id)
    results = await service.run_tests(session, rule)
    return TestRunOut(passed=bool(rule.tests_passed), results=results)


# ---- runs --------------------------------------------------------------------------------------
@router.post("/rules/{rule_id}/backtest", response_model=BacktestOut)
async def backtest(
    rule_id: uuid.UUID,
    body: BacktestRequest,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> BacktestOut:
    rule = await _rule(session, principal, rule_id)
    await enforce(request, f"det-backtest:{principal.user_id}", 30, 60)
    run, hits, total = await service.evaluate(
        session,
        _backend(request),
        rule,
        kind="backtest",
        time_range=body.time_range,
        limit=body.limit,
        user_id=principal.user_id,
    )
    if run.status != "ok":
        raise AppError(f"Backtest failed: {run.error}")
    return BacktestOut(run=RunOut.model_validate(run), hits=hits, total=total)


@router.get("/rules/{rule_id}/runs", response_model=list[RunOut])
async def runs(
    rule_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[RunOut]:
    rule = await _rule(session, principal, rule_id)
    rows = (
        (
            await session.execute(
                select(DetectionRun)
                .where(DetectionRun.rule_id == rule.id)
                .order_by(DetectionRun.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    return [RunOut.model_validate(r) for r in rows]


# ---- alerts ------------------------------------------------------------------------------------
@router.get("/alerts", response_model=list[AlertOut])
async def list_alerts(
    status: str | None = None,
    rule_id: uuid.UUID | None = None,
    severity: str | None = None,
    limit: int = 100,
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> list[AlertOut]:
    stmt = select(Alert).where(Alert.tenant_id == principal.tid)
    if status:
        stmt = stmt.where(Alert.status == status.upper())
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())
    rows = (await session.execute(stmt.order_by(Alert.event_timestamp.desc()).limit(max(1, min(limit, 500))))).scalars()
    return [AlertOut.model_validate(a) for a in rows]


async def _alert(session: AsyncSession, principal: Principal, alert_id: uuid.UUID) -> Alert:
    alert = (
        await session.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if alert is None:
        raise NotFound("Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: uuid.UUID,
    body: AlertUpdate,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> AlertOut:
    alert = await _alert(session, principal, alert_id)
    alert.status = body.status
    await session.flush()
    await session.refresh(alert)
    await audit.record(
        request,
        "detection.alert_update",
        principal=principal,
        resource_type="alert",
        resource_id=str(alert.id),
        details={"status": body.status},
    )
    return AlertOut.model_validate(alert)


@router.post("/alerts/{alert_id}/case", response_model=AlertOut, status_code=201)
async def alert_to_case(
    alert_id: uuid.UUID,
    body: AlertToCase,
    request: Request,
    principal: Principal = Depends(require(Permission.CASES_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> AlertOut:
    """Escalate an alert: open a case seeded with the matching event as evidence."""
    if Permission.DETECTIONS_WRITE not in permissions_for(principal.role):
        raise Forbidden("Missing permission: detections:write")
    alert = await _alert(session, principal, alert_id)
    if alert.case_id is not None:
        raise AppError("This alert already has a case")
    case = Case(
        tenant_id=principal.tid,
        number=await case_service.next_number(session, principal.tid),
        title=(body.title or f"Alert: {alert.rule_title}")[:200],
        description=f"Raised by detection rule '{alert.rule_title}' (v{alert.rule_version}) on event {alert.event_id}.",
        severity=alert.severity,
        created_by=principal.user_id,
    )
    session.add(case)
    await session.flush()
    await session.refresh(case)
    await case_service.log(session, principal, case, "created", details={"from_alert": str(alert.id)})
    with contextlib.suppress(AppError):  # event aged out of telemetry: the case is still created
        await case_service.add_evidence(
            session, _backend(request), principal, case, [alert.event_id], f"Matched rule '{alert.rule_title}'"
        )
    alert.case_id = case.id
    if alert.status == "OPEN":
        alert.status = "ACKNOWLEDGED"
    await session.flush()
    await session.refresh(alert)
    await audit.record(
        request,
        "detection.alert_to_case",
        principal=principal,
        resource_type="alert",
        resource_id=str(alert.id),
        details={"case_id": str(case.id)},
    )
    return AlertOut.model_validate(alert)


__all__: list[Any] = ["router"]
