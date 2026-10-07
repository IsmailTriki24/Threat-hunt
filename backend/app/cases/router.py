import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.models import Asset
from app.audit import service as audit
from app.audit.models import AuditLog
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.cases import report as report_builder
from app.cases import service
from app.cases.models import Case, CaseActivity, CaseAsset, CaseEvidence, CaseIoc, CaseReport
from app.cases.schemas import (
    ActivityOut,
    AssetLink,
    CaseCreate,
    CaseOut,
    CaseUpdate,
    EvidenceAdd,
    EvidenceOut,
    IocAdd,
    IocOut,
    NoteIn,
    ReportOut,
    TransitionRequest,
)
from app.core.db import get_session
from app.core.errors import AppError, Conflict, NotFound
from app.core.ratelimit import enforce
from app.events.search.base import SearchBackend
from app.hunts.models import Finding, Hunt
from app.investigations import iocs as ioc_lib
from app.investigations import timeline as timeline_lib
from app.users.models import User

router = APIRouter(prefix="/cases", tags=["cases"])

READ = Depends(require(Permission.CASES_READ))
WRITE = Depends(require(Permission.CASES_WRITE))


def _backend(request: Request) -> SearchBackend:
    backend: SearchBackend = request.app.state.search
    return backend


async def _case(session: AsyncSession, principal: Principal, case_id: uuid.UUID) -> Case:
    case = (
        await session.execute(select(Case).where(Case.id == case_id, Case.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if case is None:
        raise NotFound("Case not found")
    return case


# ---- CRUD ---------------------------------------------------------------------------------------
@router.get("", response_model=list[CaseOut])
async def list_cases(
    status: str | None = None,
    severity: str | None = None,
    assignee_id: uuid.UUID | None = None,
    mine: bool = False,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> list[CaseOut]:
    stmt = select(Case).where(Case.tenant_id == principal.tid)
    if status:
        stmt = stmt.where(Case.status == status)
    if severity:
        stmt = stmt.where(Case.severity == severity)
    if mine:
        stmt = stmt.where(Case.assignee_id == principal.user_id)
    elif assignee_id:
        stmt = stmt.where(Case.assignee_id == assignee_id)
    if q:
        stmt = stmt.where(Case.title.icontains(q[:100], autoescape=True))
    rows = await session.execute(
        stmt.order_by(Case.updated_at.desc()).limit(max(1, min(limit, 200))).offset(max(0, offset))
    )
    return [await service.case_out(session, c) for c in rows.scalars()]


@router.post("", response_model=CaseOut, status_code=201)
async def create_case(
    body: CaseCreate, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> CaseOut:
    event_ids = list(body.event_ids)
    hunt_id = body.hunt_id
    if body.finding_id:
        finding = (
            await session.execute(
                select(Finding).where(Finding.id == body.finding_id, Finding.tenant_id == principal.tid)
            )
        ).scalar_one_or_none()
        if finding is None:
            raise NotFound("Finding not found")
        hunt_id = hunt_id or finding.hunt_id
        event_ids += [e["id"] for e in finding.evidence]
    if (
        hunt_id
        and (await session.execute(select(Hunt.id).where(Hunt.id == hunt_id, Hunt.tenant_id == principal.tid))).first()
        is None
    ):
        raise NotFound("Hunt not found")
    if body.assignee_id:
        await service.validate_assignee(session, principal.tid, body.assignee_id)
    case = Case(
        tenant_id=principal.tid,
        number=await service.next_number(session, principal.tid),
        title=body.title,
        description=body.description,
        severity=body.severity,
        priority=body.priority,
        assignee_id=body.assignee_id,
        hunt_id=hunt_id,
        created_by=principal.user_id,
    )
    session.add(case)
    await session.flush()
    await session.refresh(case)
    await service.log(
        session, principal, case, "created", details={"from_finding": str(body.finding_id) if body.finding_id else None}
    )
    if event_ids:
        await service.add_evidence(
            session, _backend(request), principal, case, list(dict.fromkeys(event_ids)), "Added at case creation"
        )
    await audit.record(
        request,
        "case.create",
        principal=principal,
        resource_type="case",
        resource_id=str(case.id),
        details={"number": case.number, "events": len(event_ids)},
    )
    return await service.case_out(session, case)


@router.get("/{case_id}", response_model=CaseOut)
async def get_case(
    case_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> CaseOut:
    return await service.case_out(session, await _case(session, principal, case_id))


@router.patch("/{case_id}", response_model=CaseOut)
async def update_case(
    case_id: uuid.UUID,
    body: CaseUpdate,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> CaseOut:
    case = await _case(session, principal, case_id)
    service.ensure_open(case)
    changes: dict[str, Any] = {}
    for field in ("title", "description", "severity", "priority"):
        value = getattr(body, field)
        if value is not None and value != getattr(case, field):
            changes[field] = {
                "from": getattr(case, field) if field != "description" else "…",
                "to": value if field != "description" else "…",
            }
            setattr(case, field, value)
    if body.unassign and case.assignee_id:
        changes["assignee"] = {"from": str(case.assignee_id), "to": None}
        case.assignee_id = None
    elif body.assignee_id and body.assignee_id != case.assignee_id:
        await service.validate_assignee(session, principal.tid, body.assignee_id)
        changes["assignee"] = {"from": str(case.assignee_id) if case.assignee_id else None, "to": str(body.assignee_id)}
        case.assignee_id = body.assignee_id
    if changes:
        await service.log(session, principal, case, "updated", details=changes)
        await audit.record(
            request,
            "case.update",
            principal=principal,
            resource_type="case",
            resource_id=str(case.id),
            details={"fields": sorted(changes)},
        )
    return await service.case_out(session, case)


@router.post("/{case_id}/transition", response_model=CaseOut)
async def transition(
    case_id: uuid.UUID,
    body: TransitionRequest,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> CaseOut:
    case = await _case(session, principal, case_id)
    previous = case.status
    await service.apply_transition(session, principal, case, body.status, body.comment)
    await audit.record(
        request,
        "case.transition",
        principal=principal,
        resource_type="case",
        resource_id=str(case.id),
        details={"from": previous, "to": body.status},
    )
    return await service.case_out(session, case)


# ---- journal ------------------------------------------------------------------------------------
@router.post("/{case_id}/notes", response_model=ActivityOut, status_code=201)
async def add_note(
    case_id: uuid.UUID,
    body: NoteIn,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> ActivityOut:
    case = await _case(session, principal, case_id)
    row = await service.log(session, principal, case, "note", body.body)
    await audit.record(request, "case.note", principal=principal, resource_type="case", resource_id=str(case.id))
    return ActivityOut(
        id=row.id,
        kind=row.kind,
        body=row.body,
        details=row.details,
        actor_id=row.actor_id,
        actor_email=principal.email,
        created_at=row.created_at,
    )


async def _activity(session: AsyncSession, case: Case) -> list[ActivityOut]:
    rows = await session.execute(
        select(CaseActivity, User.email)
        .outerjoin(User, User.id == CaseActivity.actor_id)
        .where(CaseActivity.case_id == case.id, CaseActivity.tenant_id == case.tenant_id)
        .order_by(CaseActivity.created_at)
    )
    return [
        ActivityOut(
            id=a.id,
            kind=a.kind,
            body=a.body,
            details=a.details,
            actor_id=a.actor_id,
            actor_email=email,
            created_at=a.created_at,
        )
        for a, email in rows.all()
    ]


@router.get("/{case_id}/activity", response_model=list[ActivityOut])
async def activity(
    case_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[ActivityOut]:
    return await _activity(session, await _case(session, principal, case_id))


@router.get("/{case_id}/audit")
async def case_audit(
    case_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.AUDIT_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    await _case(session, principal, case_id)
    rows = await session.execute(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == principal.tid, AuditLog.resource_type == "case", AuditLog.resource_id == str(case_id)
        )
        .order_by(AuditLog.created_at.desc())
        .limit(500)
    )
    return [
        {
            "id": str(r.id),
            "created_at": r.created_at,
            "action": r.action,
            "outcome": r.outcome,
            "actor": r.actor_label,
            "ip": r.ip,
            "details": r.details,
        }
        for r in rows.scalars()
    ]


# ---- evidence -----------------------------------------------------------------------------------
@router.get("/{case_id}/evidence", response_model=list[EvidenceOut])
async def list_evidence(
    case_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[EvidenceOut]:
    case = await _case(session, principal, case_id)
    rows = await session.execute(
        select(CaseEvidence).where(CaseEvidence.case_id == case.id).order_by(CaseEvidence.created_at)
    )
    return [
        EvidenceOut(
            id=e.id,
            event_id=e.event_id,
            comment=e.comment,
            snapshot=e.snapshot,
            summary=service.evidence_summary(e.snapshot),
            added_by=e.added_by,
            created_at=e.created_at,
        )
        for e in rows.scalars()
    ]


@router.post("/{case_id}/evidence", response_model=list[EvidenceOut], status_code=201)
async def add_evidence(
    case_id: uuid.UUID,
    body: EvidenceAdd,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> list[EvidenceOut]:
    case = await _case(session, principal, case_id)
    added = await service.add_evidence(session, _backend(request), principal, case, body.event_ids, body.comment)
    await session.flush()
    await audit.record(
        request,
        "case.evidence.add",
        principal=principal,
        resource_type="case",
        resource_id=str(case.id),
        details={"events": len(added)},
    )
    return [
        EvidenceOut(
            id=e.id,
            event_id=e.event_id,
            comment=e.comment,
            snapshot=e.snapshot,
            summary=service.evidence_summary(e.snapshot),
            added_by=e.added_by,
            created_at=e.created_at or datetime.now(UTC),
        )
        for e in added
    ]


@router.delete("/{case_id}/evidence/{evidence_id}", status_code=204)
async def remove_evidence(
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> Response:
    case = await _case(session, principal, case_id)
    service.ensure_open(case)
    ev = (
        await session.execute(
            select(CaseEvidence).where(CaseEvidence.id == evidence_id, CaseEvidence.case_id == case.id)
        )
    ).scalar_one_or_none()
    if ev is None:
        raise NotFound("Evidence not found")
    event_id = ev.event_id
    await session.delete(ev)
    await service.log(session, principal, case, "evidence_removed", details={"event": event_id})
    await audit.record(
        request, "case.evidence.remove", principal=principal, resource_type="case", resource_id=str(case.id)
    )
    return Response(status_code=204)


# ---- IOCs ---------------------------------------------------------------------------------------
@router.get("/{case_id}/iocs", response_model=list[IocOut])
async def list_iocs(
    case_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[CaseIoc]:
    case = await _case(session, principal, case_id)
    rows = await session.execute(
        select(CaseIoc).where(CaseIoc.case_id == case.id).order_by(CaseIoc.type, CaseIoc.value)
    )
    return list(rows.scalars())


@router.post("/{case_id}/iocs", response_model=IocOut, status_code=201)
async def add_ioc(
    case_id: uuid.UUID,
    body: IocAdd,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> CaseIoc:
    case = await _case(session, principal, case_id)
    service.ensure_open(case)
    value = ioc_lib.normalize(body.type, body.value)
    if value is None:
        raise AppError(f"Invalid {body.type} indicator")
    ioc = CaseIoc(
        tenant_id=case.tenant_id, case_id=case.id, type=body.type, value=value, source="manual", context="manual"
    )
    session.add(ioc)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("IOC already recorded on this case") from None
    await session.refresh(ioc)
    await service.log(session, principal, case, "ioc_added", details={"type": body.type, "value": value})
    await audit.record(request, "case.ioc.add", principal=principal, resource_type="case", resource_id=str(case.id))
    return ioc


@router.post("/{case_id}/iocs/extract")
async def extract_iocs(
    case_id: uuid.UUID, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> dict[str, int]:
    case = await _case(session, principal, case_id)
    service.ensure_open(case)
    n = await service.recompute_iocs(session, case)
    await service.log(session, principal, case, "iocs_extracted", details={"count": n})
    await audit.record(request, "case.ioc.extract", principal=principal, resource_type="case", resource_id=str(case.id))
    return {"extracted": n}


@router.delete("/{case_id}/iocs/{ioc_id}", status_code=204)
async def remove_ioc(
    case_id: uuid.UUID,
    ioc_id: uuid.UUID,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> Response:
    case = await _case(session, principal, case_id)
    service.ensure_open(case)
    ioc = (
        await session.execute(select(CaseIoc).where(CaseIoc.id == ioc_id, CaseIoc.case_id == case.id))
    ).scalar_one_or_none()
    if ioc is None:
        raise NotFound("IOC not found")
    await session.delete(ioc)
    await service.log(session, principal, case, "ioc_removed", details={"type": ioc.type, "value": ioc.value})
    await audit.record(request, "case.ioc.remove", principal=principal, resource_type="case", resource_id=str(case.id))
    return Response(status_code=204)


# ---- assets -------------------------------------------------------------------------------------
@router.get("/{case_id}/assets")
async def list_case_assets(
    case_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[dict[str, Any]]:
    case = await _case(session, principal, case_id)
    rows = await session.execute(
        select(Asset)
        .join(CaseAsset, CaseAsset.asset_id == Asset.id)
        .where(CaseAsset.case_id == case.id, Asset.tenant_id == principal.tid)
        .order_by(Asset.type, Asset.key)
    )
    return [
        {
            "id": str(a.id),
            "type": a.type,
            "key": a.key,
            "display_name": a.display_name,
            "criticality": a.criticality,
            "last_seen": a.last_seen,
        }
        for a in rows.scalars()
    ]


@router.post("/{case_id}/assets", status_code=201)
async def link_asset(
    case_id: uuid.UUID,
    body: AssetLink,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    case = await _case(session, principal, case_id)
    service.ensure_open(case)
    asset = await service.touch_asset_links(session, principal.tid, body.asset_id)  # tenant-scoped lookup
    if asset is None:
        raise NotFound("Asset not found")
    session.add(CaseAsset(tenant_id=principal.tid, case_id=case.id, asset_id=asset.id))
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("Asset already linked") from None
    await service.log(
        session, principal, case, "asset_linked", details={"asset": asset.display_name, "type": asset.type}
    )
    await audit.record(request, "case.asset.link", principal=principal, resource_type="case", resource_id=str(case.id))
    return {"status": "linked"}


@router.delete("/{case_id}/assets/{asset_id}", status_code=204)
async def unlink_asset(
    case_id: uuid.UUID,
    asset_id: uuid.UUID,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> Response:
    case = await _case(session, principal, case_id)
    service.ensure_open(case)
    link = (
        await session.execute(select(CaseAsset).where(CaseAsset.case_id == case.id, CaseAsset.asset_id == asset_id))
    ).scalar_one_or_none()
    if link is None:
        raise NotFound("Asset link not found")
    await session.delete(link)
    await service.log(session, principal, case, "asset_unlinked", details={"asset_id": str(asset_id)})
    await audit.record(
        request, "case.asset.unlink", principal=principal, resource_type="case", resource_id=str(case.id)
    )
    return Response(status_code=204)


# ---- investigation timeline & report -----------------------------------------------------------
async def _case_timeline(
    session: AsyncSession, backend: SearchBackend, case: Case, collapse: bool = True
) -> timeline_lib.Timeline:
    """Rebuilt from live telemetry where it still exists, otherwise from the stored evidence snapshot."""
    snapshots = {
        e: s
        for e, s in (
            await session.execute(
                select(CaseEvidence.event_id, CaseEvidence.snapshot).where(CaseEvidence.case_id == case.id)
            )
        ).all()
    }
    live = {d["id"]: d for d in await backend.get_events(case.tenant_id, list(snapshots)[:200])}
    docs = [live.get(i, s) for i, s in snapshots.items()]
    return timeline_lib.build(docs, collapse=collapse)


@router.get("/{case_id}/timeline", response_model=timeline_lib.Timeline)
async def case_timeline(
    case_id: uuid.UUID,
    request: Request,
    collapse: bool = True,
    principal: Principal = Depends(require(Permission.CASES_READ)),
    session: AsyncSession = Depends(get_session),
) -> timeline_lib.Timeline:
    case = await _case(session, principal, case_id)
    return await _case_timeline(session, _backend(request), case, collapse)


@router.post("/{case_id}/reports", response_model=ReportOut, status_code=201)
async def generate_report(
    case_id: uuid.UUID, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> CaseReport:
    await enforce(request, f"report:{principal.user_id}", 10, 60)
    case = await _case(session, principal, case_id)
    out = await service.case_out(session, case)
    assets = await list_case_assets(case_id, principal, session)
    ioc_rows = [
        {"type": i.type, "value": i.value, "occurrences": i.occurrences, "source": i.source}
        for i in (await list_iocs(case_id, principal, session))
    ]
    evidence = [
        {
            "timestamp": e.snapshot.get("timestamp"),
            "summary": e.summary,
            "event_id": e.event_id,
            "host": (e.snapshot.get("host") or {}).get("hostname"),
        }
        for e in await list_evidence(case_id, principal, session)
    ]
    from app.mitre.models import MitreMapping, MitreTechnique

    mapped = await session.execute(
        select(MitreMapping, MitreTechnique.name)
        .join(MitreTechnique, MitreTechnique.id == MitreMapping.technique_id)
        .where(
            MitreMapping.tenant_id == principal.tid,
            MitreMapping.object_type == "case",
            MitreMapping.object_id == case.id,
        )
        .order_by(MitreMapping.technique_id)
    )
    techniques = [
        {
            "technique_id": m.technique_id,
            "name": name,
            "confidence": m.confidence,
            "reasoning": m.reasoning,
            "evidence_count": len(m.evidence_event_ids or []),
        }
        for m, name in mapped.all()
    ]
    journal = [a.model_dump() for a in await _activity(session, case)]
    tl = await _case_timeline(session, _backend(request), case)
    content = report_builder.build_markdown(
        out,
        assets=assets,
        iocs=ioc_rows,
        evidence=evidence,
        timeline=tl,
        activity=journal,
        generated_at=datetime.now(UTC),
        generated_by=principal.email,
        techniques=techniques,
    )
    version = (
        int(
            (
                await session.execute(
                    select(func.coalesce(func.max(CaseReport.version), 0)).where(CaseReport.case_id == case.id)
                )
            ).scalar_one()
        )
        + 1
    )
    report = CaseReport(
        tenant_id=case.tenant_id, case_id=case.id, version=version, content=content, created_by=principal.user_id
    )
    session.add(report)
    await session.flush()
    await session.refresh(report)
    await service.log(session, principal, case, "report_generated", details={"version": version})
    await audit.record(
        request,
        "case.report",
        principal=principal,
        resource_type="case",
        resource_id=str(case.id),
        details={"version": version},
    )
    return report


@router.get("/{case_id}/reports", response_model=list[ReportOut])
async def list_reports(
    case_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[CaseReport]:
    case = await _case(session, principal, case_id)
    rows = await session.execute(
        select(CaseReport).where(CaseReport.case_id == case.id).order_by(CaseReport.version.desc())
    )
    return list(rows.scalars())
