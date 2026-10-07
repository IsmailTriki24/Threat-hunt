import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.models import Asset
from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.cases import service as case_service
from app.cases.models import Case, CaseEvidence
from app.core.db import get_session
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.ratelimit import enforce
from app.events.search.base import SearchBackend
from app.events.search.query import EventQuery
from app.hunts.models import Finding, Hunt
from app.hunts.service import apply_hunt_scope
from app.mitre import suggest as engine
from app.mitre.models import MitreMapping, MitreTactic, MitreTechnique
from app.mitre.schemas import (
    MappedObject,
    MappingCreate,
    MappingOut,
    MatrixColumn,
    MatrixTechnique,
    NameCount,
    SuggestionOut,
    SuggestRequest,
    SuggestResponse,
    TacticOut,
    TechniqueDetail,
    TechniqueOut,
    TechniqueSummary,
)

router = APIRouter(prefix="/mitre", tags=["mitre"])
READ = Depends(require(Permission.MITRE_READ, tenant_scoped=False))
READ_T = Depends(require(Permission.MITRE_READ))
WRITE = Depends(require(Permission.MITRE_WRITE))

_TID = re.compile(r"^T\d{4}(\.\d{3})?$")
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _backend(request: Request) -> SearchBackend:
    backend: SearchBackend = request.app.state.search
    return backend


def _tech_out(t: MitreTechnique) -> TechniqueOut:
    return TechniqueOut(
        id=t.id,
        name=t.name,
        parent_id=t.parent_id,
        is_subtechnique=t.parent_id is not None,
        tactics=list(t.tactics or []),
        description=t.description,
        url=t.url,
        source=t.source,
    )


async def _technique(session: AsyncSession, technique_id: str) -> MitreTechnique:
    if not _TID.match(technique_id):
        raise NotFound("Technique not found")
    t = await session.get(MitreTechnique, technique_id)
    if t is None:
        raise NotFound("Technique not found")
    return t


# ---- reference data (global) ----
@router.get("/tactics", response_model=list[TacticOut])
async def list_tactics(_: Principal = READ, session: AsyncSession = Depends(get_session)) -> list[MitreTactic]:
    return list((await session.execute(select(MitreTactic).order_by(MitreTactic.position))).scalars())


@router.get("/techniques", response_model=list[TechniqueOut])
async def list_techniques(
    tactic: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
    _: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> list[TechniqueOut]:
    stmt = select(MitreTechnique)
    if tactic:
        stmt = stmt.where(MitreTechnique.tactics.contains([tactic[:64]]))
    if q:
        needle = q.strip()[:100]
        stmt = stmt.where(
            MitreTechnique.name.icontains(needle, autoescape=True)
            | MitreTechnique.id.icontains(needle, autoescape=True)
        )
    rows = await session.execute(stmt.order_by(MitreTechnique.id).limit(max(1, min(limit, 500))).offset(max(0, offset)))
    return [_tech_out(t) for t in rows.scalars()]


@router.get("/techniques/{technique_id}", response_model=TechniqueDetail)
async def get_technique(
    technique_id: str, _: Principal = READ, session: AsyncSession = Depends(get_session)
) -> TechniqueDetail:
    t = await _technique(session, technique_id)
    subs = (
        await session.execute(
            select(MitreTechnique).where(MitreTechnique.parent_id == t.id).order_by(MitreTechnique.id)
        )
    ).scalars()
    return TechniqueDetail(**_tech_out(t).model_dump(), subtechniques=[_tech_out(s) for s in subs])


@router.get("/matrix", response_model=list[MatrixColumn])
async def matrix(principal: Principal = READ_T, session: AsyncSession = Depends(get_session)) -> list[MatrixColumn]:
    """Tactic columns with techniques (sub-techniques nested) and this tenant's mapping counts."""
    stats: dict[str, tuple[int, str]] = {}
    rows = await session.execute(
        select(MitreMapping.technique_id, MitreMapping.confidence).where(MitreMapping.tenant_id == principal.tid)
    )
    for tid, conf in rows.all():
        n, top = stats.get(tid, (0, "LOW"))
        stats[tid] = (n + 1, conf if _RANK[conf] > _RANK[top] else top)
    techniques = list((await session.execute(select(MitreTechnique).order_by(MitreTechnique.id))).scalars())
    tactics = list((await session.execute(select(MitreTactic).order_by(MitreTactic.position))).scalars())

    def node(t: MitreTechnique) -> MatrixTechnique:
        n, top = stats.get(t.id, (0, ""))
        return MatrixTechnique(id=t.id, name=t.name, mapping_count=n, top_confidence=top or None)

    subs: dict[str, list[MitreTechnique]] = {}
    for t in techniques:
        if t.parent_id:
            subs.setdefault(t.parent_id, []).append(t)
    columns = []
    for tac in tactics:
        tops = []
        for t in techniques:
            if t.parent_id is None and tac.shortname in (t.tactics or []):
                m = node(t)
                m.subtechniques = [node(s) for s in subs.get(t.id, [])]
                tops.append(m)
        columns.append(MatrixColumn(tactic=TacticOut.model_validate(tac, from_attributes=True), techniques=tops))
    return columns


# ---- suggestions ----
async def _page_search(
    backend: SearchBackend, tenant_id: uuid.UUID, query: EventQuery, limit: int
) -> list[dict[str, Any]]:
    base = query.model_copy(update={"aggregations": []})
    docs: list[dict[str, Any]] = []
    while len(docs) < limit:
        page = base.model_copy(update={"offset": len(docs), "limit": min(200, limit - len(docs))})
        res = await backend.search(tenant_id, page)
        docs.extend(res.hits)
        if len(res.hits) < page.limit:
            break
    return docs


async def _events_by_ids(backend: SearchBackend, tenant_id: uuid.UUID, ids: list[str]) -> list[dict[str, Any]]:
    ids = list(dict.fromkeys(ids))
    docs: list[dict[str, Any]] = []
    for i in range(0, len(ids), 200):
        docs.extend(await backend.get_events(tenant_id, ids[i : i + 200]))
    return docs


@router.post("/suggest", response_model=SuggestResponse)
async def suggest(
    body: SuggestRequest, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> SuggestResponse:
    sources = [s for s in (body.event_ids, body.query, body.case_id, body.hunt_id) if s is not None]
    if len(sources) != 1:
        raise AppError("Provide exactly one of event_ids, query, case_id or hunt_id")
    await enforce(request, f"mitre-suggest:{principal.user_id}", 20, 60)
    backend = _backend(request)
    obj: tuple[str, uuid.UUID] | None = None
    if body.event_ids is not None:
        docs = await _events_by_ids(backend, principal.tid, body.event_ids)
        missing = set(body.event_ids) - {d["id"] for d in docs}
        if missing:
            raise AppError(f"Unknown event ids: {', '.join(sorted(missing)[:5])}")
    elif body.query is not None:
        docs = await _page_search(backend, principal.tid, body.query, body.limit)
    elif body.case_id is not None:
        if not principal.has(Permission.CASES_READ):
            raise Forbidden("Insufficient permissions")
        case = (
            await session.execute(select(Case).where(Case.id == body.case_id, Case.tenant_id == principal.tid))
        ).scalar_one_or_none()
        if case is None:
            raise NotFound("Case not found")
        rows = await session.execute(
            select(CaseEvidence.snapshot).where(CaseEvidence.case_id == case.id).limit(body.limit)
        )
        docs = [s for (s,) in rows.all()]
        obj = ("case", case.id)
    else:
        if body.hunt_id is None:  # unreachable: exactly one source was validated above
            raise AppError("Provide exactly one of event_ids, query, case_id or hunt_id")
        if not principal.has(Permission.HUNTS_READ):
            raise Forbidden("Insufficient permissions")
        hunt = (
            await session.execute(select(Hunt).where(Hunt.id == body.hunt_id, Hunt.tenant_id == principal.tid))
        ).scalar_one_or_none()
        if hunt is None:
            raise NotFound("Hunt not found")
        finding_ids = [
            e["id"]
            for (ev,) in (await session.execute(select(Finding.evidence).where(Finding.hunt_id == hunt.id))).all()
            for e in ev
        ]
        docs = await _events_by_ids(backend, principal.tid, finding_ids[: body.limit])
        if len(docs) < body.limit:
            seen = {d["id"] for d in docs}
            scoped = apply_hunt_scope(hunt, EventQuery())
            docs += [
                d
                for d in await _page_search(backend, principal.tid, scoped, body.limit - len(docs))
                if d["id"] not in seen
            ]
        obj = ("hunt", hunt.id)
    mapped: set[str] = set()
    if obj:
        rows = await session.execute(
            select(MitreMapping.technique_id).where(
                MitreMapping.tenant_id == principal.tid,
                MitreMapping.object_type == obj[0],
                MitreMapping.object_id == obj[1],
            )
        )
        mapped = {t for (t,) in rows.all()}
    out = [SuggestionOut(**s.model_dump(), mapped=s.technique_id in mapped) for s in engine.suggest(docs)]
    return SuggestResponse(analyzed_events=len(docs), suggestions=out)


# ---- mappings ----
_OBJECT_PERMISSION = {"case": Permission.CASES_WRITE, "hunt": Permission.HUNTS_WRITE, "finding": Permission.HUNTS_WRITE}


async def _resolve_object(
    session: AsyncSession, principal: Principal, object_type: str, object_id: uuid.UUID
) -> tuple[str, Case | None]:
    """Tenant-scoped lookup; returns (title, case-if-case)."""
    if object_type == "case":
        case = (
            await session.execute(select(Case).where(Case.id == object_id, Case.tenant_id == principal.tid))
        ).scalar_one_or_none()
        if case is None:
            raise NotFound("Case not found")
        return f"CASE-{case.number:04d} {case.title}", case
    if object_type == "hunt":
        hunt = (
            await session.execute(select(Hunt).where(Hunt.id == object_id, Hunt.tenant_id == principal.tid))
        ).scalar_one_or_none()
        if hunt is None:
            raise NotFound("Hunt not found")
        return hunt.title, None
    if object_type == "finding":
        finding = (
            await session.execute(select(Finding).where(Finding.id == object_id, Finding.tenant_id == principal.tid))
        ).scalar_one_or_none()
        if finding is None:
            raise NotFound("Finding not found")
        return finding.title, None
    raise AppError("Detection mappings are not available yet (detection rules arrive in Milestone 5)")


async def _require_object_write(request: Request, principal: Principal, object_type: str) -> None:
    needed = _OBJECT_PERMISSION.get(object_type)
    if needed is not None and not principal.has(needed):
        await audit.record(
            request,
            "authz.denied",
            "denied",
            principal=principal,
            details={"permission": needed.value, "path": request.url.path},
        )
        raise Forbidden("Insufficient permissions")


def _mapping_out(m: MitreMapping, t: MitreTechnique) -> MappingOut:
    return MappingOut(
        id=m.id,
        technique_id=m.technique_id,
        technique_name=t.name,
        tactics=list(t.tactics or []),
        object_type=m.object_type,
        object_id=m.object_id,
        confidence=m.confidence,
        reasoning=m.reasoning,
        evidence_event_ids=list(m.evidence_event_ids or []),
        evidence_count=len(m.evidence_event_ids or []),
        source=m.source,
        created_by=m.created_by,
        created_at=m.created_at,
    )


@router.post("/mappings", response_model=MappingOut, status_code=201)
async def create_mapping(
    body: MappingCreate, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> MappingOut:
    technique = await _technique(session, body.technique_id)
    await _require_object_write(request, principal, body.object_type)
    title, case = await _resolve_object(session, principal, body.object_type, body.object_id)
    if case is not None:
        case_service.ensure_open(case)
    evidence = list(dict.fromkeys(body.evidence_event_ids))
    if body.confidence in ("MEDIUM", "HIGH") and not evidence:
        raise AppError("MEDIUM and HIGH confidence mappings must cite at least one evidence event")
    if evidence:
        found = {d["id"] for d in await _events_by_ids(_backend(request), principal.tid, evidence)}
        missing = [e for e in evidence if e not in found]
        if missing:
            raise AppError(f"Unknown event ids: {', '.join(missing[:5])}")
    mapping = MitreMapping(
        tenant_id=principal.tid,
        technique_id=technique.id,
        object_type=body.object_type,
        object_id=body.object_id,
        confidence=body.confidence,
        reasoning=body.reasoning.strip(),
        evidence_event_ids=evidence,
        source=body.source,
        created_by=principal.user_id,
    )
    session.add(mapping)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("This technique is already mapped to the object") from None
    await session.refresh(mapping)
    if case is not None:
        await case_service.log(
            session,
            principal,
            case,
            "mitre_mapped",
            f"{technique.id} {technique.name}",
            {"technique": technique.id, "confidence": body.confidence, "evidence": len(evidence)},
        )
    await audit.record(
        request,
        "mitre.map",
        principal=principal,
        resource_type=body.object_type,
        resource_id=str(body.object_id),
        details={"technique": technique.id, "confidence": body.confidence, "title": title[:100]},
    )
    return _mapping_out(mapping, technique)


@router.get("/mappings", response_model=list[MappingOut])
async def list_mappings(
    object_type: str | None = None,
    object_id: uuid.UUID | None = None,
    technique_id: str | None = None,
    principal: Principal = READ_T,
    session: AsyncSession = Depends(get_session),
) -> list[MappingOut]:
    stmt = (
        select(MitreMapping, MitreTechnique)
        .join(MitreTechnique, MitreTechnique.id == MitreMapping.technique_id)
        .where(MitreMapping.tenant_id == principal.tid)
    )
    if object_type:
        stmt = stmt.where(MitreMapping.object_type == object_type)
    if object_id:
        stmt = stmt.where(MitreMapping.object_id == object_id)
    if technique_id:
        stmt = stmt.where(MitreMapping.technique_id == technique_id)
    rows = await session.execute(stmt.order_by(MitreMapping.technique_id, MitreMapping.created_at).limit(500))
    return [_mapping_out(m, t) for m, t in rows.all()]


@router.delete("/mappings/{mapping_id}", status_code=204)
async def delete_mapping(
    mapping_id: uuid.UUID, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> Response:
    m = (
        await session.execute(
            select(MitreMapping).where(MitreMapping.id == mapping_id, MitreMapping.tenant_id == principal.tid)
        )
    ).scalar_one_or_none()
    if m is None:
        raise NotFound("Mapping not found")
    await _require_object_write(request, principal, m.object_type)
    case: Case | None = None
    if m.object_type == "case":
        case = (
            await session.execute(select(Case).where(Case.id == m.object_id, Case.tenant_id == principal.tid))
        ).scalar_one_or_none()
        if case is not None:
            case_service.ensure_open(case)
    tid = m.technique_id
    await session.delete(m)
    if case is not None:
        await case_service.log(session, principal, case, "mitre_unmapped", tid, {"technique": tid})
    await audit.record(
        request,
        "mitre.unmap",
        principal=principal,
        resource_type=m.object_type,
        resource_id=str(m.object_id),
        details={"technique": tid},
    )
    return Response(status_code=204)


# ---- technique risk summary ----
@router.get("/techniques/{technique_id}/summary", response_model=TechniqueSummary)
async def technique_summary(
    technique_id: str, request: Request, principal: Principal = READ_T, session: AsyncSession = Depends(get_session)
) -> TechniqueSummary:
    """Tenant-wide picture of one technique, computed from stored mappings and their cited events.

    Risk rule (documented, deterministic):
      * HIGH   — at least one HIGH-confidence mapping AND (>= 2 distinct hosts OR >= 10 distinct evidence events
                 OR a host in the evidence is a known asset with HIGH/CRITICAL criticality).
      * MEDIUM — at least one MEDIUM or HIGH confidence mapping (and not HIGH by the rule above).
      * LOW    — only LOW-confidence mappings, or none.
    Every contributing factor is returned in `risk_reasons`.
    """
    t = await _technique(session, technique_id)
    rows = (
        (
            await session.execute(
                select(MitreMapping).where(MitreMapping.tenant_id == principal.tid, MitreMapping.technique_id == t.id)
            )
        )
        .scalars()
        .all()
    )
    objects: list[MappedObject] = []
    for m in rows:
        try:
            title, _ = await _resolve_object(session, principal, m.object_type, m.object_id)
        except (NotFound, AppError):
            title = "(deleted object)"
        objects.append(
            MappedObject(object_type=m.object_type, object_id=m.object_id, title=title, confidence=m.confidence)
        )
    ids = list(dict.fromkeys(e for m in rows for e in (m.evidence_event_ids or [])))[:500]
    docs = await _events_by_ids(_backend(request), principal.tid, ids)
    hosts = sorted({h for d in docs if (h := (d.get("host") or {}).get("hostname"))})
    users = sorted({u for d in docs if (u := (d.get("user") or {}).get("name"))})
    reasons: list[str] = []
    top = max((m.confidence for m in rows), key=lambda c: _RANK[c], default=None)
    critical_assets: list[str] = []
    if hosts:
        arows = await session.execute(
            select(Asset.display_name).where(
                Asset.tenant_id == principal.tid,
                Asset.type.in_(["host", "server"]),
                Asset.key.in_([h.lower() for h in hosts]),
                Asset.criticality.in_(["HIGH", "CRITICAL"]),
            )
        )
        critical_assets = [n for (n,) in arows.all()]
    risk: str = "LOW"
    if top == "HIGH" and (len(hosts) >= 2 or len(ids) >= 10 or critical_assets):
        risk = "HIGH"
        reasons.append("HIGH-confidence mapping exists")
        if len(hosts) >= 2:
            reasons.append(f"{len(hosts)} distinct hosts affected")
        if len(ids) >= 10:
            reasons.append(f"{len(ids)} distinct evidence events")
        if critical_assets:
            reasons.append(f"high-criticality asset(s) involved: {', '.join(critical_assets[:3])}")
    elif top in ("MEDIUM", "HIGH"):
        risk = "MEDIUM"
        reasons.append(f"{top}-confidence mapping exists but scope is limited (hosts={len(hosts)}, events={len(ids)})")
    elif rows:
        reasons.append("only LOW-confidence mappings")
    else:
        reasons.append("no mappings in this tenant")
    return TechniqueSummary(
        technique=_tech_out(t),
        mappings=len(rows),
        objects=objects,
        evidence_events=len(docs),
        hosts=NameCount(count=len(hosts), names=hosts[:20]),
        users=NameCount(count=len(users), names=users[:20]),
        risk=risk,
        risk_reasons=reasons,
    )
