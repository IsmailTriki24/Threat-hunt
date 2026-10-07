import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.cases import service as case_service
from app.cases import workflow
from app.cases.models import Case, CaseIoc
from app.core.config import Settings, get_settings
from app.core.crypto import encrypt_json
from app.core.db import get_session
from app.core.errors import AppError, Conflict, NotFound
from app.core.ratelimit import enforce
from app.events.search.base import SearchBackend
from app.intel import service, taxii, types
from app.intel.models import IntelEntity, IntelObservation, IntelProvider, IntelRelation
from app.intel.providers import PROVIDERS, TAXII_KEY
from app.intel.schemas import (
    BatchRequest,
    Coverage,
    EntityCreate,
    EntityDetail,
    EntityOut,
    EntityUpdate,
    LookupRequest,
    ObservationOut,
    ProviderIn,
    ProviderOut,
    RelationCreate,
    RelationOut,
)

router = APIRouter(prefix="/intel", tags=["intel"])
READ = Depends(require(Permission.INTEL_READ))
WRITE = Depends(require(Permission.INTEL_WRITE))
MANAGE = Depends(require(Permission.INTEL_MANAGE))
MAX_STIX_OBJECTS = 5000


def _out(e: IntelEntity) -> EntityOut:
    return EntityOut.model_validate(e, from_attributes=True)


async def _entity(session: AsyncSession, principal: Principal, entity_id: uuid.UUID) -> IntelEntity:
    e = (
        await session.execute(
            select(IntelEntity).where(IntelEntity.id == entity_id, IntelEntity.tenant_id == principal.tid)
        )
    ).scalar_one_or_none()
    if e is None:
        raise NotFound("Entity not found")
    return e


async def _detail(session: AsyncSession, entity: IntelEntity, coverage: Coverage | None = None) -> EntityDetail:
    await session.flush()
    await session.refresh(entity)  # server-side onupdate timestamps are expired after a flush
    obs = (
        (
            await session.execute(
                select(IntelObservation)
                .where(IntelObservation.entity_id == entity.id)
                .order_by(IntelObservation.provider)
            )
        )
        .scalars()
        .all()
    )
    rels = (
        (
            await session.execute(
                select(IntelRelation).where(
                    IntelRelation.tenant_id == entity.tenant_id,
                    (IntelRelation.src_id == entity.id) | (IntelRelation.dst_id == entity.id),
                )
            )
        )
        .scalars()
        .all()
    )
    out_rels: list[RelationOut] = []
    for r in rels:
        outgoing = r.src_id == entity.id
        other = await session.get(IntelEntity, r.dst_id if outgoing else r.src_id)
        if other is not None and other.tenant_id == entity.tenant_id:
            out_rels.append(
                RelationOut(
                    id=r.id, kind=r.kind, direction="out" if outgoing else "in", other=_out(other), source=r.source
                )
            )
    return EntityDetail(
        entity=_out(entity),
        score_breakdown=entity.score_breakdown,
        observations=[ObservationOut.model_validate(o, from_attributes=True) for o in obs],
        relations=out_rels,
        coverage=coverage,
    )


# ---- providers -----------------------------------------------------------------------------------------
@router.get("/providers", response_model=list[ProviderOut])
async def list_providers(
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[ProviderOut]:
    states = await service.provider_states(session, settings, principal.tid)
    out = [
        ProviderOut(
            key=k,
            display_name=st.provider.display_name,
            description=st.provider.description,
            supported_types=sorted(st.provider.supported_types),
            offline=st.provider.offline,
            secret_keys=st.provider.secret_keys,
            config_schema=st.provider.config_model.model_json_schema(),
            configured=st.configured,
            enabled=st.enabled and st.configured,
            last_status=st.row.last_status if st.row else "ok" if st.provider.offline else "unknown",
            last_detail=st.row.last_detail if st.row else "",
            last_checked_at=st.row.last_checked_at if st.row else None,
        )
        for k, st in states.items()
    ]
    row = (
        await session.execute(
            select(IntelProvider).where(IntelProvider.tenant_id == principal.tid, IntelProvider.provider == TAXII_KEY)
        )
    ).scalar_one_or_none()
    out.append(
        ProviderOut(
            key=TAXII_KEY,
            display_name="TAXII 2.1 feed",
            description="Pull STIX indicators from a TAXII collection into the watch-list.",
            supported_types=[],
            offline=False,
            secret_keys=["bearer"],
            config_schema=taxii.TaxiiConfig.model_json_schema(),
            configured=bool(row and row.config.get("url")),
            enabled=bool(row and row.enabled),
            last_status=row.last_status if row else "unknown",
            last_detail=row.last_detail if row else "",
            last_checked_at=row.last_checked_at if row else None,
        )
    )
    return out


@router.put("/providers/{key}", response_model=ProviderOut)
async def configure_provider(
    key: str,
    body: ProviderIn,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> ProviderOut:
    model = taxii.TaxiiConfig if key == TAXII_KEY else PROVIDERS[key].config_model if key in PROVIDERS else None
    if model is None or (key in PROVIDERS and PROVIDERS[key].offline):
        raise NotFound("Provider not found or not configurable")
    try:
        config = model.model_validate(body.config).model_dump(mode="json") if (body.config or key == TAXII_KEY) else {}
    except ValueError as exc:
        raise AppError(f"Invalid provider config: {str(exc)[:300]}") from None
    allowed = (
        set(PROVIDERS[key].secret_keys + PROVIDERS[key].optional_secrets)
        if key in PROVIDERS
        else {"bearer", "username", "password"}
    )
    if body.secrets is not None and not set(body.secrets) <= allowed:
        raise AppError(f"Unknown secret name(s); allowed: {', '.join(sorted(allowed))}")
    row = (
        await session.execute(
            select(IntelProvider).where(IntelProvider.tenant_id == principal.tid, IntelProvider.provider == key)
        )
    ).scalar_one_or_none()
    if row is None:
        row = IntelProvider(tenant_id=principal.tid, provider=key)
        session.add(row)
    row.enabled, row.config = body.enabled, config
    if body.secrets is not None:
        row.secrets_enc = encrypt_json(settings, body.secrets) if body.secrets else None
    await session.flush()
    await audit.record(
        request,
        "intel.provider.update",
        principal=principal,
        resource_type="intel_provider",
        resource_id=key,
        details={"enabled": body.enabled, "secrets_changed": body.secrets is not None},
    )
    return next(p for p in await list_providers(principal, session, settings) if p.key == key)


@router.post("/providers/{key}/test")
async def test_provider(
    key: str,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    await enforce(request, f"intel-test:{principal.tid}", 10, 60)
    states = await service.provider_states(session, settings, principal.tid)
    if key not in states:
        raise NotFound("Provider not found")
    st = states[key]
    if not st.configured:
        return {"ok": False, "detail": "not configured"}
    # A harmless well-known indicator exercises auth + connectivity without needing a real hit.
    probe = next(iter(sorted(st.provider.supported_types & {"domain", "ip", "sha256"})), None)
    sample = {
        "domain": "example.com",
        "ip": "93.184.216.34",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    ok, detail = True, "offline provider"
    if not st.provider.offline and probe:
        entity = IntelEntity(
            tenant_id=principal.tid, type=probe, value=sample[probe], tags=[], score_breakdown=[], notes=""
        )
        res = await service._run(st, entity, asyncio.Semaphore(1))  # noqa: SLF001
        ok, detail = res.status != "error", res.summary or res.status
    if st.row:
        st.row.last_status, st.row.last_detail, st.row.last_checked_at = (
            "ok" if ok else "down",
            detail[:300],
            datetime.now(UTC),
        )
    await audit.record(
        request,
        "intel.provider.test",
        principal=principal,
        resource_type="intel_provider",
        resource_id=key,
        details={"ok": ok},
    )
    return {"ok": ok, "detail": detail}


# ---- lookup & entities ---------------------------------------------------------------------------------
@router.post("/lookup", response_model=EntityDetail)
async def lookup(
    body: LookupRequest,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> EntityDetail:
    await enforce(request, f"intel-lookup:{principal.user_id}", 30, 60)
    type_ = body.type or types.detect_type(body.value)
    if type_ is None:
        raise AppError("Could not recognise the indicator type; specify it explicitly")
    if body.providers and not set(body.providers) <= set(PROVIDERS):
        raise AppError("Unknown provider key")
    entity = await service.upsert_entity(
        session, principal.tid, type_, body.value, source="lookup", user_id=principal.user_id
    )
    cov = (
        await service.enrich_many(session, settings, principal.tid, [entity], refresh=body.refresh, only=body.providers)
    ).get(entity.id)
    await audit.record(
        request,
        "intel.lookup",
        principal=principal,
        resource_type="intel_entity",
        resource_id=str(entity.id),
        details={"type": type_, "verdict": entity.verdict, "score": entity.score},
    )
    return await _detail(session, entity, cov)


@router.get("/entities", response_model=list[EntityOut])
async def list_entities(
    type: str | None = None,
    verdict: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> list[EntityOut]:
    stmt = select(IntelEntity).where(IntelEntity.tenant_id == principal.tid)
    if type:
        stmt = stmt.where(IntelEntity.type == type)
    if verdict:
        stmt = stmt.where(IntelEntity.verdict == verdict)
    if q:
        stmt = stmt.where(IntelEntity.value.icontains(q[:100], autoescape=True))
    rows = await session.execute(
        stmt.order_by(IntelEntity.score.desc(), IntelEntity.updated_at.desc())
        .limit(max(1, min(limit, 500)))
        .offset(max(0, offset))
    )
    return [_out(e) for e in rows.scalars()]


@router.post("/entities", response_model=EntityDetail, status_code=201)
async def create_entity(
    body: EntityCreate, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> EntityDetail:
    norm = types.normalize(body.type, body.value)
    if norm is None:
        raise AppError(f"Invalid {body.type} value")
    exists = (
        await session.execute(
            select(IntelEntity.id).where(
                IntelEntity.tenant_id == principal.tid, IntelEntity.type == body.type, IntelEntity.value == norm
            )
        )
    ).first()
    if exists:
        raise Conflict("Entity already exists")
    entity = await service.upsert_entity(
        session, principal.tid, body.type, norm, source="manual", user_id=principal.user_id
    )
    entity.watch_verdict, entity.watch_confidence, entity.notes, entity.tags = (
        body.watch_verdict,
        body.watch_confidence,
        body.notes,
        body.tags,
    )
    await service.rescore(session, entity)
    await audit.record(
        request, "intel.entity.create", principal=principal, resource_type="intel_entity", resource_id=str(entity.id)
    )
    return await _detail(session, entity)


@router.get("/entities/{entity_id}", response_model=EntityDetail)
async def get_entity(
    entity_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> EntityDetail:
    return await _detail(session, await _entity(session, principal, entity_id))


@router.patch("/entities/{entity_id}", response_model=EntityDetail)
async def update_entity(
    entity_id: uuid.UUID,
    body: EntityUpdate,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> EntityDetail:
    e = await _entity(session, principal, entity_id)
    if body.clear_watch:
        e.watch_verdict, e.watch_confidence = None, 0
    elif body.watch_verdict is not None:
        e.watch_verdict = body.watch_verdict
        e.watch_confidence = body.watch_confidence if body.watch_confidence is not None else (e.watch_confidence or 80)
    elif body.watch_confidence is not None:
        e.watch_confidence = body.watch_confidence
    if body.notes is not None:
        e.notes = body.notes
    if body.tags is not None:
        e.tags = body.tags
    await service.rescore(session, e)
    await audit.record(
        request,
        "intel.entity.update",
        principal=principal,
        resource_type="intel_entity",
        resource_id=str(e.id),
        details={"watch_verdict": e.watch_verdict, "verdict": e.verdict},
    )
    return await _detail(session, e)


@router.delete("/entities/{entity_id}", status_code=204)
async def delete_entity(
    entity_id: uuid.UUID, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> Response:
    e = await _entity(session, principal, entity_id)
    await session.delete(e)
    await audit.record(
        request, "intel.entity.delete", principal=principal, resource_type="intel_entity", resource_id=str(entity_id)
    )
    return Response(status_code=204)


@router.post("/entities/{entity_id}/enrich", response_model=EntityDetail)
async def enrich_entity(
    entity_id: uuid.UUID,
    request: Request,
    refresh: bool = False,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> EntityDetail:
    await enforce(request, f"intel-lookup:{principal.user_id}", 30, 60)
    e = await _entity(session, principal, entity_id)
    cov = (await service.enrich_many(session, settings, principal.tid, [e], refresh=refresh)).get(e.id)
    await audit.record(
        request,
        "intel.enrich",
        principal=principal,
        resource_type="intel_entity",
        resource_id=str(e.id),
        details={"verdict": e.verdict, "score": e.score},
    )
    return await _detail(session, e, cov)


@router.get("/entities/{entity_id}/sightings")
async def entity_sightings(
    entity_id: uuid.UUID,
    request: Request,
    days: int = 30,
    principal: Principal = Depends(require(Permission.EVENTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    e = await _entity(session, principal, entity_id)
    backend: SearchBackend = request.app.state.search
    return await service.sightings(backend, principal.tid, e, max(1, min(days, 90)))


@router.post("/entities/{entity_id}/relations", status_code=201)
async def add_relation(
    entity_id: uuid.UUID,
    body: RelationCreate,
    request: Request,
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    src = await _entity(session, principal, entity_id)
    dst = await _entity(session, principal, body.dst_id)  # both ends must belong to the caller's tenant
    if src.id == dst.id:
        raise AppError("An entity cannot relate to itself")
    session.add(IntelRelation(tenant_id=principal.tid, src_id=src.id, dst_id=dst.id, kind=body.kind, source="manual"))
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("Relation already exists") from None
    await audit.record(
        request, "intel.relation.add", principal=principal, resource_type="intel_entity", resource_id=str(src.id)
    )
    return {"status": "created"}


@router.delete("/relations/{relation_id}", status_code=204)
async def delete_relation(
    relation_id: uuid.UUID, request: Request, principal: Principal = WRITE, session: AsyncSession = Depends(get_session)
) -> Response:
    rel = (
        await session.execute(
            select(IntelRelation).where(IntelRelation.id == relation_id, IntelRelation.tenant_id == principal.tid)
        )
    ).scalar_one_or_none()
    if rel is None:
        raise NotFound("Relation not found")
    await session.delete(rel)
    await audit.record(
        request,
        "intel.relation.delete",
        principal=principal,
        resource_type="intel_relation",
        resource_id=str(relation_id),
    )
    return Response(status_code=204)


@router.post("/lookup-batch")
async def lookup_batch(
    body: BatchRequest, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> list[dict[str, Any]]:
    """Cached verdicts only — never triggers outbound calls — so UIs can badge lists of indicators cheaply."""
    out = []
    for item in body.items:
        norm = types.normalize(item.type, item.value)
        e = (
            (
                await session.execute(
                    select(IntelEntity).where(
                        IntelEntity.tenant_id == principal.tid, IntelEntity.type == item.type, IntelEntity.value == norm
                    )
                )
            ).scalar_one_or_none()
            if norm
            else None
        )
        out.append(
            {
                "type": item.type,
                "value": item.value,
                "entity_id": str(e.id) if e else None,
                "verdict": e.verdict if e else None,
                "score": e.score if e else None,
            }
        )
    return out


@router.post("/enrich-case/{case_id}")
async def enrich_case(
    case_id: uuid.UUID,
    request: Request,
    refresh: bool = False,
    principal: Principal = Depends(require(Permission.INTEL_WRITE)),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if not principal.has(Permission.CASES_READ):
        raise NotFound("Case not found")
    await enforce(request, f"intel-case:{principal.user_id}", 6, 60)
    case = (
        await session.execute(select(Case).where(Case.id == case_id, Case.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if case is None:
        raise NotFound("Case not found")
    iocs = (await session.execute(select(CaseIoc).where(CaseIoc.case_id == case.id).limit(50))).scalars().all()
    entities = [
        await service.upsert_entity(session, principal.tid, i.type, i.value, source="case", user_id=principal.user_id)
        for i in iocs
    ]
    await service.enrich_many(session, settings, principal.tid, entities, refresh=refresh)
    summary = [
        {"type": e.type, "value": e.value, "verdict": e.verdict, "score": e.score, "entity_id": str(e.id)}
        for e in entities
    ]
    bad = sum(1 for e in entities if e.verdict == "malicious")
    if not workflow.is_locked(case.status):
        await case_service.log(
            session, principal, case, "iocs_enriched", details={"checked": len(entities), "malicious": bad}
        )
    await audit.record(
        request,
        "intel.enrich_case",
        principal=principal,
        resource_type="case",
        resource_id=str(case.id),
        details={"checked": len(entities), "malicious": bad},
    )
    return {"checked": len(entities), "malicious": bad, "results": summary}


# ---- STIX / TAXII ----------------------------------------------------------------------------------------
@router.post("/import/stix")
async def import_stix(
    request: Request,
    bundle: dict[str, Any] = Body(...),
    principal: Principal = WRITE,
    session: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    objects = bundle.get("objects")
    if bundle.get("type") != "bundle" or not isinstance(objects, list):
        raise AppError("Body must be a STIX 2.x bundle with an 'objects' list")
    if len(objects) > MAX_STIX_OBJECTS:
        raise AppError(f"Bundle too large (max {MAX_STIX_OBJECTS} objects)")
    result = await service.import_stix(session, principal.tid, principal.user_id, objects, "stix-import")
    await audit.record(request, "intel.import.stix", principal=principal, details=result)
    return result


@router.post("/taxii/pull")
async def taxii_pull(
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, int]:
    await enforce(request, f"taxii:{principal.tid}", 3, 60)
    row = (
        await session.execute(
            select(IntelProvider).where(IntelProvider.tenant_id == principal.tid, IntelProvider.provider == TAXII_KEY)
        )
    ).scalar_one_or_none()
    if row is None or not row.enabled or not row.config.get("url"):
        raise AppError("Configure the TAXII feed first")
    from app.core.crypto import decrypt_json
    from app.core.ssrf import SsrfError

    try:
        objects = await taxii.pull(row.config, {k: str(v) for k, v in decrypt_json(settings, row.secrets_enc).items()})
    except (SsrfError, ValueError) as exc:
        row.last_status, row.last_detail, row.last_checked_at = "down", str(exc)[:300], datetime.now(UTC)
        await session.commit()  # keep the failure visible even though the request errors out
        raise AppError(f"TAXII pull failed: {str(exc)[:200]}") from None
    except Exception as exc:  # network errors etc.
        row.last_status, row.last_detail, row.last_checked_at = "down", type(exc).__name__, datetime.now(UTC)
        await session.commit()
        raise AppError(f"TAXII pull failed ({type(exc).__name__})") from None
    result = await service.import_stix(session, principal.tid, principal.user_id, objects, "taxii")
    row.last_status, row.last_detail, row.last_checked_at = (
        "ok",
        f"imported {result['created']} new, {result['updated']} updated"[:300],
        datetime.now(UTC),
    )
    await audit.record(request, "intel.taxii.pull", principal=principal, details=result)
    return result


__all__ = ["func", "router"]
