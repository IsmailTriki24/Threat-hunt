import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from sqlalchemy import String, case, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.cases.models import Case
from app.core.config import Settings, get_settings
from app.core.crypto import decrypt_json, encrypt_json
from app.core.db import get_session
from app.core.errors import AppError, Conflict, NotFound
from app.core.ratelimit import enforce
from app.events.search.query import EventQuery
from app.intel import types as intel_types
from app.iochunt import ingest, ioa_catalog, runner
from app.iochunt import threats as threat_svc
from app.iochunt.feeds import registry
from app.iochunt.models import Ioc, IocAllow, IocFeed, IocHunt, IocMatch, SignalMatch, Threat, ThreatIoa, ThreatTtp
from app.iochunt.schemas import (
    AllowIn,
    AllowOut,
    Bulletin,
    FeedCreate,
    FeedOut,
    FeedTypeOut,
    FeedUpdate,
    HuntDetail,
    HuntOut,
    IoaCreate,
    IoaOut,
    IocOut,
    IocPage,
    ManualIoc,
    MatchOut,
    Overview,
    RejectIn,
    SecretValue,
    SignalMatchOut,
    ThreatPage,
    ThreatReject,
    ThreatRow,
    ThreatValidate,
    TtpCreate,
    TtpOut,
    ValidateIn,
)
from app.mitre.models import MitreTechnique

router = APIRouter(prefix="/ioc", tags=["ioc-hunting"])
READ = Depends(require(Permission.IOCHUNT_READ))
VALIDATE = Depends(require(Permission.IOCHUNT_VALIDATE))
MANAGE = Depends(require(Permission.IOCHUNT_MANAGE))


def _validate_feed_config(feed_type: str, config: dict[str, Any]) -> None:
    try:
        registry.build(feed_type, config)
    except KeyError:
        raise AppError(f"Unknown feed type '{feed_type}'") from None
    except ValueError as exc:
        raise AppError(f"Invalid feed configuration: {str(exc).splitlines()[0][:200]}") from None


def _feed_out(feed: IocFeed, settings: Settings, count: int = 0) -> FeedOut:
    keys = sorted(decrypt_json(settings, feed.secrets_enc)) if feed.secrets_enc else []
    return FeedOut(
        id=feed.id,
        name=feed.name,
        feed_type=feed.feed_type,
        config=feed.config,
        has_secrets=bool(keys),
        secret_keys=keys,
        enabled=feed.enabled,
        interval_minutes=feed.interval_minutes,
        max_age_days=feed.max_age_days,
        min_confidence=feed.min_confidence,
        max_items=feed.max_items,
        last_run_at=feed.last_run_at,
        last_status=feed.last_status,
        last_detail=feed.last_detail,
        last_new=feed.last_new,
        last_seen_total=feed.last_seen_total,
        ioc_count=count,
    )


async def _feed(session: AsyncSession, principal: Principal, feed_id: uuid.UUID) -> IocFeed:
    feed = (
        await session.execute(select(IocFeed).where(IocFeed.id == feed_id, IocFeed.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if feed is None:
        raise NotFound("Feed not found")
    return feed


# ---- feeds -------------------------------------------------------------------------------------------
@router.get("/feed-types", response_model=list[FeedTypeOut])
async def feed_types(_: Principal = READ) -> list[FeedTypeOut]:
    return [
        FeedTypeOut(
            type=c.feed_type,
            name=c.display_name,
            description=c.description,
            needs_secret=c.needs_secret,
            secret_names=c.secret_names,
            config_schema=c.config_model.model_json_schema(),
        )
        for c in registry.FEEDS.values()
    ]


@router.get("/feeds", response_model=list[FeedOut])
async def list_feeds(
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[FeedOut]:
    feeds = (
        (await session.execute(select(IocFeed).where(IocFeed.tenant_id == principal.tid).order_by(IocFeed.name)))
        .scalars()
        .all()
    )
    counts = dict(
        (
            await session.execute(
                select(Ioc.feed_id, func.count()).where(Ioc.tenant_id == principal.tid).group_by(Ioc.feed_id)
            )
        ).all()
    )
    return [_feed_out(f, settings, counts.get(f.id, 0)) for f in feeds]


@router.post("/feeds", response_model=FeedOut, status_code=201)
async def create_feed(
    body: FeedCreate,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> FeedOut:
    _validate_feed_config(body.feed_type, body.config)
    feed = IocFeed(
        tenant_id=principal.tid,
        name=body.name,
        feed_type=body.feed_type,
        config=body.config,
        secrets_enc=encrypt_json(settings, dict(body.secrets)) if body.secrets else None,
        enabled=body.enabled,
        interval_minutes=body.interval_minutes,
        max_age_days=body.max_age_days,
        min_confidence=body.min_confidence,
        max_items=body.max_items,
    )
    session.add(feed)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("A feed with this name already exists") from None
    await audit.record(
        request,
        "iocfeed.create",
        principal=principal,
        resource_type="ioc_feed",
        resource_id=str(feed.id),
        details={"type": body.feed_type},
    )
    return _feed_out(feed, settings)


@router.patch("/feeds/{feed_id}", response_model=FeedOut)
async def update_feed(
    feed_id: uuid.UUID,
    body: FeedUpdate,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> FeedOut:
    feed = await _feed(session, principal, feed_id)
    if body.config is not None:
        _validate_feed_config(feed.feed_type, body.config)
        feed.config = body.config
    for attr in ("name", "enabled", "interval_minutes", "max_age_days", "min_confidence", "max_items"):
        v = getattr(body, attr)
        if v is not None:
            setattr(feed, attr, v)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("A feed with this name already exists") from None
    await audit.record(
        request,
        "iocfeed.update",
        principal=principal,
        resource_type="ioc_feed",
        resource_id=str(feed.id),
        details={"fields": sorted(body.model_dump(exclude_none=True))},
    )
    return _feed_out(feed, settings)


@router.put("/feeds/{feed_id}/secrets/{name}", status_code=204)
async def set_feed_secret(
    feed_id: uuid.UUID,
    name: Annotated[str, Path(pattern=r"^[A-Za-z0-9_.-]{1,64}$")],
    body: SecretValue,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Response:
    feed = await _feed(session, principal, feed_id)
    current = {k: str(v) for k, v in decrypt_json(settings, feed.secrets_enc).items()} if feed.secrets_enc else {}
    current[name] = body.value
    feed.secrets_enc = encrypt_json(settings, current)
    await audit.record(
        request,
        "iocfeed.secret_set",
        principal=principal,
        resource_type="ioc_feed",
        resource_id=str(feed.id),
        details={"name": name},
    )
    return Response(status_code=204)


@router.delete("/feeds/{feed_id}", status_code=204)
async def delete_feed(
    feed_id: uuid.UUID, request: Request, principal: Principal = MANAGE, session: AsyncSession = Depends(get_session)
) -> Response:
    feed = await _feed(session, principal, feed_id)
    await session.delete(feed)  # imported indicators are kept (feed_id is set to NULL)
    await audit.record(
        request, "iocfeed.delete", principal=principal, resource_type="ioc_feed", resource_id=str(feed_id)
    )
    return Response(status_code=204)


@router.post("/feeds/{feed_id}/run", response_model=FeedOut)
async def run_feed_now(
    feed_id: uuid.UUID,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> FeedOut:
    await enforce(request, f"iocfeed-run:{principal.tid}", 10, 60)
    feed = await _feed(session, principal, feed_id)
    await ingest.run_feed(session, settings, feed)
    await ingest.prescreen(session, request.app.state.search, principal.tid)
    await audit.record(
        request,
        "iocfeed.run",
        principal=principal,
        resource_type="ioc_feed",
        resource_id=str(feed.id),
        details={"status": feed.last_status},
    )
    return _feed_out(feed, settings)


# ---- IOC database -------------------------------------------------------------------------------------
@router.get("/iocs", response_model=IocPage)
async def list_iocs(
    status: str | None = None,
    type: str | None = None,  # noqa: A002
    source: str | None = None,
    min_confidence: int = Query(default=0, ge=0, le=100),
    seen: bool | None = None,
    q: str | None = Query(default=None, max_length=200),
    max_age_days: int | None = Query(default=None, ge=1, le=365),
    sort: str = Query(default="priority", pattern="^(priority|confidence|recent)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100_000),
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> IocPage:
    base = [Ioc.tenant_id == principal.tid]
    where = list(base)
    if status:
        where.append(Ioc.status == status.upper())
    if type:
        where.append(Ioc.type == type.lower())
    if source:
        where.append(Ioc.source == source)
    if min_confidence:
        where.append(Ioc.confidence >= min_confidence)
    if seen is True:
        where.append(Ioc.seen_count > 0)
    if seen is False:
        where.append(Ioc.seen_count == 0)
    if q:
        where.append(
            or_(
                Ioc.value.ilike(f"%{q.strip()}%"),
                Ioc.malware.ilike(f"%{q.strip()}%"),
                Ioc.description.ilike(f"%{q.strip()}%"),
            )
        )
    if max_age_days:
        where.append(Ioc.last_seen >= datetime.now(UTC) - timedelta(days=max_age_days))
    total = (await session.execute(select(func.count()).select_from(Ioc).where(*where))).scalar_one()
    order = {
        "priority": (Ioc.seen_count.desc(), Ioc.confidence.desc(), Ioc.last_seen.desc()),
        "confidence": (Ioc.confidence.desc(), Ioc.last_seen.desc()),
        "recent": (Ioc.last_seen.desc(),),
    }[sort]
    rows = (
        (await session.execute(select(Ioc).where(*where).order_by(*order).limit(limit).offset(offset))).scalars().all()
    )
    facets: dict[str, dict[str, int]] = {}
    for name, col in (("status", Ioc.status), ("type", Ioc.type), ("source", Ioc.source)):
        facets[name] = {
            str(k): v for k, v in (await session.execute(select(col, func.count()).where(*base).group_by(col))).all()
        }
    return IocPage(total=total, items=[IocOut.model_validate(r) for r in rows], facets=facets)


@router.post("/iocs", response_model=IocOut, status_code=201)
async def add_ioc(
    body: ManualIoc, request: Request, principal: Principal = VALIDATE, session: AsyncSession = Depends(get_session)
) -> IocOut:
    value = ingest.refang(body.value)
    norm = intel_types.normalize(body.type, value)
    if norm is None:
        raise AppError(f"'{body.value[:80]}' is not a valid {body.type}")
    allow = await ingest.allow_pairs(session, principal.tid)
    why = ingest.rejected_reason(body.type, norm, allow)
    if why:
        raise AppError(f"Not accepted: {why}")
    now = datetime.now(UTC)
    existing = (
        await session.execute(
            select(Ioc).where(Ioc.tenant_id == principal.tid, Ioc.type == body.type, Ioc.value == norm)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise Conflict("This indicator is already in the database")
    ioc = Ioc(
        tenant_id=principal.tid,
        source="manual",
        type=body.type,
        value=norm,
        confidence=body.confidence,
        first_seen=now,
        last_seen=now,
        valid_until=now + timedelta(days=body.valid_days),
        threat_type=body.threat_type,
        description=body.description,
        tags=["manual", *body.tags],
        status="NEW",
    )
    session.add(ioc)
    await session.flush()
    await session.refresh(ioc)
    await audit.record(
        request,
        "ioc.add",
        principal=principal,
        resource_type="ioc",
        resource_id=str(ioc.id),
        details={"type": body.type},
    )
    return IocOut.model_validate(ioc)


async def _iocs_for(session: AsyncSession, principal: Principal, ids: list[uuid.UUID]) -> list[Ioc]:
    rows = list((await session.execute(select(Ioc).where(Ioc.tenant_id == principal.tid, Ioc.id.in_(ids)))).scalars())
    if len(rows) != len(set(ids)):
        raise NotFound("One or more indicators were not found")
    return rows


@router.post("/iocs/validate", response_model=HuntOut, status_code=201)
async def validate_iocs(
    body: ValidateIn, request: Request, principal: Principal = VALIDATE, session: AsyncSession = Depends(get_session)
) -> HuntOut:
    """Approve indicators and launch the automatic hunt. The hunt runs in the worker within about a minute and opens the case itself."""
    await enforce(request, f"ioc-validate:{principal.tid}", 20, 60)
    rows = await _iocs_for(session, principal, body.ioc_ids)
    bad = [r for r in rows if r.status == "EXPIRED"]
    if bad:
        raise Conflict(f"{len(bad)} selected indicator(s) have expired; remove them from the selection")
    now = datetime.now(UTC)
    for r in rows:
        r.status, r.status_reason, r.validated_by, r.validated_at = (
            "VALIDATED",
            "approved for hunting",
            principal.user_id,
            now,
        )
    hunt = await runner.create_hunt(
        session, principal.tid, principal.user_id, rows, name=body.name, lookback_days=body.lookback_days
    )
    await audit.record(
        request,
        "ioc.validate",
        principal=principal,
        resource_type="ioc_hunt",
        resource_id=str(hunt.id),
        details={"iocs": len(rows), "lookback_days": body.lookback_days},
    )
    return _hunt_out(hunt, None)


@router.post("/iocs/reject", status_code=200)
async def reject_iocs(
    body: RejectIn, request: Request, principal: Principal = VALIDATE, session: AsyncSession = Depends(get_session)
) -> dict[str, int]:
    rows = await _iocs_for(session, principal, body.ioc_ids)
    n = 0
    for r in rows:
        if r.status in ("NEW", "EXPIRED"):
            r.status, r.status_reason = "REJECTED", (body.reason or "rejected by an analyst")[:300]
            n += 1
    await audit.record(request, "ioc.reject", principal=principal, resource_type="ioc", details={"count": n})
    return {"rejected": n}


# ---- allow-list ---------------------------------------------------------------------------------------
@router.get("/allowlist", response_model=list[AllowOut])
async def list_allow(principal: Principal = READ, session: AsyncSession = Depends(get_session)) -> list[AllowOut]:
    rows = (
        (
            await session.execute(
                select(IocAllow).where(IocAllow.tenant_id == principal.tid).order_by(IocAllow.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [AllowOut.model_validate(r) for r in rows]


@router.post("/allowlist", response_model=AllowOut, status_code=201)
async def add_allow(
    body: AllowIn, request: Request, principal: Principal = MANAGE, session: AsyncSession = Depends(get_session)
) -> AllowOut:
    norm = intel_types.normalize(body.type, ingest.refang(body.value))
    if norm is None:
        raise AppError(f"'{body.value[:80]}' is not a valid {body.type}")
    row = IocAllow(
        tenant_id=principal.tid, type=body.type, value=norm, reason=body.reason, created_by=principal.user_id
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("Already allow-listed") from None
    # anything already queued that this entry covers is retired from the queue
    for ioc in (
        await session.execute(select(Ioc).where(Ioc.tenant_id == principal.tid, Ioc.status == "NEW"))
    ).scalars():
        if ingest.rejected_reason(ioc.type, ioc.value, [(row.type, row.value)]):
            ioc.status, ioc.status_reason = "REJECTED", "allow-listed"
    await session.refresh(row)
    await audit.record(request, "ioc.allow", principal=principal, resource_type="ioc_allow", resource_id=str(row.id))
    return AllowOut.model_validate(row)


@router.delete("/allowlist/{allow_id}", status_code=204)
async def delete_allow(
    allow_id: uuid.UUID, request: Request, principal: Principal = MANAGE, session: AsyncSession = Depends(get_session)
) -> Response:
    row = (
        await session.execute(select(IocAllow).where(IocAllow.id == allow_id, IocAllow.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if row is None:
        raise NotFound("Entry not found")
    await session.delete(row)
    await audit.record(
        request, "ioc.allow_remove", principal=principal, resource_type="ioc_allow", resource_id=str(allow_id)
    )
    return Response(status_code=204)


# ---- hunts --------------------------------------------------------------------------------------------
def _hunt_out(h: IocHunt, case: Case | None, threat_name: str | None = None) -> HuntOut:
    out = HuntOut.model_validate(h)
    out.ioc_count = len(h.ioc_ids)
    out.threat_name = threat_name
    if case is not None:
        out.case_number, out.case_status = case.number, case.status
    return out


@router.get("/hunts", response_model=list[HuntOut])
async def list_hunts(
    limit: int = Query(default=50, ge=1, le=200),
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> list[HuntOut]:
    rows = (
        (
            await session.execute(
                select(IocHunt)
                .where(IocHunt.tenant_id == principal.tid)
                .order_by(IocHunt.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    cases = {
        c.id: c
        for c in (
            await session.execute(
                select(Case).where(Case.id.in_([r.case_id for r in rows if r.case_id] or [uuid.UUID(int=0)]))
            )
        ).scalars()
    }
    names = {
        t.id: t.name
        for t in (
            await session.execute(
                select(Threat).where(Threat.id.in_([r.threat_id for r in rows if r.threat_id] or [uuid.UUID(int=0)]))
            )
        ).scalars()
    }
    return [
        _hunt_out(r, cases.get(r.case_id) if r.case_id else None, names.get(r.threat_id) if r.threat_id else None)
        for r in rows
    ]


@router.get("/hunts/{hunt_id}", response_model=HuntDetail)
async def get_hunt(
    hunt_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> HuntDetail:
    h = (
        await session.execute(select(IocHunt).where(IocHunt.id == hunt_id, IocHunt.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if h is None:
        raise NotFound("Hunt not found")
    case = await session.get(Case, h.case_id) if h.case_id else None
    rows = (
        await session.execute(
            select(IocMatch, Ioc.value, Ioc.type)
            .join(Ioc, Ioc.id == IocMatch.ioc_id)
            .where(IocMatch.hunt_id == h.id)
            .order_by(IocMatch.event_timestamp.desc())
            .limit(500)
        )
    ).all()
    matches = []
    for m, value, typ in rows:
        mo = MatchOut.model_validate(m)
        mo.ioc_value, mo.ioc_type = value, typ
        matches.append(mo)
    tname = (
        (await session.execute(select(Threat.name).where(Threat.id == h.threat_id))).scalar_one_or_none()
        if h.threat_id
        else None
    )
    sigs = (
        (
            await session.execute(
                select(SignalMatch)
                .where(SignalMatch.hunt_id == h.id)
                .order_by(SignalMatch.event_timestamp.desc())
                .limit(500)
            )
        )
        .scalars()
        .all()
    )
    detail = HuntDetail.model_validate(
        {
            **_hunt_out(h, case, tname).model_dump(),
            "matches": matches,
            "signal_matches": [SignalMatchOut.model_validate(x) for x in sigs],
        }
    )
    return detail


@router.post("/hunts/{hunt_id}/retry", response_model=HuntOut)
async def retry_hunt(
    hunt_id: uuid.UUID, request: Request, principal: Principal = VALIDATE, session: AsyncSession = Depends(get_session)
) -> HuntOut:
    h = (
        await session.execute(select(IocHunt).where(IocHunt.id == hunt_id, IocHunt.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if h is None:
        raise NotFound("Hunt not found")
    if h.status not in ("FAILED", "PARTIAL"):
        raise Conflict("Only failed or partial hunts can be retried")
    await session.execute(
        update(IocHunt).where(IocHunt.id == h.id).values(status="PENDING", error="", finished_at=None)
    )
    await session.refresh(h)
    await audit.record(request, "ioc.hunt_retry", principal=principal, resource_type="ioc_hunt", resource_id=str(h.id))
    return _hunt_out(h, None)


@router.get("/overview", response_model=Overview)
async def overview(principal: Principal = READ, session: AsyncSession = Depends(get_session)) -> Overview:
    t = principal.tid
    by_status = {
        str(k): v
        for k, v in (
            await session.execute(select(Ioc.status, func.count()).where(Ioc.tenant_id == t).group_by(Ioc.status))
        ).all()
    }
    new_24h = (
        await session.execute(
            select(func.count())
            .select_from(Ioc)
            .where(Ioc.tenant_id == t, Ioc.created_at >= datetime.now(UTC) - timedelta(hours=24))
        )
    ).scalar_one()
    seen = (
        await session.execute(
            select(func.count()).select_from(Ioc).where(Ioc.tenant_id == t, Ioc.status == "NEW", Ioc.seen_count > 0)
        )
    ).scalar_one()
    feeds = (
        await session.execute(
            select(func.count(), func.count().filter(IocFeed.last_status == "error")).where(
                IocFeed.tenant_id == t, IocFeed.enabled.is_(True)
            )
        )
    ).one()
    hunts = {
        str(k): v
        for k, v in (
            await session.execute(
                select(IocHunt.status, func.count()).where(IocHunt.tenant_id == t).group_by(IocHunt.status)
            )
        ).all()
    }
    open_cases = (
        await session.execute(
            select(func.count(func.distinct(IocHunt.case_id)))
            .select_from(IocHunt)
            .join(Case, Case.id == IocHunt.case_id)
            .where(IocHunt.tenant_id == t, Case.status != "CLOSED")
        )
    ).scalar_one()
    return Overview(
        iocs_by_status=by_status,
        new_last_24h=new_24h,
        seen_in_environment=seen,
        feeds=feeds[0],
        feeds_failing=feeds[1],
        hunts_by_status=hunts,
        open_ioc_cases=open_cases,
    )


# ---- threats (bulletins) ------------------------------------------------------------------------------------
async def _row(
    session: AsyncSession,
    th: Threat,
    counts: dict[str, dict[uuid.UUID, int]] | None = None,
    cases: dict[uuid.UUID, Case] | None = None,
) -> ThreatRow:
    c = counts or {}
    case = (cases or {}).get(th.case_id) if th.case_id else None
    return ThreatRow(
        id=th.id,
        name=th.name,
        kind=th.kind,
        aliases=th.aliases,
        mitre_id=th.mitre_id,
        severity=th.severity,
        confidence=th.confidence,
        status=th.status,
        first_seen=th.first_seen,
        last_updated=th.last_updated,
        ioc_count=th.ioc_count,
        ioc_types=th.ioc_types,
        new_ioc_count=c.get("new", {}).get(th.id, 0),
        ioa_count=c.get("ioa", {}).get(th.id, 0),
        ttp_count=c.get("ttp", {}).get(th.id, 0),
        seen_count=th.seen_count,
        sources=th.sources,
        case_id=th.case_id,
        case_number=case.number if case else None,
        case_status=case.status if case else None,
        last_hunted_at=th.last_hunted_at,
    )


async def _counts(session: AsyncSession, ids: list[uuid.UUID]) -> dict[str, dict[uuid.UUID, int]]:
    if not ids:
        return {}

    async def grouped(col: Any, *where: Any) -> dict[uuid.UUID, int]:
        rows = (await session.execute(select(col, func.count()).where(*where).group_by(col))).all()
        return {k: n for k, n in rows if k is not None}

    return {
        "new": await grouped(Ioc.threat_id, Ioc.threat_id.in_(ids), Ioc.status == "NEW"),
        "ioa": await grouped(ThreatIoa.threat_id, ThreatIoa.threat_id.in_(ids)),
        "ttp": await grouped(ThreatTtp.threat_id, ThreatTtp.threat_id.in_(ids)),
    }


_SEVERITY_RANK = case({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}, value=Threat.severity, else_=0)


@router.get("/threats", response_model=ThreatPage)
async def list_threats(
    status: str | None = None,
    kind: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    min_confidence: int = Query(default=0, ge=0, le=100),
    seen: bool | None = None,
    sort: str = Query(default="updated", pattern="^(updated|confidence|iocs|seen|name)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100_000),
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> ThreatPage:
    base = [Threat.tenant_id == principal.tid, Threat.ioc_count > 0]
    where = list(base)
    if status:
        where.append(Threat.status == status.upper())
    if kind:
        where.append(Threat.kind == kind.lower())
    if min_confidence:
        where.append(Threat.confidence >= min_confidence)
    if seen is True:
        where.append(Threat.seen_count > 0)
    if q:
        needle = f"%{q.strip()}%"
        where.append(
            or_(Threat.name.ilike(needle), Threat.description.ilike(needle), Threat.aliases.cast(String).ilike(needle))
        )
    total = (await session.execute(select(func.count()).select_from(Threat).where(*where))).scalar_one()
    order = {
        "updated": (
            Threat.seen_count.desc(),
            _SEVERITY_RANK.desc(),
            Threat.confidence.desc(),
            Threat.last_updated.desc().nullslast(),
        ),
        "confidence": (Threat.confidence.desc(), Threat.last_updated.desc().nullslast()),
        "iocs": (Threat.ioc_count.desc(),),
        "seen": (Threat.seen_count.desc(), Threat.confidence.desc()),
        "name": (Threat.name.asc(),),
    }[sort]
    rows = (
        (await session.execute(select(Threat).where(*where).order_by(*order).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    counts = await _counts(session, [r.id for r in rows])
    cases = {
        c.id: c
        for c in (
            await session.execute(
                select(Case).where(Case.id.in_([r.case_id for r in rows if r.case_id] or [uuid.UUID(int=0)]))
            )
        ).scalars()
    }
    facets = {
        name: {
            str(k): v for k, v in (await session.execute(select(col, func.count()).where(*base).group_by(col))).all()
        }
        for name, col in (("status", Threat.status), ("kind", Threat.kind))
    }
    return ThreatPage(total=total, items=[await _row(session, r, counts, cases) for r in rows], facets=facets)


async def _threat(session: AsyncSession, principal: Principal, threat_id: uuid.UUID) -> Threat:
    th = (
        await session.execute(select(Threat).where(Threat.id == threat_id, Threat.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if th is None:
        raise NotFound("Threat not found")
    return th


@router.get("/threats/{threat_id}", response_model=Bulletin)
async def get_bulletin(
    threat_id: uuid.UUID, principal: Principal = READ, session: AsyncSession = Depends(get_session)
) -> Bulletin:
    th = await _threat(session, principal, threat_id)
    counts = await _counts(session, [th.id])
    case = await session.get(Case, th.case_id) if th.case_id else None
    row = await _row(session, th, counts, {case.id: case} if case else {})
    ttp_rows = (await session.execute(select(ThreatTtp).where(ThreatTtp.threat_id == th.id))).scalars().all()
    tech = {
        t.id: t
        for t in (
            await session.execute(
                select(MitreTechnique).where(MitreTechnique.id.in_([t.technique_id for t in ttp_rows] or ["-"]))
            )
        ).scalars()
    }
    ttps = [
        TtpOut(
            technique_id=t.technique_id,
            name=tech[t.technique_id].name if t.technique_id in tech else "",
            tactics=tech[t.technique_id].tactics if t.technique_id in tech else [],
            url=tech[t.technique_id].url if t.technique_id in tech else "",
            source=t.source,
            confidence=t.confidence,
            note=t.note,
        )
        for t in sorted(ttp_rows, key=lambda x: (-threat_svc.TTP_RANK.get(x.source, 0), x.technique_id))
    ]
    ioas = [
        IoaOut.model_validate(i)
        for i in (
            await session.execute(
                select(ThreatIoa).where(ThreatIoa.threat_id == th.id).order_by(ThreatIoa.technique_id, ThreatIoa.name)
            )
        ).scalars()
    ]
    iocs = (
        (
            await session.execute(
                select(Ioc)
                .where(Ioc.threat_id == th.id, Ioc.status != "EXPIRED")
                .order_by(Ioc.seen_count.desc(), Ioc.confidence.desc(), Ioc.last_seen.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    hunts = (
        (
            await session.execute(
                select(IocHunt).where(IocHunt.threat_id == th.id).order_by(IocHunt.created_at.desc()).limit(10)
            )
        )
        .scalars()
        .all()
    )
    return Bulletin(
        **row.model_dump(),
        description=th.description,
        references=th.references,
        status_reason=th.status_reason,
        ttps=ttps,
        ioas=ioas,
        iocs=[IocOut.model_validate(i) for i in iocs],
        hunts=[_hunt_out(h, None, th.name) for h in hunts],
    )


@router.get("/threats/{threat_id}/iocs", response_model=IocPage)
async def threat_iocs(
    threat_id: uuid.UUID,
    type: str | None = None,
    status: str | None = None,  # noqa: A002
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100_000),
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
) -> IocPage:
    th = await _threat(session, principal, threat_id)
    where = [Ioc.threat_id == th.id]
    where.append(Ioc.status == status.upper() if status else Ioc.status != "EXPIRED")
    if type:
        where.append(Ioc.type == type.lower())
    total = (await session.execute(select(func.count()).select_from(Ioc).where(*where))).scalar_one()
    rows = (
        (
            await session.execute(
                select(Ioc)
                .where(*where)
                .order_by(Ioc.seen_count.desc(), Ioc.confidence.desc(), Ioc.last_seen.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return IocPage(total=total, items=[IocOut.model_validate(r) for r in rows], facets={})


@router.post("/threats/{threat_id}/validate", response_model=HuntOut, status_code=201)
async def validate_threat(
    threat_id: uuid.UUID,
    body: ThreatValidate,
    request: Request,
    principal: Principal = VALIDATE,
    session: AsyncSession = Depends(get_session),
) -> HuntOut:
    """Validate a whole bulletin: its indicators, behaviours and techniques are hunted together in every source, then the case is built."""
    await enforce(request, f"ioc-validate:{principal.tid}", 20, 60)
    th = await _threat(session, principal, threat_id)
    if (
        await session.execute(
            select(IocHunt.id).where(IocHunt.threat_id == th.id, IocHunt.status.in_(("PENDING", "RUNNING")))
        )
    ).first():
        raise Conflict("A hunt for this threat is already in progress")
    excluded = set(body.exclude_ioc_ids)
    candidates = list(
        (
            await session.execute(
                select(Ioc)
                .where(
                    Ioc.threat_id == th.id,
                    Ioc.status.in_(("NEW", "REJECTED")),
                    Ioc.id.notin_(excluded or {uuid.UUID(int=0)}),
                )
                .order_by(Ioc.seen_count.desc(), Ioc.confidence.desc(), Ioc.last_seen.desc())
            )
        ).scalars()
    )
    ioas = (
        list(
            (
                await session.execute(
                    select(ThreatIoa).where(
                        ThreatIoa.threat_id == th.id,
                        ThreatIoa.id.notin_(set(body.exclude_ioa_ids) or {uuid.UUID(int=0)}),
                    )
                )
            ).scalars()
        )
        if body.include_signals
        else []
    )
    ttps = (
        sorted(
            {
                t
                for t in (
                    await session.execute(select(ThreatTtp.technique_id).where(ThreatTtp.threat_id == th.id))
                ).scalars()
            }
        )
        if body.include_signals
        else []
    )
    if not candidates and not ioas and not ttps:
        raise Conflict("Nothing left to hunt: every indicator is already validated, rejected or expired")
    now = datetime.now(UTC)
    for c in candidates:
        c.status, c.status_reason, c.validated_by, c.validated_at = (
            "VALIDATED",
            "approved with its threat bulletin",
            principal.user_id,
            now,
        )
    th.status, th.status_reason, th.validated_by, th.validated_at = (
        "VALIDATED",
        "bulletin approved for hunting",
        principal.user_id,
        now,
    )
    batch = candidates[: runner.MAX_IOCS_PER_HUNT]  # highest priority first; the rest follow in scheduled batches
    if th.case_id and (await session.get(Case, th.case_id)) is not None:
        # a bulletin that was already hunted: add the new indicators to the same case
        hunt = IocHunt(
            tenant_id=principal.tid,
            name=(body.name or f"Update: {th.name}")[:200],
            mode="rehunt",
            status="PENDING",
            ioc_ids=[str(i.id) for i in batch],
            lookback_days=body.lookback_days,
            requested_by=principal.user_id,
            case_id=th.case_id,
            threat_id=th.id,
            signals={"ioa_ids": [str(i.id) for i in ioas], "ttps": ttps, "full_window": True},
            hypothesis=runner.threat_hypothesis(
                "the organisation", th, batch, len(ioas), len(ttps), body.lookback_days
            ),
        )
        session.add(hunt)
        await session.flush()
    else:
        hunt = await runner.create_hunt(
            session,
            principal.tid,
            principal.user_id,
            batch,
            name=body.name,
            lookback_days=body.lookback_days,
            threat=th,
            ioa_ids=[i.id for i in ioas],
            ttps=ttps,
        )
    await audit.record(
        request,
        "ioc.validate_threat",
        principal=principal,
        resource_type="ioc_hunt",
        resource_id=str(hunt.id),
        details={
            "threat": th.name,
            "iocs": len(candidates),
            "hunted_now": len(batch),
            "ioas": len(ioas),
            "ttps": len(ttps),
        },
    )
    return _hunt_out(hunt, None, th.name)


@router.post("/threats/{threat_id}/reject")
async def reject_threat(
    threat_id: uuid.UUID,
    body: ThreatReject,
    request: Request,
    principal: Principal = VALIDATE,
    session: AsyncSession = Depends(get_session),
) -> dict[str, int]:
    th = await _threat(session, principal, threat_id)
    th.status, th.status_reason = "REJECTED", (body.reason or "rejected by an analyst")[:300]
    res = await session.execute(
        update(Ioc)
        .where(Ioc.threat_id == th.id, Ioc.status == "NEW")
        .values(status="REJECTED", status_reason=th.status_reason)
        .returning(Ioc.id)
    )
    n = len(res.all())
    await audit.record(
        request,
        "ioc.reject_threat",
        principal=principal,
        resource_type="threat",
        resource_id=str(th.id),
        details={"iocs": n},
    )
    return {"rejected": n}


@router.post("/threats/{threat_id}/ioas", response_model=IoaOut, status_code=201)
async def add_ioa(
    threat_id: uuid.UUID,
    body: IoaCreate,
    request: Request,
    principal: Principal = VALIDATE,
    session: AsyncSession = Depends(get_session),
) -> IoaOut:
    th = await _threat(session, principal, threat_id)
    try:
        if not EventQuery(text=body.query_text).effective_filters():
            raise ValueError("the query has no field filters")
    except ValueError as exc:
        raise AppError(f"Invalid behaviour query: {str(exc)[:200]}") from None
    ioa = ThreatIoa(
        tenant_id=principal.tid,
        threat_id=th.id,
        name=body.name,
        description=body.description,
        technique_id=body.technique_id,
        query_text=body.query_text,
        trend_query=body.trend_query,
        severity=body.severity,
        source="manual",
        created_by=principal.user_id,
    )
    session.add(ioa)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("This threat already has a behaviour with that name") from None
    await audit.record(request, "ioc.ioa_add", principal=principal, resource_type="threat", resource_id=str(th.id))
    return IoaOut.model_validate(ioa)


@router.delete("/threats/{threat_id}/ioas/{ioa_id}", status_code=204)
async def delete_ioa(
    threat_id: uuid.UUID,
    ioa_id: uuid.UUID,
    request: Request,
    principal: Principal = VALIDATE,
    session: AsyncSession = Depends(get_session),
) -> Response:
    th = await _threat(session, principal, threat_id)
    ioa = (
        await session.execute(select(ThreatIoa).where(ThreatIoa.id == ioa_id, ThreatIoa.threat_id == th.id))
    ).scalar_one_or_none()
    if ioa is None:
        raise NotFound("Behaviour not found")
    if ioa.source != "manual":
        raise Conflict(
            "Built-in and rule-derived behaviours cannot be deleted; exclude them when validating the bulletin"
        )
    await session.delete(ioa)
    await audit.record(request, "ioc.ioa_delete", principal=principal, resource_type="threat", resource_id=str(th.id))
    return Response(status_code=204)


@router.post("/threats/{threat_id}/ttps", response_model=TtpOut, status_code=201)
async def add_ttp(
    threat_id: uuid.UUID,
    body: TtpCreate,
    request: Request,
    principal: Principal = VALIDATE,
    session: AsyncSession = Depends(get_session),
) -> TtpOut:
    th = await _threat(session, principal, threat_id)
    tech = await session.get(MitreTechnique, body.technique_id)
    if tech is None:
        raise NotFound("Unknown ATT&CK technique")
    stmt = insert(ThreatTtp).values(
        id=uuid.uuid4(),
        tenant_id=principal.tid,
        threat_id=th.id,
        technique_id=tech.id,
        source="manual",
        confidence="HIGH",
        note=body.note or "Added by an analyst",
    )
    await session.execute(
        stmt.on_conflict_do_update(
            constraint="uq_threat_ttp", set_={"source": "manual", "confidence": "HIGH", "note": stmt.excluded.note}
        )
    )
    await threat_svc.refresh(session, principal.tid, {th.id})  # link behaviours for the new technique
    await audit.record(
        request,
        "ioc.ttp_add",
        principal=principal,
        resource_type="threat",
        resource_id=str(th.id),
        details={"technique": tech.id},
    )
    return TtpOut(
        technique_id=tech.id,
        name=tech.name,
        tactics=tech.tactics,
        url=tech.url,
        source="manual",
        confidence="HIGH",
        note=body.note,
    )


@router.post("/threats/regroup")
async def regroup(
    request: Request, principal: Principal = MANAGE, session: AsyncSession = Depends(get_session)
) -> dict[str, int]:
    """Re-run grouping and refresh every bulletin (after loading ATT&CK software data, or after rule changes)."""
    await threat_svc.sync(session, principal.tid, everything=True)
    n = await threat_svc.refresh(session, principal.tid)
    await audit.record(request, "ioc.regroup", principal=principal, details={"threats": n})
    return {"threats": n}


@router.get("/ioa-catalog")
async def ioa_catalog_list(_: Principal = READ) -> list[dict[str, str]]:
    return [
        {
            "name": d.name,
            "technique": d.technique,
            "severity": d.severity,
            "description": d.description,
            "query": d.readable,
            "trend_query": d.trend,
        }
        for d in ioa_catalog.CATALOG
    ]
