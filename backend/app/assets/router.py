import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets import service
from app.assets.models import Asset
from app.assets.schemas import AssetCreate, AssetOut, AssetUpdate, DiscoverRequest, DiscoverResult
from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.cases.models import Case, CaseAsset
from app.core.db import get_session
from app.core.errors import Conflict, NotFound
from app.core.ratelimit import enforce
from app.events.search.base import SearchBackend
from app.events.search.query import Aggregation, EventQuery, Filter, TimeRange

router = APIRouter(prefix="/assets", tags=["assets"])


def _out(a: Asset) -> AssetOut:
    return AssetOut.model_validate(a, from_attributes=True)


async def _get(session: AsyncSession, principal: Principal, asset_id: uuid.UUID) -> Asset:
    asset = (
        await session.execute(select(Asset).where(Asset.id == asset_id, Asset.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if asset is None:
        raise NotFound("Asset not found")
    return asset


@router.get("", response_model=list[AssetOut])
async def list_assets(
    type: str | None = None,
    criticality: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
    principal: Principal = Depends(require(Permission.ASSETS_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[AssetOut]:
    stmt = select(Asset).where(Asset.tenant_id == principal.tid)
    if type:
        stmt = stmt.where(Asset.type == type)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if q:
        stmt = stmt.where(Asset.key.contains(q.lower()[:100], autoescape=True))
    rows = await session.execute(
        stmt.order_by(Asset.last_seen.desc().nullslast(), Asset.key)
        .limit(max(1, min(limit, 500)))
        .offset(max(0, offset))
    )
    return [_out(a) for a in rows.scalars()]


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(
    body: AssetCreate,
    request: Request,
    principal: Principal = Depends(require(Permission.ASSETS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> AssetOut:
    key = service.normalize_key(body.type, body.key)
    asset = Asset(
        tenant_id=principal.tid,
        type=body.type,
        key=key,
        display_name=body.display_name or body.key.strip(),
        criticality=body.criticality,
        owner=body.owner,
        tags=body.tags,
        attributes=body.attributes,
    )
    session.add(asset)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("Asset already exists") from None
    await session.refresh(asset)
    await audit.record(request, "asset.create", principal=principal, resource_type="asset", resource_id=str(asset.id))
    return _out(asset)


@router.post("/discover", response_model=DiscoverResult)
async def discover_assets(
    body: DiscoverRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.ASSETS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> DiscoverResult:
    await enforce(request, f"discover:{principal.tid}", 6, 60)
    created, updated = await service.discover(session, request.app.state.search, principal.tid, body.days)
    await audit.record(request, "asset.discover", principal=principal, details={"created": created, "updated": updated})
    return DiscoverResult(created=created, updated=updated)


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.ASSETS_READ)),
    session: AsyncSession = Depends(get_session),
) -> AssetOut:
    return _out(await _get(session, principal, asset_id))


@router.patch("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    request: Request,
    principal: Principal = Depends(require(Permission.ASSETS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> AssetOut:
    asset = await _get(session, principal, asset_id)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(asset, k, v)
    await audit.record(
        request,
        "asset.update",
        principal=principal,
        resource_type="asset",
        resource_id=str(asset.id),
        details=body.model_dump(mode="json", exclude_none=True),
    )
    return _out(asset)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Permission.ASSETS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    asset = await _get(session, principal, asset_id)
    await session.delete(asset)
    await audit.record(request, "asset.delete", principal=principal, resource_type="asset", resource_id=str(asset_id))
    return Response(status_code=204)


async def _asset_events(
    backend: SearchBackend,
    principal: Principal,
    asset: Asset,
    days: int,
    limit: int,
    aggs: list[Aggregation] | None = None,
) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
    """Events about this asset. The identity can appear in several fields, so each is queried and merged."""
    end = datetime.now(UTC)
    tr = TimeRange(start=end - timedelta(days=days), end=end)
    total, hits = 0, []
    merged_aggs: dict[str, dict[Any, int]] = {}
    for field in service.EVENT_FIELDS[asset.type]:
        query = EventQuery(
            time_range=tr, limit=limit, filters=[Filter(field=field, op="eq", value=asset.key)], aggregations=aggs or []
        )
        res = await backend.search(principal.tid, query)
        total += res.total
        hits.extend(res.hits)
        for name, agg in res.aggregations.items():
            merged_aggs.setdefault(name, {})
            for b in agg.buckets:
                merged_aggs[name][b.key] = merged_aggs[name].get(b.key, 0) + b.count
    seen: set[str] = set()
    unique = []
    for h in sorted(hits, key=lambda x: x["timestamp"], reverse=True):
        if h["id"] not in seen:
            seen.add(h["id"])
            unique.append(h)
    return total, unique[:limit], merged_aggs


@router.get("/{asset_id}/events")
async def asset_events(
    asset_id: uuid.UUID,
    request: Request,
    days: int = 7,
    limit: int = 50,
    principal: Principal = Depends(require(Permission.EVENTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    asset = await _get(session, principal, asset_id)
    total, hits, _ = await _asset_events(
        request.app.state.search, principal, asset, max(1, min(days, 90)), max(1, min(limit, 200))
    )
    return {"total": total, "hits": hits}


_RELATED = {
    "host": [("users", "user.name"), ("destinations", "network.dst_ip"), ("processes", "process.name")],
    "server": [("users", "user.name"), ("sources", "network.src_ip"), ("processes", "process.name")],
    "user": [("hosts", "host.hostname"), ("processes", "process.name"), ("destinations", "network.dst_ip")],
    "ip": [("hosts", "host.hostname"), ("users", "user.name"), ("ports", "network.dst_port")],
    "domain": [("hosts", "host.hostname"), ("processes", "process.name")],
    "application": [("hosts", "host.hostname"), ("users", "user.name")],
    "cloud": [("users", "user.name")],
}


@router.get("/{asset_id}/related")
async def related(
    asset_id: uuid.UUID,
    request: Request,
    days: int = 7,
    principal: Principal = Depends(require(Permission.EVENTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> dict[str, list[dict[str, Any]]]:
    """Relationships derived from telemetry (who/what/where this asset interacts with), not stored links."""
    asset = await _get(session, principal, asset_id)
    aggs = [Aggregation(name=n, type="terms", field=f, size=10) for n, f in _RELATED[asset.type]]
    _, _, merged = await _asset_events(request.app.state.search, principal, asset, max(1, min(days, 90)), 1, aggs)
    return {
        n: [{"key": k, "count": c} for k, c in sorted(v.items(), key=lambda kv: -kv[1])[:10]] for n, v in merged.items()
    }


@router.get("/{asset_id}/cases")
async def asset_cases(
    asset_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.CASES_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    await _get(session, principal, asset_id)
    rows = await session.execute(
        select(Case.id, Case.number, Case.title, Case.status, Case.severity)
        .join(CaseAsset, CaseAsset.case_id == Case.id)
        .where(CaseAsset.asset_id == asset_id, CaseAsset.tenant_id == principal.tid)
        .order_by(Case.number.desc())
    )
    return [
        {"id": str(r.id), "number": r.number, "title": r.title, "status": r.status, "severity": r.severity}
        for r in rows
    ]


__all__ = ["func", "router"]
