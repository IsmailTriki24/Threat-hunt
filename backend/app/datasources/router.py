import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.connectors import registry
from app.core.config import Settings, get_settings
from app.core.crypto import decrypt_json
from app.core.db import get_session
from app.core.errors import AppError, Conflict, NotFound, Unauthorized
from app.core.ratelimit import enforce
from app.datasources import service
from app.datasources.models import DataSource
from app.datasources.schemas import ConnectorInfo, DataSourceCreate, DataSourceOut, DataSourceUpdate, SecretValue
from app.events import service as ingest_service
from app.events.search.base import SearchBackend
from app.tenants.models import Tenant

router = APIRouter(prefix="/data-sources", tags=["data-sources"])
ingest_router = APIRouter(prefix="/ingest", tags=["ingest"])

READ = Depends(require(Permission.DATASOURCES_READ))
MANAGE = Depends(require(Permission.DATASOURCES_MANAGE))


async def _get(session: AsyncSession, principal: Principal, ds_id: uuid.UUID) -> DataSource:
    ds = (
        await session.execute(select(DataSource).where(DataSource.id == ds_id, DataSource.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if ds is None:
        raise NotFound("Data source not found")
    return ds


def _validate(connector_type: str, config: dict[str, Any]) -> None:
    if connector_type not in registry.available():
        raise AppError(f"Unknown connector type; available: {', '.join(registry.available())}")
    try:
        registry.build(connector_type, config)
    except (ValidationError, ValueError) as exc:
        raise AppError(f"Invalid connector config: {str(exc)[:300]}") from None


@router.get("/connectors", response_model=list[ConnectorInfo])
async def list_connectors(_: Principal = READ) -> list[ConnectorInfo]:
    out = []
    for t in registry.available():
        cls = registry._REGISTRY[t]  # noqa: SLF001
        out.append(
            ConnectorInfo(
                type=t,
                display_name=cls.display_name,
                supports_collect=cls.supports_collect,
                config_schema=cls.config_model.model_json_schema(),
            )
        )
    return out


@router.get("", response_model=list[DataSourceOut])
async def list_sources(
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[DataSourceOut]:
    rows = await session.execute(
        select(DataSource).where(DataSource.tenant_id == principal.tid).order_by(DataSource.name)
    )
    return [service.to_out(d, settings) for d in rows.scalars()]


@router.post("", response_model=DataSourceOut, status_code=201)
async def create_source(
    body: DataSourceCreate,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DataSourceOut:
    _validate(body.connector_type, body.config)
    raw_key, key_hash = service.new_ingest_key()
    ds = DataSource(
        tenant_id=principal.tid,
        name=body.name,
        connector_type=body.connector_type,
        config=body.config,
        secrets_enc=service.encrypt_secrets(settings, body.secrets),
        enabled=body.enabled,
        ingest_key_hash=key_hash,
    )
    session.add(ds)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("A data source with this name already exists") from None
    await session.refresh(ds)
    await audit.record(
        request,
        "datasource.create",
        principal=principal,
        resource_type="datasource",
        resource_id=str(ds.id),
        details={"connector": body.connector_type},
    )
    return service.to_out(ds, settings, ingest_key=raw_key)


@router.get("/{ds_id}", response_model=DataSourceOut)
async def get_source(
    ds_id: uuid.UUID,
    principal: Principal = READ,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DataSourceOut:
    return service.to_out(await _get(session, principal, ds_id), settings)


@router.patch("/{ds_id}", response_model=DataSourceOut)
async def update_source(
    ds_id: uuid.UUID,
    body: DataSourceUpdate,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DataSourceOut:
    ds = await _get(session, principal, ds_id)
    if body.config is not None:
        _validate(ds.connector_type, body.config)
        ds.config = body.config
    if body.secrets is not None:
        ds.secrets_enc = service.encrypt_secrets(settings, body.secrets)
    if body.name is not None:
        ds.name = body.name
    if body.enabled is not None:
        ds.enabled = body.enabled
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("A data source with this name already exists") from None
    await audit.record(
        request,
        "datasource.update",
        principal=principal,
        resource_type="datasource",
        resource_id=str(ds.id),
        details={"fields": sorted(body.model_dump(exclude_none=True)), "secrets_changed": body.secrets is not None},
    )
    return service.to_out(ds, settings)


@router.put("/{ds_id}/secrets/{name}", status_code=204)
async def set_secret(
    ds_id: uuid.UUID,
    name: Annotated[str, Path(pattern=r"^[A-Za-z0-9_.-]{1,64}$")],
    body: SecretValue,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Write-only: set or rotate ONE credential; other secrets are kept. The value is never echoed or logged."""
    ds = await _get(session, principal, ds_id)
    current = {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()} if ds.secrets_enc else {}
    if name not in current and len(current) >= 10:
        raise AppError("A data source can hold at most 10 secrets")
    current[name] = body.value
    ds.secrets_enc = service.encrypt_secrets(settings, current)
    await audit.record(
        request,
        "datasource.secret_set",
        principal=principal,
        resource_type="datasource",
        resource_id=str(ds.id),
        details={"name": name},
    )
    return Response(status_code=204)


@router.delete("/{ds_id}", status_code=204)
async def delete_source(
    ds_id: uuid.UUID, request: Request, principal: Principal = MANAGE, session: AsyncSession = Depends(get_session)
) -> Response:
    ds = await _get(session, principal, ds_id)
    await session.delete(ds)
    await audit.record(
        request, "datasource.delete", principal=principal, resource_type="datasource", resource_id=str(ds_id)
    )
    return Response(status_code=204)


@router.post("/{ds_id}/rotate-key", response_model=DataSourceOut)
async def rotate_key(
    ds_id: uuid.UUID,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DataSourceOut:
    ds = await _get(session, principal, ds_id)
    raw, ds.ingest_key_hash = service.new_ingest_key()
    await audit.record(
        request, "datasource.rotate_key", principal=principal, resource_type="datasource", resource_id=str(ds.id)
    )
    return service.to_out(ds, settings, ingest_key=raw)


@router.post("/{ds_id}/test")
async def test_source(
    ds_id: uuid.UUID,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    await enforce(request, f"dstest:{principal.tid}", 20, 60)
    ds = await _get(session, principal, ds_id)
    result = await service.build_connector(ds, settings).test_connection()
    ds.health_status = "ok" if result.ok else "down"
    ds.health_detail = result.detail[:300]
    ds.health_checked_at = datetime.now(UTC)
    await audit.record(
        request,
        "datasource.test",
        principal=principal,
        resource_type="datasource",
        resource_id=str(ds.id),
        details={"ok": result.ok},
    )
    return {"ok": result.ok, "detail": result.detail}


@router.post("/{ds_id}/collect")
async def collect_now(
    ds_id: uuid.UUID,
    request: Request,
    principal: Principal = MANAGE,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, int]:
    await enforce(request, f"dscollect:{principal.tid}", 6, 60)
    ds = await _get(session, principal, ds_id)
    if not service.build_connector(ds, settings).supports_collect:
        raise AppError("This connector is push-based; send events to its ingest endpoint instead")
    n = await service.collect_source(session, request.app.state.search, settings, ds)
    await audit.record(
        request,
        "datasource.collect",
        principal=principal,
        resource_type="datasource",
        resource_id=str(ds.id),
        details={"accepted": n},
    )
    return {"accepted": n}


# ---- push ingestion authenticated by a per-source key (service identity, no user session) ------------
@ingest_router.post("/{ds_id}", response_model=ingest_service.IngestResponse)
async def ingest_with_key(
    ds_id: uuid.UUID,
    body: dict[str, list[dict[str, Any]]],
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> ingest_service.IngestResponse:
    header = request.headers.get("authorization", "")
    scheme, _, key = header.partition(" ")
    if scheme.lower() != "bearer" or not key.startswith(service.KEY_PREFIX):
        raise Unauthorized("Invalid ingest key")
    await enforce(request, f"ingest-key:{request.client.host if request.client else 'x'}", 600, 60)
    ds = await service.find_by_key(session, key)
    # The key identifies the source; the path id must agree so a leaked URL alone is useless.
    if ds is None or ds.id != ds_id or not ds.enabled:
        await audit.record(request, "ingest.denied", "denied", actor_label=f"datasource:{ds_id}")
        raise Unauthorized("Invalid ingest key")
    tenant = await session.get(Tenant, ds.tenant_id)
    if tenant is None or not tenant.is_active:
        raise Unauthorized("Invalid ingest key")
    events = body.get("events")
    if not events or len(events) > settings.ingest_max_batch:
        raise AppError(f"Provide 1-{settings.ingest_max_batch} events under the 'events' key")
    await enforce(request, f"ingest:{ds.tenant_id}", 120, 60)
    backend: SearchBackend = request.app.state.search
    response = await service.ingest_batch(session, backend, settings, ds, events)
    await audit.record(
        request,
        "ingest.datasource",
        tenant_id=ds.tenant_id,
        actor_label=f"datasource:{ds.name}",
        resource_type="datasource",
        resource_id=str(ds.id),
        details={"accepted": response.accepted, "duplicates": response.duplicates, "rejected": len(response.rejected)},
    )
    return response
