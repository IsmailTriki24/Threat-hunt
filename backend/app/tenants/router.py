import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.deps import Principal, get_principal, require
from app.auth.rbac import Permission, Role
from app.core.db import get_session
from app.core.errors import AppError, Conflict, NotFound
from app.core.security import hash_password
from app.tenants.models import Tenant
from app.tenants.schemas import TenantCreate, TenantOut, TenantUpdate
from app.users.models import Membership, User

router = APIRouter(prefix="/tenants", tags=["tenants"])


def _out(t: Tenant) -> TenantOut:
    return TenantOut(
        id=t.id,
        slug=t.slug,
        name=t.name,
        is_active=t.is_active,
        retention_days=t.retention_days,
        created_at=t.created_at,
    )


@router.get("/current", response_model=TenantOut)
async def current_tenant(
    principal: Principal = Depends(get_principal), session: AsyncSession = Depends(get_session)
) -> TenantOut:
    tenant = await session.get(Tenant, principal.tid)
    if tenant is None:
        raise NotFound("Tenant not found")
    return _out(tenant)


@router.get("", response_model=list[TenantOut])
async def list_tenants(
    _: Principal = Depends(require(Permission.TENANTS_MANAGE, tenant_scoped=False)),
    session: AsyncSession = Depends(get_session),
) -> list[TenantOut]:
    return [_out(t) for t in (await session.execute(select(Tenant).order_by(Tenant.name))).scalars()]


@router.post("", response_model=TenantOut, status_code=201)
async def create_tenant(
    body: TenantCreate,
    request: Request,
    principal: Principal = Depends(require(Permission.TENANTS_MANAGE, tenant_scoped=False)),
    session: AsyncSession = Depends(get_session),
) -> TenantOut:
    if bool(body.admin_email) != bool(body.admin_password):
        raise AppError("admin_email and admin_password must be provided together")
    tenant = Tenant(slug=body.slug, name=body.name, retention_days=body.retention_days)
    session.add(tenant)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("Tenant slug already exists") from None
    if body.admin_email and body.admin_password:
        admin = User(email=body.admin_email.lower(), password_hash=hash_password(body.admin_password))
        session.add(admin)
        try:
            await session.flush()
        except IntegrityError:
            raise Conflict("Admin email already registered") from None
        session.add(Membership(user_id=admin.id, tenant_id=tenant.id, role=Role.TENANT_ADMIN.value))
    await audit.record(
        request,
        "tenant.create",
        principal=principal,
        tenant_id=tenant.id,
        resource_type="tenant",
        resource_id=str(tenant.id),
    )
    return _out(tenant)


@router.patch("/{tenant_id}", response_model=TenantOut)
async def update_tenant(
    tenant_id: uuid.UUID,
    body: TenantUpdate,
    request: Request,
    principal: Principal = Depends(require(Permission.TENANTS_MANAGE, tenant_scoped=False)),
    session: AsyncSession = Depends(get_session),
) -> TenantOut:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise NotFound("Tenant not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(tenant, field, value)
    await audit.record(
        request,
        "tenant.update",
        principal=principal,
        tenant_id=tenant.id,
        resource_type="tenant",
        resource_id=str(tenant.id),
        details=body.model_dump(mode="json", exclude_none=True),
    )
    return _out(tenant)
