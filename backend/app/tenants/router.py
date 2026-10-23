import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth import service as auth_service
from app.auth.deps import Principal, get_principal, require
from app.auth.rbac import TENANT_ROLES, Permission
from app.core.db import get_session
from app.core.errors import AppError, Conflict, NotFound
from app.core.security import hash_password
from app.tenants import service
from app.tenants.models import Tenant
from app.tenants.schemas import TenantCreate, TenantOut, TenantSummary, TenantUpdate
from app.users import service as users
from app.users.models import Membership, User
from app.users.schemas import MemberOut, PlatformMemberCreate, PlatformMemberUpdate

router = APIRouter(prefix="/tenants", tags=["tenants"])

PLATFORM = Depends(require(Permission.TENANTS_MANAGE, tenant_scoped=False))


def _out(t: Tenant) -> TenantOut:
    return TenantOut(
        id=t.id,
        slug=t.slug,
        name=t.name,
        is_active=t.is_active,
        retention_days=t.retention_days,
        created_at=t.created_at,
    )


def _summary(t: Tenant, c: service.TenantCounts) -> TenantSummary:
    return TenantSummary(
        **_out(t).model_dump(),
        member_count=c.members,
        admin_count=c.admins,
        data_source_count=c.data_sources,
        data_sources_down=c.data_sources_down,
    )


async def _tenant(session: AsyncSession, tenant_id: uuid.UUID) -> Tenant:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise NotFound("Tenant not found")
    return tenant


@router.get("/current", response_model=TenantOut)
async def current_tenant(
    principal: Principal = Depends(get_principal), session: AsyncSession = Depends(get_session)
) -> TenantOut:
    return _out(await _tenant(session, principal.tid))


@router.get("", response_model=list[TenantSummary])
async def list_tenants(_: Principal = PLATFORM, session: AsyncSession = Depends(get_session)) -> list[TenantSummary]:
    tenants = list((await session.execute(select(Tenant).order_by(Tenant.name))).scalars())
    counts = await service.counts_for(session, [t.id for t in tenants])
    return [_summary(t, counts[t.id]) for t in tenants]


@router.post("", response_model=TenantOut, status_code=201)
async def create_tenant(
    body: TenantCreate,
    request: Request,
    principal: Principal = PLATFORM,
    session: AsyncSession = Depends(get_session),
) -> TenantOut:
    if bool(body.admin_email) != bool(body.admin_password):
        raise AppError("admin_email and admin_password must be provided together")
    tenant, admin = await service.provision_tenant(
        session,
        slug=body.slug,
        name=body.name,
        retention_days=body.retention_days,
        admin_email=body.admin_email,
        admin_password=body.admin_password,
    )
    await audit.record(
        request,
        "tenant.create",
        principal=principal,
        tenant_id=tenant.id,
        resource_type="tenant",
        resource_id=str(tenant.id),
        details={"admin": admin.email if admin else None},
    )
    return _out(tenant)


@router.get("/{tenant_id}", response_model=TenantSummary)
async def get_tenant(
    tenant_id: uuid.UUID, _: Principal = PLATFORM, session: AsyncSession = Depends(get_session)
) -> TenantSummary:
    tenant = await _tenant(session, tenant_id)
    return _summary(tenant, (await service.counts_for(session, [tenant.id]))[tenant.id])


@router.patch("/{tenant_id}", response_model=TenantOut)
async def update_tenant(
    tenant_id: uuid.UUID,
    body: TenantUpdate,
    request: Request,
    principal: Principal = PLATFORM,
    session: AsyncSession = Depends(get_session),
) -> TenantOut:
    tenant = await _tenant(session, tenant_id)
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


# ---- membership of any tenant, managed by the platform operator ---------------------------------------
@router.get("/{tenant_id}/members", response_model=list[MemberOut])
async def list_tenant_members(
    tenant_id: uuid.UUID, _: Principal = PLATFORM, session: AsyncSession = Depends(get_session)
) -> list[MemberOut]:
    await _tenant(session, tenant_id)
    rows = await session.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.tenant_id == tenant_id)
        .order_by(User.email)
    )
    return await users.with_platform_admins(session, [users.member_out(u, m) for u, m in rows.all()])


@router.post("/{tenant_id}/members", response_model=MemberOut, status_code=201)
async def add_tenant_member(
    tenant_id: uuid.UUID,
    body: PlatformMemberCreate,
    request: Request,
    principal: Principal = PLATFORM,
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    """Create a user in the tenant, or attach an existing account to it (one person, several tenants)."""
    await _tenant(session, tenant_id)
    if body.role not in TENANT_ROLES:
        raise AppError("Role cannot be assigned to a tenant member")
    email = body.email.lower()
    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    attached = user is not None
    if user is None:
        if body.password is None:
            raise AppError("A password is required to create a new user")
        user = User(email=email, full_name=body.full_name, password_hash=hash_password(body.password))
        session.add(user)
        await session.flush()
    elif user.is_super_admin:
        raise AppError("Platform super admins cannot be tenant members")
    membership = Membership(user_id=user.id, tenant_id=tenant_id, role=body.role.value)
    session.add(membership)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("User is already a member of this tenant") from None
    await audit.record(
        request,
        "tenant.member_add",
        principal=principal,
        tenant_id=tenant_id,
        resource_type="user",
        resource_id=str(user.id),
        details={"role": body.role.value, "existing_account": attached},
    )
    return users.member_out(user, membership)


@router.patch("/{tenant_id}/members/{user_id}", response_model=MemberOut)
async def update_tenant_member(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    body: PlatformMemberUpdate,
    request: Request,
    principal: Principal = PLATFORM,
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    row = (
        await session.execute(
            select(User, Membership)
            .join(Membership, Membership.user_id == User.id)
            .where(Membership.tenant_id == tenant_id, User.id == user_id)
            .with_for_update(of=Membership)
        )
    ).first()
    if row is None:
        raise NotFound("Member not found")
    user, membership = row
    if body.role is not None and body.role not in TENANT_ROLES:
        raise AppError("Role cannot be assigned to a tenant member")
    if users.removes_admin(membership, new_role=body.role, new_active=body.is_active):
        await users.ensure_tenant_keeps_an_admin(session, tenant_id, user.id)
    if body.role is not None:
        membership.role = body.role.value
    if body.is_active is not None:
        membership.is_active = body.is_active
    if body.new_password is not None:
        user.password_hash = hash_password(body.new_password)
    if body.is_active is False or body.new_password is not None:
        await auth_service.revoke_user_tokens(session, user.id, tenant_id if body.new_password is None else None)
    await audit.record(
        request,
        "tenant.member_update",
        principal=principal,
        tenant_id=tenant_id,
        resource_type="user",
        resource_id=str(user.id),
        details={
            **body.model_dump(mode="json", exclude_none=True, exclude={"new_password"}),
            "password_reset": body.new_password is not None,
        },
    )
    return users.member_out(user, membership)
