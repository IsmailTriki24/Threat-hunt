import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth import service as auth_service
from app.auth.deps import Principal, require
from app.auth.rbac import TENANT_ROLES, Permission, Role
from app.core.db import get_session
from app.core.errors import AppError, Conflict, NotFound
from app.core.security import hash_password
from app.users.models import Membership, User
from app.users.schemas import MemberOut, MemberUpdate, UserCreate

router = APIRouter(prefix="/users", tags=["users"])


def _out(user: User, membership: Membership) -> MemberOut:
    return MemberOut(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role,
        is_active=membership.is_active and user.is_active,
        last_login_at=user.last_login_at,
    )


@router.get("", response_model=list[MemberOut])
async def list_members(
    principal: Principal = Depends(require(Permission.USERS_READ)), session: AsyncSession = Depends(get_session)
) -> list[MemberOut]:
    rows = await session.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.tenant_id == principal.tid)
        .order_by(User.email)
    )
    return [_out(u, m) for u, m in rows.all()]


@router.post("", response_model=MemberOut, status_code=201)
async def create_member(
    body: UserCreate,
    request: Request,
    principal: Principal = Depends(require(Permission.USERS_MANAGE)),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    if body.role not in TENANT_ROLES:
        raise AppError("Role cannot be assigned to a tenant member")
    user = User(email=body.email.lower(), full_name=body.full_name, password_hash=hash_password(body.password))
    session.add(user)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("Email already registered") from None
    membership = Membership(user_id=user.id, tenant_id=principal.tid, role=body.role.value)
    session.add(membership)
    await session.flush()
    await audit.record(
        request,
        "user.create",
        principal=principal,
        resource_type="user",
        resource_id=str(user.id),
        details={"role": body.role.value},
    )
    return _out(user, membership)


@router.patch("/{user_id}", response_model=MemberOut)
async def update_member(
    user_id: uuid.UUID,
    body: MemberUpdate,
    request: Request,
    principal: Principal = Depends(require(Permission.USERS_MANAGE)),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    # Lookup is constrained by the caller's tenant: another tenant's user is indistinguishable from missing.
    row = (
        await session.execute(
            select(User, Membership)
            .join(Membership, Membership.user_id == User.id)
            .where(Membership.tenant_id == principal.tid, User.id == user_id)
        )
    ).first()
    if row is None:
        raise NotFound("User not found")
    user, membership = row
    if user.id == principal.user_id:
        raise AppError("You cannot change your own role or status")
    if body.role is not None:
        if body.role not in TENANT_ROLES:
            raise AppError("Role cannot be assigned to a tenant member")
        membership.role = body.role.value
    if body.is_active is not None:
        membership.is_active = body.is_active
        if not body.is_active:
            await auth_service.revoke_user_tokens(session, user.id, principal.tid)
    await audit.record(
        request,
        "user.update",
        principal=principal,
        resource_type="user",
        resource_id=str(user.id),
        details=body.model_dump(mode="json", exclude_none=True),
    )
    return _out(user, membership)


__all__ = ["Role", "router"]
