import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import RefreshToken
from app.auth.rbac import Role, permissions_for
from app.auth.schemas import SessionInfo, TenantRef
from app.core.config import Settings
from app.core.errors import Forbidden, Unauthorized
from app.core.security import (
    create_access_token,
    hash_opaque_token,
    hash_password,
    needs_rehash,
    new_opaque_token,
    verify_password,
)
from app.tenants.models import Tenant
from app.users.models import Membership, User


async def available_tenants(session: AsyncSession, user: User) -> list[Tenant]:
    stmt = select(Tenant).where(Tenant.is_active.is_(True)).order_by(Tenant.name)
    if not user.is_super_admin:
        stmt = stmt.join(Membership, Membership.tenant_id == Tenant.id).where(
            Membership.user_id == user.id, Membership.is_active.is_(True)
        )
    return list((await session.execute(stmt)).scalars())


async def resolve_role(session: AsyncSession, user: User, tenant_id: uuid.UUID | None) -> Role:
    if user.is_super_admin:
        return Role.SUPER_ADMIN
    if tenant_id is None:
        raise Forbidden("No active tenant membership")
    role = (
        await session.execute(
            select(Membership.role)
            .join(Tenant, Tenant.id == Membership.tenant_id)
            .where(
                Membership.user_id == user.id,
                Membership.tenant_id == tenant_id,
                Membership.is_active.is_(True),
                Tenant.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if role is None:
        raise Forbidden("No active membership in the requested tenant")
    return Role(role)


async def authenticate(session: AsyncSession, email: str, password: str) -> User:
    user = (await session.execute(select(User).where(User.email == email.lower()))).scalar_one_or_none()
    ok = verify_password(user.password_hash if user else None, password)
    if not ok or user is None or not user.is_active:
        raise Unauthorized("Invalid credentials")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = datetime.now(UTC)
    return user


async def pick_tenant(session: AsyncSession, user: User, requested: uuid.UUID | None) -> uuid.UUID | None:
    tenants = await available_tenants(session, user)
    if requested is not None:
        if requested not in {t.id for t in tenants}:
            raise Forbidden("No active membership in the requested tenant")
        return requested
    if tenants:
        return tenants[0].id if not user.is_super_admin else None
    if user.is_super_admin:
        return None
    raise Forbidden("No active tenant membership")


def _ref(t: Tenant) -> TenantRef:
    return TenantRef(id=t.id, slug=t.slug, name=t.name)


async def build_session_info(session: AsyncSession, user: User, tenant_id: uuid.UUID | None) -> SessionInfo:
    tenants = await available_tenants(session, user)
    role = await resolve_role(session, user, tenant_id)
    current = next((t for t in tenants if t.id == tenant_id), None)
    return SessionInfo(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=role.value,
        permissions=sorted(p.value for p in permissions_for(role)),
        tenant=_ref(current) if current else None,
        available_tenants=[_ref(t) for t in tenants],
    )


async def issue_refresh_token(
    session: AsyncSession,
    settings: Settings,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID | None,
    family_id: uuid.UUID | None = None,
) -> str:
    raw = new_opaque_token()
    session.add(
        RefreshToken(
            family_id=family_id or uuid.uuid4(),
            user_id=user_id,
            tenant_id=tenant_id,
            token_hash=hash_opaque_token(raw),
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days),
        )
    )
    return raw


async def rotate_refresh_token(
    session: AsyncSession, settings: Settings, raw: str
) -> tuple[str, User, uuid.UUID | None]:
    row = (
        await session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw)).with_for_update()
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.expires_at < now or row.revoked_at is not None:
        raise Unauthorized("Invalid refresh token")
    if row.used_at is not None:
        # Reuse of a rotated token: assume theft, kill the whole family.
        await revoke_family(session, row.family_id)
        await session.commit()
        raise Unauthorized("Invalid refresh token")
    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise Unauthorized("Invalid refresh token")
    # Membership may have been revoked since the token was issued.
    await resolve_role(session, user, row.tenant_id)
    row.used_at = now
    new_raw = await issue_refresh_token(
        session, settings, user_id=user.id, tenant_id=row.tenant_id, family_id=row.family_id
    )
    return new_raw, user, row.tenant_id


async def revoke_family(session: AsyncSession, family_id: uuid.UUID) -> None:
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )


async def revoke_user_tokens(session: AsyncSession, user_id: uuid.UUID, tenant_id: uuid.UUID | None = None) -> None:
    stmt = update(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
    if tenant_id is not None:
        stmt = stmt.where(RefreshToken.tenant_id == tenant_id)
    await session.execute(stmt.values(revoked_at=datetime.now(UTC)))


async def revoke_by_raw(session: AsyncSession, raw: str) -> None:
    row = (
        await session.execute(select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw)))
    ).scalar_one_or_none()
    if row:
        await revoke_family(session, row.family_id)


def make_access(settings: Settings, user: User, tenant_id: uuid.UUID | None) -> tuple[str, int]:
    return create_access_token(settings, user_id=user.id, tenant_id=tenant_id)
