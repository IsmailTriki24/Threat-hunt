import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import jwt
from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import Permission, Role, permissions_for
from app.core.config import get_settings
from app.core.db import get_session
from app.core.errors import AppError, Forbidden, Unauthorized
from app.core.logging import bind_log_context
from app.core.security import decode_access_token
from app.tenants.models import Tenant
from app.users.models import Membership, User


class TenantContextRequired(AppError):
    status_code = 400
    code = "tenant_context_required"


@dataclass(frozen=True)
class Principal:
    """Authenticated identity. `tenant_id` is derived server-side, never taken from request input."""

    user_id: uuid.UUID
    email: str
    role: Role
    tenant_id: uuid.UUID | None
    is_super_admin: bool

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.role)

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    @property
    def tid(self) -> uuid.UUID:
        if self.tenant_id is None:
            raise TenantContextRequired("Select a tenant before using tenant-scoped endpoints")
        return self.tenant_id


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise Unauthorized("Authentication required")
    return token


async def get_principal(request: Request, session: AsyncSession = Depends(get_session)) -> Principal:
    token = _bearer(request)
    try:
        claims = decode_access_token(get_settings(), token)
        user_id = uuid.UUID(claims["sub"])
        tid_claim = claims.get("tid")
        tenant_id = uuid.UUID(tid_claim) if tid_claim else None
    except (jwt.PyJWTError, ValueError, KeyError):
        raise Unauthorized("Invalid or expired token") from None

    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise Unauthorized("Invalid or expired token")

    # Re-validate on every request so deactivation/role changes take effect immediately.
    if user.is_super_admin:
        role = Role.SUPER_ADMIN
        if tenant_id is not None:
            tenant = await session.get(Tenant, tenant_id)
            if tenant is None or not tenant.is_active:
                raise Unauthorized("Invalid or expired token")
    else:
        if tenant_id is None:
            raise Unauthorized("Invalid or expired token")
        row = (
            await session.execute(
                select(Membership.role)
                .join(Tenant, Tenant.id == Membership.tenant_id)
                .where(
                    Membership.user_id == user_id,
                    Membership.tenant_id == tenant_id,
                    Membership.is_active.is_(True),
                    Tenant.is_active.is_(True),
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise Unauthorized("Invalid or expired token")
        role = Role(row)

    principal = Principal(user.id, user.email, role, tenant_id, user.is_super_admin)
    bind_log_context(user_id=str(user.id), tenant_id=str(tenant_id) if tenant_id else None)
    request.state.principal = principal
    return principal


def require(permission: Permission, *, tenant_scoped: bool = True) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory: authenticate, authorize, and (optionally) require a tenant context."""

    async def dependency(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(permission):
            from app.audit import service as audit

            await audit.record(
                request,
                "authz.denied",
                "denied",
                principal=principal,
                details={"permission": permission.value, "path": request.url.path},
            )
            raise Forbidden("Insufficient permissions")
        if tenant_scoped:
            _ = principal.tid  # raises when no tenant context
        return principal

    return dependency


__all__ = ["Principal", "get_principal", "require"]
