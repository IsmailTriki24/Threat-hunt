import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import Role
from app.core.errors import Conflict
from app.core.security import hash_password
from app.datasources.models import DataSource
from app.tenants.models import Tenant
from app.users.models import Membership, User


@dataclass(frozen=True)
class TenantCounts:
    members: int
    admins: int
    data_sources: int
    data_sources_down: int


async def provision_tenant(
    session: AsyncSession,
    *,
    slug: str,
    name: str,
    retention_days: int = 90,
    admin_email: str | None = None,
    admin_password: str | None = None,
) -> tuple[Tenant, User | None]:
    """Create a tenant and, optionally, its first TENANT_ADMIN. The one path used by the API and the CLI."""
    tenant = Tenant(slug=slug, name=name, retention_days=retention_days)
    session.add(tenant)
    try:
        await session.flush()
    except IntegrityError:
        raise Conflict("Tenant slug already exists") from None
    admin: User | None = None
    if admin_email and admin_password:
        admin = User(email=admin_email.lower(), password_hash=hash_password(admin_password))
        session.add(admin)
        try:
            await session.flush()
        except IntegrityError:
            raise Conflict("Admin email already registered") from None
        session.add(Membership(user_id=admin.id, tenant_id=tenant.id, role=Role.TENANT_ADMIN.value))
        await session.flush()
    return tenant, admin


async def counts_for(session: AsyncSession, tenant_ids: list[uuid.UUID]) -> dict[uuid.UUID, TenantCounts]:
    """Member and log-source totals for several tenants in two queries."""
    members = {
        tid: (total, admins)
        for tid, total, admins in (
            await session.execute(
                select(
                    Membership.tenant_id,
                    func.count(),
                    func.count().filter(Membership.role == Role.TENANT_ADMIN.value),
                )
                .where(Membership.tenant_id.in_(tenant_ids), Membership.is_active.is_(True))
                .group_by(Membership.tenant_id)
            )
        ).all()
    }
    sources = {
        tid: (total, down)
        for tid, total, down in (
            await session.execute(
                select(
                    DataSource.tenant_id,
                    func.count(),
                    func.count().filter(DataSource.health_status == "down"),
                )
                .where(DataSource.tenant_id.in_(tenant_ids))
                .group_by(DataSource.tenant_id)
            )
        ).all()
    }
    out: dict[uuid.UUID, TenantCounts] = {}
    for tid in tenant_ids:
        n_members, n_admins = members.get(tid, (0, 0))
        n_sources, n_down = sources.get(tid, (0, 0))
        out[tid] = TenantCounts(n_members, n_admins, n_sources, n_down)
    return out
