import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import Role
from app.core.errors import Conflict
from app.users.models import Membership, User
from app.users.schemas import MemberOut


def member_out(user: User, membership: Membership) -> MemberOut:
    return MemberOut(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role,
        is_active=membership.is_active and user.is_active,
        last_login_at=user.last_login_at,
    )


async def ensure_tenant_keeps_an_admin(session: AsyncSession, tenant_id: uuid.UUID, leaving: uuid.UUID) -> None:
    """A tenant must always have someone who can manage it. Call before demoting or deactivating `leaving`."""
    remaining = (
        await session.execute(
            select(func.count())
            .select_from(Membership)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.tenant_id == tenant_id,
                Membership.role == Role.TENANT_ADMIN.value,
                Membership.is_active.is_(True),
                User.is_active.is_(True),
                Membership.user_id != leaving,
            )
        )
    ).scalar_one()
    if remaining == 0:
        raise Conflict("A tenant must keep at least one active tenant admin")


def removes_admin(membership: Membership, *, new_role: Role | None, new_active: bool | None) -> bool:
    """True when applying the change would stop this membership from acting as an active tenant admin."""
    if membership.role != Role.TENANT_ADMIN.value or not membership.is_active:
        return False
    return (new_role is not None and new_role is not Role.TENANT_ADMIN) or new_active is False
