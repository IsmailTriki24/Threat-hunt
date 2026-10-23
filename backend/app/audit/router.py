import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.models import AuditLog
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.core.db import get_session

router = APIRouter(prefix="/audit", tags=["audit"])


@dataclass
class AuditFilter:
    action: str | None = None
    outcome: str | None = None
    actor_id: uuid.UUID | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = 100
    offset: int = 0

    def apply(self, stmt: Select[Any]) -> Select[Any]:
        if self.action:
            stmt = stmt.where(AuditLog.action.startswith(self.action[:100], autoescape=True))
        if self.outcome:
            stmt = stmt.where(AuditLog.outcome == self.outcome)
        if self.actor_id:
            stmt = stmt.where(AuditLog.actor_id == self.actor_id)
        if self.resource_type:
            stmt = stmt.where(AuditLog.resource_type == self.resource_type)
        if self.resource_id:
            stmt = stmt.where(AuditLog.resource_id == self.resource_id)
        if self.since:
            stmt = stmt.where(AuditLog.created_at >= self.since)
        if self.until:
            stmt = stmt.where(AuditLog.created_at < self.until)
        return stmt.order_by(AuditLog.created_at.desc()).limit(max(1, min(self.limit, 500))).offset(max(0, self.offset))


def _row(r: AuditLog) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "created_at": r.created_at,
        "tenant_id": str(r.tenant_id) if r.tenant_id else None,
        "action": r.action,
        "outcome": r.outcome,
        "actor": r.actor_label,
        "actor_id": str(r.actor_id) if r.actor_id else None,
        "resource_type": r.resource_type,
        "resource_id": r.resource_id,
        "ip": r.ip,
        "request_id": r.request_id,
        "details": r.details,
    }


@router.get("")
async def list_audit(
    f: AuditFilter = Depends(),
    principal: Principal = Depends(require(Permission.AUDIT_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Tenant audit trail. Always scoped to the caller's tenant (platform-level events have no tenant)."""
    rows = await session.execute(f.apply(select(AuditLog).where(AuditLog.tenant_id == principal.tid)))
    return [_row(r) for r in rows.scalars()]


@router.get("/platform")
async def list_platform_audit(
    tenant_id: uuid.UUID | None = None,
    f: AuditFilter = Depends(),
    _: Principal = Depends(require(Permission.AUDIT_PLATFORM, tenant_scoped=False)),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Audit trail across every tenant, plus platform events that belong to none (failed logins, tenant creation)."""
    stmt = select(AuditLog)
    if tenant_id:
        stmt = stmt.where(AuditLog.tenant_id == tenant_id)
    return [_row(r) for r in (await session.execute(f.apply(stmt))).scalars()]
