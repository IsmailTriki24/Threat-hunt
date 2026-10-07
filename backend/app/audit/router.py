import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.models import AuditLog
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.core.db import get_session

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_audit(
    action: str | None = None,
    outcome: str | None = None,
    actor_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
    principal: Principal = Depends(require(Permission.AUDIT_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Tenant audit trail. Always scoped to the caller's tenant (platform-level events have no tenant)."""
    stmt = select(AuditLog).where(AuditLog.tenant_id == principal.tid)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action[:100], autoescape=True))
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        stmt = stmt.where(AuditLog.created_at < until)
    rows = await session.execute(
        stmt.order_by(AuditLog.created_at.desc()).limit(max(1, min(limit, 500))).offset(max(0, offset))
    )
    return [
        {
            "id": str(r.id),
            "created_at": r.created_at,
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
        for r in rows.scalars()
    ]
