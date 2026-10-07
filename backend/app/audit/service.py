import logging
import uuid
from typing import Any

from fastapi import Request

from app.audit.models import AuditLog
from app.auth.deps import Principal

log = logging.getLogger("app.audit")

_SENSITIVE = {"password", "token", "secret", "authorization"}


def _scrub(details: dict[str, Any]) -> dict[str, Any]:
    return {k: ("[redacted]" if k.lower() in _SENSITIVE else v) for k, v in details.items()}


async def record(
    request: Request,
    action: str,
    outcome: str = "success",
    *,
    principal: Principal | None = None,
    tenant_id: uuid.UUID | None = None,
    actor_label: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Persist an audit record in its own transaction so it survives a rolled-back request."""
    entry = AuditLog(
        tenant_id=tenant_id or (principal.tenant_id if principal else None),
        actor_id=principal.user_id if principal else None,
        actor_label=(principal.email if principal else actor_label or "")[:320] or None,
        action=action,
        outcome=outcome,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:256] or None,
        request_id=getattr(request.state, "request_id", None),
        details=_scrub(details or {}),
    )
    try:
        async with request.app.state.sessionmaker() as session:
            session.add(entry)
            await session.commit()
    except Exception:
        # Never let an audit failure leak details to the client; surface loudly to operators.
        log.exception("failed to persist audit record", extra={"audit_action": action})
        raise
