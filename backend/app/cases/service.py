import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets import service as asset_service
from app.assets.models import Asset
from app.auth.deps import Principal
from app.auth.rbac import Permission, Role, permissions_for
from app.cases import workflow
from app.cases.models import Case, CaseActivity, CaseAsset, CaseCounter, CaseEvidence, CaseIoc
from app.cases.schemas import CaseOut, PersonRef
from app.core.errors import AppError, Conflict
from app.events.search.base import SearchBackend
from app.events.summary import summarize
from app.investigations import iocs
from app.users.models import Membership, User


async def next_number(session: AsyncSession, tenant_id: uuid.UUID) -> int:
    """Atomic per-tenant counter (row lock via upsert), so concurrent creates never share a number."""
    stmt = (
        insert(CaseCounter)
        .values(tenant_id=tenant_id, last=1)
        .on_conflict_do_update(index_elements=[CaseCounter.tenant_id], set_={"last": CaseCounter.last + 1})
        .returning(CaseCounter.last)
    )
    return int((await session.execute(stmt)).scalar_one())


async def log(
    session: AsyncSession,
    principal: Principal,
    case: Case,
    kind: str,
    body: str = "",
    details: dict[str, Any] | None = None,
) -> CaseActivity:
    entry = CaseActivity(
        tenant_id=case.tenant_id,
        case_id=case.id,
        actor_id=principal.user_id,
        kind=kind,
        body=body,
        details=details or {},
    )
    session.add(entry)
    case.updated_at = datetime.now(UTC)
    await session.flush()
    await session.refresh(entry)
    return entry


async def validate_assignee(session: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID) -> User:
    row = (
        await session.execute(
            select(User, Membership.role)
            .join(Membership, Membership.user_id == User.id)
            .where(
                User.id == user_id,
                Membership.tenant_id == tenant_id,
                Membership.is_active.is_(True),
                User.is_active.is_(True),
            )
        )
    ).first()
    if row is None or Permission.CASES_WRITE not in permissions_for(Role(row[1])):
        raise AppError("Assignee must be an active member of this tenant who can work cases")
    user: User = row[0]
    return user


async def case_out(session: AsyncSession, case: Case) -> CaseOut:
    async def count(model: Any) -> int:
        return int(
            (
                await session.execute(select(func.count()).select_from(model).where(model.case_id == case.id))
            ).scalar_one()
        )

    assignee = await session.get(User, case.assignee_id) if case.assignee_id else None
    return CaseOut(
        id=case.id,
        case_id=f"CASE-{case.number:04d}",
        number=case.number,
        title=case.title,
        description=case.description,
        severity=case.severity,
        priority=case.priority,
        status=case.status,
        resolution=case.resolution,
        hunt_id=case.hunt_id,
        created_by=case.created_by,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        assignee=PersonRef(id=assignee.id, email=assignee.email, full_name=assignee.full_name) if assignee else None,
        evidence_count=await count(CaseEvidence),
        ioc_count=await count(CaseIoc),
        asset_count=await count(CaseAsset),
        allowed_transitions=sorted(workflow.TRANSITIONS.get(case.status, set())),
    )


def ensure_open(case: Case) -> None:
    if workflow.is_locked(case.status):
        raise Conflict("Case is closed; reopen it before changing evidence, IOCs or assets")


async def add_evidence(
    session: AsyncSession, backend: SearchBackend, principal: Principal, case: Case, event_ids: list[str], comment: str
) -> list[CaseEvidence]:
    ensure_open(case)
    ids = list(dict.fromkeys(event_ids))
    docs = await backend.get_events(case.tenant_id, ids)  # tenant-scoped lookup
    found = {d["id"]: d for d in docs}
    missing = [i for i in ids if i not in found]
    if missing:
        raise AppError(f"Unknown event ids: {', '.join(missing[:5])}")
    existing = set(
        (
            await session.execute(
                select(CaseEvidence.event_id).where(CaseEvidence.case_id == case.id, CaseEvidence.event_id.in_(ids))
            )
        ).scalars()
    )
    added: list[CaseEvidence] = []
    for i in ids:
        if i in existing:
            continue
        ev = CaseEvidence(
            tenant_id=case.tenant_id,
            case_id=case.id,
            event_id=i,
            comment=comment,
            snapshot=found[i],
            added_by=principal.user_id,
        )
        session.add(ev)
        added.append(ev)
    if not added:
        return added
    new_docs = [found[e.event_id] for e in added]
    await extract_iocs(session, case, new_docs)
    assets = await asset_service.assets_from_events(session, case.tenant_id, new_docs)
    for asset in assets:
        await session.execute(
            insert(CaseAsset)
            .values(id=uuid.uuid4(), tenant_id=case.tenant_id, case_id=case.id, asset_id=asset.id)
            .on_conflict_do_nothing(constraint="uq_case_asset")
        )
    await log(
        session,
        principal,
        case,
        "evidence_added",
        comment,
        {"events": [e.event_id for e in added], "assets_linked": len(assets)},
    )
    return added


async def extract_iocs(session: AsyncSession, case: Case, docs: list[dict[str, Any]]) -> int:
    counts: dict[tuple[str, str], tuple[int, str]] = {}
    for d in docs:
        for c in iocs.extract(d):
            n, ctx = counts.get((c.type, c.value), (0, c.context))
            counts[(c.type, c.value)] = (n + 1, ctx)
    for (type_, value), (n, ctx) in counts.items():
        stmt = (
            insert(CaseIoc)
            .values(
                id=uuid.uuid4(),
                tenant_id=case.tenant_id,
                case_id=case.id,
                type=type_,
                value=value,
                source="extracted",
                occurrences=n,
                context=ctx,
            )
            .on_conflict_do_update(constraint="uq_case_ioc", set_={"occurrences": CaseIoc.occurrences + n})
        )
        await session.execute(stmt)
    return len(counts)


async def recompute_iocs(session: AsyncSession, case: Case) -> int:
    """Rebuild extracted IOCs from the evidence snapshots; manual IOCs are untouched."""
    from sqlalchemy import delete

    await session.execute(delete(CaseIoc).where(CaseIoc.case_id == case.id, CaseIoc.source == "extracted"))
    docs = [
        e
        for (e,) in (await session.execute(select(CaseEvidence.snapshot).where(CaseEvidence.case_id == case.id))).all()
    ]
    return await extract_iocs(session, case, docs)


async def apply_transition(session: AsyncSession, principal: Principal, case: Case, target: str, comment: str) -> None:
    workflow.check_transition(case.status, target, comment)
    previous = case.status
    case.status = target
    if target in ("RESOLVED", "FALSE_POSITIVE", "CLOSED"):
        case.resolution = comment.strip()
    if target == "CLOSED":
        case.closed_at = datetime.now(UTC)
    elif previous == "CLOSED":
        case.closed_at = None
    await log(session, principal, case, "status_change", comment, {"from": previous, "to": target})


def evidence_summary(snapshot: dict[str, Any]) -> str:
    return summarize(snapshot)


async def touch_asset_links(session: AsyncSession, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> Asset | None:
    return (
        await session.execute(select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id))
    ).scalar_one_or_none()


__all__ = ["update"]
