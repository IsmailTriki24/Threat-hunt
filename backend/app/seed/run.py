import logging
import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth.rbac import Role
from app.core.security import hash_password
from app.events.schema import Event
from app.events.search.base import SearchBackend
from app.seed import synthetic
from app.tenants.models import Tenant
from app.users.models import Membership, User

log = logging.getLogger("app.seed")

TENANTS = [("acme-bank", "Acme Bank (demo)", True), ("globex-bank", "Globex Bank (demo)", False)]
USERS = [
    ("superadmin@hunt.example", "Platform Admin", None, None),
    ("admin@acme.example", "Acme Admin", "acme-bank", Role.TENANT_ADMIN),
    ("analyst@acme.example", "Acme SOC Analyst", "acme-bank", Role.SOC_ANALYST),
    ("hunter@acme.example", "Acme Threat Hunter", "acme-bank", Role.THREAT_HUNTER),
    ("responder@acme.example", "Acme Incident Responder", "acme-bank", Role.INCIDENT_RESPONDER),
    ("viewer@acme.example", "Acme Viewer", "acme-bank", Role.VIEWER),
    ("admin@globex.example", "Globex Admin", "globex-bank", Role.TENANT_ADMIN),
    ("analyst@globex.example", "Globex SOC Analyst", "globex-bank", Role.SOC_ANALYST),
]


async def seed_demo(sessionmaker: async_sessionmaker[AsyncSession], backend: SearchBackend, password: str) -> str:
    generated = not password
    password = password or secrets.token_urlsafe(18)
    pw_hash = hash_password(password)
    tenant_ids: dict[str, uuid.UUID] = {}
    created_users = 0
    async with sessionmaker() as session:
        for slug, name, _ in TENANTS:
            tenant = (await session.execute(select(Tenant).where(Tenant.slug == slug))).scalar_one_or_none()
            if tenant is None:
                tenant = Tenant(slug=slug, name=name)
                session.add(tenant)
                await session.flush()
                tenant_ids[slug] = tenant.id
                log.info("seeded tenant", extra={"slug": slug})
        for email, full_name, user_slug, role in USERS:
            if (await session.execute(select(User).where(User.email == email))).scalar_one_or_none():
                continue
            user = User(email=email, full_name=full_name, password_hash=pw_hash, is_super_admin=user_slug is None)
            session.add(user)
            await session.flush()
            created_users += 1
            if user_slug and role:
                tenant = (await session.execute(select(Tenant).where(Tenant.slug == user_slug))).scalar_one()
                session.add(Membership(user_id=user.id, tenant_id=tenant.id, role=role.value))
        await session.commit()

    # Telemetry only for tenants created by this run, so re-running never duplicates data.
    for slug, _, with_attack in TENANTS:
        if slug not in tenant_ids:
            continue
        raw = synthetic.generate(with_attack=with_attack, seed=7 if with_attack else 11)
        events = [Event.from_input(e, tenant_ids[slug]) for e in raw]
        for i in range(0, len(events), 500):
            result = await backend.index_events(events[i : i + 500])
            if result.failed:
                log.error("seed events rejected", extra={"tenant": slug, "failed": result.failed[:3]})
        log.info("seeded events", extra={"tenant": slug, "count": len(events)})
        await backend.refresh()
        if with_attack:
            await _seed_case(sessionmaker, backend, tenant_ids[slug])
    return password if generated and created_users else ""


async def _seed_case(
    sessionmaker: async_sessionmaker[AsyncSession], backend: SearchBackend, tenant_id: uuid.UUID
) -> None:
    """A realistic, ready-to-explore investigation built from the synthetic attack chain."""
    from app.assets import service as asset_service
    from app.auth.deps import Principal
    from app.cases import service as case_service
    from app.cases.models import Case
    from app.datasources.models import DataSource
    from app.datasources.service import new_ingest_key
    from app.events.search.query import EventQuery

    async with sessionmaker() as session:
        analyst = (await session.execute(select(User).where(User.email == "analyst@acme.example"))).scalar_one()
        principal = Principal(analyst.id, analyst.email, Role.SOC_ANALYST, tenant_id, False)
        ids: list[str] = []
        for text in ("host.hostname:ws-fin-014 user.name:mharper severity>=60", "user.name:svc_backup severity>=65"):
            res = await backend.search(
                tenant_id, EventQuery(text=text, limit=50, sort=[{"field": "timestamp", "order": "asc"}])
            )
            ids += [h["id"] for h in res.hits]
        case = Case(
            tenant_id=tenant_id,
            number=await case_service.next_number(session, tenant_id),
            title="Suspicious PowerShell from Office on WS-FIN-014",
            severity="HIGH",
            priority="P2",
            description="Word spawned an encoded PowerShell command, followed by C2-like outbound traffic, a "
            "scheduled task, an LSASS memory dump and a network logon to SRV-FILE-02 with svc_backup.",
            assignee_id=analyst.id,
            created_by=analyst.id,
            status="INVESTIGATING",
        )
        session.add(case)
        await session.flush()
        await session.refresh(case)
        await case_service.log(session, principal, case, "created")
        await case_service.log(
            session,
            principal,
            case,
            "status_change",
            "Triage complete; host isolated pending review",
            {"from": "OPEN", "to": "INVESTIGATING"},
        )
        await case_service.add_evidence(
            session, backend, principal, case, list(dict.fromkeys(ids)), "Seeded demo evidence"
        )
        await asset_service.discover(session, backend, tenant_id, 2)
        raw, key_hash = new_ingest_key()
        session.add(
            DataSource(
                tenant_id=tenant_id, name="Sysmon push (demo)", connector_type="sysmon", ingest_key_hash=key_hash
            )
        )
        del raw  # demo source's key is intentionally unrecoverable; rotate it in the UI to obtain one
        await session.commit()
