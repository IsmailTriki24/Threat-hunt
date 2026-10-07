from datetime import timedelta

from sqlalchemy import select

from app.events.search.query import EventQuery, TimeRange
from app.seed.run import seed_demo
from app.tenants.models import Tenant
from app.users.models import Membership, User


async def test_seed_creates_isolated_demo_tenants_and_is_idempotent(app):
    sm, backend = app.state.sessionmaker, app.state.search
    assert await seed_demo(sm, backend, "Demo-Passw0rd-Test!") == ""
    await app.state.opensearch.indices.refresh(index=backend.pattern, ignore_unavailable=True)
    async with sm() as s:
        tenants = {t.slug: t for t in (await s.execute(select(Tenant))).scalars() if t.slug.endswith("-bank")}
        rows = (await s.execute(select(User.email, Membership.role, Membership.tenant_id).join(Membership))).all()
    by_email = {r.email: r for r in rows}
    assert by_email["analyst@acme.example"].tenant_id == tenants["acme-bank"].id
    assert by_email["analyst@globex.example"].tenant_id == tenants["globex-bank"].id
    assert by_email["admin@acme.example"].role == "TENANT_ADMIN"
    async with sm() as s:
        assert (
            (await s.execute(select(User).where(User.email == "superadmin@hunt.example"))).scalar_one().is_super_admin
        )

    wide = TimeRange.last(timedelta(hours=26))
    acme = await backend.search(tenants["acme-bank"].id, EventQuery(q="comsvcs", time_range=wide))
    globex = await backend.search(tenants["globex-bank"].id, EventQuery(q="comsvcs", time_range=wide))
    assert acme.total == 1 and globex.total == 0

    before = (await backend.search(tenants["acme-bank"].id, EventQuery(time_range=wide))).total
    await seed_demo(sm, backend, "Demo-Passw0rd-Test!")
    await app.state.opensearch.indices.refresh(index=backend.pattern, ignore_unavailable=True)
    assert (await backend.search(tenants["acme-bank"].id, EventQuery(time_range=wide))).total == before


async def test_generated_seed_password_is_returned_once(app, make):
    # Everything already exists, so nothing is regenerated; the function must not invent credentials.
    assert await seed_demo(app.state.sessionmaker, app.state.search, "") == ""


async def test_seed_builds_demo_case_assets_and_data_source(app):
    import sqlalchemy as sa

    from app.assets.models import Asset
    from app.cases.models import Case, CaseEvidence, CaseIoc
    from app.datasources.models import DataSource

    async with app.state.sessionmaker() as s:
        acme = (await s.execute(sa.select(Tenant).where(Tenant.slug == "acme-bank"))).scalar_one()
        case = (await s.execute(sa.select(Case).where(Case.tenant_id == acme.id))).scalar_one()
        evidence = (
            await s.execute(sa.select(sa.func.count()).select_from(CaseEvidence).where(CaseEvidence.case_id == case.id))
        ).scalar_one()
        iocs = {v for (v,) in (await s.execute(sa.select(CaseIoc.value).where(CaseIoc.case_id == case.id))).all()}
        hosts = {
            k
            for (k,) in (
                await s.execute(sa.select(Asset.key).where(Asset.tenant_id == acme.id, Asset.type == "host"))
            ).all()
        }
        sources = (await s.execute(sa.select(DataSource.name).where(DataSource.tenant_id == acme.id))).scalars().all()
    assert case.status == "INVESTIGATING" and case.number == 1 and evidence >= 8
    assert "203.0.113.45" in iocs and "cdn-update-check.example" in iocs
    assert {"ws-fin-014", "srv-file-02"} <= hosts and sources == ["Sysmon push (demo)"]
