"""Moving a tenant (settings, members, log sources and IOC feeds with credentials) between deployments."""

import json
import stat
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa

from app.auth.rbac import Role
from app.cli import _export_tenant, _import_tenant
from app.core.config import get_settings
from app.core.crypto import decrypt_json
from app.core.errors import AppError, Conflict
from app.datasources import service as ds_service
from app.datasources.models import DataSource
from app.iochunt.models import IocFeed
from app.tenants import bundle
from app.tenants.models import Tenant
from app.users.models import Membership, User
from tests.conftest import PASSWORD

PASS = "correct horse battery staple"
SECRET = "SUPER-SECRET-TOKEN-123"
FEED_SECRET = "FEED-API-KEY-456"


async def _seed(make, app):
    """A tenant with an admin, an analyst, one pull source with a credential, one push source and two IOC feeds."""
    t = await make.tenant("Bank Of Test")
    admin, _ = await make.login_as(t, Role.TENANT_ADMIN)
    analyst, _ = await make.login_as(t, Role.SOC_ANALYST)
    async with app.state.sessionmaker() as s:
        s.add(
            DataSource(
                tenant_id=t.id,
                name="LR",
                connector_type="generic_rest",
                config={"url": "https://siem.bank.example/api"},
                secrets_enc=ds_service.encrypt_secrets(get_settings(), {"authorization": SECRET}),
            )
        )
        s.add(DataSource(tenant_id=t.id, name="push", connector_type="sysmon", config={}, enabled=False))
        s.add(
            IocFeed(
                tenant_id=t.id,
                name="OTX",
                feed_type="otx",
                config={"max_pages": 5},
                secrets_enc=ds_service.encrypt_secrets(get_settings(), {"api_key": FEED_SECRET}),
                interval_minutes=120,
                max_age_days=30,
                min_confidence=40,
                max_items=900,
                last_run_at=datetime.now(UTC),
                last_status="error",
                last_detail="old failure",
            )
        )
        s.add(IocFeed(tenant_id=t.id, name="Feodo", feed_type="feodo", config={}, enabled=False))
        await s.commit()
    return t, admin, analyst


async def _export(app, slug):
    async with app.state.sessionmaker() as s:
        return await bundle.export_tenant(s, get_settings(), slug)


async def _import(app, payload, slug=None):
    async with app.state.sessionmaker() as s:
        out = await bundle.import_tenant(s, get_settings(), payload, slug)
        await s.commit()
        return out


async def test_round_trip_recreates_the_tenant_its_sources_and_credentials(app, make, db):
    t, admin, analyst = await _seed(make, app)
    payload = await _export(app, t.slug)
    # through the file format, as a real move would
    payload = bundle.unseal(bundle.seal(payload, PASS), PASS)
    out = await _import(app, payload, slug="bank-copy")
    assert (
        out["data_sources"] == 2 and out["feeds"] == 2 and out["members_attached"] == 2 and out["members_created"] == 0
    )

    copy = (await db.execute(sa.select(Tenant).where(Tenant.slug == "bank-copy"))).scalar_one()
    assert copy.name == "Bank Of Test" and copy.id != t.id
    sources = {
        d.name: d for d in (await db.execute(sa.select(DataSource).where(DataSource.tenant_id == copy.id))).scalars()
    }
    assert sources["LR"].config == {"url": "https://siem.bank.example/api"}
    assert decrypt_json(get_settings(), sources["LR"].secrets_enc) == {"authorization": SECRET}
    assert sources["push"].enabled is False
    roles = dict(
        (await db.execute(sa.select(Membership.user_id, Membership.role).where(Membership.tenant_id == copy.id))).all()
    )
    assert roles == {admin.id: "TENANT_ADMIN", analyst.id: "SOC_ANALYST"}
    # fresh runtime state and fresh ingest keys: nothing is carried over from the source deployment
    assert all(d.events_total == 0 and d.cursor is None and d.ingest_key_hash for d in sources.values())
    original = (
        await db.execute(sa.select(DataSource).where(DataSource.tenant_id == t.id, DataSource.name == "push"))
    ).scalar_one()
    assert original.ingest_key_hash != sources["push"].ingest_key_hash


async def test_feeds_arrive_with_their_settings_and_credentials_but_not_their_run_history(app, make, db):
    t, *_ = await _seed(make, app)
    payload = bundle.unseal(bundle.seal(await _export(app, t.slug), PASS), PASS)
    await _import(app, payload, slug="bank-feeds")
    copy = (await db.execute(sa.select(Tenant).where(Tenant.slug == "bank-feeds"))).scalar_one()
    feeds = {f.name: f for f in (await db.execute(sa.select(IocFeed).where(IocFeed.tenant_id == copy.id))).scalars()}
    otx = feeds["OTX"]
    assert (otx.feed_type, otx.config, otx.interval_minutes, otx.max_age_days) == ("otx", {"max_pages": 5}, 120, 30)
    assert (otx.min_confidence, otx.max_items, otx.enabled) == (40, 900, True)
    assert decrypt_json(get_settings(), otx.secrets_enc) == {"api_key": FEED_SECRET}
    assert feeds["Feodo"].enabled is False and feeds["Feodo"].secrets_enc is None
    # runs at the next refresh, with no history carried over from the other deployment
    assert otx.last_run_at is None and otx.last_status == "" and otx.last_detail == ""
    assert "FEED-API-KEY-456" not in json.dumps(bundle.seal(payload, PASS).decode())


async def test_a_bundle_written_before_feeds_were_moved_still_imports(app, make, db):
    t, *_ = await _seed(make, app)
    payload = await _export(app, t.slug)
    del payload["feeds"]
    out = await _import(app, payload, slug="bank-old-bundle")
    assert out["feeds"] == 0 and out["data_sources"] == 2


async def test_an_unknown_feed_type_stops_the_whole_import(app, make, db):
    t, *_ = await _seed(make, app)
    payload = await _export(app, t.slug)
    payload["feeds"].append({**payload["feeds"][0], "name": "bad", "feed_type": "no-such-feed"})
    with pytest.raises(AppError):
        await _import(app, payload, slug="bank-bad-feed")
    assert (await db.execute(sa.select(Tenant).where(Tenant.slug == "bank-bad-feed"))).first() is None


async def test_only_push_sources_get_an_ingest_key_printed(app, make):
    t, *_ = await _seed(make, app)
    out = await _import(app, await _export(app, t.slug), slug="bank-keys")
    assert list(out["ingest_keys"]) == ["push"] and out["ingest_keys"]["push"].startswith(ds_service.KEY_PREFIX)


async def test_members_arrive_with_a_working_password(app, make, client):
    t, *_ = await _seed(make, app)
    payload = await _export(app, t.slug)
    fresh = "new-person@bank.example"
    payload["members"] = [{**payload["members"][0], "email": fresh}]  # an account this deployment has never seen
    from app.core.security import hash_password

    payload["members"][0]["password_hash"] = hash_password(PASSWORD)
    out = await _import(app, payload, slug="bank-people")
    assert out["members_created"] == 1
    login = await client.post("/api/v1/auth/login", json={"email": fresh, "password": PASSWORD})
    assert login.status_code == 200 and login.json()["session"]["tenant"]["slug"] == "bank-people"


async def test_super_admins_are_never_exported(app, make, db):
    t, *_ = await _seed(make, app)
    sa_user = await make.user(None, None, super_admin=True)
    async with app.state.sessionmaker() as s:
        s.add(Membership(user_id=sa_user.id, tenant_id=t.id, role=Role.VIEWER.value))
        await s.commit()
    payload = await _export(app, t.slug)
    assert sa_user.email not in {m["email"] for m in payload["members"]}


def test_the_sealed_file_reveals_nothing_without_the_passphrase():
    payload = {
        "tenant": {"name": "Bank Of Test"},
        "data_sources": [{"secrets": {"authorization": SECRET}, "config": {"url": "https://10.9.8.7"}}],
    }
    blob = bundle.seal(payload, PASS)
    for leaked in (SECRET.encode(), b"Bank Of Test", b"10.9.8.7", b"authorization"):
        assert leaked not in blob
    assert json.loads(blob)["format"] == 1
    assert bundle.unseal(blob, PASS) == payload
    assert bundle.seal(payload, PASS) != blob  # fresh salt every time


def test_wrong_passphrase_and_tampering_are_refused_with_one_message():
    blob = bundle.seal({"tenant": {}}, PASS)
    with pytest.raises(AppError, match="Wrong passphrase"):
        bundle.unseal(blob, "not the passphrase at all")
    env = json.loads(blob)
    env["token"] = env["token"][:-4] + ("AAAA" if not env["token"].endswith("AAAA") else "BBBB")
    with pytest.raises(AppError, match="Wrong passphrase"):
        bundle.unseal(json.dumps(env).encode(), PASS)
    with pytest.raises(AppError, match="Wrong passphrase"):
        bundle.unseal(b"not json", PASS)


async def test_import_never_touches_an_existing_tenant(app, make, db):
    t, *_ = await _seed(make, app)
    payload = await _export(app, t.slug)
    before = (
        await db.execute(sa.select(sa.func.count()).select_from(DataSource).where(DataSource.tenant_id == t.id))
    ).scalar_one()
    with pytest.raises(Conflict, match="already exists"):
        await _import(app, payload)  # same slug as the source tenant
    after = (
        await db.execute(sa.select(sa.func.count()).select_from(DataSource).where(DataSource.tenant_id == t.id))
    ).scalar_one()
    assert before == after == 2


async def test_import_is_all_or_nothing(app, make, db):
    t, *_ = await _seed(make, app)
    payload = await _export(app, t.slug)
    payload["data_sources"].append(
        {"name": "x", "connector_type": "no-such-connector", "config": {}, "secrets": {}, "enabled": True}
    )
    with pytest.raises(AppError):
        await _import(app, payload, slug="bank-broken")
    assert (await db.execute(sa.select(Tenant).where(Tenant.slug == "bank-broken"))).first() is None
    with pytest.raises(AppError, match="not a tenant bundle"):
        await _import(app, {"nonsense": True}, slug="bank-nonsense")


async def test_cli_export_writes_a_private_file_and_never_overwrites_then_import_reads_it(app, make, db, tmp_path):
    t, *_ = await _seed(make, app)
    out = tmp_path / "bank.tenant-bundle"
    await _export_tenant(get_settings(), app.state.sessionmaker, t.slug, str(out), PASS)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        await _export_tenant(get_settings(), app.state.sessionmaker, t.slug, str(out), PASS)
    with pytest.raises(SystemExit, match="No tenant"):
        await _export_tenant(get_settings(), app.state.sessionmaker, "nobody", str(tmp_path / "x"), PASS)
    with pytest.raises(SystemExit, match="Wrong passphrase"):
        await _import_tenant(get_settings(), app.state.sessionmaker, str(out), "wrong wrong wrong", "bank-cli")
    await _import_tenant(get_settings(), app.state.sessionmaker, str(out), PASS, "bank-cli")
    assert (await db.execute(sa.select(Tenant).where(Tenant.slug == "bank-cli"))).scalar_one()
    assert (
        await db.execute(sa.select(sa.func.count()).select_from(User).where(User.email.like("u-%")))
    ).scalar_one() > 0
