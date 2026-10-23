"""The platform operator (super admin) provisions tenants, their admins and their log sources."""

import pytest
import sqlalchemy as sa

from app.audit.models import AuditLog
from app.auth.rbac import Role
from app.users.models import Membership, User
from tests.conftest import PASSWORD

T = "/api/v1/tenants"
NEW_PASSWORD = "Another-Passw0rd!"


async def _operator(make):
    sa_user = await make.user(None, None, super_admin=True)
    return sa_user, make.headers(sa_user, None)


async def _new_tenant(client, h, slug, admin=None):
    body = {"slug": slug, "name": slug.title()}
    if admin:
        body |= {"admin_email": admin, "admin_password": NEW_PASSWORD}
    r = await client.post(T, headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def _login(client, email, password=NEW_PASSWORD, tenant_id=None):
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password, "tenant_id": tenant_id})


# ---- tenants ------------------------------------------------------------------------------------------
async def test_operator_sees_every_tenant_with_counts(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "bank-a", "admin@bank-a.example")
    b = await _new_tenant(client, h, "bank-b")
    _, op_in_a = await make.login_as(await make.tenant(), Role.SUPER_ADMIN)  # unrelated tenant exists too
    rows = {r["slug"]: r for r in (await client.get(T, headers=h)).json()}
    assert rows["bank-a"]["member_count"] == 1 and rows["bank-a"]["admin_count"] == 1
    assert rows["bank-b"]["member_count"] == 0 and rows["bank-b"]["data_source_count"] == 0
    assert len(rows) >= 3
    one = (await client.get(f"{T}/{a['id']}", headers=h)).json()
    assert one["slug"] == "bank-a" and one["admin_count"] == 1
    assert (await client.get(f"{T}/{b['id']}", headers=h)).status_code == 200
    assert (await client.get(f"{T}/{'0' * 8}-0000-0000-0000-{'0' * 12}", headers=h)).status_code == 404
    assert op_in_a  # operator acting inside a tenant keeps platform powers
    assert (await client.get(T, headers=op_in_a)).status_code == 200


async def test_tenant_slug_is_unique_and_validated(client, make):
    _, h = await _operator(make)
    await _new_tenant(client, h, "dup-co")
    assert (await client.post(T, headers=h, json={"slug": "dup-co", "name": "x"})).status_code == 409
    assert (await client.post(T, headers=h, json={"slug": "Bad Slug", "name": "x"})).status_code == 422
    assert (
        await client.post(T, headers=h, json={"slug": "ok-co", "name": "x", "admin_email": "a@b.example"})
    ).status_code == 400


async def test_a_new_tenant_admin_can_log_in_and_is_confined_to_their_tenant(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "conf-a", "admin@conf-a.example")
    b = await _new_tenant(client, h, "conf-b", "admin@conf-b.example")
    session = (await _login(client, "admin@conf-a.example")).json()
    assert session["session"]["role"] == "TENANT_ADMIN" and session["session"]["tenant"]["id"] == a["id"]
    assert [t["id"] for t in session["session"]["available_tenants"]] == [a["id"]]
    ha = {"authorization": f"Bearer {session['access_token']}"}
    assert (await client.get(f"{T}/{b['id']}/members", headers=ha)).status_code == 403
    assert (
        await client.get(f"{T}/{a['id']}/members", headers=ha)
    ).status_code == 403  # platform route, even for their own
    assert (await client.get(T, headers=ha)).status_code == 403
    r = await client.post(
        "/api/v1/auth/switch-tenant", headers={**ha, "x-requested-with": "threat-hunt"}, json={"tenant_id": b["id"]}
    )
    assert r.status_code == 403


async def test_disabling_a_tenant_locks_everyone_out_immediately(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "lock-a", "admin@lock-a.example")
    token = (await _login(client, "admin@lock-a.example")).json()["access_token"]
    ha = {"authorization": f"Bearer {token}"}
    assert (await client.get("/api/v1/users", headers=ha)).status_code == 200
    assert (await client.patch(f"{T}/{a['id']}", headers=h, json={"is_active": False})).json()["is_active"] is False
    assert (await client.get("/api/v1/users", headers=ha)).status_code == 401
    assert (await _login(client, "admin@lock-a.example")).status_code in (401, 403)
    await client.patch(f"{T}/{a['id']}", headers=h, json={"is_active": True})
    assert (await client.get("/api/v1/users", headers=ha)).status_code == 200


# ---- members ------------------------------------------------------------------------------------------
async def test_operator_adds_members_and_reuses_an_account_across_tenants(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "mem-a", "admin@mem-a.example")
    b = await _new_tenant(client, h, "mem-b", "admin@mem-b.example")
    body = {
        "email": "Shared@Example.com",
        "full_name": "Shared Analyst",
        "password": NEW_PASSWORD,
        "role": "SOC_ANALYST",
    }
    r = await client.post(f"{T}/{a['id']}/members", headers=h, json=body)
    assert r.status_code == 201 and r.json()["email"] == "shared@example.com"
    # the same person in a second tenant: no password needed, different role
    r = await client.post(f"{T}/{b['id']}/members", headers=h, json={"email": "shared@example.com", "role": "VIEWER"})
    assert r.status_code == 201 and r.json()["role"] == "VIEWER"
    assert (
        await client.post(f"{T}/{b['id']}/members", headers=h, json={"email": "shared@example.com", "role": "VIEWER"})
    ).status_code == 409
    login = (await _login(client, "shared@example.com")).json()["session"]
    assert {t["slug"] for t in login["available_tenants"]} == {"mem-a", "mem-b"}
    in_b = (await _login(client, "shared@example.com", tenant_id=b["id"])).json()["session"]
    assert in_b["role"] == "VIEWER" and "datasources:manage" not in in_b["permissions"]
    members = (await client.get(f"{T}/{a['id']}/members", headers=h)).json()
    assert {m["email"] for m in members} == {"admin@mem-a.example", "shared@example.com"}


async def test_member_creation_rules(client, make, db):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "rule-a")
    m = f"{T}/{a['id']}/members"
    assert (
        await client.post(m, headers=h, json={"email": "n@x.example", "role": "VIEWER"})
    ).status_code == 400  # needs password
    assert (
        await client.post(m, headers=h, json={"email": "n@x.example", "password": NEW_PASSWORD, "role": "SUPER_ADMIN"})
    ).status_code == 400
    assert (
        await client.post(m, headers=h, json={"email": "n@x.example", "password": "short", "role": "VIEWER"})
    ).status_code == 422
    other_sa, _ = await _operator(make)
    assert (await client.post(m, headers=h, json={"email": other_sa.email, "role": "VIEWER"})).status_code == 400
    assert (
        await client.post(
            f"{T}/{'0' * 8}-0000-0000-0000-{'0' * 12}/members",
            headers=h,
            json={"email": "n@x.example", "password": NEW_PASSWORD, "role": "VIEWER"},
        )
    ).status_code == 404
    count = (
        await db.execute(sa.select(sa.func.count()).select_from(Membership).where(Membership.tenant_id == a["id"]))
    ).scalar_one()
    assert count == 0


async def test_operator_changes_role_deactivates_and_resets_password(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "upd-a", "admin@upd-a.example")
    await client.post(
        f"{T}/{a['id']}/members",
        headers=h,
        json={"email": "u@upd-a.example", "password": NEW_PASSWORD, "role": "VIEWER"},
    )
    uid = next(
        m["user_id"]
        for m in (await client.get(f"{T}/{a['id']}/members", headers=h)).json()
        if m["email"] == "u@upd-a.example"
    )
    path = f"{T}/{a['id']}/members/{uid}"
    assert (await client.patch(path, headers=h, json={"role": "THREAT_HUNTER"})).json()["role"] == "THREAT_HUNTER"
    assert (await client.patch(path, headers=h, json={"role": "SUPER_ADMIN"})).status_code == 400
    old = (await _login(client, "u@upd-a.example")).json()["access_token"]
    # a password reset signs the user out everywhere and the old password stops working
    assert (await client.patch(path, headers=h, json={"new_password": "Rotated-Passw0rd-1"})).status_code == 200
    assert (await _login(client, "u@upd-a.example")).status_code == 401
    assert (await _login(client, "u@upd-a.example", "Rotated-Passw0rd-1")).status_code == 200
    assert old  # access tokens are short-lived; refresh tokens were revoked
    assert (await client.patch(path, headers=h, json={"is_active": False})).json()["is_active"] is False
    assert (await _login(client, "u@upd-a.example", "Rotated-Passw0rd-1")).status_code in (401, 403)


async def test_a_tenant_can_never_be_left_without_an_admin(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "last-a", "admin@last-a.example")
    admin_id = (await client.get(f"{T}/{a['id']}/members", headers=h)).json()[0]["user_id"]
    path = f"{T}/{a['id']}/members/{admin_id}"
    assert (await client.patch(path, headers=h, json={"role": "VIEWER"})).status_code == 409
    assert (await client.patch(path, headers=h, json={"is_active": False})).status_code == 409
    second = (
        await client.post(
            f"{T}/{a['id']}/members",
            headers=h,
            json={"email": "two@last-a.example", "password": NEW_PASSWORD, "role": "TENANT_ADMIN"},
        )
    ).json()
    assert (await client.patch(path, headers=h, json={"role": "VIEWER"})).status_code == 200  # now there is another
    assert (
        await client.patch(f"{T}/{a['id']}/members/{second['user_id']}", headers=h, json={"is_active": False})
    ).status_code == 409


async def test_tenant_admin_cannot_remove_the_other_admin_from_a_tenant_without_one(client, make):
    t = await make.tenant()
    admin, ha = await make.login_as(t, Role.TENANT_ADMIN)
    other, _ = await make.login_as(t, Role.TENANT_ADMIN)
    assert (await client.patch(f"/api/v1/users/{other.id}", headers=ha, json={"role": "VIEWER"})).status_code == 200
    assert (
        await client.patch(f"/api/v1/users/{admin.id}", headers=ha, json={"role": "VIEWER"})
    ).status_code == 400  # self


# ---- log sources are assigned to a tenant by the operator ----------------------------------------------
async def test_operator_assigns_log_sources_and_each_tenant_sees_only_its_own(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "src-a", "admin@src-a.example")
    await _new_tenant(client, h, "src-b", "admin@src-b.example")
    sessions = {}
    for slug in ("a", "b"):
        token = (await _login(client, f"admin@src-{slug}.example")).json()["access_token"]
        sessions[slug] = {"authorization": f"Bearer {token}"}
    # the operator switches into tenant A and attaches two sources
    sw = await client.post(
        "/api/v1/auth/switch-tenant", headers={**h, "x-requested-with": "threat-hunt"}, json={"tenant_id": a["id"]}
    )
    assert sw.status_code == 200
    op_a = {"authorization": f"Bearer {sw.json()['access_token']}"}
    for name in ("LogRhythm", "Trend"):
        r = await client.post(
            "/api/v1/data-sources", headers=op_a, json={"name": name, "connector_type": "sysmon", "config": {}}
        )
        assert r.status_code == 201, r.text
    assert {d["name"] for d in (await client.get("/api/v1/data-sources", headers=sessions["a"])).json()} == {
        "LogRhythm",
        "Trend",
    }
    assert (await client.get("/api/v1/data-sources", headers=sessions["b"])).json() == []
    summary = {t["slug"]: t for t in (await client.get(T, headers=h)).json()}
    assert summary["src-a"]["data_source_count"] == 2 and summary["src-b"]["data_source_count"] == 0
    assert (
        await client.post(
            "/api/v1/data-sources", headers=sessions["a"], json={"name": "mine", "connector_type": "sysmon"}
        )
    ).status_code == 403


# ---- platform audit -------------------------------------------------------------------------------------
async def test_platform_audit_spans_tenants_and_is_operator_only(client, make):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "aud-a", "admin@aud-a.example")
    b = await _new_tenant(client, h, "aud-b")
    await client.post(
        f"{T}/{b['id']}/members",
        headers=h,
        json={"email": "x@aud-b.example", "password": NEW_PASSWORD, "role": "VIEWER"},
    )
    everything = (await client.get("/api/v1/audit/platform?action=tenant.", headers=h)).json()
    assert {"tenant.create", "tenant.member_add"} <= {r["action"] for r in everything}
    only_b = (await client.get(f"/api/v1/audit/platform?tenant_id={b['id']}", headers=h)).json()
    assert only_b and {r["tenant_id"] for r in only_b} == {b["id"]}
    assert all(r["actor"] for r in only_b)
    token = (await _login(client, "admin@aud-a.example")).json()["access_token"]
    ha = {"authorization": f"Bearer {token}"}
    assert (await client.get("/api/v1/audit/platform", headers=ha)).status_code == 403
    own = (await client.get("/api/v1/audit", headers=ha)).json()
    assert {r["tenant_id"] for r in own} <= {a["id"]}  # a tenant admin still sees only their own tenant


async def test_member_changes_never_log_the_password(client, make, db):
    _, h = await _operator(make)
    a = await _new_tenant(client, h, "log-a", "admin@log-a.example")
    uid = (await client.get(f"{T}/{a['id']}/members", headers=h)).json()[0]["user_id"]
    await client.patch(f"{T}/{a['id']}/members/{uid}", headers=h, json={"new_password": "Super-Secret-Passw0rd"})
    rows = (await db.execute(sa.select(AuditLog).where(AuditLog.action == "tenant.member_update"))).scalars().all()
    assert rows and all("Super-Secret" not in str(r.details) for r in rows)
    assert any(r.details.get("password_reset") is True for r in rows)


# ---- bootstrap -------------------------------------------------------------------------------------------
async def test_cli_create_tenant_provisions_tenant_and_admin(app, db):
    from app.cli import _create_tenant

    await _create_tenant(app.state.sessionmaker, "cli-bank", "CLI Bank", "Admin@Cli-Bank.example", PASSWORD)
    user = (await db.execute(sa.select(User).where(User.email == "admin@cli-bank.example"))).scalar_one()
    role = (await db.execute(sa.select(Membership.role).where(Membership.user_id == user.id))).scalar_one()
    assert role == "TENANT_ADMIN" and not user.is_super_admin
    with pytest.raises(SystemExit, match="slug already exists"):
        await _create_tenant(app.state.sessionmaker, "cli-bank", "Again", "other@cli-bank.example", PASSWORD)
    with pytest.raises(SystemExit, match="already registered"):
        await _create_tenant(app.state.sessionmaker, "cli-bank-2", "Two", "admin@cli-bank.example", PASSWORD)
