import pytest

from app.auth.rbac import ROLE_PERMISSIONS, TENANT_ROLES, Permission, Role

ANALYST_ROLES = [Role.VIEWER, Role.SOC_ANALYST, Role.THREAT_HUNTER, Role.INCIDENT_RESPONDER]


def test_every_role_has_a_permission_set():
    assert set(ROLE_PERMISSIONS) == set(Role)


def test_super_admin_is_not_assignable_to_tenant_members():
    assert Role.SUPER_ADMIN not in TENANT_ROLES


def test_only_privileged_roles_can_manage():
    for role in ANALYST_ROLES:
        perms = ROLE_PERMISSIONS[role]
        assert Permission.USERS_MANAGE not in perms and Permission.EVENTS_INGEST not in perms
        assert Permission.TENANTS_MANAGE not in perms
    assert Permission.TENANTS_MANAGE not in ROLE_PERMISSIONS[Role.TENANT_ADMIN]
    assert Permission.TENANTS_MANAGE in ROLE_PERMISSIONS[Role.SUPER_ADMIN]


@pytest.mark.parametrize("role", ANALYST_ROLES)
async def test_non_admin_roles_are_denied_privileged_endpoints(client, make, role):
    t = await make.tenant()
    _, h = await make.login_as(t, role)
    assert (await client.get("/api/v1/users", headers=h)).status_code == 403
    assert (
        await client.post(
            "/api/v1/users",
            headers=h,
            json={"email": "x@test.example", "password": "Another-Passw0rd!", "role": "VIEWER"},
        )
    ).status_code == 403
    assert (await client.post("/api/v1/events/ingest", headers=h, json={"events": [{}]})).status_code == 403
    assert (await client.get("/api/v1/tenants", headers=h)).status_code == 403
    assert (await client.post("/api/v1/tenants", headers=h, json={"slug": "evil-co", "name": "x"})).status_code == 403
    # but reading events is allowed
    assert (await client.post("/api/v1/events/search", headers=h, json={})).status_code == 200


async def test_tenant_admin_cannot_manage_platform(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    assert (await client.post("/api/v1/tenants", headers=h, json={"slug": "new-co", "name": "New"})).status_code == 403
    assert (await client.get("/api/v1/users", headers=h)).status_code == 200


async def test_denied_attempts_are_audited(client, make, db):
    from sqlalchemy import select

    from app.audit.models import AuditLog

    t = await make.tenant()
    u, h = await make.login_as(t, Role.VIEWER)
    await client.get("/api/v1/users", headers=h)
    rows = (
        (await db.execute(select(AuditLog).where(AuditLog.actor_id == u.id, AuditLog.action == "authz.denied")))
        .scalars()
        .all()
    )
    assert rows and rows[0].tenant_id == t.id and rows[0].outcome == "denied"


async def test_cannot_create_super_admin_member_or_self_modify(client, make):
    t = await make.tenant()
    admin, h = await make.login_as(t, Role.TENANT_ADMIN)
    r = await client.post(
        "/api/v1/users",
        headers=h,
        json={"email": "sa@test.example", "password": "Another-Passw0rd!", "role": "SUPER_ADMIN"},
    )
    assert r.status_code == 400
    assert (await client.patch(f"/api/v1/users/{admin.id}", headers=h, json={"role": "VIEWER"})).status_code == 400


async def test_super_admin_needs_tenant_context_for_tenant_endpoints(client, make):
    sa = await make.user(None, None, super_admin=True)
    h = make.headers(sa, None)
    assert (await client.post("/api/v1/events/search", headers=h, json={})).status_code == 400
    assert (await client.get("/api/v1/tenants", headers=h)).status_code == 200
    r = await client.post(
        "/api/v1/tenants",
        headers=h,
        json={
            "slug": "created-by-sa",
            "name": "Created",
            "admin_email": "ta@created.example",
            "admin_password": "Another-Passw0rd!",
        },
    )
    assert r.status_code == 201
    login = await client.post(
        "/api/v1/auth/login", json={"email": "ta@created.example", "password": "Another-Passw0rd!"}
    )
    assert login.json()["session"]["role"] == "TENANT_ADMIN"
