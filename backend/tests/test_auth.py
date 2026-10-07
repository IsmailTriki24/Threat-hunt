import httpx

from app.auth.rbac import Role
from tests.conftest import PASSWORD

CSRF = {"x-requested-with": "threat-hunt"}


async def _login(client: httpx.AsyncClient, email: str, password: str = PASSWORD, **extra: object) -> httpx.Response:
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password, **extra})


async def test_login_success_returns_session_and_cookie(client, make):
    t = await make.tenant()
    u = await make.user(t, Role.SOC_ANALYST)
    r = await _login(client, u.email)
    assert r.status_code == 200
    body = r.json()
    assert body["session"]["role"] == "SOC_ANALYST"
    assert body["session"]["tenant"]["id"] == str(t.id)
    assert "events:read" in body["session"]["permissions"] and "events:ingest" not in body["session"]["permissions"]
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api/v1/auth" in cookie
    assert "refresh_token" not in body


async def test_login_failures_are_uniform(client, make):
    t = await make.tenant()
    u = await make.user(t, Role.VIEWER)
    wrong_pw = await _login(client, u.email, "nope-nope-nope-1")
    no_user = await _login(client, "ghost@test.example")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json()["error"]["message"] == no_user.json()["error"]["message"]


async def test_login_rate_limited_per_email(client, make):
    t = await make.tenant()
    u = await make.user(t, Role.VIEWER)
    codes = [(await _login(client, u.email, "bad-password-12")).status_code for _ in range(12)]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


async def test_cannot_login_into_foreign_tenant(client, make):
    a, b = await make.tenant(), await make.tenant()
    u = await make.user(a, Role.TENANT_ADMIN)
    r = await _login(client, u.email, tenant_id=str(b.id))
    assert r.status_code in (401, 403)


async def test_me_and_protected_routes_need_token(client, make):
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    assert (await client.get("/api/v1/events/fields", headers={"authorization": "Bearer garbage"})).status_code == 401


async def test_refresh_rotates_and_detects_reuse(client, make):
    t = await make.tenant()
    u = await make.user(t, Role.SOC_ANALYST)
    r = await _login(client, u.email)
    old = r.cookies["refresh_token"]
    client.cookies.set("refresh_token", old, path="/api/v1/auth")

    r2 = await client.post("/api/v1/auth/refresh", headers=CSRF)
    assert r2.status_code == 200
    new = r2.cookies["refresh_token"]
    assert new != old

    # replaying the already-rotated token is treated as theft and burns the whole family
    client.cookies.set("refresh_token", old, path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh", headers=CSRF)).status_code == 401
    client.cookies.set("refresh_token", new, path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh", headers=CSRF)).status_code == 401


async def test_refresh_requires_csrf_header(client, make):
    t = await make.tenant()
    u = await make.user(t, Role.SOC_ANALYST)
    r = await _login(client, u.email)
    client.cookies.set("refresh_token", r.cookies["refresh_token"], path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 400


async def test_logout_revokes_refresh_token(client, make):
    t = await make.tenant()
    u = await make.user(t, Role.SOC_ANALYST)
    r = await _login(client, u.email)
    tok = r.cookies["refresh_token"]
    client.cookies.set("refresh_token", tok, path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/logout", headers=CSRF)).status_code == 204
    client.cookies.set("refresh_token", tok, path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh", headers=CSRF)).status_code == 401


async def test_deactivated_membership_invalidates_access_token_immediately(client, make, app):
    t = await make.tenant()
    admin, admin_h = await make.login_as(t, Role.TENANT_ADMIN)
    victim, victim_h = await make.login_as(t, Role.SOC_ANALYST)
    assert (await client.get("/api/v1/auth/me", headers=victim_h)).status_code == 200
    r = await client.patch(f"/api/v1/users/{victim.id}", json={"is_active": False}, headers=admin_h)
    assert r.status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=victim_h)).status_code == 401


async def test_expired_and_forged_tokens_rejected(client, make):
    import jwt as pyjwt

    t = await make.tenant()
    u = await make.user(t, Role.TENANT_ADMIN)
    forged = pyjwt.encode(
        {
            "sub": str(u.id),
            "tid": str(t.id),
            "typ": "access",
            "iss": "threat-hunt",
            "aud": "threat-hunt-api",
            "iat": 0,
            "exp": 9999999999,
        },
        "wrong-key-wrong-key-wrong-key-123456",
        "HS256",
    )
    assert (await client.get("/api/v1/auth/me", headers={"authorization": f"Bearer {forged}"})).status_code == 401
    none_alg = pyjwt.encode({"sub": str(u.id)}, key="", algorithm="none")
    assert (await client.get("/api/v1/auth/me", headers={"authorization": f"Bearer {none_alg}"})).status_code == 401
