import sqlalchemy as sa

from app.audit.models import AuditLog
from app.auth.rbac import Role


async def test_health_and_ready(client):
    assert (await client.get("/health")).json() == {"status": "ok"}
    r = await client.get("/ready")
    assert r.status_code == 200
    comps = r.json()["components"]
    assert comps["postgres"]["status"] == comps["redis"]["status"] == comps["opensearch"]["status"] == "ok"


async def test_metrics_exposed_in_test_env(client):
    await client.get("/health")
    r = await client.get("/metrics")
    assert r.status_code == 200 and "http_requests_total" in r.text


async def test_security_headers_and_request_id(client):
    r = await client.get("/health", headers={"x-request-id": "abc123"})
    assert r.headers["x-request-id"] == "abc123"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    bad = await client.get("/health", headers={"x-request-id": "evil\nheader"})
    assert bad.headers["x-request-id"] != "evil\nheader"


async def test_oversized_body_rejected(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    big = '{"events":[{"x":"' + "a" * (11 * 1024 * 1024) + '"}]}'
    r = await client.post("/api/v1/events/ingest", headers={**h, "content-type": "application/json"}, content=big)
    assert r.status_code == 413


async def test_unhandled_errors_are_generic(client, app, make, monkeypatch):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.VIEWER)

    async def boom(*a, **k):
        raise RuntimeError("secret connection string postgres://user:pw@host")

    monkeypatch.setattr(app.state.search, "search", boom)
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://t") as c:
        r = await c.post("/api/v1/events/search", headers=h, json={})
    assert r.status_code == 500 and "secret" not in r.text and r.json()["error"]["request_id"]


async def test_audit_log_is_append_only(db, client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.VIEWER)
    await client.post("/api/v1/events/search", headers=h, json={"q": "abc"})
    row = (await db.execute(sa.select(AuditLog).where(AuditLog.tenant_id == t.id))).scalars().first()
    assert row and row.action == "event.search" and row.details["q"] == "abc"
    for stmt in ("UPDATE audit_logs SET outcome='x'", "DELETE FROM audit_logs"):
        try:
            await db.execute(sa.text(stmt))
            raise AssertionError("mutation should have been rejected")
        except sa.exc.DBAPIError as exc:
            assert "append-only" in str(exc)
            await db.rollback()


async def test_login_audited_without_password(client, make, db):
    t = await make.tenant()
    u = await make.user(t, Role.VIEWER)
    await client.post("/api/v1/auth/login", json={"email": u.email, "password": "wrong-password-1"})
    rows = (await db.execute(sa.select(AuditLog).where(AuditLog.actor_label == u.email))).scalars().all()
    assert rows and rows[0].outcome == "failure" and "wrong-password" not in str(rows[0].details)
