"""Tenant isolation is a security requirement: these tests attack it from every direction."""

import uuid

import jwt as pyjwt

from app.auth.rbac import Role
from app.core.config import get_settings
from app.events.schema import Event
from tests.helpers import ev


async def _two_tenants(make):
    a, b = await make.tenant(), await make.tenant()
    await make.index(a, [ev(host={"hostname": "A-HOST"}, process={"name": "secret-a.exe"})])
    await make.index(b, [ev(host={"hostname": "B-HOST"}, process={"name": "secret-b.exe"})])
    return a, b


async def test_search_only_returns_own_tenant(client, make):
    a, b = await _two_tenants(make)
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    _, hb = await make.login_as(b, Role.SOC_ANALYST)
    ra = (await client.post("/api/v1/events/search", headers=ha, json={})).json()
    rb = (await client.post("/api/v1/events/search", headers=hb, json={})).json()
    assert {h["host"]["hostname"] for h in ra["hits"]} == {"A-HOST"}
    assert {h["host"]["hostname"] for h in rb["hits"]} == {"B-HOST"}
    assert all(h["tenant_id"] == str(a.id) for h in ra["hits"])


async def test_get_event_across_tenants_is_404(client, make):
    a, b = await _two_tenants(make)
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    _, hb = await make.login_as(b, Role.SOC_ANALYST)
    a_event = (await client.post("/api/v1/events/search", headers=ha, json={})).json()["hits"][0]["id"]
    assert (await client.get(f"/api/v1/events/{a_event}", headers=ha)).status_code == 200
    assert (await client.get(f"/api/v1/events/{a_event}", headers=hb)).status_code == 404


async def test_aggregations_do_not_leak_other_tenants(client, make):
    a, b = await _two_tenants(make)
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    r = (
        await client.post(
            "/api/v1/events/search",
            headers=ha,
            json={"aggregations": [{"name": "hosts", "field": "host.hostname", "size": 50}]},
        )
    ).json()
    assert [bk["key"] for bk in r["aggregations"]["hosts"]["buckets"]] == ["a-host"]


async def test_client_supplied_tenant_id_is_rejected_in_query_and_filters(client, make):
    a, b = await _two_tenants(make)
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    r = await client.post("/api/v1/events/search", headers=ha, json={"tenant_id": str(b.id)})
    assert r.status_code == 422
    r = await client.post(
        "/api/v1/events/search", headers=ha, json={"filters": [{"field": "tenant_id", "op": "eq", "value": str(b.id)}]}
    )
    assert r.status_code == 422
    # query-string / header spoofing is simply ignored
    r = await client.post(f"/api/v1/events/search?tenant_id={b.id}", headers={**ha, "x-tenant-id": str(b.id)}, json={})
    assert {h["host"]["hostname"] for h in r.json()["hits"]} == {"A-HOST"}


async def test_query_string_cannot_widen_scope(client, make):
    a, b = await _two_tenants(make)
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    for q in [f"tenant_id:{b.id}", "*", 'x" OR tenant_id:*', "secret-b.exe", "secret-b*", f'"{b.id}"']:
        r = await client.post("/api/v1/events/search", headers=ha, json={"q": q})
        assert r.status_code == 200, q
        assert all(h["tenant_id"] == str(a.id) for h in r.json()["hits"]), q


async def test_ingest_cannot_write_into_another_tenant(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    payload = {
        "source_type": "canonical",
        "events": [
            {"timestamp": "2026-01-01T00:00:00Z", "source": "sysmon", "event_type": "other", "tenant_id": str(b.id)}
        ],
    }
    r = (await client.post("/api/v1/events/ingest", headers=ha, json=payload)).json()
    assert r["accepted"] == 0 and r["rejected"]  # extra fields (incl. tenant_id) are forbidden
    # even when accepted, tenant is stamped from the principal
    payload["events"][0].pop("tenant_id")
    payload["events"][0]["timestamp"] = ev().timestamp.isoformat()
    assert (await client.post("/api/v1/events/ingest", headers=ha, json=payload)).json()["accepted"] == 1
    _, hb = await make.login_as(b, Role.SOC_ANALYST)
    assert (await client.post("/api/v1/events/search", headers=hb, json={})).json()["total"] == 0


async def test_same_native_id_in_two_tenants_does_not_collide(client, make):
    a, b = await make.tenant(), await make.tenant()
    e = ev(original_id="record-1")
    assert Event.from_input(e, a.id).id != Event.from_input(e, b.id).id
    await make.index(a, [e])
    await make.index(b, [e])
    for t in (a, b):
        _, h = await make.login_as(t, Role.VIEWER)
        assert (await client.post("/api/v1/events/search", headers=h, json={})).json()["total"] == 1


async def test_token_for_tenant_without_membership_is_rejected(client, make):
    a, b = await make.tenant(), await make.tenant()
    u = await make.user(a, Role.TENANT_ADMIN)
    # a hand-signed token (e.g. a stolen secret scenario is out of scope; here: a legit token minted for the wrong tid)
    h = make.headers(u, b)
    assert (await client.post("/api/v1/events/search", headers=h, json={})).status_code == 401
    assert (await client.get("/api/v1/auth/me", headers=h)).status_code == 401


async def test_tid_claim_tampering_requires_valid_signature(client, make):
    a, b = await make.tenant(), await make.tenant()
    u = await make.user(a, Role.TENANT_ADMIN)
    good = make.headers(u, a)["authorization"].split()[1]
    claims = pyjwt.decode(good, options={"verify_signature": False})
    claims["tid"] = str(b.id)
    tampered = pyjwt.encode(claims, "attacker-key-attacker-key-attacker-key-1", "HS256")
    assert (await client.get("/api/v1/auth/me", headers={"authorization": f"Bearer {tampered}"})).status_code == 401
    assert pyjwt.decode(good, get_settings().jwt_secret, algorithms=["HS256"], audience="threat-hunt-api")[
        "tid"
    ] == str(a.id)


async def test_user_management_is_tenant_scoped(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    ub, _ = await make.login_as(b, Role.SOC_ANALYST)
    listing = (await client.get("/api/v1/users", headers=ha)).json()
    assert str(ub.id) not in {m["user_id"] for m in listing}
    r = await client.patch(f"/api/v1/users/{ub.id}", headers=ha, json={"is_active": False})
    assert r.status_code == 404
    assert (await client.patch(f"/api/v1/users/{uuid.uuid4()}", headers=ha, json={"role": "VIEWER"})).status_code == 404


async def test_switch_tenant_requires_membership(client, make):
    a, b = await make.tenant(), await make.tenant()
    u = await make.user(a, Role.TENANT_ADMIN)
    r = await client.post(
        "/api/v1/auth/switch-tenant",
        headers={**make.headers(u, a), "x-requested-with": "threat-hunt"},
        json={"tenant_id": str(b.id)},
    )
    assert r.status_code == 403


async def test_retention_delete_is_tenant_scoped(make, app):
    a, b = await make.tenant(), await make.tenant()
    old = ev(minutes_ago=60 * 24 * 3)
    await make.index(a, [old])
    await make.index(b, [old])
    backend = app.state.search
    from datetime import UTC, datetime, timedelta

    deleted = await backend.delete_before(a.id, (datetime.now(UTC) - timedelta(days=1)).isoformat())
    assert deleted == 1
    from app.events.search.query import EventQuery, TimeRange

    wide = EventQuery(time_range=TimeRange.last(timedelta(days=10)))
    assert (await backend.search(b.id, wide)).total == 1
    assert (await backend.search(a.id, wide)).total == 0
