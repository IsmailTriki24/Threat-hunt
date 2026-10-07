from app.auth.rbac import Role
from tests.helpers import ev

A = "/api/v1/assets"


async def test_asset_crud_and_normalisation(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    r = await client.post(
        A, headers=h, json={"type": "user", "key": "CORP\\Alice", "criticality": "HIGH", "tags": ["vip"]}
    )
    assert r.status_code == 201 and r.json()["key"] == "alice"
    assert (await client.post(A, headers=h, json={"type": "user", "key": "alice"})).status_code == 409
    assert (await client.post(A, headers=h, json={"type": "ip", "key": "nope"})).status_code == 400
    assert (await client.post(A, headers=h, json={"type": "mainframe", "key": "x"})).status_code == 422
    aid = r.json()["id"]
    up = await client.patch(f"{A}/{aid}", headers=h, json={"owner": "Finance", "criticality": "CRITICAL"})
    assert up.json()["owner"] == "Finance" and up.json()["criticality"] == "CRITICAL"
    assert [a["key"] for a in (await client.get(A, headers=h, params={"type": "user", "q": "ali"})).json()] == ["alice"]
    assert (await client.delete(f"{A}/{aid}", headers=h)).status_code == 204
    _, viewer = await make.login_as(t, Role.VIEWER)
    assert (await client.get(A, headers=viewer)).status_code == 200
    assert (await client.post(A, headers=viewer, json={"type": "host", "key": "x"})).status_code == 403


async def test_discovery_events_and_related_are_derived_from_telemetry(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    await make.index(
        t,
        [
            ev(10, host={"hostname": "WS-01", "ip": ["10.0.0.5"]}, user={"name": "alice"}, process={"name": "a.exe"}),
            ev(5, host={"hostname": "WS-01", "ip": ["10.0.0.5"]}, user={"name": "bob"}, process={"name": "b.exe"}),
            ev(
                4,
                event_type="network_connection",
                host={"hostname": "WS-02", "ip": ["10.0.0.6"]},
                user={"name": "alice"},
                network={"src_ip": "10.0.0.6", "dst_ip": "203.0.113.5", "dst_port": 443},
            ),
        ],
    )
    d = (await client.post(f"{A}/discover", headers=h, json={"days": 1})).json()
    assert d["created"] >= 5 and d["updated"] == 0
    assert (await client.post(f"{A}/discover", headers=h, json={"days": 1})).json()["created"] == 0  # idempotent
    assets = {(a["type"], a["key"]): a for a in (await client.get(A, headers=h)).json()}
    assert {("host", "ws-01"), ("host", "ws-02"), ("user", "alice"), ("user", "bob"), ("ip", "10.0.0.5")} <= set(assets)
    assert assets[("host", "ws-01")]["event_count"] == 2 and assets[("host", "ws-01")]["first_seen"]
    host_id = assets[("host", "ws-01")]["id"]
    events = (await client.get(f"{A}/{host_id}/events", headers=h)).json()
    assert events["total"] == 2 and {e["host"]["hostname"] for e in events["hits"]} == {"WS-01"}
    rel = (await client.get(f"{A}/{host_id}/related", headers=h)).json()
    assert {u["key"] for u in rel["users"]} == {"alice", "bob"}
    ip_id = assets[("ip", "10.0.0.6")]["id"]
    assert (await client.get(f"{A}/{ip_id}/events", headers=h)).json()["total"] >= 1
    user_rel = (await client.get(f"{A}/{assets[('user', 'alice')]['id']}/related", headers=h)).json()
    assert {x["key"] for x in user_rel["hosts"]} == {"ws-01", "ws-02"}


async def test_assets_are_tenant_isolated_and_link_to_cases(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    _, hb = await make.login_as(b, Role.TENANT_ADMIN)
    aid = (await client.post(A, headers=ha, json={"type": "host", "key": "secret-host"})).json()["id"]
    assert (await client.get(A, headers=hb)).json() == []
    for method, url in [
        ("get", f"{A}/{aid}"),
        ("delete", f"{A}/{aid}"),
        ("get", f"{A}/{aid}/events"),
        ("get", f"{A}/{aid}/related"),
        ("get", f"{A}/{aid}/cases"),
    ]:
        assert (await getattr(client, method)(url, headers=hb)).status_code == 404
    assert (await client.patch(f"{A}/{aid}", headers=hb, json={"owner": "x"})).status_code == 404
    # same key may exist independently per tenant
    assert (await client.post(A, headers=hb, json={"type": "host", "key": "secret-host"})).status_code == 201
    case = (await client.post("/api/v1/cases", headers=ha, json={"title": "c"})).json()
    assert (
        await client.post(f"/api/v1/cases/{case['id']}/assets", headers=ha, json={"asset_id": aid})
    ).status_code == 201
    assert (
        await client.post(f"/api/v1/cases/{case['id']}/assets", headers=ha, json={"asset_id": aid})
    ).status_code == 409
    assert [c["id"] for c in (await client.get(f"{A}/{aid}/cases", headers=ha)).json()] == [case["id"]]
    assert (await client.delete(f"/api/v1/cases/{case['id']}/assets/{aid}", headers=ha)).status_code == 204
