import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import sqlalchemy as sa

from app.auth.rbac import Role
from app.connectors import generic_rest
from app.core.config import get_settings
from app.datasources.models import DataSource

D = "/api/v1/data-sources"
SYSMON = {
    "EventID": 1,
    "UtcTime": "2026-03-01T10:00:00Z",
    "Computer": "WS-9",
    "User": "CORP\\alice",
    "Image": "C:\\x\\a.exe",
    "CommandLine": "a.exe",
    "ProcessId": 4,
    "RecordID": 9,
}


async def _create(client, h, **kw):
    body = {"name": f"src-{kw.pop('suffix', 'a')}", "connector_type": "sysmon", **kw}
    r = await client.post(D, headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def test_catalog_lists_connectors_with_schemas(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    cat = {c["type"]: c for c in (await client.get(f"{D}/connectors", headers=h)).json()}
    assert {
        "sysmon",
        "zeek",
        "suricata",
        "wazuh",
        "windows_eventlog",
        "generic_json",
        "generic_rest",
        "canonical",
    } <= set(cat)
    assert cat["generic_rest"]["supports_collect"] and "url" in cat["generic_rest"]["config_schema"]["properties"]


async def test_crud_validation_and_permissions(client, make):
    t = await make.tenant()
    _, admin = await make.login_as(t, Role.TENANT_ADMIN)
    _, analyst = await make.login_as(t, Role.SOC_ANALYST)
    ds = await _create(client, admin)
    assert ds["ingest_key"].startswith("hk_") and ds["health_status"] == "unknown"
    assert (await client.post(D, headers=admin, json={"name": "src-a", "connector_type": "sysmon"})).status_code == 409
    assert (await client.post(D, headers=admin, json={"name": "x", "connector_type": "nope"})).status_code == 400
    assert (
        await client.post(
            D, headers=admin, json={"name": "x", "connector_type": "generic_rest", "config": {"url": "ftp://x"}}
        )
    ).status_code == 400
    assert (
        await client.post(D, headers=admin, json={"name": "x", "connector_type": "sysmon", "config": {"evil": 1}})
    ).status_code == 400
    assert (await client.get(f"{D}/{ds['id']}", headers=analyst)).json()["ingest_key"] is None  # never re-disclosed
    assert (await client.post(D, headers=analyst, json={"name": "y", "connector_type": "sysmon"})).status_code == 403
    assert (await client.patch(f"{D}/{ds['id']}", headers=analyst, json={"enabled": False})).status_code == 403
    assert (await client.post(f"{D}/{ds['id']}/rotate-key", headers=analyst)).status_code == 403
    assert (await client.delete(f"{D}/{ds['id']}", headers=analyst)).status_code == 403
    assert (await client.patch(f"{D}/{ds['id']}", headers=admin, json={"enabled": False})).json()["enabled"] is False
    assert (await client.delete(f"{D}/{ds['id']}", headers=admin)).status_code == 204


async def test_secrets_are_encrypted_at_rest_and_never_returned(client, make, db):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    ds = await _create(
        client,
        h,
        suffix="rest",
        connector_type="generic_rest",
        config={"url": "https://api.example.com/x"},
        secrets={"authorization": "Bearer SUPER-SECRET-TOKEN"},
    )
    assert ds["has_secrets"] and ds["secret_keys"] == ["authorization"]
    assert "SUPER-SECRET" not in json.dumps(ds) and "SUPER-SECRET" not in (await client.get(D, headers=h)).text
    row = (await db.execute(sa.select(DataSource).where(DataSource.id == ds["id"]))).scalar_one()
    assert (
        b"SUPER-SECRET" not in bytes(row.secrets_enc)
        and row.ingest_key_hash
        and ds["ingest_key"] not in row.ingest_key_hash
    )


async def test_ingest_with_key_stamps_tenant_from_the_source_and_updates_health(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    _, hb = await make.login_as(b, Role.SOC_ANALYST)
    ds = await _create(client, ha)
    url, key = f"/api/v1/ingest/{ds['id']}", {"authorization": f"Bearer {ds['ingest_key']}"}
    r = await client.post(url, headers=key, json={"events": [SYSMON, {"EventID": 99}]})
    assert r.status_code == 200 and r.json()["accepted"] == 1 and len(r.json()["rejected"]) == 1
    await make.app.state.opensearch.indices.refresh(index=make.app.state.search.pattern, ignore_unavailable=True)
    ha_search = (
        await client.post(
            "/api/v1/events/search",
            headers=ha,
            json={"time_range": {"start": "2026-02-28T00:00:00Z", "end": "2026-03-02T00:00:00Z"}},
        )
    ).json()
    assert ha_search["total"] == 1
    assert (
        await client.post(
            "/api/v1/events/search",
            headers=hb,
            json={"time_range": {"start": "2026-02-28T00:00:00Z", "end": "2026-03-02T00:00:00Z"}},
        )
    ).json()["total"] == 0
    got = (await client.get(f"{D}/{ds['id']}", headers=ha)).json()
    assert got["events_total"] == 1 and got["health_status"] == "ok" and got["last_ingest_at"]


@pytest.mark.parametrize(
    "hdr", [{}, {"authorization": "Bearer nope"}, {"authorization": "Basic abc"}, {"authorization": "Bearer hk_wrong"}]
)
async def test_ingest_requires_valid_key(client, make, hdr):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    ds = await _create(client, h)
    r = await client.post(f"/api/v1/ingest/{ds['id']}", headers=hdr, json={"events": [SYSMON]})
    assert r.status_code == 401


async def test_key_is_bound_to_its_source_tenant_and_rotation_revokes(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    _, hb = await make.login_as(b, Role.TENANT_ADMIN)
    da, db_ = await _create(client, ha), await _create(client, hb)
    # A's key against B's source id (cross-tenant write attempt) and a user JWT as ingest key
    assert (
        await client.post(
            f"/api/v1/ingest/{db_['id']}",
            headers={"authorization": f"Bearer {da['ingest_key']}"},
            json={"events": [SYSMON]},
        )
    ).status_code == 401
    assert (await client.post(f"/api/v1/ingest/{da['id']}", headers=ha, json={"events": [SYSMON]})).status_code == 401
    # B cannot see, rotate, test or delete A's source
    for method, url in [
        ("get", f"{D}/{da['id']}"),
        ("post", f"{D}/{da['id']}/rotate-key"),
        ("post", f"{D}/{da['id']}/test"),
        ("delete", f"{D}/{da['id']}"),
        ("post", f"{D}/{da['id']}/collect"),
    ]:
        assert (await getattr(client, method)(url, headers=hb)).status_code == 404
    rotated = (await client.post(f"{D}/{da['id']}/rotate-key", headers=ha)).json()
    old = {"authorization": f"Bearer {da['ingest_key']}"}
    assert (await client.post(f"/api/v1/ingest/{da['id']}", headers=old, json={"events": [SYSMON]})).status_code == 401
    new = {"authorization": f"Bearer {rotated['ingest_key']}"}
    assert (await client.post(f"/api/v1/ingest/{da['id']}", headers=new, json={"events": [SYSMON]})).status_code == 200
    await client.patch(f"{D}/{da['id']}", headers=ha, json={"enabled": False})
    assert (await client.post(f"/api/v1/ingest/{da['id']}", headers=new, json={"events": [SYSMON]})).status_code == 401


async def test_ingest_batch_limits_and_audit(client, make, db):
    from app.audit.models import AuditLog

    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    ds = await _create(client, h)
    key = {"authorization": f"Bearer {ds['ingest_key']}"}
    url = f"/api/v1/ingest/{ds['id']}"
    assert (await client.post(url, headers=key, json={"events": []})).status_code == 400
    assert (await client.post(url, headers=key, json={"events": [{}] * 1001})).status_code == 400
    assert (await client.post(url, headers=key, json={"nope": [{}]})).status_code == 400
    assert (await client.post(url, headers=key, json={"nope": 1})).status_code == 422
    await client.post(url, headers=key, json={"events": [SYSMON]})
    await client.post(url, headers={"authorization": "Bearer hk_bad"}, json={"events": [SYSMON]})
    actions = {a for (a,) in (await db.execute(sa.select(AuditLog.action).where(AuditLog.tenant_id == t.id))).all()}
    assert "ingest.datasource" in actions


# ---- pull connector through the SSRF guard ---------------------------------------------------------
@pytest.fixture
def rest_mock(monkeypatch):
    records = [
        {"ts": (datetime.now(UTC) - timedelta(minutes=m)).isoformat(), "who": f"user{m}", "id": f"r{m}"}
        for m in (3, 2, 1)
    ]
    seen = {"requests": []}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["requests"].append(request)
        if request.headers.get("authorization") != "Bearer tok":
            return httpx.Response(401)
        return httpx.Response(200, json={"data": {"items": records}})

    async def resolve(host, port):
        return {"siem.example.com": ["93.184.216.34"], "intranet.example.com": ["10.0.0.7"]}.get(host, [host])

    monkeypatch.setattr(generic_rest, "HTTP_TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(generic_rest, "RESOLVER", resolve)
    return seen


REST_CFG = {
    "url": "https://siem.example.com/api/events",
    "records_path": "data.items",
    "since_param": "since",
    "mapping": {
        "source": "siem",
        "default_event_type": "authentication",
        "field_map": {"timestamp": "ts", "user.name": "who", "original_id": "id"},
    },
}


async def test_pull_connector_collects_with_secret_header_and_cursor(client, make, rest_mock, app):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    ds = await _create(
        client,
        h,
        suffix="pull",
        connector_type="generic_rest",
        config=REST_CFG,
        secrets={"authorization": "Bearer tok"},
    )
    test = (await client.post(f"{D}/{ds['id']}/test", headers=h)).json()
    assert test["ok"] and "200" in test["detail"]
    r = await client.post(f"{D}/{ds['id']}/collect", headers=h)
    assert r.json() == {"accepted": 3}
    assert rest_mock["requests"][-1].headers["host"] == "siem.example.com" and str(
        rest_mock["requests"][-1].url
    ).startswith("https://93.184.216.34")
    await app.state.opensearch.indices.refresh(index=app.state.search.pattern, ignore_unavailable=True)
    assert (
        await client.post(
            "/api/v1/events/search", headers=h, json={"filters": [{"field": "source", "op": "eq", "value": "siem"}]}
        )
    ).json()["total"] == 3
    again = (await client.post(f"{D}/{ds['id']}/collect", headers=h)).json()
    assert again == {"accepted": 0}  # deterministic ids => duplicates are ignored
    assert "since=" in str(rest_mock["requests"][-1].url)  # cursor sent on the second pull
    got = (await client.get(f"{D}/{ds['id']}", headers=h)).json()
    assert got["events_total"] == 3 and got["health_status"] == "ok"


async def test_pull_failure_marks_health_and_ssrf_targets_are_blocked(client, make, rest_mock):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    bad_token = await _create(
        client,
        h,
        suffix="badtok",
        connector_type="generic_rest",
        config=REST_CFG,
        secrets={"authorization": "Bearer wrong"},
    )
    assert (await client.post(f"{D}/{bad_token['id']}/collect", headers=h)).json() == {"accepted": 0}
    assert (await client.get(f"{D}/{bad_token['id']}", headers=h)).json()["health_status"] == "down"
    internal = await _create(
        client,
        h,
        suffix="internal",
        connector_type="generic_rest",
        config={**REST_CFG, "url": "http://intranet.example.com/api"},
    )
    t2 = (await client.post(f"{D}/{internal['id']}/test", headers=h)).json()
    assert t2["ok"] is False and "SsrfError" in t2["detail"]
    meta = await _create(
        client,
        h,
        suffix="meta",
        connector_type="generic_rest",
        config={**REST_CFG, "url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert (await client.post(f"{D}/{meta['id']}/test", headers=h)).json()["ok"] is False
    push = await _create(client, h, suffix="push")
    assert (await client.post(f"{D}/{push['id']}/collect", headers=h)).status_code == 400


def test_encryption_key_required_in_production():
    from app.core.config import Settings

    base = dict(app_env="production", jwt_secret="x" * 40, database_url="postgresql+asyncpg://u:realpw@h/db")
    with pytest.raises(ValueError, match="DATA_ENCRYPTION_KEY"):
        Settings(**base)
    with pytest.raises(ValueError, match="OUTBOUND_ALLOW_PRIVATE"):
        Settings(**base, data_encryption_key="k" * 44, outbound_allow_private=True)
    assert get_settings().outbound_allow_private is False


async def test_set_one_secret_keeps_the_others_and_never_echoes(client, make, db):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    r = await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "s",
            "connector_type": "generic_rest",
            "config": {"url": "https://example.com/x"},
            "secrets": {"authorization": "Bearer OLD-VALUE"},
        },
    )
    ds = r.json()
    put = await client.put(
        f"/api/v1/data-sources/{ds['id']}/secrets/extra", headers=h, json={"value": "NEW-SECRET-VALUE"}
    )
    assert put.status_code == 204 and "NEW-SECRET" not in put.text
    got = (await client.get(f"/api/v1/data-sources/{ds['id']}", headers=h)).json()
    assert got["secret_keys"] == ["authorization", "extra"] and "NEW-SECRET" not in json.dumps(got)
    row = (await db.execute(sa.select(DataSource).where(DataSource.id == uuid.UUID(ds["id"])))).scalar_one()
    assert b"NEW-SECRET" not in bytes(row.secrets_enc) and b"OLD-VALUE" not in bytes(row.secrets_enc)
    # overwrite one, validation, permissions, tenant isolation
    assert (
        await client.put(f"/api/v1/data-sources/{ds['id']}/secrets/authorization", headers=h, json={"value": "v2"})
    ).status_code == 204
    for bad in ("bad name", "x" * 65):
        assert (
            await client.put(f"/api/v1/data-sources/{ds['id']}/secrets/{bad}", headers=h, json={"value": "v"})
        ).status_code in (404, 422)
    assert (
        await client.put(f"/api/v1/data-sources/{ds['id']}/secrets/a", headers=h, json={"value": ""})
    ).status_code == 422
    _, analyst = await make.login_as(t, Role.SOC_ANALYST)
    assert (
        await client.put(f"/api/v1/data-sources/{ds['id']}/secrets/a", headers=analyst, json={"value": "v"})
    ).status_code == 403
    _, other = await make.login_as(await make.tenant(), Role.TENANT_ADMIN)
    assert (
        await client.put(f"/api/v1/data-sources/{ds['id']}/secrets/a", headers=other, json={"value": "v"})
    ).status_code == 404
