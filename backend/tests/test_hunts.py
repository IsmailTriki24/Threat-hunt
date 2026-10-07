import csv
import io
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.auth.rbac import Role
from tests.helpers import ev

H = "/api/v1/hunts"


async def _hunt(client, h, **kw):
    r = await client.post(
        H, headers=h, json={"title": "PowerShell persistence", "hypothesis": "PowerShell used for persistence", **kw}
    )
    assert r.status_code == 201, r.text
    return r.json()


async def test_hunt_lifecycle(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    hunt = await _hunt(client, h)
    assert hunt["status"] == "DRAFT" and hunt["finding_count"] == 0
    r = await client.patch(f"{H}/{hunt['id']}", headers=h, json={"status": "ACTIVE", "conclusion": "wip"})
    assert r.json()["status"] == "ACTIVE" and r.json()["conclusion"] == "wip"
    assert [x["id"] for x in (await client.get(H, headers=h)).json()] == [hunt["id"]]
    assert (await client.delete(f"{H}/{hunt['id']}", headers=h)).status_code == 204
    assert (await client.get(f"{H}/{hunt['id']}", headers=h)).status_code == 404


async def test_hunt_validation(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    now = datetime.now(UTC)
    for body in [
        {"title": ""},
        {"title": "x", "status": "NOPE"},
        {"title": "x", "time_start": now.isoformat()},
        {"title": "x", "time_start": now.isoformat(), "time_end": (now - timedelta(hours=1)).isoformat()},
        {"title": "x", "data_sources": ["Bad Source"]},
        {"title": "x", "tenant_id": str(uuid.uuid4())},
    ]:
        assert (await client.post(H, headers=h, json=body)).status_code == 422, body


@pytest.mark.parametrize(
    "role,can_write,can_delete",
    [
        (Role.VIEWER, False, False),
        (Role.SOC_ANALYST, True, False),
        (Role.INCIDENT_RESPONDER, True, False),
        (Role.THREAT_HUNTER, True, True),
        (Role.TENANT_ADMIN, True, True),
    ],
)
async def test_hunt_permissions(client, make, role, can_write, can_delete):
    t = await make.tenant()
    _, owner = await make.login_as(t, Role.TENANT_ADMIN)
    hunt = await _hunt(client, owner)
    _, h = await make.login_as(t, role)
    assert (await client.get(H, headers=h)).status_code == 200
    assert (await client.post(H, headers=h, json={"title": "t"})).status_code == (201 if can_write else 403)
    assert (await client.patch(f"{H}/{hunt['id']}", headers=h, json={"title": "n"})).status_code == (
        200 if can_write else 403
    )
    assert (await client.post(f"{H}/{hunt['id']}/notes", headers=h, json={"body": "n"})).status_code == (
        201 if can_write else 403
    )
    assert (await client.post("/api/v1/saved-queries", headers=h, json={"name": "q", "query": {}})).status_code == (
        201 if can_write else 403
    )
    assert (await client.delete(f"{H}/{hunt['id']}", headers=h)).status_code == (204 if can_delete else 403)


async def test_hunt_objects_are_tenant_isolated(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    _, hb = await make.login_as(b, Role.TENANT_ADMIN)
    hunt = await _hunt(client, ha)
    sq = (
        await client.post("/api/v1/saved-queries", headers=ha, json={"name": "q", "hunt_id": hunt["id"], "query": {}})
    ).json()
    hid = hunt["id"]
    assert (await client.get(H, headers=hb)).json() == []
    for method, url, body in [
        ("get", f"{H}/{hid}", None),
        ("patch", f"{H}/{hid}", {"title": "pwn"}),
        ("delete", f"{H}/{hid}", None),
        ("get", f"{H}/{hid}/findings", None),
        ("get", f"{H}/{hid}/notes", None),
        ("post", f"{H}/{hid}/notes", {"body": "x"}),
        ("post", f"{H}/{hid}/run", {"query": {}}),
        ("post", f"{H}/{hid}/findings", {"title": "f", "event_ids": []}),
        ("delete", f"/api/v1/saved-queries/{sq['id']}", None),
    ]:
        r = await getattr(client, method)(url, headers=hb, **({"json": body} if body is not None else {}))
        assert r.status_code == 404, (method, url, r.status_code)
    assert (
        await client.post("/api/v1/saved-queries", headers=hb, json={"name": "q", "hunt_id": hid, "query": {}})
    ).status_code == 404
    assert (await client.get("/api/v1/saved-queries", headers=hb)).json() == []
    assert (await client.get(f"{H}/{hid}", headers=ha)).status_code == 200  # still intact


async def test_run_applies_hunt_scope_and_records_history(client, make):
    t = await make.tenant()
    await make.index(
        t,
        [
            ev(1, source="sysmon", host={"hostname": "A"}),
            ev(2, source="windows", host={"hostname": "B"}),
            ev(60 * 48, source="sysmon", host={"hostname": "OLD"}),
        ],
    )
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    now = datetime.now(UTC)
    hunt = await _hunt(
        client, h, data_sources=["sysmon"], time_start=(now - timedelta(hours=72)).isoformat(), time_end=now.isoformat()
    )
    r = await client.post(f"{H}/{hunt['id']}/run", headers=h, json={"query": {"text": "has:host.hostname"}})
    assert r.status_code == 200
    assert sorted(x["host"]["hostname"] for x in r.json()["hits"]) == ["A", "OLD"]  # source scope + hunt window
    hist = (await client.get("/api/v1/query-history", headers=h)).json()
    assert (
        hist[0]["hunt_id"] == hunt["id"] and hist[0]["total"] == 2 and hist[0]["query"]["text"] == "has:host.hostname"
    )
    # explicit analyst time range wins over the hunt default
    r = await client.post(
        f"{H}/{hunt['id']}/run",
        headers=h,
        json={"query": {"time_range": {"start": (now - timedelta(hours=1)).isoformat(), "end": now.isoformat()}}},
    )
    assert [x["host"]["hostname"] for x in r.json()["hits"]] == ["A"]
    assert (await client.get(f"{H}/{hunt['id']}", headers=h)).json()["id"] == hunt["id"]


async def test_history_is_private_per_user_and_includes_plain_searches(client, make):
    t = await make.tenant()
    _, h1 = await make.login_as(t, Role.SOC_ANALYST)
    _, h2 = await make.login_as(t, Role.SOC_ANALYST)
    await client.post("/api/v1/events/search", headers=h1, json={"q": "secret-investigation"})
    mine = (await client.get("/api/v1/query-history", headers=h1)).json()
    assert mine and mine[0]["query"]["q"] == "secret-investigation"
    assert (await client.get("/api/v1/query-history", headers=h2)).json() == []
    assert (await client.delete("/api/v1/query-history", headers=h1)).status_code == 204
    assert (await client.get("/api/v1/query-history", headers=h1)).json() == []


async def test_saved_queries_roundtrip_and_validation(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    body = {
        "name": "Office spawning PS",
        "query": {"text": "process.parent.name:WINWORD.EXE process.name:powershell.exe"},
    }
    saved = (await client.post("/api/v1/saved-queries", headers=h, json=body)).json()
    assert saved["query"]["text"].startswith("process.parent.name")
    assert (await client.get("/api/v1/saved-queries", headers=h)).json()[0]["id"] == saved["id"]
    bad = await client.post("/api/v1/saved-queries", headers=h, json={"name": "x", "query": {"text": "evil.field:1"}})
    assert bad.status_code == 422
    assert (await client.delete(f"/api/v1/saved-queries/{saved['id']}", headers=h)).status_code == 204


async def test_findings_snapshot_evidence_and_reject_foreign_or_unknown_events(client, make):
    a, b = await make.tenant(), await make.tenant()
    await make.index(a, [ev(1, host={"hostname": "A-HOST"}, process={"name": "powershell.exe", "pid": 1})])
    await make.index(b, [ev(1, host={"hostname": "B-HOST"})])
    _, ha = await make.login_as(a, Role.THREAT_HUNTER)
    _, hb = await make.login_as(b, Role.THREAT_HUNTER)
    a_id = (await client.post("/api/v1/events/search", headers=ha, json={})).json()["hits"][0]["id"]
    b_id = (await client.post("/api/v1/events/search", headers=hb, json={})).json()["hits"][0]["id"]
    hunt = await _hunt(client, ha)
    ok = await client.post(
        f"{H}/{hunt['id']}/findings", headers=ha, json={"title": "PS", "severity": "HIGH", "event_ids": [a_id, a_id]}
    )
    assert ok.status_code == 201
    assert len(ok.json()["evidence"]) == 1 and ok.json()["evidence"][0]["summary"].startswith("powershell.exe started")
    assert (
        await client.post(f"{H}/{hunt['id']}/findings", headers=ha, json={"title": "x", "event_ids": [b_id]})
    ).status_code == 400
    assert (
        await client.post(f"{H}/{hunt['id']}/findings", headers=ha, json={"title": "x", "event_ids": ["a" * 32]})
    ).status_code == 400
    assert (
        await client.post(f"{H}/{hunt['id']}/findings", headers=ha, json={"title": "x", "event_ids": ["../etc"]})
    ).status_code == 422
    assert (await client.get(H, headers=ha)).json()[0]["finding_count"] == 1
    fid = ok.json()["id"]
    assert (await client.delete(f"{H}/{hunt['id']}/findings/{fid}", headers=ha)).status_code == 204


async def test_notes(client, make):
    t = await make.tenant()
    u, h = await make.login_as(t, Role.SOC_ANALYST)
    hunt = await _hunt(client, h)
    n = (await client.post(f"{H}/{hunt['id']}/notes", headers=h, json={"body": "<script>alert(1)</script>"})).json()
    assert n["author_id"] == str(u.id)
    assert (await client.get(f"{H}/{hunt['id']}/notes", headers=h)).json()[0][
        "body"
    ] == "<script>alert(1)</script>"  # stored verbatim, rendered as text
    assert (await client.post(f"{H}/{hunt['id']}/notes", headers=h, json={"body": ""})).status_code == 422


async def test_export_csv_neutralises_formulas_and_is_tenant_scoped(client, make):
    a, b = await make.tenant(), await make.tenant()
    await make.index(
        a, [ev(1, process={"name": "=cmd|' /C calc'!A0", "command_line": "+SUM(1)"}, host={"hostname": "@evil"})]
    )
    await make.index(b, [ev(1, host={"hostname": "OTHER-TENANT"})])
    _, ha = await make.login_as(a, Role.VIEWER)
    r = await client.post("/api/v1/events/export", headers=ha, json={"query": {}})
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 1 and "OTHER-TENANT" not in r.text
    assert (
        rows[0]["process"].startswith("'=")
        and rows[0]["command_line"].startswith("'+")
        and rows[0]["host"].startswith("'@")
    )
    j = await client.post("/api/v1/events/export", headers=ha, json={"query": {}, "format": "json"})
    assert len(j.json()) == 1
    assert (
        await client.post("/api/v1/events/export", headers=ha, json={"query": {}, "max_rows": 5001})
    ).status_code == 422


async def test_hunt_actions_are_audited(client, make, db):
    import sqlalchemy as sa

    from app.audit.models import AuditLog

    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    hunt = await _hunt(client, h)
    await client.post(f"{H}/{hunt['id']}/run", headers=h, json={"query": {}})
    await client.post("/api/v1/events/export", headers=h, json={"query": {}})
    actions = {r for (r,) in (await db.execute(sa.select(AuditLog.action).where(AuditLog.tenant_id == t.id))).all()}
    assert {"hunt.create", "hunt.run", "event.export"} <= actions
