# ruff: noqa: E501
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.auth.rbac import Role
from app.detections import service
from app.detections.models import Alert, DetectionRule
from tests.helpers import ev

D = "/api/v1/detections"

SIGMA = """
title: Encoded PowerShell
description: powershell with an encoded command
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc'
  condition: sel
level: high
tags: [attack.execution, attack.t1059.001]
"""

POSITIVE = {
    "timestamp": "2026-10-08T10:00:00Z",
    "source": "sysmon",
    "event_type": "process_creation",
    "process": {
        "name": "powershell.exe",
        "executable": "C:\\Windows\\System32\\powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
    },
}
NEGATIVE = {
    **POSITIVE,
    "process": {
        "name": "powershell.exe",
        "executable": "C:\\Windows\\System32\\powershell.exe",
        "command_line": "powershell.exe -File a.ps1",
    },
}


async def _rule(client, h, content=SIGMA, fmt="sigma", **extra):
    r = await client.post(f"{D}/rules", headers=h, json={"format": fmt, "content": content, **extra})
    assert r.status_code == 201, r.text
    return r.json()


async def _activate(client, h, rid):
    for body in (POSITIVE, NEGATIVE):
        r = await client.post(
            f"{D}/rules/{rid}/tests", headers=h, json={"name": "t", "event": body, "expect_match": body is POSITIVE}
        )
        assert r.status_code == 201, r.text
    assert (await client.post(f"{D}/rules/{rid}/tests/run", headers=h)).json()["passed"] is True
    assert (await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "TESTING"})).status_code == 200
    r = await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "ACTIVE"})
    assert r.status_code == 200, r.text
    return r.json()


async def test_create_compiles_and_maps_attack(client, make, db):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    rule = await _rule(client, h)
    assert rule["status"] == "DRAFT" and rule["executable"] and rule["severity"] == "HIGH"
    assert rule["techniques"] == ["T1059.001"] and rule["version"] == 1
    assert (await client.get(f"{D}/rules/{rule['id']}/versions", headers=h)).json()[0]["version"] == 1


async def test_unsupported_rule_is_stored_but_never_deployable(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    rule = await _rule(client, h, SIGMA.replace("condition: sel", "condition: sel | count() > 5"))
    assert not rule["executable"] and rule["unsupported"]
    r = await client.post(f"{D}/rules/{rule['id']}/transition", headers=h, json={"to": "TESTING"})
    assert r.status_code == 400


async def test_bad_input(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    for body in [
        {"format": "nope", "content": "x"},
        {"format": "sigma", "content": "not: [valid"},
        {"format": "sigma", "content": "a: &x [1]\nb: *x"},
        {"format": "sigma", "content": ""},
        {"format": "sigma", "content": SIGMA, "tenant_id": str(uuid.uuid4())},
        {"format": "sigma", "content": SIGMA, "hunt_id": str(uuid.uuid4())},
    ]:
        assert (await client.post(f"{D}/rules", headers=h, json=body)).status_code in (400, 404, 422), body


async def test_activation_requires_passing_tests(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    rule = await _rule(client, h)
    rid = rule["id"]
    assert (
        await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "ACTIVE"})
    ).status_code == 409  # DRAFT -> ACTIVE illegal
    await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "TESTING"})
    assert (
        await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "ACTIVE"})
    ).status_code == 400  # no tests
    # a failing expectation blocks activation
    await client.post(
        f"{D}/rules/{rid}/tests", headers=h, json={"name": "wrong", "event": NEGATIVE, "expect_match": True}
    )
    run = (await client.post(f"{D}/rules/{rid}/tests/run", headers=h)).json()
    assert run["passed"] is False and run["results"][0]["matched"] is False
    assert (await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "ACTIVE"})).status_code == 400


async def test_full_lifecycle_and_edit_resets(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    rid = (await _rule(client, h))["id"]
    r = await _activate(client, h, rid)
    assert r["status"] == "ACTIVE" and r["tests_passed"] is True and r["test_count"] == 2
    # editing creates a new version and takes the rule out of production
    edited = (
        await client.put(
            f"{D}/rules/{rid}", headers=h, json={"content": SIGMA.replace("high", "critical"), "note": "raise"}
        )
    ).json()
    assert (
        edited["version"] == 2
        and edited["status"] == "DRAFT"
        and edited["severity"] == "CRITICAL"
        and edited["tests_passed"] is None
    )
    assert [v["version"] for v in (await client.get(f"{D}/rules/{rid}/versions", headers=h)).json()] == [2, 1]
    # adding a test case to an active rule re-opens validation
    await client.post(f"{D}/rules/{rid}/tests/run", headers=h)
    await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "TESTING"})
    assert (await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "ACTIVE"})).status_code == 200
    await client.post(
        f"{D}/rules/{rid}/tests", headers=h, json={"name": "more", "event": NEGATIVE, "expect_match": False}
    )
    got = (await client.get(f"{D}/rules/{rid}", headers=h)).json()
    assert got["status"] == "TESTING" and got["tests_passed"] is None
    assert (await client.delete(f"{D}/rules/{rid}", headers=h)).status_code == 204


@pytest.mark.parametrize(
    "role,write,manage",
    [
        (Role.VIEWER, False, False),
        (Role.SOC_ANALYST, True, False),
        (Role.THREAT_HUNTER, True, True),
        (Role.TENANT_ADMIN, True, True),
    ],
)
async def test_permissions(client, make, role, write, manage):
    t = await make.tenant()
    _, admin = await make.login_as(t, Role.TENANT_ADMIN)
    rid = (await _rule(client, admin))["id"]
    _, h = await make.login_as(t, role)
    assert (await client.get(f"{D}/rules", headers=h)).status_code == 200
    r = await client.post(f"{D}/rules", headers=h, json={"format": "sigma", "content": SIGMA})
    assert (r.status_code == 201) is write
    r = await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "TESTING"})
    assert (r.status_code == 200) is write
    await client.post(
        f"{D}/rules/{rid}/tests", headers=admin, json={"name": "p", "event": POSITIVE, "expect_match": True}
    )
    await client.post(f"{D}/rules/{rid}/tests/run", headers=admin)
    r = await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "ACTIVE"})
    assert (r.status_code == 200) is manage
    assert (await client.delete(f"{D}/rules/{rid}", headers=h)).status_code == (204 if manage else 403)


async def test_tenant_isolation(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    _, hb = await make.login_as(b, Role.TENANT_ADMIN)
    rid = (await _rule(client, ha))["id"]
    assert (await client.get(f"{D}/rules", headers=hb)).json() == []
    for method, path in [
        ("get", f"/rules/{rid}"),
        ("get", f"/rules/{rid}/tests"),
        ("get", f"/rules/{rid}/runs"),
        ("delete", f"/rules/{rid}"),
    ]:
        assert (await getattr(client, method)(f"{D}{path}", headers=hb)).status_code == 404
    assert (await client.post(f"{D}/rules/{rid}/backtest", headers=hb, json={})).status_code == 404


async def test_validate_endpoint(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    r = (
        await client.post(
            f"{D}/validate", headers=h, json={"format": "sigma", "content": SIGMA, "events": [POSITIVE, NEGATIVE]}
        )
    ).json()
    assert r["ok"] and r["executable"] and [x["matched"] for x in r["results"]] == [True, False]
    assert r["results"][0]["explanation"] == ["sel"]
    bad = (await client.post(f"{D}/validate", headers=h, json={"format": "sigma", "content": "title: [x"})).json()
    assert bad["ok"] is False and bad["error"]


async def test_hunt_to_detection(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    hunt = (await client.post("/api/v1/hunts", headers=h, json={"title": "ps hunt"})).json()
    body = {
        "title": "Suspicious ps",
        "text": "process.name:powershell.exe process.command_line:*enc*",
        "severity": "HIGH",
        "hunt_id": hunt["id"],
    }
    r = await client.post(f"{D}/rules/from-query", headers=h, json=body)
    assert r.status_code == 201, r.text
    rule = r.json()
    assert (
        rule["format"] == "hunt_query"
        and rule["hunt_id"] == hunt["id"]
        and rule["severity"] == "HIGH"
        and rule["executable"]
    )
    # free text is not a faithful detection
    r = await client.post(f"{D}/rules/from-query", headers=h, json={**body, "text": "mimikatz", "hunt_id": None})
    assert r.status_code == 201 and not r.json()["executable"]
    # a foreign hunt id is rejected
    r = await client.post(f"{D}/rules/from-query", headers=h, json={**body, "hunt_id": str(uuid.uuid4())})
    assert r.status_code == 404


async def test_backtest_does_not_alert(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    rid = (await _rule(client, h))["id"]
    await make.index(
        t,
        [
            ev(
                5,
                process={
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\powershell.exe",
                    "command_line": "powershell.exe -enc QQ==",
                },
            ),
            ev(5, process={"name": "cmd.exe", "command_line": "cmd /c dir"}),
        ],
    )
    r = await client.post(f"{D}/rules/{rid}/backtest", headers=h, json={})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1 and r.json()["run"]["kind"] == "backtest"
    assert (await client.get(f"{D}/alerts", headers=h)).json() == []
    assert len((await client.get(f"{D}/rules/{rid}/runs", headers=h)).json()) == 1


async def test_scheduled_run_alerts_once_and_escalates(client, make, app):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    rid = (await _rule(client, h))["id"]
    await make.index(
        t,
        [
            ev(
                30,
                process={
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\powershell.exe",
                    "command_line": "powershell.exe -enc OLD",
                },
            )
        ],
    )
    await _activate(client, h, rid)  # activation marks "now" as the high-water mark: old events do not alert
    sm, backend = app.state.sessionmaker, app.state.search
    assert (await service.run_scheduled(sm, backend))["alerts"] == 0
    await make.index(
        t,
        [
            ev(
                1,
                process={
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\powershell.exe",
                    "command_line": "powershell.exe -enc NEW",
                },
            ),
            ev(1, process={"name": "notepad.exe"}),
        ],
    )
    s1 = await service.run_scheduled(sm, backend)
    s2 = await service.run_scheduled(sm, backend)  # overlap window re-reads the event: must not duplicate
    assert s1["alerts"] == 1 and s2["alerts"] == 0 and s1["errors"] == 0
    alerts = (await client.get(f"{D}/alerts", headers=h)).json()
    assert len(alerts) == 1 and alerts[0]["severity"] == "HIGH" and alerts[0]["status"] == "OPEN"
    assert alerts[0]["snapshot"]["process"]["command_line"].endswith("NEW")
    assert (await client.get(f"{D}/overview", headers=h)).json()["open_alerts"] == 1
    # triage + escalate
    aid = alerts[0]["id"]
    assert (await client.patch(f"{D}/alerts/{aid}", headers=h, json={"status": "CLOSED"})).json()["status"] == "CLOSED"
    r = await client.post(f"{D}/alerts/{aid}/case", headers=h, json={})
    assert r.status_code == 201 and r.json()["case_id"]
    case = (await client.get(f"/api/v1/cases/{r.json()['case_id']}", headers=h)).json()
    assert case["evidence_count"] == 1 and case["severity"] == "HIGH"
    assert (await client.post(f"{D}/alerts/{aid}/case", headers=h, json={})).status_code == 400
    # another tenant sees nothing
    _, hb = await make.login_as(await make.tenant(), Role.TENANT_ADMIN)
    assert (await client.get(f"{D}/alerts", headers=hb)).json() == []
    assert (await client.patch(f"{D}/alerts/{aid}", headers=hb, json={"status": "OPEN"})).status_code == 404


async def test_disabled_rules_do_not_run(client, make, app, db):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    rid = (await _rule(client, h))["id"]
    await _activate(client, h, rid)
    assert (await client.post(f"{D}/rules/{rid}/transition", headers=h, json={"to": "DISABLED"})).status_code == 200
    await make.index(
        t,
        [
            ev(
                0.5,
                process={
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\powershell.exe",
                    "command_line": "powershell.exe -enc X",
                },
            )
        ],
    )
    await service.run_scheduled(app.state.sessionmaker, app.state.search)
    from sqlalchemy import func, select

    assert (await db.execute(select(func.count()).select_from(Alert).where(Alert.tenant_id == t.id))).scalar_one() == 0


async def test_engine_error_is_recorded_not_raised(app, make, client, monkeypatch):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    rid = (await _rule(client, h))["id"]
    await _activate(client, h, rid)

    async def boom(*a, **k):
        raise RuntimeError("engine down\nsecret detail")

    monkeypatch.setattr(app.state.search, "search", boom)
    s = await service.run_scheduled(app.state.sessionmaker, app.state.search)
    assert s["errors"] >= 1  # other tenants' active rules share the database
    got = (await client.get(f"{D}/rules/{rid}", headers=h)).json()
    assert got["last_run_status"] == "error" and got["last_run_error"] == "engine down"


async def test_formats_and_overview(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.VIEWER)
    assert {f["id"] for f in (await client.get(f"{D}/formats", headers=h)).json()} == {"sigma", "hunt_query"}
    o = (await client.get(f"{D}/overview", headers=h)).json()
    assert o["open_alerts"] == 0 and o["coverage"] == []
    _ = (DetectionRule, datetime, UTC, timedelta)
