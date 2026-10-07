import uuid

import pytest

from app.auth.rbac import Role
from tests.helpers import ev
from tests.mitre_helpers import mitre_loaded  # noqa: F401

pytestmark = pytest.mark.usefixtures("mitre_loaded")
M = "/api/v1/mitre"
PS = {"process": {"name": "powershell.exe", "pid": 7, "command_line": "powershell -enc AAAA"}}


async def _setup(client, make, role=Role.THREAT_HUNTER, n=1, host="WS-01"):
    t = await make.tenant()
    await make.index(t, [ev(i + 1, host={"hostname": f"{host}" if n == 1 else f"{host}-{i}"}, **PS) for i in range(n)])
    u, h = await make.login_as(t, role)
    ids = [x["id"] for x in (await client.post("/api/v1/events/search", headers=h, json={})).json()["hits"]]
    return t, u, h, ids


async def _case(client, h, **kw):
    return (await client.post("/api/v1/cases", headers=h, json={"title": "c", **kw})).json()


def body(case_id, ids, **kw):
    return {
        "technique_id": "T1059.001",
        "object_type": "case",
        "object_id": case_id,
        "confidence": "HIGH",
        "reasoning": "Encoded PowerShell observed in process.command_line",
        "evidence_event_ids": ids,
        **kw,
    }


async def test_reference_endpoints(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.VIEWER)
    tactics = (await client.get(f"{M}/tactics", headers=h)).json()
    assert [x["shortname"] for x in tactics][:4] == [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
    ]
    ex = (await client.get(f"{M}/techniques", headers=h, params={"tactic": "execution", "limit": 500})).json()
    assert "T1059.001" in {x["id"] for x in ex} and all("execution" in x["tactics"] for x in ex)
    assert [x["id"] for x in (await client.get(f"{M}/techniques", headers=h, params={"q": "powershell"})).json()] == [
        "T1059.001"
    ]
    assert (await client.get(f"{M}/techniques", headers=h, params={"q": "%"})).json() == []
    d = (await client.get(f"{M}/techniques/T1059", headers=h)).json()
    assert {s["id"] for s in d["subtechniques"]} >= {"T1059.001", "T1059.003"} and d["is_subtechnique"] is False
    for bad in ("T1059.0011", "nope", "T9999"):
        assert (await client.get(f"{M}/techniques/{bad}", headers=h)).status_code == 404
    assert (await client.get(f"{M}/tactics")).status_code == 401


async def test_mapping_lifecycle_and_case_journal(client, make):
    t, u, h, ids = await _setup(client, make)
    case = await _case(client, h)
    r = await client.post(f"{M}/mappings", headers=h, json=body(case["id"], ids))
    assert r.status_code == 201, r.text
    m = r.json()
    assert m["technique_name"] == "PowerShell" and m["evidence_count"] == 1 and m["tactics"] == ["execution"]
    assert (await client.post(f"{M}/mappings", headers=h, json=body(case["id"], ids))).status_code == 409
    listed = (
        await client.get(f"{M}/mappings", headers=h, params={"object_type": "case", "object_id": case["id"]})
    ).json()
    assert [x["id"] for x in listed] == [m["id"]]
    kinds = [a["kind"] for a in (await client.get(f"/api/v1/cases/{case['id']}/activity", headers=h)).json()]
    assert "mitre_mapped" in kinds
    assert (await client.delete(f"{M}/mappings/{m['id']}", headers=h)).status_code == 204
    kinds = [a["kind"] for a in (await client.get(f"/api/v1/cases/{case['id']}/activity", headers=h)).json()]
    assert "mitre_unmapped" in kinds
    assert (await client.delete(f"{M}/mappings/{m['id']}", headers=h)).status_code == 404


async def test_mapping_requires_reasoning_and_evidence_for_medium_high(client, make):
    t, u, h, ids = await _setup(client, make)
    case = await _case(client, h)
    base = body(case["id"], ids)
    assert (await client.post(f"{M}/mappings", headers=h, json={**base, "reasoning": "short"})).status_code == 422
    assert (
        await client.post(f"{M}/mappings", headers=h, json={k: v for k, v in base.items() if k != "reasoning"})
    ).status_code == 422
    for conf in ("MEDIUM", "HIGH"):
        r = await client.post(f"{M}/mappings", headers=h, json={**base, "confidence": conf, "evidence_event_ids": []})
        assert r.status_code == 400 and "evidence" in r.json()["error"]["message"]
    low = await client.post(f"{M}/mappings", headers=h, json={**base, "confidence": "LOW", "evidence_event_ids": []})
    assert low.status_code == 201 and low.json()["evidence_count"] == 0
    assert (await client.post(f"{M}/mappings", headers=h, json={**base, "technique_id": "T9999"})).status_code == 404
    assert (await client.post(f"{M}/mappings", headers=h, json={**base, "technique_id": "bogus"})).status_code == 422
    assert (
        await client.post(
            f"{M}/mappings", headers=h, json={**base, "technique_id": "T1003.001", "evidence_event_ids": ["a" * 32]}
        )
    ).status_code == 400
    det = await client.post(f"{M}/mappings", headers=h, json={**base, "object_type": "detection"})
    assert det.status_code == 400 and "Milestone 5" in det.json()["error"]["message"]
    assert (
        await client.post(f"{M}/mappings", headers=h, json={**base, "tenant_id": str(uuid.uuid4())})
    ).status_code == 422


async def test_mapping_objects_hunts_and_findings_and_closed_case_lock(client, make):
    t, u, h, ids = await _setup(client, make)
    hunt = (await client.post("/api/v1/hunts", headers=h, json={"title": "H"})).json()
    finding = (
        await client.post(f"/api/v1/hunts/{hunt['id']}/findings", headers=h, json={"title": "F", "event_ids": ids})
    ).json()
    for typ, oid in (("hunt", hunt["id"]), ("finding", finding["id"])):
        assert (await client.post(f"{M}/mappings", headers=h, json=body(oid, ids, object_type=typ))).status_code == 201
    case = await _case(client, h)
    mid = (await client.post(f"{M}/mappings", headers=h, json=body(case["id"], ids))).json()["id"]
    for to, c in (("INVESTIGATING", ""), ("FALSE_POSITIVE", "benign test"), ("CLOSED", "done")):
        assert (
            await client.post(f"/api/v1/cases/{case['id']}/transition", headers=h, json={"status": to, "comment": c})
        ).status_code == 200
    assert (
        await client.post(f"{M}/mappings", headers=h, json=body(case["id"], ids, technique_id="T1027"))
    ).status_code == 409
    assert (await client.delete(f"{M}/mappings/{mid}", headers=h)).status_code == 409


@pytest.mark.parametrize(
    "role,can_map",
    [
        (Role.VIEWER, False),
        (Role.SOC_ANALYST, True),
        (Role.THREAT_HUNTER, True),
        (Role.INCIDENT_RESPONDER, True),
        (Role.TENANT_ADMIN, True),
    ],
)
async def test_permissions(client, make, role, can_map):
    t, _, admin, ids = await _setup(client, make, role=Role.TENANT_ADMIN)
    case = await _case(client, admin)
    _, h = await make.login_as(t, role)
    assert (await client.get(f"{M}/matrix", headers=h)).status_code == 200
    assert (await client.get(f"{M}/mappings", headers=h)).status_code == 200
    r = await client.post(f"{M}/mappings", headers=h, json=body(case["id"], ids))
    assert r.status_code == (201 if can_map else 403)
    assert (await client.post(f"{M}/suggest", headers=h, json={"event_ids": ids})).status_code == (
        200 if can_map else 403
    )
    if can_map:
        assert (await client.delete(f"{M}/mappings/{r.json()['id']}", headers=h)).status_code == 204


async def test_mitre_isolation_of_mappings_matrix_and_summary(client, make):
    a, _, ha, ids_a = await _setup(client, make)
    b, _, hb, ids_b = await _setup(client, make)
    case_a, case_b = await _case(client, ha), await _case(client, hb)
    ma = (await client.post(f"{M}/mappings", headers=ha, json=body(case_a["id"], ids_a))).json()
    # B cannot map to A's case, cite A's events, read or delete A's mapping
    assert (await client.post(f"{M}/mappings", headers=hb, json=body(case_a["id"], ids_b))).status_code == 404
    assert (await client.post(f"{M}/mappings", headers=hb, json=body(case_b["id"], ids_a))).status_code == 400
    assert (await client.delete(f"{M}/mappings/{ma['id']}", headers=hb)).status_code == 404
    assert (await client.get(f"{M}/mappings", headers=hb, params={"object_id": case_a["id"]})).json() == []

    def count(cols, tid="T1059"):
        top = next(t for c in cols for t in c["techniques"] if t["id"] == tid)
        return top, next(s for s in top["subtechniques"] if s["id"] == "T1059.001")

    _, sub_b = count((await client.get(f"{M}/matrix", headers=hb)).json())
    assert sub_b["mapping_count"] == 0 and sub_b["top_confidence"] is None
    _, sub_a = count((await client.get(f"{M}/matrix", headers=ha)).json())
    assert sub_a["mapping_count"] == 1 and sub_a["top_confidence"] == "HIGH"
    s = (await client.get(f"{M}/techniques/T1059.001/summary", headers=hb)).json()
    assert s["mappings"] == 0 and s["objects"] == [] and s["risk"] == "LOW"
    assert (await client.post(f"{M}/suggest", headers=hb, json={"case_id": case_a["id"]})).status_code == 404


async def test_risk_summary_rules(client, make):
    t = await make.tenant()
    await make.index(
        t,
        [
            ev(1, host={"hostname": "WS-A"}, user={"name": "u1"}, **PS),
            ev(2, host={"hostname": "WS-A"}, user={"name": "u2"}, **PS),
            ev(3, host={"hostname": "WS-B"}, user={"name": "u1"}, **PS),
        ],
    )
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    hits = (await client.post("/api/v1/events/search", headers=h, json={})).json()["hits"]
    by_host = {}
    for x in hits:
        by_host.setdefault(x["host"]["hostname"], []).append(x["id"])
    summary = lambda tid="T1059.001": client.get(f"{M}/techniques/{tid}/summary", headers=h)  # noqa: E731

    s0 = (await summary()).json()
    assert s0["risk"] == "LOW" and s0["mappings"] == 0 and s0["risk_reasons"] == ["no mappings in this tenant"]

    low = await _case(client, h, title="low")
    await client.post(f"{M}/mappings", headers=h, json={**body(low["id"], []), "confidence": "LOW"})
    assert (await summary()).json()["risk"] == "LOW"

    one = await _case(client, h, title="one host")
    await client.post(
        f"{M}/mappings", headers=h, json=body(one["id"], by_host["WS-B"], confidence="HIGH", technique_id="T1027")
    )
    s1 = (await summary("T1027")).json()
    assert s1["risk"] == "MEDIUM" and s1["hosts"] == {"count": 1, "names": ["WS-B"]} and s1["evidence_events"] == 1

    crit = await make_asset(client, h, "ws-b", "CRITICAL")
    s1b = (await summary("T1027")).json()
    assert crit and s1b["risk"] == "HIGH" and any("high-criticality" in r for r in s1b["risk_reasons"])

    wide = await _case(client, h, title="wide")
    await client.post(f"{M}/mappings", headers=h, json=body(wide["id"], by_host["WS-A"] + by_host["WS-B"]))
    s2 = (await summary()).json()
    assert (
        s2["risk"] == "HIGH" and s2["hosts"]["count"] == 2 and s2["users"]["count"] == 2 and s2["evidence_events"] == 3
    )
    assert {o["object_type"] for o in s2["objects"]} == {"case"} and s2["mappings"] == 2
    medium = await _case(client, h, title="med")
    await client.post(
        f"{M}/mappings",
        headers=h,
        json={**body(medium["id"], by_host["WS-A"][:1]), "confidence": "MEDIUM", "technique_id": "T1204.002"},
    )
    assert (await summary("T1204.002")).json()["risk"] == "MEDIUM"


async def make_asset(client, h, key, criticality):
    r = await client.post("/api/v1/assets", headers=h, json={"type": "host", "key": key, "criticality": criticality})
    return r.status_code == 201


async def test_suggest_for_case_and_hunt_flags_already_mapped(client, make):
    t, _, h, ids = await _setup(client, make)
    case = await _case(client, h, event_ids=ids)
    hunt = (await client.post("/api/v1/hunts", headers=h, json={"title": "H"})).json()
    await client.post(f"/api/v1/hunts/{hunt['id']}/findings", headers=h, json={"title": "F", "event_ids": ids})
    first = (await client.post(f"{M}/suggest", headers=h, json={"case_id": case["id"]})).json()
    assert {s["technique_id"] for s in first["suggestions"]} >= {"T1059.001", "T1027"} and not any(
        s["mapped"] for s in first["suggestions"]
    )
    await client.post(f"{M}/mappings", headers=h, json=body(case["id"], ids))
    again = {
        s["technique_id"]: s
        for s in (await client.post(f"{M}/suggest", headers=h, json={"case_id": case["id"]})).json()["suggestions"]
    }
    assert again["T1059.001"]["mapped"] is True and again["T1027"]["mapped"] is False
    via_hunt = (await client.post(f"{M}/suggest", headers=h, json={"hunt_id": hunt["id"]})).json()
    assert via_hunt["analyzed_events"] >= 1 and via_hunt["suggestions"]


async def test_report_lists_mapped_techniques_with_reasoning(client, make):
    t, _, h, ids = await _setup(client, make, role=Role.TENANT_ADMIN)
    case = await _case(client, h, event_ids=ids)
    empty = (await client.post(f"/api/v1/cases/{case['id']}/reports", headers=h)).json()["content"]
    assert "## MITRE ATT&CK techniques" in empty and "_No techniques mapped._" in empty
    await client.post(
        f"{M}/mappings", headers=h, json=body(case["id"], ids, reasoning="Encoded | PowerShell\nINJECT observed")
    )
    md = (await client.post(f"/api/v1/cases/{case['id']}/reports", headers=h)).json()["content"]
    assert "| T1059.001 | PowerShell | HIGH | 1 |" in md and "Encoded \\| PowerShell INJECT observed" in md


async def test_mapping_actions_are_audited(client, make, db):
    import sqlalchemy as sa

    from app.audit.models import AuditLog

    t, _, h, ids = await _setup(client, make)
    case = await _case(client, h)
    m = (await client.post(f"{M}/mappings", headers=h, json=body(case["id"], ids))).json()
    await client.delete(f"{M}/mappings/{m['id']}", headers=h)
    actions = {a for (a,) in (await db.execute(sa.select(AuditLog.action).where(AuditLog.tenant_id == t.id))).all()}
    assert {"mitre.map", "mitre.unmap"} <= actions
