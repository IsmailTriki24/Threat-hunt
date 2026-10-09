# ruff: noqa: E501
"""An AI investigation opens a case: the hunt report becomes the case's first report, with the verified evidence, indicators and
ATT&CK mappings attached. Idempotent per run, permission-gated, tenant-scoped, and never able to lose the investigation."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select

from app.ai import casebuilder
from app.ai.models import AiRun
from app.auth import rbac
from app.auth.rbac import Permission, Role
from app.mitre.models import MitreMapping, MitreTechnique
from tests import ai_scenario as sc
from tests.ai_policies import Hunter
from tests.test_ai import conclude, tool
from tests.test_ai_agent import Scripted, _parse_sse, _seeded

A = "/api/v1/ai"
C = "/api/v1/cases"
GOAL = {"goal": "Hunt for encoded PowerShell and anything it led to", "mode": "standard"}


@pytest.fixture
def llm(app):
    def install(p):
        app.state.llm = p
        return p

    yield install
    app.state.llm = None


async def _hunter_run(client, h, **extra):
    r = await client.post(f"{A}/runs", headers=h, json={**GOAL, **extra})
    assert r.status_code == 201, r.text
    return r.json()


async def _report(client, h, case_id, which=0):
    reports = (await client.get(f"{C}/{case_id}/reports", headers=h)).json()
    return reports[which]


async def test_a_finished_hunt_opens_a_case_with_the_report_evidence_and_journal(client, make, llm, app):
    async with app.state.sessionmaker() as s:  # the platform's ATT&CK reference data (loaded by `init` in production)
        added_ref = await s.get(MitreTechnique, "T1059.001") is None
        if added_ref:
            s.add(MitreTechnique(id="T1059.001", name="PowerShell", tactics=["execution"]))
            await s.commit()
    try:
        await _first_case_assertions(client, make, llm, app)
    finally:
        if added_ref:
            async with app.state.sessionmaker() as s:
                await s.execute(delete(MitreMapping).where(MitreMapping.technique_id == "T1059.001"))
                await s.execute(delete(MitreTechnique).where(MitreTechnique.id == "T1059.001"))
                await s.commit()


async def _first_case_assertions(client, make, llm, app):
    t, h = await _seeded(make, app)
    llm(Hunter())
    run = await _hunter_run(client, h, open_case=True)
    assert run["status"] == "COMPLETED" and run["case_id"] and run["case_number"] >= 1
    case = (await client.get(f"{C}/{run['case_id']}", headers=h)).json()
    assert (
        case["status"] == "OPEN"
        and case["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
        and "Threat indicators observed" in case["description"]
    )
    assert case["title"].endswith(f"- {datetime.now(UTC):%B %Y}")
    rep = await _report(client, h, run["case_id"])
    assert rep["kind"] == "hunt" and rep["version"] == 1
    d = rep["data"]  # the structured form the presentation draws its charts from
    assert (
        d["schema_version"] == 1
        and d["verdict"] == "findings"
        and d["stats"]["queries"] >= 3
        and d["stats"]["findings"] >= 1
    )
    assert d["timeline"] and any(t["cited"] for t in d["timeline"]) and d["hosts"] and d["sections"]
    md = rep["content"]
    for part in (
        "## Hunting Summary",
        "**Scope of Hunt:**",
        "> **Threat indicators observed",
        "## Details",
        "## Findings",
        "## Hunt Queries",
        "| Search | Status | Results |",
        "## Recommendations",
        "## References",
    ):
        assert part in md, part
    assert "powershell" in md.lower() and sc.C2_IP in md  # the real findings and indicators, not boilerplate
    # verified evidence and indicators landed on the case, tenant-scoped
    ev = (await client.get(f"{C}/{run['case_id']}/evidence", headers=h)).json()
    threat = {
        i for f in run["conclusion"]["findings"] if f["supported"] and f["severity"] != "INFO" for i in f["event_ids"]
    }
    gt, decoy = await sc.load_truth(app, t)
    got = {e["event_id"] for e in ev}
    assert got == threat and len(got) >= 3  # exactly the verified events the threat findings cite
    assert got <= gt and not (got & decoy)  # the intrusion, never the benign look-alike the hunter ruled out
    iocs = (await client.get(f"{C}/{run['case_id']}/iocs", headers=h)).json()
    assert any(i["value"] == sc.C2_IP for i in iocs)
    activity = (await client.get(f"{C}/{run['case_id']}/activity", headers=h)).json()
    created = next(a for a in activity if a["kind"] == "created")
    assert created["details"]["ai_run_id"] == run["id"] and created["details"]["verdict"] == "findings"
    assert any(a["kind"] == "report_generated" for a in activity)
    # the run is linked back, and a later read still shows it
    assert (await client.get(f"{A}/runs/{run['id']}", headers=h)).json()["case_id"] == run["case_id"]
    async with (
        app.state.sessionmaker() as s
    ):  # ATT&CK mapping only for techniques the findings support and the reference data knows
        maps = (await s.execute(select(MitreMapping).where(MitreMapping.object_id == run["case_id"]))).scalars().all()
    assert (
        [m.technique_id for m in maps] == ["T1059.001"]
        and maps[0].source == "suggestion"
        and maps[0].evidence_event_ids
    )


async def test_nothing_is_opened_unless_asked(client, make, llm, app):
    _, h = await _seeded(make, app)
    llm(Hunter())
    run = await _hunter_run(client, h)
    assert run["case_id"] is None and run["case_number"] is None


async def test_a_clean_but_incomplete_hunt_does_not_claim_all_clear(client, make, llm, app):
    _, h = await _seeded(make, app)
    llm(Scripted(tool("search_events", query="process.name:*nonexistent.exe*"), conclude([])))
    run = await _hunter_run(client, h, mode="quick", open_case=True)
    case = (await client.get(f"{C}/{run['case_id']}", headers=h)).json()
    assert case["severity"] in ("INFO", "LOW") and case["priority"] == "P4"
    md = (await _report(client, h, run["case_id"]))["content"]
    assert (
        "No Threat Indicators Observed - No further action is required" not in md
    )  # LOW confidence / unresolved: never an all-clear
    assert "> **" in md and "## Hunt Queries" in md and "No results returned for this query" in md


async def test_the_case_can_be_opened_afterwards_and_asking_again_refreshes_instead_of_duplicating(
    client, make, llm, app
):
    _, h = await _seeded(make, app)
    llm(Hunter())
    run = await _hunter_run(client, h)
    first = await client.post(f"{A}/runs/{run['id']}/case", headers=h)
    assert first.status_code == 200 and first.json()["created"] is True
    again = await client.post(f"{A}/runs/{run['id']}/case", headers=h)
    assert (
        again.json()["created"] is False
        and again.json()["case_id"] == first.json()["case_id"]
        and again.json()["number"] == first.json()["number"]
    )
    reports = (await client.get(f"{C}/{first.json()['case_id']}/reports", headers=h)).json()
    assert [r["version"] for r in reports] == [2, 1] and all(r["kind"] == "hunt" for r in reports)
    assert len((await client.get(C, headers=h)).json()) == 1
    evidence = (await client.get(f"{C}/{first.json()['case_id']}/evidence", headers=h)).json()
    assert len(evidence) == len({e["event_id"] for e in evidence})  # refreshing does not duplicate evidence


async def test_a_user_without_case_permission_gets_the_run_but_no_case(client, make, llm, app, monkeypatch):
    _, h = await _seeded(make, app)
    llm(Hunter())
    reduced = rbac.ROLE_PERMISSIONS[Role.THREAT_HUNTER] - {Permission.CASES_WRITE}
    monkeypatch.setitem(rbac.ROLE_PERMISSIONS, Role.THREAT_HUNTER, reduced)
    run = await _hunter_run(client, h, open_case=True)
    assert run["status"] == "COMPLETED" and run["case_id"] is None
    assert (await client.post(f"{A}/runs/{run['id']}/case", headers=h)).status_code == 403


async def test_a_failure_while_opening_the_case_never_loses_the_investigation(client, make, llm, app, monkeypatch):
    _, h = await _seeded(make, app)
    llm(Hunter())

    async def boom(*a, **k):
        raise RuntimeError("case builder exploded")

    monkeypatch.setattr(casebuilder, "open_case", boom)
    run = await _hunter_run(client, h, open_case=True)
    assert run["status"] == "COMPLETED" and run["case_id"] is None
    assert (await client.get(f"{A}/runs/{run['id']}", headers=h)).status_code == 200  # saved
    assert (await client.get(C, headers=h)).json() == []  # and no half-built case was left behind


async def test_one_tenant_cannot_open_a_case_from_another_tenants_run(client, make, llm, app):
    _, h1 = await _seeded(make, app)
    llm(Hunter())
    run = await _hunter_run(client, h1)
    t2 = await make.tenant()
    _, h2 = await make.login_as(t2, Role.THREAT_HUNTER)
    assert (await client.post(f"{A}/runs/{run['id']}/case", headers=h2)).status_code == 404


async def test_a_run_without_a_conclusion_cannot_open_a_case(client, make, llm, app):
    _, h = await _seeded(make, app)
    llm(Scripted(tool("search_events", query="process.name:*x*"), conclude([])))
    run = await _hunter_run(client, h, mode="quick")
    async with app.state.sessionmaker() as s:
        row = await s.get(AiRun, run["id"])
        row.conclusion = None
        await s.commit()
    r = await client.post(f"{A}/runs/{run['id']}/case", headers=h)
    assert r.status_code == 400 and "no conclusion" in r.json()["error"]["message"]
    assert (await client.get(C, headers=h)).json() == []


async def test_streamed_runs_report_their_case_and_a_resume_refreshes_it(client, make, llm, app):
    _, h = await _seeded(make, app)
    llm(Hunter())
    r = await client.post(f"{A}/runs/stream", headers=h, json={**GOAL, "open_case": True})
    done = _parse_sse(r.text)[-1]
    assert done[0] == "done" and done[1]["case_id"] and done[1]["case_number"]
    case_id = done[1]["case_id"]
    reports = (await client.get(f"{C}/{case_id}/reports", headers=h)).json()
    assert [x["version"] for x in reports] == [1]
    # an interrupted run that is resumed to the end refreshes the same case (new report version, same case number)
    async with app.state.sessionmaker() as s:
        row = await s.get(AiRun, done[1]["id"])
        row.status = "INCOMPLETE"
        await s.commit()
    llm(Scripted(tool("search_events", query="process.name:*powershell.exe*"), conclude([])))
    r2 = await client.post(f"{A}/runs/{done[1]['id']}/resume/stream", headers=h, json={"mode": "quick"})
    last = _parse_sse(r2.text)[-1]
    assert last[0] == "done" and last[1]["case_id"] == case_id
    reports2 = (await client.get(f"{C}/{case_id}/reports", headers=h)).json()
    assert [x["version"] for x in reports2] == [2, 1]
    assert len((await client.get(C, headers=h)).json()) == 1
