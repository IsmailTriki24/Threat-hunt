# ruff: noqa: E501, F811
"""The AI hunting agent searches the LIVE SIEMs: coverage knows about them (so an empty stored copy is not "nothing to hunt"), siem_search is
budgeted, honest about failures, and what it shows is storable evidence; siem_findings reports what the sweep already found."""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.ai import agent, tools
from app.ai import state as st
from app.auth.rbac import Role
from app.core.config import get_settings
from app.core.crypto import encrypt_json
from app.datasources.models import DataSource
from app.detections.models import Alert, DetectionRule
from tests.test_ai import A, Scripted, conclude, llm, nb, real_steps, results, tool  # noqa: F401
from tests.test_ai_agent import H1, _run
from tests.test_ioc_sweep import wire  # noqa: F401
from tests.test_logrhythm_ioc import lr_log, make_siem

NOW = datetime.now(UTC).replace(microsecond=0)


async def _hunter(make, app, handler, *, trend=False):
    """A tenant whose ONLY telemetry is a live LogRhythm: the stored index is empty, as it is once collection is switched off."""
    t = await make.tenant()
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    async with app.state.sessionmaker() as db:
        db.add(
            DataSource(
                tenant_id=t.id,
                name="LogRhythm SIEM",
                connector_type="logrhythm",
                config={"base_url": "https://lr.example", "hostname": "dc1"},
                secrets_enc=encrypt_json(get_settings(), {"token": "T"}),
                enabled=False,
            )
        )
        await db.commit()
    return t, h


def siem_results(p):
    return [r for r in results(p.calls[-1]["messages"])]


def logs():
    return [
        lr_log(1, originIp="203.0.113.5", impactedHost="srv9.corp.example", login="bob"),
        lr_log(2, originIp="203.0.113.50"),
    ]


# ---- coverage ---------------------------------------------------------------------------------------------
def test_live_sources_count_as_coverage_so_an_empty_stored_copy_is_not_nothing_to_hunt():
    inv = st.Investigation.new("hunt", 24, "quick")
    inv.coverage = agent.coverage_of(
        {
            "total": 0,
            "event_types": {},
            "live_sources": [
                {"name": "LogRhythm SIEM", "kind": "logrhythm", "event_types": ["authentication", "network_connection"]}
            ],
            "stored_newest": "2026-10-13T10:00:00+00:00",
        }
    )
    assert (
        "authentication" in inv.coverage["event_types"] and inv.coverage["live_sources"][0]["name"] == "LogRhythm SIEM"
    )
    assert agent.gate_reasons(inv, st.MODES["quick"])  # still has to test hypotheses: the live SIEMs can be asked
    inv.coverage = agent.coverage_of({"total": 0, "event_types": {}})
    assert (
        agent.gate_reasons(inv, st.MODES["quick"]) == []
    )  # nothing stored AND no live source: genuinely nothing to hunt
    assert "Live SIEMs" in _brief(inv, with_live=True)


def _brief(inv, with_live):
    if with_live:
        inv.coverage = agent.coverage_of(
            {
                "total": 0,
                "live_sources": [{"name": "LogRhythm SIEM", "kind": "logrhythm", "event_types": ["authentication"]}],
                "stored_newest": None,
            }
        )
    return inv.brief({"queries": 5}, st.MODES["quick"])


async def test_the_agent_is_told_about_the_live_sources_and_that_the_stored_copy_is_not_current(
    client, make, llm, app, wire
):
    wire(make_siem(logs())[0])
    t, h = await _hunter(make, app, None)
    p = llm(Scripted(nb(H1), tool("siem_search", query="203.0.113.5", hypothesis="H1"), conclude([])))
    run = await _run(client, h, mode="quick")
    assert "siem_search" in p.calls[0]["tools"] and "siem_findings" in p.calls[0]["tools"]
    assert "LIVE SIEMs" in p.calls[0]["system"] and "NOT current" in p.calls[0]["system"]
    cov = run["conclusion"]["coverage"]["telemetry"]
    assert cov["total"] == 0 and cov["live_sources"][0]["name"] == "LogRhythm SIEM"
    assert "LogRhythm SIEM" in str(p.calls[1]["messages"])  # the state brief names the live source


# ---- siem_search ------------------------------------------------------------------------------------------
async def test_siem_search_returns_only_real_hits_with_their_source_and_stores_them_so_they_can_be_cited(
    client, make, llm, app, wire
):
    wire(make_siem(logs())[0])
    t, h = await _hunter(make, app, None)

    def cite(messages):
        return [e["id"] for r in results(messages) for e in (r.get("data") or {}).get("events", [])]

    p = llm(Scripted(nb(H1), tool("siem_search", query="203.0.113.5", hypothesis="H1", purpose="test"), conclude(cite)))
    run = await _run(client, h, mode="quick")
    step = next(s for s in real_steps(run) if s["name"] == "siem_search")
    assert (
        step["status"] == "ok" and step["total"] == 1 and step["returned"] == 1
    )  # the look-alike 203.0.113.50 was dropped
    res = next(r for r in results(p.calls[-1]["messages"]) if (r.get("data") or {}).get("sources"))["data"]
    assert (
        res["events"][0]["from"] == "LogRhythm SIEM"
        and res["sources"][0]["status"] == "ok"
        and res["sources"][0]["read"] >= 1
    )
    eid = res["events"][0]["id"]
    # the event the model was shown exists in the store, so the conclusion's citation is real and a case can use it
    assert (await app.state.search.get_event(t.id, eid)) is not None
    assert run["status"] == "COMPLETED" and eid in str(run["conclusion"])


async def test_a_failing_siem_is_reported_as_unanswered_not_as_an_empty_result(client, make, llm, app, wire):
    wire(lambda request: httpx.Response(500, json={}))
    t, h = await _hunter(make, app, None)
    p = llm(Scripted(nb(H1), tool("siem_search", query="203.0.113.5", hypothesis="H1"), conclude([])))
    run = await _run(client, h, mode="quick")
    step = next(s for s in real_steps(run) if s["name"] == "siem_search")
    assert step["status"] == "error" and step["kind"] == "backend_unavailable"
    assert "UNANSWERED" in step["error"] and "LogRhythm SIEM" in step["error"]
    assert any("siem_search" in g and "UNANSWERED" in g for g in run["conclusion"]["coverage"]["gaps"])


async def test_an_empty_live_result_says_what_it_does_and_does_not_mean(client, make, llm, app, wire):
    wire(make_siem([])[0])
    t, h = await _hunter(make, app, None)
    p = llm(Scripted(nb(H1), tool("siem_search", query="198.51.100.77", hypothesis="H1"), conclude([])))
    run = await _run(client, h, mode="quick")
    step = next(s for s in real_steps(run) if s["name"] == "siem_search")
    assert step["status"] == "empty"
    data = next(r for r in results(p.calls[-1]["messages"]) if (r.get("data") or {}).get("sources"))["data"]
    assert "not proof of absence" in data["note"] and data["sources"][0]["matched"] == 0


async def test_siem_searches_are_budgeted_and_a_query_with_nothing_to_search_is_refused(
    client, make, llm, app, wire, monkeypatch
):
    s = get_settings().model_copy(update={"ai_siem_max_calls": 1})
    monkeypatch.setattr(tools, "get_settings", lambda: s)
    monkeypatch.setattr("app.ai.agent.get_settings", lambda: s)
    wire(make_siem(logs())[0])
    t, h = await _hunter(make, app, None)
    llm(
        Scripted(
            nb(H1),
            tool("siem_search", query="203.0.113.5", hypothesis="H1"),
            tool("siem_search", query="198.51.100.9", hypothesis="H1"),
            tool("siem_search", query="   ", hypothesis="H1"),
            conclude([]),
        )
    )
    run = await _run(client, h, mode="quick")
    steps = [s for s in real_steps(run) if s["name"] == "siem_search"]
    assert [x["status"] for x in steps] == ["ok", "error", "error"]
    assert steps[1]["kind"] == "budget" and "budget" in steps[1]["error"]
    assert steps[2]["kind"] in ("budget", "invalid_query", "invalid_arguments")


async def test_a_query_no_siem_could_answer_does_not_use_up_the_search_budget(
    client, make, llm, app, wire, monkeypatch
):
    s = get_settings().model_copy(update={"ai_siem_max_calls": 1})
    monkeypatch.setattr(tools, "get_settings", lambda: s)
    monkeypatch.setattr("app.ai.agent.get_settings", lambda: s)
    wire(make_siem(logs())[0])
    t, h = await _hunter(make, app, None)
    llm(
        Scripted(
            nb(H1),
            tool("siem_search", query="event_type:authentication outcome:failure", hypothesis="H1"),
            tool("siem_search", query="203.0.113.5", hypothesis="H1"),
            conclude([]),
        )
    )
    run = await _run(client, h, mode="quick")
    steps = [s for s in real_steps(run) if s["name"] == "siem_search"]
    assert [x["status"] for x in steps] == ["empty", "ok"]


async def test_siem_search_can_be_limited_to_one_family_and_reports_when_none_is_configured(
    client, make, llm, app, wire
):
    wire(make_siem(logs())[0])
    t, h = await _hunter(make, app, None)
    llm(Scripted(nb(H1), tool("siem_search", query="203.0.113.5", where="trend", hypothesis="H1"), conclude([])))
    run = await _run(client, h, mode="quick")
    step = next(s for s in real_steps(run) if s["name"] == "siem_search")
    assert (
        step["status"] == "error" and step["kind"] == "unavailable"
    )  # only LogRhythm is configured: the model is told, not given an empty result


# ---- siem_findings ----------------------------------------------------------------------------------------
async def test_siem_findings_lists_what_the_sweep_already_found_and_makes_it_citable(client, make, llm, app, wire):
    wire(make_siem([])[0])
    t, h = await _hunter(make, app, None)
    ev_id = uuid.uuid4().hex
    async with app.state.sessionmaker() as db:
        rule = DetectionRule(
            tenant_id=t.id,
            title="Password spraying",
            description="d",
            format="siem",
            content="built-in:Password spraying",
            version=1,
            status="ACTIVE",
            severity="HIGH",
            unsupported=[],
            warnings=[],
            techniques=["T1110.003"],
            tactics=[],
            tags=["siem-builtin", "siem:password_spray"],
            tests_passed=True,
            activated_at=NOW,
        )
        db.add(rule)
        await db.flush()
        snap = {
            "id": ev_id,
            "timestamp": (NOW - timedelta(hours=1)).isoformat(),
            "source": "logrhythm",
            "event_type": "authentication",
            "message": "Password spraying: 40 events involving 15 accounts from 10.9.9.9",
            "host": {"hostname": "dc1"},
            "tenant_id": str(t.id),
        }
        db.add(
            Alert(
                tenant_id=t.id,
                rule_id=rule.id,
                rule_version=1,
                rule_title=rule.title,
                severity="HIGH",
                event_id=ev_id,
                event_timestamp=NOW - timedelta(hours=1),
                snapshot=snap,
                status="OPEN",
            )
        )
        await db.commit()
    p = llm(Scripted(nb(H1), tool("siem_findings"), conclude([ev_id])))
    run = await _run(client, h, mode="quick")
    step = next(s for s in real_steps(run) if s["name"] == "siem_findings")
    assert step["status"] == "ok" and step["total"] == 1
    data = next(r for r in results(p.calls[-1]["messages"]) if (r.get("data") or {}).get("alerts"))["data"]
    assert (
        data["alerts"][0]["alert"] == "Password spraying"
        and data["alerts"][0]["attack"] == ["T1110.003"]
        and data["alerts"][0]["host"] == "dc1"
    )


def test_the_report_counts_live_searches_as_telemetry_and_labels_them():
    from app.ai import hunt_report

    assert "siem_search" in hunt_report.TELEMETRY_TOOLS and hunt_report.TOOL_LABEL["siem_search"] == "Live SIEM search"
