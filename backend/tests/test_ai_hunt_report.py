# ruff: noqa: E501
"""Hunt report engine: a finished AI run becomes a structured hunting report. Pure functions, so every branch of the verdict logic,
the query sections and the safety of untrusted text can be pinned down without a database."""

from datetime import UTC, datetime

from app.ai import hunt_report as hr
from app.ai import playbooks

CREATED = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def finding(**kw):
    return {
        "title": "Encoded PowerShell from Word", "description": "winword spawned powershell -enc", "severity": "HIGH",
        "classification": "strongly_supported", "event_ids": ["e1", "e2"], "queries": ["q2"], "techniques": ["T1059.001"],
        "alternative_explanations": ["Software deployment"], "supported": True, **kw,
    }  # fmt: skip


def conclusion(**kw):
    c = {
        "summary": "Two hosts ran encoded PowerShell launched by Word.", "confidence": "HIGH", "findings": [finding()],
        "next_steps": ["Isolate WS-02"], "unresolved_questions": [], "validation_notes": [], "events_reviewed": 12,
        "hypotheses": [{"id": "H1", "statement": "Encoded PowerShell is malicious", "status": "supported"}],
        "coverage": {"queries": 2, "ok": 2, "errors": 0, "gaps": []}, "stop_reason": "objective_addressed", "forced": False,
        "intel": {}, "playbooks_used": [], "playbooks": [], **kw,
    }  # fmt: skip
    return c


def tool_step(ref, query, total, *, status="ok", error=None, **kw):
    return {"type": "tool", "name": "search_events", "input": {"query": query}, "ref": ref, "status": status, "error": error, "total": total, "returned": min(total, 10), **kw}  # fmt: skip


def run(c=None, steps=None, **kw):
    state = {
        "evidence": {
            "e1": {"id": "e1", "timestamp": "2026-10-08T09:01:02Z", "host": "WS-02", "user": "bob", "summary": "powershell.exe -enc ...", "tags": ["attack.t1059.001"]},
            "e2": {"id": "e2", "timestamp": "2026-10-08T09:02:00Z", "host": "WS-02", "user": "bob", "summary": "winword.exe started"},
        },
        "queries": [{"ref": "q2", "event_ids": ["e1", "e2"]}],
    }  # fmt: skip
    return {
        "id": "run-1", "goal": "hunt encoded powershell", "hours_back": 744, "mode": "standard", "model": "m-1", "status": "COMPLETED",
        "created_at": CREATED, "steps": steps if steps is not None else [tool_step("q2", "process.name:*powershell.exe*", 2)],
        "conclusion": conclusion() if c is None else c, "state": state, **kw,
    }  # fmt: skip


# ---- verdict: honest by construction --------------------------------------------------------------------------------------


def test_verified_strong_findings_make_a_findings_report_with_the_right_severity():
    r = hr.build(run())
    assert r.verdict == "findings" and r.severity == "HIGH" and r.priority == "P2"
    assert r.verdict_line.startswith("Threat indicators observed")
    assert r.evidence_ids == ["e1", "e2"]
    assert r.technique_claims == [
        {
            "technique_id": "T1059.001",
            "confidence": "HIGH",
            "reasoning": r.technique_claims[0]["reasoning"],
            "event_ids": ["e1", "e2"],
        }
    ]


def test_only_suspicious_findings_demand_review_and_cap_severity_at_medium():
    r = hr.build(run(conclusion(findings=[finding(classification="suspicious", severity="CRITICAL")])))
    assert r.verdict == "suspicious" and r.severity == "MEDIUM" and r.priority == "P3"


def test_a_complete_hunt_with_nothing_left_undone_may_say_no_further_action():
    c = conclusion(findings=[], confidence="MEDIUM", hypotheses=[{"id": "H1", "statement": "x", "status": "refuted"}])
    r = hr.build(run(c))
    assert r.verdict == "clean" and r.verdict_line == "No Threat Indicators Observed - No further action is required"
    assert r.severity == "INFO" and r.priority == "P4"


def test_claims_that_cite_no_retrieved_event_never_count_as_findings():
    c = conclusion(findings=[finding(supported=False, event_ids=[]), finding(supported=False, classification="confirmed", event_ids=[])],
                   confidence="MEDIUM", hypotheses=[])  # fmt: skip
    r = hr.build(run(c))
    assert r.findings == [] and r.verdict != "findings"
    assert any("2 claim(s)" in n and "discarded" in n for n in r.notes)


def test_a_failed_search_means_the_result_is_unknown_not_clean():
    steps = [
        tool_step("q1", "process.name:*cmd.exe*", 0, status="error", error="the search backend timed out; UNANSWERED")
    ]
    r = hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=[]), steps))
    assert r.verdict == "clean_with_gaps" and "could not be completed" in r.verdict_line
    assert any("could not be completed" in g for g in r.gaps)
    md = hr.to_markdown(r)
    assert "FAILED" in md and "its result is unknown, not empty" in md and "No results returned" not in md


def test_telemetry_a_playbook_needs_but_the_tenant_lacks_blocks_a_clean_verdict():
    pb = {"id": "dns-tunneling", "title": "DNS tunneling", "attack": ["T1071.004"], "feasibility": "blocked", "missing": ["dns_query"], "total": 3, "run": 0,
          "steps": [{"purpose": "test", "tool": "search_events", "goal": "Look at DNS", "done": False}]}  # fmt: skip
    r = hr.build(
        run(
            conclusion(
                findings=[], confidence="MEDIUM", hypotheses=[], playbooks_used=["dns-tunneling"], playbooks=[pb]
            )
        )
    )
    assert r.verdict == "clean_with_gaps"
    assert any("DNS tunneling" in g and "blocked" in g for g in r.gaps)
    assert any("ingest dns_query" in x for x in r.recommendations)


def test_a_skipped_refute_step_is_a_gap():
    pb = {"id": "p", "title": "Some hunt", "attack": ["T1047"], "feasibility": "ready", "missing": [], "total": 2, "run": 1,
          "steps": [{"purpose": "test", "tool": "search_events", "goal": "a", "done": True}, {"purpose": "refute", "tool": "search_events", "goal": "Rule out management tooling", "done": False}]}  # fmt: skip
    r = hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=[], playbooks=[pb])))
    assert r.verdict == "clean_with_gaps" and any(
        "refute/scope" in g and "Rule out management tooling" in g for g in r.gaps
    )


def test_an_unfinished_or_forced_hunt_is_inconclusive_even_with_no_findings():
    base = dict(findings=[], confidence="MEDIUM", hypotheses=[])
    assert hr.build(run(conclusion(**base), status="INCOMPLETE")).verdict == "inconclusive"
    assert hr.build(run(conclusion(**base, forced=True))).verdict == "inconclusive"
    assert hr.build(run(conclusion(**base, stop_reason="budget_tool_calls"))).verdict == "inconclusive"
    open_h = [{"id": "H1", "statement": "x", "status": "open"}]
    assert hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=open_h))).verdict == "inconclusive"
    # a stall ("low_value") is how a clean hunt normally ends: that is not an incomplete hunt
    assert hr.build(run(conclusion(**base, stop_reason="low_value"))).verdict == "clean"


def test_environment_telemetry_limits_are_notes_not_blockers():
    c = conclusion(
        findings=[],
        confidence="MEDIUM",
        hypotheses=[],
        coverage={"gaps": ["no dns_query telemetry in the window - questions that need it cannot be answered"]},
    )
    r = hr.build(run(c))
    assert r.verdict == "clean" and r.notes and not r.gaps  # fmt: skip


def test_low_confidence_is_never_reported_as_clean():
    assert hr.build(run(conclusion(findings=[], confidence="LOW", hypotheses=[]))).verdict == "clean_with_gaps"


# ---- structure ------------------------------------------------------------------------------------------------------------


def test_scope_and_title_follow_the_run():
    r = hr.build(run())
    assert r.scope == "September 07, 2026 through October 08, 2026 (UTC) - Total Days: 31" and r.days == 31
    assert r.title.endswith("- October 2026")
    short = hr.build(run(hours_back=6))
    assert short.scope.startswith("the last 6 hour(s): October 08, 2026 06:00 through October 08, 2026 12:00 (UTC)")
    named = hr.build(run(conclusion(report_title="Kerberoasting on domain controllers")))
    assert named.title == "Kerberoasting on domain controllers - October 2026"
    dated = hr.build(run(conclusion(report_title="Passkey phishing - September 2026")))
    assert dated.title == "Passkey phishing - September 2026"  # a year already in the title is not repeated


def test_the_title_falls_back_to_the_playbook_then_the_goal():
    with_pb = hr.build(run(conclusion(playbooks_used=["suspicious-powershell-execution"])))
    assert with_pb.title == "Suspicious PowerShell execution - October 2026"
    assert hr.build(run()).title == "Threat hunt: hunt encoded powershell - October 2026"


def test_every_query_that_ran_becomes_a_section_with_its_real_result():
    steps = [
        tool_step("q2", "process.name:*powershell.exe* process.command_line:encodedcommand", 2),
        tool_step("q3", "process.name:*wmic.exe*", 0, status="empty"),
        tool_step("q4", "process.name:*cmd.exe*", 5, cached=True),  # served from cache: not a separate search
        {"type": "tool", "name": "update_notebook", "input": {"ops": []}},  # not a search
        {"type": "tool", "name": "enrich_indicator", "auto": True, "input": {}},
        tool_step("q5", "x:1", 1, status="partial"),
    ]
    r = hr.build(run(steps=steps))
    assert [s.ref for s in r.sections] == ["q2", "q3", "q5"]
    first, zero, partial = r.sections
    assert first.status == "SUCCEEDED" and first.results == 2 and [x["id"] for x in first.rows] == ["e1", "e2"]
    assert first.rows[0]["host"] == "WS-02" and first.rows[0]["time"] == "2026-10-08 09:01:02"
    assert zero.results == 0 and partial.status == "PARTIAL"
    md = hr.to_markdown(r)
    assert "| Search | Status | Results |" in md and "_No results returned for this query_" in md
    assert "`process.name:*powershell.exe* process.command_line:encodedcommand`" in md


def test_a_playbook_step_gives_its_section_the_steps_own_name():
    pb = playbooks.catalog()["suspicious-powershell-execution"]
    steps = [
        tool_step(
            "q2",
            pb.steps[0].query,
            2,
            pb={"id": pb.id, "step": 1, "of": len(pb.steps), "purpose": "test", "confidence": 1.0},
        )
    ]
    r = hr.build(run(steps=steps))
    assert r.sections[0].title.startswith("Find PowerShell launched with an encoded command")
    assert "Playbook step 1 of" in r.sections[0].description


def test_attack_techniques_come_from_findings_playbooks_and_sensor_tags_with_official_links():
    c = conclusion(playbooks_used=["lateral-movement-wmi"], findings=[finding(techniques=["T1059.001"])])
    r = hr.build(run(c), technique_names={"T1059.001": "PowerShell"})
    by_id = {a["id"]: a for a in r.attack}
    assert by_id["T1059.001"]["source"] == "finding" and by_id["T1059.001"]["name"] == "PowerShell"
    assert by_id["T1047"]["source"] == "playbook"
    assert by_id["T1059.001"]["url"] == "https://attack.mitre.org/techniques/T1059/001/"
    md = hr.to_markdown(r)
    assert "[T1059.001](https://attack.mitre.org/techniques/T1059/001/) - PowerShell _(finding)_" in md


def test_recommendations_merge_the_models_with_defensive_hardening_for_the_tactics_hunted():
    c = conclusion(
        recommendations=["Rotate the credentials of bob immediately."],
        playbooks_used=["suspicious-powershell-execution"],
    )
    r = hr.build(run(c))
    assert r.recommendations[0] == "Rotate the credentials of bob immediately."
    assert "Isolate WS-02" in r.recommendations
    assert any("application control" in x for x in r.recommendations)  # execution tactic hardening
    assert len(r.recommendations) == len(set(r.recommendations)) <= 10


def test_references_are_attack_pages_web_sources_and_the_attribution_for_playbooks():
    steps = [
        tool_step(
            "q1",
            "x:1",
            1,
            sources=[
                {"title": "Vendor write-up", "url": "https://example.org/a", "domain": "example.org"},
                {"title": "bad", "url": "javascript:alert(1)", "domain": "x"},
            ],
        )
    ]
    r = hr.build(run(conclusion(playbooks_used=["lateral-movement-wmi"]), steps))
    urls = [x["url"] for x in r.references]
    assert "https://example.org/a" in urls and not any(u.startswith("javascript") for u in urls)
    assert any("attack.mitre.org/techniques/T1047" in u for u in urls)
    assert any("Anthropic-Cybersecurity-Skills" in u for u in urls)


def test_malicious_indicators_become_case_iocs():
    intel = {"ip:45.77.65.211": {"kind": "ip", "value": "45.77.65.211", "verdict": "malicious", "providers": []},
             "hash:" + "a" * 64: {"kind": "hash", "value": "a" * 64, "verdict": "unknown", "providers": []},
             "domain:evil.example": {"kind": "domain", "value": "evil.example", "verdict": "suspicious", "providers": []}}  # fmt: skip
    r = hr.build(run(conclusion(intel=intel)))
    assert {(i["type"], i["value"]) for i in r.indicators} == {("ip", "45.77.65.211"), ("domain", "evil.example")}
    md = hr.to_markdown(r)
    assert "## Threat Intelligence on Indicators Met" in md and "not that it is safe" in md


# ---- the document ---------------------------------------------------------------------------------------------------------


def test_the_report_has_the_sections_an_analyst_expects_in_order():
    md = hr.to_markdown(
        hr.build(run(conclusion(playbooks_used=["lateral-movement-wmi"], recommendations=["Do the thing carefully."])))
    )
    order = ["# ", "## Hunting Summary", "**Scope of Hunt:**", "> **", "## Details", "**Related ATT&CK Techniques**", "## Findings", "## Hunt Queries",
             "## Recommendations", "## References", "_Generated by the AI hunting agent (m-1), run run-1."]  # fmt: skip
    pos = [md.index(o) for o in order]
    assert pos == sorted(pos)
    assert "AI-generated analysis" in md


def test_untrusted_text_cannot_inject_markup_links_or_table_breaks():
    evil = "Click <script>alert(1)</script> [here](javascript:alert(1)) | a|b\n# fake heading"
    c = conclusion(summary=evil, report_title=evil, threat_background=evil, recommendations=[evil + " padding to length"],
                   findings=[finding(title=evil, description=evil)], unresolved_questions=[evil])  # fmt: skip
    steps = [
        tool_step("q2", "process.name:*x* `tick`", 1, hypothesis=None),
        tool_step("q9", "a", 1, sources=[{"title": evil, "url": "https://ok.example/x", "domain": "ok.example"}]),
    ]
    md = hr.to_markdown(hr.build(run(c, steps)))
    assert "<script" not in md and "](javascript:" not in md
    assert "# fake heading" not in [ln.strip() for ln in md.splitlines()]  # line-initial markup in prose is neutralised
    assert sum(1 for ln in md.splitlines() if ln.startswith("# ")) == 1  # the only H1 is the report title
    blocks, cur = [], []
    for ln in md.splitlines() + [""]:
        if ln.startswith("|"):
            cur.append(ln)
        elif cur:
            blocks.append(cur)
            cur = []
    for b in blocks:  # every row of a table has the same number of real (unescaped) cell separators
        counts = {ln.replace("\\|", "").count("|") for ln in b}
        assert len(counts) == 1, b
    assert "`` process.name:*x* `tick` ``" in md  # a backtick in a query cannot break out of its code span


def test_a_huge_hunt_is_capped_and_says_so():
    steps = [tool_step(f"q{i}", f"host.hostname:ws-{i}", 1) for i in range(1, 45)]
    r = hr.build(run(steps=steps))
    assert len(r.sections) == hr.MAX_SECTIONS and r.omitted_sections == 14
    assert "14 further search(es)" in hr.to_markdown(r)


def test_a_run_with_no_conclusion_still_produces_an_honest_report():
    r = hr.build(run(c={}, status="FAILED"))
    assert r.verdict == "inconclusive" and "No conclusion was produced" in r.summary
    assert hr.to_markdown(r).startswith("# ")


def test_a_playbook_that_was_mostly_skipped_cannot_support_a_clean_verdict():
    steps = [{"purpose": "test", "tool": "search_events", "goal": f"step {i}", "done": i < 3} for i in range(6)]
    pb = {
        "id": "p",
        "title": "Some hunt",
        "attack": ["T1047"],
        "feasibility": "ready",
        "missing": [],
        "total": 6,
        "run": 3,
        "steps": steps,
    }
    r = hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=[], playbooks=[pb])))
    assert r.verdict == "clean_with_gaps" and any("only partly followed: 3 of 6" in g for g in r.gaps)
    done = {**pb, "run": 5, "steps": [{**x, "done": True} for x in steps[:5]] + [{**steps[5], "done": False}]}
    assert (
        hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=[], playbooks=[done]))).verdict == "clean"
    )  # 5/6 is enough


def test_a_section_says_what_to_look_for_not_just_its_own_title_again():
    pb = playbooks.catalog()["suspicious-powershell-execution"]
    steps = [
        tool_step(
            "q2",
            pb.steps[0].query,
            0,
            status="empty",
            pb={"id": pb.id, "step": 1, "of": len(pb.steps), "purpose": "test", "confidence": 1.0},
        )
    ]
    s = hr.build(run(steps=steps)).sections[0]
    assert s.description.startswith("What to look for:") and pb.steps[0].look_for[:30] in s.description


def test_informational_findings_are_observations_and_never_make_an_incident():
    """Seen in a real run: the model could not answer ("no process telemetry") and filed an INFO finding saying Office never appears."""
    info = finding(
        title="Office processes appear nowhere in the telemetry",
        severity="INFO",
        classification="strongly_supported",
        techniques=[],
    )
    c = conclusion(
        findings=[info], confidence="MEDIUM", hypotheses=[{"id": "H1", "statement": "x", "status": "inconclusive"}]
    )
    r = hr.build(run(c))
    assert r.findings == [] and len(r.observations) == 1
    assert r.verdict == "inconclusive"  # the open hypothesis, not the INFO finding, decides
    assert (
        r.severity == "LOW" and r.evidence_ids == [] and r.technique_claims == []
    )  # nothing is attached to the case as evidence of a threat
    md = hr.to_markdown(r)
    assert "Threat indicators observed" not in md and "## Findings" not in md
    assert "## Observations" in md and "not threat indicators" in md
    done = conclusion(
        findings=[info], confidence="MEDIUM", hypotheses=[{"id": "H1", "statement": "x", "status": "refuted"}]
    )
    assert hr.build(run(done)).verdict == "clean"  # and an observation does not stop a clean verdict either


def test_a_low_severity_verified_finding_is_still_a_finding():
    r = hr.build(run(conclusion(findings=[finding(severity="LOW")])))
    assert r.verdict == "findings" and r.severity == "LOW" and r.priority == "P4"


def test_the_models_own_malformed_queries_are_not_reported_as_things_that_could_not_be_checked():
    steps = [
        tool_step(
            "q1",
            "process.name:",
            0,
            status="error",
            error="invalid query: missing value for process.name",
            kind="invalid_query",
        ),
        tool_step("q2", "x", 0, status="error", error="invalid arguments: limit", kind="invalid_arguments"),
        tool_step("q3", "process.name:*cmd.exe*", 3),
    ]
    r = hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=[]), steps))
    assert [s.ref for s in r.sections] == ["q3"] and r.gaps == [] and r.verdict == "clean"
    assert any("2 search attempt(s) were rejected as malformed" in n for n in r.notes)
    # but a search that reached the backend and failed is a real gap
    real = [tool_step("q9", "process.name:*cmd.exe*", 0, status="error", error="timed out", kind="timeout")]
    assert hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=[]), real)).verdict == "clean_with_gaps"


# ---- the structured form behind the presentation --------------------------------------------------------------------------


def test_the_structured_report_carries_what_the_charts_need():
    import json

    steps = [tool_step("q2", "process.name:*powershell.exe*", 2), tool_step("q3", "process.name:*wmic.exe*", 0, status="empty"),
             tool_step("q4", "x:1", 0, status="error", error="timed out", kind="timeout"), tool_step("q5", "y:1", 7)]  # fmt: skip
    r = hr.build(
        run(steps=steps), technique_names={"T1059.001": "PowerShell"}, technique_tactics={"T1059.001": ["execution"]}
    )
    d = r.to_dict()
    json.dumps(d)  # JSON-safe: it is stored as JSONB
    assert (
        d["schema_version"] == 1
        and d["verdict"] == "findings"
        and d["window_start"] < d["window_end"]
        and d["hours_back"] == 744
    )
    assert (
        d["stats"]["queries"] == 4
        and d["stats"]["with_results"] == 2
        and d["stats"]["no_results"] == 1
        and d["stats"]["failed"] == 1
    )
    assert (
        d["stats"]["events_reviewed"] == 2
        and d["stats"]["hosts"] == 1
        and d["stats"]["findings"] == 1
        and d["stats"]["techniques"] >= 1
    )
    assert d["hosts"] == [{"host": "WS-02", "events": 2}]
    assert [t["id"] for t in d["timeline"]] == ["e1", "e2"] and all(t["cited"] for t in d["timeline"])
    assert {a["id"]: a["tactics"] for a in d["attack"]}["T1059.001"] == ["execution"]
    assert d["sections"][0]["status"] == "SUCCEEDED" and d["sections"][0]["rows"][0]["host"] == "WS-02"


def test_a_sub_technique_without_its_own_tactics_inherits_its_parents():
    r = hr.build(run(), technique_tactics={"T1059": ["execution"]})
    assert {a["id"]: a["tactics"] for a in r.attack}["T1059.001"] == ["execution"]


def test_a_large_review_is_thinned_for_the_timeline_but_keeps_every_cited_event():
    ev = {
        f"x{i}": {
            "id": f"x{i}",
            "timestamp": f"2026-10-08T{(i // 60) % 24:02d}:{i % 60:02d}:00Z",
            "host": f"h{i % 5}",
            "summary": "s",
        }
        for i in range(600)
    }
    ev["e1"] = {"id": "e1", "timestamp": "2026-10-08T09:01:02Z", "host": "WS-02", "summary": "cited"}
    r = hr.build({**run(), "state": {"evidence": ev, "queries": []}}, technique_names={})
    ids = [t["id"] for t in r.timeline]
    assert (
        len(ids) <= 150
        and "e1" in ids
        and ids == sorted(ids, key=lambda i: next(t["timestamp"] for t in r.timeline if t["id"] == i))
    )
    assert r.stats["events_reviewed"] == 601


def test_a_finding_that_reports_an_absence_is_an_observation_even_with_a_severity():
    """Seen in a real run: 'No privilege escalation detected on the domain controller', LOW, confirmed."""
    for title in ("No privilege escalation detected on the domain controller", "No evidence of lateral movement", "Nothing suspicious found in service installs",
                  "Absence of Kerberoasting activity", "No anomalous logons observed"):  # fmt: skip
        r = hr.build(
            run(
                conclusion(
                    findings=[finding(title=title, severity="LOW", classification="confirmed")],
                    confidence="MEDIUM",
                    hypotheses=[],
                )
            )
        )
        assert r.findings == [] and len(r.observations) == 1 and r.verdict == "clean", title
    # but a negative-sounding title that reports a weakness or an event is still a finding
    for title in (
        "No MFA enforced on admin accounts",
        "No logging on the file server",
        "Not-allowed outbound connection to rare domain",
    ):
        r = hr.build(run(conclusion(findings=[finding(title=title, severity="MEDIUM")])))
        assert len(r.findings) == 1 and r.verdict == "findings", title


def test_titles_lose_the_models_own_classification_prefix_and_negative_findings_are_still_caught():
    """Seen in a real run: 'Strongly supported: Ransomware deployment is NOT occurring in this window' (LOW, suspicious)."""
    prefixed = finding(
        title="Confirmed: Phishing-based account compromise is the dominant attack",
        severity="MEDIUM",
        classification="confirmed",
    )
    absent = finding(
        title="Strongly supported: Ransomware deployment is NOT occurring in this window",
        severity="LOW",
        classification="suspicious",
    )
    r = hr.build(run(conclusion(findings=[prefixed, absent])))
    assert [f["title"] for f in r.findings] == [
        "Phishing-based account compromise is the dominant attack"
    ]  # the prefix is a badge, not a title
    assert [f["title"] for f in r.observations] == ["Ransomware deployment is NOT occurring in this window"]
    assert r.verdict == "findings" and r.severity == "MEDIUM"
    only_absent = hr.build(run(conclusion(findings=[absent], confidence="MEDIUM", hypotheses=[])))
    assert only_absent.verdict == "clean" and only_absent.findings == []


def test_repeated_gaps_are_summarised_not_listed_one_by_one():
    leads = [f"unexplored lead hash:{'ab' * 32}{i} (score 3; suspicious_path)" for i in range(5)]
    c = conclusion(
        findings=[], confidence="MEDIUM", hypotheses=[],
        unresolved_questions=[*leads, "H1 [open] Phishing-driven credential abuse is dominant", "H2 [open] Ransomware deployment is occurring", "Why is the sign-in from Tunis?"],
        coverage={"gaps": ["q13 search_events: only part of 141 matches was read (10); results are incomplete", "q24 search_events: only part of 80 matches was read (15); results are incomplete", "q8 aggregate_events: backend failed"]},
    )  # fmt: skip
    r = hr.build(run(c))
    assert len(r.gaps) == 5, (
        r.gaps
    )  # two one-off items + one summary line each for leads, partial reads and open hypotheses
    assert any(
        g.startswith("5 unexplored lead(s) were not followed up, e.g. hash:") and "and 2 more" in g for g in r.gaps
    )
    assert any(g == "2 search(es) read only part of their matches, so those results are incomplete" for g in r.gaps)
    assert any(
        g.startswith("2 hypothesis(es) were left open: H1: Phishing-driven") and "H2: Ransomware" in g for g in r.gaps
    )
    assert "Open question: Why is the sign-in from Tunis?" in r.gaps and any(
        "q8" in g for g in r.gaps
    )  # one-off items stay as they are
    assert all(len(g) < 260 for g in r.gaps)  # a 64-character hash is shortened, never dumped whole


def test_repeated_backend_failures_fold_into_one_line():
    gaps = [
        f"q{n} aggregate_events: telemetry backend failed (internal_error); that question is UNANSWERED, not negative"
        for n in (60, 63, 74, 108, 145, 150)
    ]
    r = hr.build(run(conclusion(findings=[], confidence="MEDIUM", hypotheses=[], coverage={"gaps": gaps})))
    assert (
        len(r.gaps) == 1
        and r.gaps[0].startswith("6 search(es) failed with a backend error")
        and "q60" in r.gaps[0]
        and r.gaps[0].endswith("…)")
    )
