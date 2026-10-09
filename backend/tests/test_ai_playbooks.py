"""Hunt playbooks: curated knowledge the agent can open. The catalog is validated against the real query parser and
field registry, covers every upstream threat-hunting skill it was distilled from (and invents none), and reaches the
agent as guidance - never as evidence."""

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from app.ai import playbooks
from app.ai import state as st
from app.ai.playbooks import Playbook, Step
from tests.test_ai import conclude, nb, tool
from tests.test_ai_agent import Scripted, _run, _seeded, real_steps

UPSTREAM = [x for x in (Path(__file__).parent / "playbook_upstream_sources.txt").read_text().split() if x]
FILES = sorted(playbooks.DATA.glob("*.yaml"))


@pytest.fixture
def llm(app):
    def install(p):
        app.state.llm = p
        return p

    yield install
    app.state.llm = None


# ---- the catalog ------------------------------


def test_every_playbook_file_loads_and_ids_match_file_names():
    cat = playbooks.catalog()
    assert FILES and len(cat) == len(FILES), "a playbook file failed validation (run: python -m app.ai.playbooks.check)"
    assert {p.id for p in cat.values()} == {f.stem for f in FILES}
    assert len({p.title for p in cat.values()}) == len(cat)


def test_every_upstream_threat_hunting_skill_is_covered_and_no_provenance_is_invented():
    covered = {s for p in playbooks.catalog().values() for s in p.sources}
    assert set(UPSTREAM) - covered == set(), "upstream skills with no playbook"
    assert covered - set(UPSTREAM) == set(), "sources that are not upstream skill names"
    assert len(UPSTREAM) == 65


def test_playbooks_meet_the_quality_bar():
    for pb in playbooks.catalog().values():
        purposes = {s.purpose for s in pb.steps}
        assert "test" in purposes and purposes & {"refute", "scope"}, (
            f"{pb.id}: needs a test step and a refute/scope step"
        )
        queries = [(s.tool, s.query, s.field) for s in pb.steps if s.query]
        assert len(queries) == len(set(queries)), f"{pb.id}: duplicate steps"
        assert any(s.tool in ("search_events", "aggregate_events") for s in pb.steps), pb.id
        assert len(pb.model_dump_json()) <= playbooks.MAX_PLAYBOOK_CHARS


def test_playbook_text_carries_no_instructions_for_the_model():
    for pb in playbooks.catalog().values():
        assert not st.injection_suspected(pb.model_dump()), f"{pb.id}: instruction-like text"
        blob = json.dumps(pb.model_dump()).lower()
        assert "submit_conclusion" not in blob and "ignore previous" not in blob


def test_signals_are_the_ones_the_agent_actually_derives():
    derived = set(playbooks.SIGNALS)
    src = Path(st.__file__).read_text()
    for sig in derived:
        assert f'"{sig}"' in src, f"{sig} is not a signal the agent derives"


def test_the_validator_rejects_queries_that_parse_but_silently_match_nothing():
    base = dict(purpose="test", goal="g goal", tool="search_events", look_for="look for it")
    Step(
        **base, query="user.name:(svc_a|svc_b) process.name:*powershell.exe* process.command_line:encodedcommand"
    )  # fine
    for bad in (
        "process.name:(cmd.exe|powershell.exe)",  # exact match: misses full-path names that EDR sensors report
        "process.parent.name:(winword.exe|excel.exe)",
        "process.name:(*cmd.exe|*pwsh.exe)",  # wildcards inside an alternation are taken literally and can never match
        "process.command_line:(enc|iex)",  # alternation on analysed text = exact whole-value match
        "process.command_line:down*",
        "file.path:*temp*x*y",
        "process.name:cmd.exe OR process.name:powershell.exe",
        "not_a_field:1",
    ):
        with pytest.raises(ValidationError):
            Step(**base, query=bad)
    with pytest.raises(ValidationError):
        Step(**{**base, "tool": "aggregate_events"}, query="process.name:*cmd.exe*", field="process.command_line")


def test_the_schema_is_strict():
    raw = yaml.safe_load(next(iter(FILES)).read_text())
    Playbook.model_validate(raw)
    for mutate in (
        lambda d: d.update(attack=["T99"]),
        lambda d: d.update(needs=["emails"]),
        lambda d: d.update(signals=["bad_signal"]),
        lambda d: d.update(unexpected="x"),
        lambda d: d.update(id="Bad Id"),
        lambda d: d.update(steps=d["steps"][:1]),
    ):
        d = json.loads(json.dumps(raw))
        mutate(d)
        with pytest.raises(ValidationError):
            Playbook.model_validate(d)


# ---- relevance and feasibility ------------------------------


def test_search_ranks_by_words_attack_ids_and_signals():
    top = lambda **kw: [p.id for p, _ in playbooks.search(**kw)]  # noqa: E731
    assert top(text="hunt encoded powershell download cradle")[0] == "suspicious-powershell-execution"
    assert "lateral-movement-wmi" in top(text="", attack=("T1047",))
    assert "suspicious-powershell-execution" in top(text="", signals=("encoded_command",))
    assert top(text="zzz qqq nothing relevant") == []
    parent = top(text="", attack=("T1059",))  # a parent technique still finds its sub-technique playbooks
    assert "suspicious-powershell-execution" in parent


def test_feasibility_reflects_the_telemetry_the_tenant_really_has():
    pb = playbooks.catalog()["suspicious-powershell-execution"]
    assert playbooks.feasibility(pb, None)["status"] == "unknown"
    assert playbooks.feasibility(pb, {"process_creation": 10, "authentication": 4})["status"] == "ready"
    blocked = playbooks.feasibility(pb, {"authentication": 4})
    assert (
        blocked["status"] == "blocked"
        and blocked["missing"] == ["process_creation"]
        and "declare_gap" in blocked["note"]
    )
    needy = [p for p in playbooks.catalog().values() if len(p.needs) > 1]
    if needy:
        partial = playbooks.feasibility(needy[0], {needy[0].needs[0]: 1})
        assert partial["status"] == "partial"


def test_investigation_suggests_playbooks_from_objective_signals_and_attack_tags():
    inv = st.Investigation.new("look for encoded powershell on workstations", 24, "standard")
    assert "suspicious-powershell-execution" in [p.id for p, _ in inv.suggested_playbooks()]
    inv2 = st.Investigation.new("anything strange on dc01", 24, "standard")
    assert inv2.suggested_playbooks() == []  # nothing in the objective, nothing seen yet
    inv2.evidence["e1"] = {"id": "e1", "tags": ["attack.t1047", "logrhythm"], "summary": "AIE alert"}
    assert inv2.attack_ids_seen() == ("T1047",)
    assert "lateral-movement-wmi" in [p.id for p, _ in inv2.suggested_playbooks()]
    inv2.playbooks_used.append("lateral-movement-wmi")  # already opened: not suggested again
    assert "lateral-movement-wmi" not in [p.id for p, _ in inv2.suggested_playbooks()]
    brief = st.Investigation.new("look for encoded powershell", 24, "standard").brief(
        {"steps": 5}, st.MODES["standard"]
    )
    assert "Hunt playbooks that fit" in brief and "suspicious-powershell-execution" in brief


# ---- the tool in a real run ------------------------------


async def test_agent_finds_opens_and_follows_a_playbook(client, make, llm, app):
    _, h = await _seeded(make, app)
    p = llm(
        Scripted(
            tool("hunt_playbook", action="search", query="encoded powershell"),
            tool("hunt_playbook", action="get", id="suspicious-powershell-execution"),
            tool("hunt_playbook", action="get", id="suspicious-powershell-exec"),
            tool("hunt_playbook", action="list"),
            conclude([]),
        )
    )
    run = await _run(client, h, goal="hunt encoded powershell and what it led to", mode="quick")
    s = [x for x in real_steps(run) if x["name"] == "hunt_playbook"]
    assert s[0]["status"] == "ok" and "suspicious-powershell-execution" in s[0]["result_preview"]
    assert s[1]["playbook"]["id"] == "suspicious-powershell-execution" and "T1059.001" in s[1]["playbook"]["attack"]
    assert s[1]["playbook"]["feasibility"] in ("ready", "unknown", "partial", "blocked")
    assert s[2]["status"] == "error" and "unknown playbook id" in s[2]["error"]
    assert "closest: suspicious-powershell-execution" in s[2]["error"]  # a typo gets the id it was probably meant to be
    assert s[3]["returned"] == len(playbooks.catalog())
    # the model saw the steps (queries in this platform's language) and the platform tracked that it used them
    seen = json.dumps(p.calls[2]["messages"])  # the turn right after `get` (older results are compacted later)
    assert "process.name:*powershell.exe*" in seen and "benign" in seen
    assert run["conclusion"]["playbooks_used"] == ["suspicious-powershell-execution"]
    # and the very first brief already pointed at the relevant playbook
    first_brief = json.dumps(p.calls[0]["messages"])
    assert "Hunt playbooks that fit" in first_brief and "suspicious-powershell-execution" in first_brief


async def test_playbooks_cannot_widen_what_the_agent_may_do(client, make, llm, app):
    """A playbook step naming a tool the agent was never offered is just text: the platform still refuses the call."""
    _, h = await _seeded(make, app)
    llm(Scripted(nb({"op": "note", "text": "following the playbook"}), tool("delete_events", ids=["x"]), conclude([])))
    run = await _run(client, h, mode="quick")
    bad = next(x for x in real_steps(run) if x["name"] == "delete_events")
    assert bad["status"] == "error" and "not available" in bad["error"]


def test_logon_type_filters_accept_both_spellings_sensors_use():
    """LogRhythm reports numeric logon types ('3'), the Windows collector words ('network'): each misses the other."""
    words = {"2": "interactive", "3": "network", "10": "remoteinteractive", "11": "cachedinteractive"}
    from app.events.search import dsl

    for pb in playbooks.catalog().values():
        for s in pb.steps:
            if not s.query:
                continue
            for f in dsl.parse(s.query)[1]:
                if f.field != "auth.logon_type" or f.negate:
                    continue
                vals = {str(v) for v in (f.value if isinstance(f.value, list) else [f.value])}
                for num, word in words.items():
                    assert num not in vals or word in vals, f"{pb.id}: logon_type {num} without '{word}' ({s.query})"


def test_placeholder_values_are_always_flagged_for_replacement():
    """A query with a stand-in value (all-zero hash, .invalid domain, evil.exe) must tell the agent to replace it.

    Running it as-is returns nothing, which must never be read as 'clean'."""
    import re

    marker = re.compile(r"0{32,}|\.invalid\b|\bevil\.exe\b|\bexample-bad\b|\bPLACEHOLDER\b|\bREPLACE\b")
    for pb in playbooks.catalog().values():
        for s in pb.steps:
            if s.query and marker.search(s.query):
                assert re.search(r"(?i)\breplace\b", s.look_for + s.goal), (
                    f"{pb.id}: placeholder query without 'replace' guidance"
                )
