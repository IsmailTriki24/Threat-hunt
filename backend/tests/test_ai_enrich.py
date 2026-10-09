"""Indicator enrichment for the agent: the tenant's intel providers are used (same machinery as the Threat Intel page),
public indicators are looked up automatically, internal details never leave, and verdicts steer the investigation."""

import json

import pytest
from sqlalchemy import select

from app.ai import enrich, tools, websearch
from app.ai import state as st
from app.core.config import get_settings
from app.intel import service as intel_service
from app.intel.models import IntelEntity
from app.intel.providers.base import Context, Provider, ProviderResult
from tests import ai_scenario as sc
from tests.test_ai import conclude, nb, tool
from tests.test_ai_agent import H1, Scripted, _run, _seeded

BAD = {sc.C2_IP, sc.C2_DOMAIN, sc.IMPLANT_SHA}


class FakeIntel(Provider):
    key = "virustotal"  # a real provider key, so the platform's own trust weights apply to its answers
    display_name = "Fake VirusTotal"
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    offline = True  # enabled and "configured" without credentials, and never served from the observation cache
    calls: list[tuple[str, str]] = []

    async def lookup(self, ctx: Context, type_: str, value: str) -> ProviderResult:
        self.calls.append((type_, value))
        if value in BAD:
            return ProviderResult("ok", "malicious", 90, "Flagged by 41/70 engines", {"detections": 41})
        return ProviderResult("not_found", summary="never seen")


@pytest.fixture
def intel(monkeypatch):
    fake = FakeIntel()
    fake.calls = []
    monkeypatch.setattr(intel_service, "PROVIDERS", {"virustotal": fake})
    return fake


@pytest.fixture
def cfg(monkeypatch):
    def apply(**kw):
        s = get_settings().model_copy(update=kw)
        monkeypatch.setattr(tools, "get_settings", lambda: s)
        monkeypatch.setattr("app.ai.agent.get_settings", lambda: s)
        return s

    return apply


@pytest.fixture
def llm(app):
    def install(p):
        app.state.llm = p
        return p

    yield install
    app.state.llm = None


def steps_of(run, name="enrich_indicator"):
    return [s for s in run["steps"] if s["type"] == "tool" and s["name"] == name]


# ---- selection and privacy (pure) ------------------------------


def _inv(*ents: st.Entity, hosts=()) -> st.Investigation:
    inv = st.Investigation.new("hunt", 24, "standard")
    for e in ents:
        inv.entities[st.ekey(e.type, e.value)] = e
    for h in hosts:
        inv.entities[st.ekey("host", h)] = st.Entity("host", h)
    return inv


def test_pick_chooses_public_indicators_only_best_leads_first():
    inv = _inv(
        st.Entity("ip", "10.0.0.12", count=9),  # internal: never
        st.Entity("ip", "45.77.65.211", count=1, flags=["external_connection"]),
        st.Entity("domain", "update-cdn-sync.example.net", count=2),
        st.Entity("domain", "update.microsoft.com", count=50),  # ubiquitous benign infrastructure: skipped
        st.Entity("domain", "dc01.corp.local", count=5),  # internal suffix
        st.Entity("hash", sc.IMPLANT_SHA, count=3),
        st.Entity("file", "upd.exe", count=2, flags=["suspicious_path"]),
        st.Entity("file", "chrome.exe", count=40, flags=["suspicious_path"]),  # a ubiquitous binary says nothing
        st.Entity("file", "notes.txt", count=3, flags=["x"]),  # not an executable
        st.Entity("process", "readme.exe", count=1),  # unflagged, low score: names alone are weak
        st.Entity("user", "bob", count=5),
    )
    got = {(k, v) for _, k, v in enrich.pick(inv, 10, 10)}
    assert got == {
        ("ip", "45.77.65.211"),
        ("domain", "update-cdn-sync.example.net"),
        ("hash", sc.IMPLANT_SHA),
        ("file", "upd.exe"),
    }
    assert len(enrich.pick(inv, 2, 10)) == 2  # per-turn cap
    inv.enriched = ["ip:45.77.65.211", "hash:" + sc.IMPLANT_SHA]
    assert {v for _, _, v in enrich.pick(inv, 10, 10)} == {"update-cdn-sync.example.net", "upd.exe"}  # never twice
    assert enrich.pick(inv, 10, 2) == []  # run-level cap already reached (2 done)


def test_internal_identifiers_are_never_looked_up():
    inv = _inv(hosts=["ws-02", "dc01"])
    inv.evidence["e1"] = {"id": "e1", "host": "WS-02", "user": "bob"}
    r = lambda k, v: enrich.internal_reason(inv, k, v)  # noqa: E731
    assert r("ip", "192.168.1.5") and r("ip", "127.0.0.1") and r("ip", "169.254.1.1")
    assert r("ip", "45.77.65.211") is None
    assert r("domain", "ws-02.example.net") and r("domain", "fileserver") and r("domain", "a.corp.local")
    assert r("domain", "evil.example.org") is None
    assert r("url", "http://10.1.2.3/a") and r("url", "http://evil.example.org/dl?user=bob")
    assert r("url", "http://evil.example.org/dl.php") is None
    assert r("file", "bob_passwords.exe") and r("file", "svchost.exe")
    assert r("file", "upd.exe") is None
    assert r("hash", sc.IMPLANT_SHA) is None


def test_classify_handles_every_kind_the_agent_meets():
    assert enrich.classify("C:\\Users\\bob\\AppData\\upd.exe") == ("file", "upd.exe")
    assert enrich.classify("45.77.65.211") == ("ip", "45.77.65.211")
    assert enrich.classify(sc.IMPLANT_SHA.upper()) == ("hash", sc.IMPLANT_SHA)
    assert enrich.classify("http://evil.example.org/a.php")[0] == "url"
    assert enrich.classify("evil.example.org") == ("domain", "evil.example.org")
    assert enrich.classify("not an indicator") is None


def test_malicious_intel_makes_an_entity_a_top_lead():
    e = st.Entity("ip", "45.77.65.211", count=1)
    inv = _inv(e)
    before = e.score
    enrich.record(
        inv,
        "ip",
        e.value,
        {
            "indicator": {"kind": "ip", "value": e.value},
            "verdict": "malicious",
            "score": 90,
            "answered": 1,
            "providers": [{"provider": "vt", "status": "ok", "verdict": "malicious"}],
        },
        st.ekey("ip", e.value),
    )
    assert "intel_malicious" in e.flags and e.score >= before + 3
    brief = inv.brief({"steps": 1}, st.MODES["standard"])
    assert "Threat intelligence" in brief and "MALICIOUS" in brief and "vt=malicious" in brief


# ---- the tool ------------------------------


async def test_model_can_enrich_an_indicator_with_the_tenants_providers(client, make, llm, app, intel, cfg):
    cfg(tavily_api_key="", ai_auto_enrich=False)
    t, h = await _seeded(make, app)
    llm(
        Scripted(
            tool("enrich_indicator", value=sc.C2_IP),
            tool("enrich_indicator", value="10.0.0.12"),
            tool("enrich_indicator", value="WS-02.corp.local"),
            conclude([]),
        )
    )
    run = await _run(client, h, mode="quick")
    a, b, c = steps_of(run)
    assert (
        a["status"] == "ok"
        and a["intel"]["verdict"] == "malicious"
        and a["intel"]["providers"][0]["provider"] == "virustotal"
    )
    assert b["status"] == "error" and "internal" in b["error"] and c["status"] == "error"
    assert intel.calls == [("ip", sc.C2_IP)]  # the refused lookups never reached a provider
    async with app.state.sessionmaker() as s:  # stored in the tenant's intel cache like a manual lookup
        rows = (await s.execute(select(IntelEntity).where(IntelEntity.value == sc.C2_IP))).scalars().all()
    assert len(rows) == 1 and rows[0].verdict == "malicious"


async def test_without_any_provider_answer_it_falls_back_to_public_threat_intel_sites(
    client, make, llm, app, intel, cfg, monkeypatch
):
    cfg(tavily_api_key="tvly-test", ai_auto_enrich=False)
    seen = {}

    async def fake_search(settings, query, max_results=5, *, include_domains=None, **_):
        seen.update(query=query, domains=include_domains)
        return [
            {
                "title": "VT report",
                "url": "https://www.virustotal.com/gui/file/x",
                "domain": "www.virustotal.com",
                "snippet": "49/72 detections",
                "score": 0.9,
            }
        ]

    monkeypatch.setattr(websearch, "search", fake_search)
    _, h = await _seeded(make, app)
    llm(Scripted(tool("enrich_indicator", value="198.51.100.77"), conclude([])))  # the provider has never seen it
    run = await _run(client, h, mode="quick")
    (step,) = steps_of(run)
    assert step["status"] == "ok" and step["intel"]["verdict"] == "unknown" and step["intel"]["web"] == 1
    assert [x["domain"] for x in step["sources"]] == ["www.virustotal.com"]
    assert (
        "virustotal.com" in seen["domains"]
        and "otx.alienvault.com" in seen["domains"]
        and "198.51.100.77" in seen["query"]
    )


async def test_enrichment_does_not_spend_the_models_web_search_budget(client, make, llm, app, intel, cfg, monkeypatch):
    cfg(tavily_api_key="tvly-test", ai_auto_enrich=False, ai_web_max_calls=1)

    async def fake_search(*a, **k):
        return []

    monkeypatch.setattr(websearch, "search", fake_search)
    _, h = await _seeded(make, app)
    llm(
        Scripted(
            tool("enrich_indicator", value="198.51.100.77"),
            tool("web_search", query="CVE-2024-3400 exploitation"),
            conclude([]),
        )
    )
    run = await _run(client, h, mode="quick")
    assert steps_of(run, "web_search")[0]["status"] != "error"


# ---- automatic enrichment ------------------------------


async def test_public_indicators_are_enriched_automatically_and_steer_the_hunt(client, make, llm, app, intel, cfg):
    cfg(tavily_api_key="", ai_auto_enrich_per_turn=5)
    _, h = await _seeded(make, app)
    p = llm(Scripted(nb(H1), tool("search_events", query="process.name:powershell.exe"), conclude([])))
    run = await _run(client, h, mode="quick")
    auto = steps_of(run)
    assert auto and all(s["auto"] for s in auto)
    asked = {(s["input"]["kind"], s["input"]["value"]) for s in auto}
    assert {("ip", sc.C2_IP), ("domain", sc.C2_DOMAIN), ("hash", sc.IMPLANT_SHA)} <= asked
    assert not any(v.startswith("10.") for _, v in asked) and not any(
        k == "file" and v == "powershell.exe" for k, v in asked
    )
    assert {v for _, v in intel.calls} <= {v for _, v in asked}  # providers only ever saw what was selected
    assert all(not v.startswith(("10.", "192.168.")) for _, v in intel.calls)
    assert len(intel.calls) == len(set(intel.calls))  # each indicator once
    bad = [s for s in auto if s["input"]["value"] in BAD]
    assert bad and all(s["intel"]["verdict"] == "malicious" for s in bad)
    # the model is told, in its state, what the providers said - and that intel is context, not proof
    briefs = json.dumps([m["content"] for c in p.calls[2:] for m in c["messages"] if m["role"] == "user"])
    assert "Threat intelligence" in briefs and "MALICIOUS" in briefs and "virustotal=malicious" in briefs
    assert "intel_malicious" in json.dumps(
        run["conclusion"]["entities"]
    )  # and it flagged the entities as high-priority leads


async def test_automatic_enrichment_is_capped_and_can_be_switched_off(client, make, llm, app, intel, cfg):
    cfg(tavily_api_key="", ai_auto_enrich_per_turn=1, ai_auto_enrich_max=2)
    _, h = await _seeded(make, app)
    llm(
        Scripted(
            tool("search_events", query="process.name:powershell.exe"),
            tool("search_events", query="host.hostname:ws-02", purpose="scope"),
            tool("search_events", query="host.hostname:ws-03", purpose="scope"),
            conclude([]),
        )
    )
    run = await _run(client, h, mode="standard")
    assert len(steps_of(run)) == 2  # run-level cap; at most one per turn
    cfg(tavily_api_key="", ai_auto_enrich=False)
    intel.calls.clear()
    llm(Scripted(tool("search_events", query="process.name:powershell.exe"), conclude([])))
    assert steps_of(await _run(client, h, mode="quick")) == [] and intel.calls == []


async def test_a_failing_provider_is_reported_not_retried_and_never_fatal(
    client, make, llm, app, intel, cfg, monkeypatch
):
    cfg(tavily_api_key="", ai_auto_enrich_per_turn=5)

    async def boom(*a, **k):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(intel, "lookup", boom)
    _, h = await _seeded(make, app)
    llm(Scripted(tool("search_events", query="process.name:powershell.exe"), conclude([])))
    run = await _run(client, h, mode="quick")
    assert run["status"] == "COMPLETED"
    auto = steps_of(run)
    assert auto and len(auto) == len({s["input"]["value"] for s in auto})  # asked once each
    assert all("exploded" not in json.dumps(s) for s in auto)  # provider internals do not leak


def test_microsoft_office_components_are_not_looked_up_by_name():
    inv = _inv(
        st.Entity("process", "officeclicktorun.exe", count=8, flags=["suspicious_path"]),
        st.Entity("process", "integrator.exe", count=3, flags=["suspicious_path"]),
        st.Entity("process", "upd.exe", count=1, flags=["suspicious_path"]),
    )
    assert {v for _, _, v in enrich.pick(inv, 10, 10)} == {"upd.exe"}


def test_provider_wording_reaches_the_model_and_the_analyst():
    inv = _inv(st.Entity("hash", sc.IMPLANT_SHA, count=1))
    answered = {
        "indicator": {"kind": "hash", "value": sc.IMPLANT_SHA}, "verdict": "unknown", "score": 0, "answered": 1,
        "providers": [
            {"provider": "virustotal", "status": "ok", "verdict": "unknown",
             "summary": "0/75 engines flag as malicious"},
        ],
    }  # fmt: skip
    summary = enrich.record(inv, "hash", sc.IMPLANT_SHA, answered, st.ekey("hash", sc.IMPLANT_SHA))
    assert summary["providers"][0]["summary"] == "0/75 engines flag as malicious"
    assert "virustotal=unknown (0/75 engines flag as malicious)" in inv.brief({"steps": 1}, st.MODES["standard"])
    assert "intel_malicious" not in inv.entities[st.ekey("hash", sc.IMPLANT_SHA)].flags  # no detections: not a lead


async def test_the_web_is_only_searched_when_no_provider_answered(client, make, llm, app, intel, cfg, monkeypatch):
    cfg(tavily_api_key="tvly-test", ai_auto_enrich=False)
    queries = []

    async def fake_search(settings, query, *a, **k):
        queries.append(query)
        return []

    monkeypatch.setattr(websearch, "search", fake_search)
    _, h = await _seeded(make, app)
    llm(
        Scripted(
            tool("enrich_indicator", value=sc.C2_IP), tool("enrich_indicator", value="198.51.100.77"), conclude([])
        )
    )
    await _run(client, h, mode="quick")
    assert len(queries) == 1 and "198.51.100.77" in queries[0]  # the answered one (malicious) needed no web search
