"""Web search for the agent (Tavily): offered only when configured, never leaks internal identifiers, budgeted,
and its results are untrusted context that does not count as telemetry."""

import json

import httpx
import pytest

from app.ai import state as st
from app.ai import tools, websearch
from app.core.config import get_settings
from tests.test_ai import conclude, nb, tool
from tests.test_ai_agent import H1, Scripted, _run, _seeded, real_steps

pytestmark = pytest.mark.asyncio

RESULTS = [
    {
        "title": "Emotet  malware\nanalysis",
        "url": "https://example.org/emotet",
        "domain": "example.org",
        "snippet": "Emotet uses macro documents.",
        "score": 0.91,
    },
    {
        "title": "Another",
        "url": "https://blog.example.net/x",
        "domain": "blog.example.net",
        "snippet": "More.",
        "score": 0.5,
    },
]


@pytest.fixture
def web(monkeypatch):
    """Web search configured, with the network call replaced by a recorder."""
    keys = {"tavily_api_key": "tvly-test", "ai_web_max_calls": 2, "ai_auto_enrich": False}
    s = get_settings().model_copy(update=keys)
    monkeypatch.setattr(tools, "get_settings", lambda: s)
    monkeypatch.setattr("app.ai.agent.get_settings", lambda: s)
    sent: list[str] = []

    async def fake(settings, query, max_results=5, **_):  # include_domains etc. are accepted and ignored
        sent.append(query)
        return RESULTS[:max_results]

    monkeypatch.setattr(websearch, "search", fake)
    return sent


@pytest.fixture
def llm(app):
    def install(p):
        app.state.llm = p
        return p

    yield install
    app.state.llm = None


def _transport(status=200, body=None, seen=None):
    def handler(req: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(req)
        return httpx.Response(status, json=body if body is not None else {})

    return httpx.MockTransport(handler)


async def test_client_sends_bearer_auth_and_cleans_results():
    s = get_settings().model_copy(update={"tavily_api_key": "tvly-secret"})
    seen: list[httpx.Request] = []
    body = {
        "results": [
            {"title": "A  b\n c", "url": "https://x.example/p", "content": "x" * 5000, "score": 0.8},
            {"title": "bad", "url": "javascript:alert(1)", "content": "no"},
            {"title": "also bad", "url": "file:///etc/passwd", "content": "no"},
        ]
    }
    out = await websearch.search(s, "emotet", 5, transport=_transport(body=body, seen=seen))
    assert seen[0].headers["authorization"] == "Bearer tvly-secret"
    sent = json.loads(seen[0].content)
    assert sent["query"] == "emotet" and sent["include_raw_content"] is False and sent["include_answer"] is False
    assert "tvly-secret" not in seen[0].url.query.decode()  # never in the URL
    assert [r["domain"] for r in out] == ["x.example"]  # non-http(s) links are dropped
    assert out[0]["title"] == "A b c" and len(out[0]["snippet"]) == websearch.SNIPPET_CHARS


@pytest.mark.parametrize(("status", "transient"), [(401, False), (403, False), (429, True), (503, True), (400, False)])
async def test_client_classifies_failures_without_leaking_the_key(status, transient):
    s = get_settings().model_copy(update={"tavily_api_key": "tvly-secret"})
    with pytest.raises(websearch.WebSearchError) as ei:
        await websearch.search(s, "emotet", 3, transport=_transport(status, {"detail": "tvly-secret echoed"}))
    assert ei.value.transient is transient and "tvly-secret" not in str(ei.value)


async def test_client_requires_a_key():
    with pytest.raises(websearch.WebSearchError):
        await websearch.search(get_settings().model_copy(update={"tavily_api_key": ""}), "x")


def test_tool_is_enabled_only_with_a_key_and_a_budget(monkeypatch):
    def cfg(**kw):
        return lambda: get_settings().model_copy(update=kw)

    monkeypatch.setattr(tools, "get_settings", cfg(tavily_api_key=""))
    assert not tools.TOOLS["web_search"].enabled()
    monkeypatch.setattr(tools, "get_settings", cfg(tavily_api_key="tvly-x"))
    assert tools.TOOLS["web_search"].enabled()
    monkeypatch.setattr(tools, "get_settings", cfg(tavily_api_key="tvly-x", ai_web_max_calls=0))
    assert not tools.TOOLS["web_search"].enabled()


def test_web_searches_do_not_count_as_telemetry_queries():
    inv = st.Investigation.new("hunt", 24, "quick")
    inv.record(st.QueryRecord(ref="q1", tool="web_search", args={}, key="k1", status="ok"))
    assert inv.ok_queries() == 0
    inv.record(st.QueryRecord(ref="q2", tool="search_events", args={}, key="k2", status="ok"))
    assert inv.ok_queries() == 1


async def test_agent_uses_web_context_and_it_is_not_telemetry(client, make, llm, app, web):
    _, h = await _seeded(make, app)
    p = llm(
        Scripted(
            nb(H1),
            tool("web_search", query="Emotet macro dropper encoded powershell behaviour", hypothesis="H1"),
            conclude([]),
        )
    )
    run = await _run(client, h, mode="quick")
    assert "web_search" in p.calls[0]["tools"]
    assert web == ["Emotet macro dropper encoded powershell behaviour"]
    step = next(s for s in real_steps(run) if s["name"] == "web_search")
    assert step["status"] == "ok" and step["returned"] == 2
    assert [x["domain"] for x in step["sources"]] == ["example.org", "blog.example.net"]  # the UI can link the sources
    envelope = json.dumps([m for m in p.calls[-1]["messages"]])
    assert "untrusted_web_content" in envelope
    # no telemetry query ran, so the web result does not satisfy the "enough successful queries" requirement
    assert run["conclusion"]["coverage"]["events_reviewed"] == 0


async def test_queries_containing_internal_identifiers_are_refused_and_never_sent(client, make, llm, app, web):
    _, h = await _seeded(make, app)
    llm(
        Scripted(
            tool("search_events", query="process.name:powershell.exe"),  # puts host WS-02 / user bob into the evidence
            tool("web_search", query="what is running on WS-02"),
            tool("web_search", query="bob logged on powershell enc"),
            tool("web_search", query="beacon to 10.0.0.12 port 443"),
            tool("web_search", query="beacon to 45.77.65.211 port 443"),  # a public IP is a legitimate thing to look up
            conclude([]),
        )
    )
    run = await _run(client, h, mode="standard")
    steps = [s for s in real_steps(run) if s["name"] == "web_search"]
    assert [s["status"] for s in steps] == ["error", "error", "error", "ok"]
    assert (
        "host or user name" in steps[0]["error"]
        and "host or user name" in steps[1]["error"]
        and "internal IP" in steps[2]["error"]
    )
    assert web == ["beacon to 45.77.65.211 port 443"]  # the refused queries never left the platform
    assert not any("WS-02" in q or "bob" in q or "10.0.0.12" in q for q in web)


async def test_web_search_budget_is_per_run(client, make, llm, app, web):
    _, h = await _seeded(make, app)
    llm(
        Scripted(
            tool("web_search", query="CVE-2024-3400 exploitation"),
            tool("web_search", query="CVE-2023-4966 exploitation"),
            tool("web_search", query="CVE-2021-44228 exploitation"),
            conclude([]),
        )
    )
    run = await _run(client, h, mode="standard")
    steps = [s for s in real_steps(run) if s["name"] == "web_search"]
    assert [s["status"] for s in steps] == ["ok", "ok", "error"]  # ai_web_max_calls=2
    assert "budget" in steps[2]["error"] and len(web) == 2


async def test_provider_outage_is_reported_as_unanswered(client, make, llm, app, monkeypatch):
    s = get_settings().model_copy(update={"tavily_api_key": "tvly-test"})
    monkeypatch.setattr(tools, "get_settings", lambda: s)

    async def down(*a, **k):
        raise websearch.WebSearchError("the web search service is busy", transient=True)

    async def nosleep(*_):
        return None

    monkeypatch.setattr(websearch, "search", down)
    monkeypatch.setattr(tools.asyncio, "sleep", nosleep)
    _, h = await _seeded(make, app)
    llm(Scripted(tool("web_search", query="CVE-2024-3400 exploitation"), conclude([])))
    run = await _run(client, h, mode="quick")
    step = next(x for x in real_steps(run) if x["name"] == "web_search")
    assert step["status"] == "error" and "UNANSWERED" in step["error"]


async def test_tool_is_not_offered_or_callable_without_a_key(client, make, llm, app, monkeypatch):
    off = get_settings().model_copy(update={"tavily_api_key": ""})
    monkeypatch.setattr(tools, "get_settings", lambda: off)
    _, h = await _seeded(make, app)
    p = llm(Scripted(tool("web_search", query="CVE-2024-3400 exploitation"), conclude([])))
    run = await _run(client, h, mode="quick")
    assert "web_search" not in p.calls[0]["tools"]
    step = next(x for x in real_steps(run) if x["name"] == "web_search")
    assert step["status"] == "error" and "not available" in step["error"]
