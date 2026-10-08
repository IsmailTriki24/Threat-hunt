# ruff: noqa: E501
import json
import uuid
from typing import Any

import httpx
import pytest

from app.ai import providers
from app.ai.providers import LLMResponse, ProviderUnavailable, ToolCall
from app.auth.rbac import Role
from tests.helpers import ev
from tests.mitre_helpers import mitre_loaded  # noqa: F401

A = "/api/v1/ai"
PS = {
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\powershell.exe",
    "command_line": "powershell.exe -enc QQ==",
}


class Scripted:
    """Deterministic provider: each item is an LLMResponse or a callable(messages, tools) -> LLMResponse."""

    name, model = "scripted", "scripted-1"

    def __init__(self, *script: Any) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    async def complete(self, system, messages, tools, max_tokens=2048):
        self.calls.append(
            {
                "system": system,
                "messages": json.loads(json.dumps(messages, default=str)),
                "tools": [t["name"] for t in tools],
            }
        )
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, Exception):
            raise item
        return item(messages, tools) if callable(item) else item


def tool(name: str, **inp: Any) -> LLMResponse:
    return LLMResponse(
        tool_calls=[ToolCall(id=f"c-{uuid.uuid4().hex[:6]}", name=name, input=inp)], input_tokens=10, output_tokens=5
    )


def conclude(ids: Any, **extra: Any) -> Any:
    def make(messages, tools):
        found = ids(messages) if callable(ids) else ids
        f = {
            "title": "Encoded PowerShell",
            "description": "seen",
            "severity": "high",
            "event_ids": found,
            "techniques": ["T1059.001", "T9999"],
            **extra,
        }
        return tool("submit_conclusion", summary="did it", confidence="high", findings=[f])

    return make


def seen_ids(messages: list[dict[str, Any]]) -> list[str]:
    last = messages[-1]["content"][0]["content"]
    return [e["id"] for e in json.loads(last)["data"]["events"]]


@pytest.fixture
def llm(app):
    def install(p):
        app.state.llm = p
        return p

    yield install
    app.state.llm = None


async def _setup(make, role=Role.THREAT_HUNTER):
    t = await make.tenant()
    _, h = await make.login_as(t, role)
    await make.index(t, [ev(5, process=PS), ev(5, process={"name": "cmd.exe"})])
    return t, h


@pytest.mark.usefixtures("mitre_loaded")
async def test_investigation_with_verified_evidence_and_save(client, make, llm):
    t, h = await _setup(make)
    hunt = (await client.post("/api/v1/hunts", headers=h, json={"title": "ps"})).json()
    p = llm(
        Scripted(
            tool("search_events", query="process.name:powershell.exe"), conclude(lambda m: [*seen_ids(m), "f" * 32])
        )
    )
    r = await client.post(f"{A}/runs", headers=h, json={"goal": "find encoded powershell", "hunt_id": hunt["id"]})
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["status"] == "COMPLETED" and run["provider"] == "scripted"
    c = run["conclusion"]
    f = c["findings"][0]
    assert f["supported"] and len(f["event_ids"]) == 1 and f["rejected_event_ids"] == ["f" * 32]
    assert f["techniques"] == ["T1059.001"] and f["rejected_techniques"] == ["T9999"]
    assert c["confidence"] == "HIGH" and any("discarded" in n for n in c["validation_notes"])
    assert [s["type"] for s in run["steps"]] == ["tool"] and run["steps"][0]["name"] == "search_events"
    assert run["input_tokens"] > 0
    # results reached the model inside the untrusted-data envelope
    tool_msg = p.calls[1]["messages"][-1]["content"][0]["content"]
    assert json.loads(tool_msg)["untrusted_data"] is True
    # save -> a real hunt finding with an evidence snapshot
    s = await client.post(f"{A}/runs/{run['id']}/save", headers=h, json={"finding_indexes": [0]})
    assert s.status_code == 200 and len(s.json()["saved_findings"]) == 1
    findings = (await client.get(f"/api/v1/hunts/{hunt['id']}/findings", headers=h)).json()
    assert findings[0]["title"].startswith("[AI]") and findings[0]["evidence"][0]["id"] == f["event_ids"][0]


async def test_fabricated_citations_are_unsupported(client, make, llm):
    t, h = await _setup(make)
    hunt = (await client.post("/api/v1/hunts", headers=h, json={"title": "x"})).json()
    llm(Scripted(conclude(["a" * 32])))  # concludes without ever searching
    run = (
        await client.post(f"{A}/runs", headers=h, json={"goal": "anything suspicious?", "hunt_id": hunt["id"]})
    ).json()
    f = run["conclusion"]["findings"][0]
    assert not f["supported"] and f["event_ids"] == []
    assert run["conclusion"]["confidence"] == "LOW" and run["conclusion"]["model_confidence"] == "HIGH"
    assert (
        await client.post(f"{A}/runs/{run['id']}/save", headers=h, json={"finding_indexes": [0]})
    ).status_code == 409


async def test_cannot_cite_another_tenants_events(client, make, llm, app):
    a, ha = await _setup(make)
    b = await make.tenant()
    await make.index(b, [ev(5, process=PS)])
    other = (
        await app.state.search.search(
            b.id, __import__("app.events.search.query", fromlist=["EventQuery"]).EventQuery(limit=5)
        )
    ).hits[0]["id"]
    llm(Scripted(conclude([other])))
    run = (await client.post(f"{A}/runs", headers=ha, json={"goal": "look for anything odd"})).json()
    assert (
        run["conclusion"]["findings"][0]["rejected_event_ids"] == [other]
        and not run["conclusion"]["findings"][0]["supported"]
    )
    # tool access is tenant scoped too
    llm(Scripted(tool("get_event", event_id=other), conclude([])))
    run = (await client.post(f"{A}/runs", headers=ha, json={"goal": "fetch that foreign event"})).json()
    assert run["steps"][0]["error"] == "event not found"


async def test_model_mistakes_are_tool_errors_not_crashes(client, make, llm):
    _, h = await _setup(make)
    p = llm(
        Scripted(
            tool("rm_rf", path="/"),
            tool("search_events", query="notafield:1"),
            tool("search_events", query="x", limit=9999),
            tool("aggregate_events", field="process.name"),
            tool("lookup_ioc", value="203.0.113.9"),
            tool("mitre_technique", technique_id="T1059.001"),
            conclude([]),
        )
    )
    run = (await client.post(f"{A}/runs", headers=h, json={"goal": "exercise the tools"})).json()
    errs = [s["error"] for s in run["steps"]]
    assert "not available" in errs[0] and "invalid query" in errs[1] and "invalid arguments" in errs[2]
    assert errs[3] is None and errs[4] is None and run["status"] == "COMPLETED"
    assert '"known": false' in run["steps"][4]["result_preview"].lower().replace('"known":false', '"known": false')
    assert p.calls[0]["tools"] == [
        "search_events",
        "aggregate_events",
        "get_event",
        "lookup_ioc",
        "mitre_technique",
        "submit_conclusion",
    ]


async def test_budget_exhaustion_is_incomplete(client, make, llm):
    _, h = await _setup(make)
    p = llm(Scripted(tool("search_events", query="process.name:cmd.exe")))  # never concludes
    run = (await client.post(f"{A}/runs", headers=h, json={"goal": "loop forever please"})).json()
    assert run["status"] == "INCOMPLETE" and run["conclusion"] is None and "budget" in run["error"]
    assert p.calls[-1]["tools"] == ["submit_conclusion"]  # final turn offers only the conclusion tool


async def test_provider_failure_is_recorded_safely(client, make, llm):
    _, h = await _setup(make)
    llm(Scripted(ProviderUnavailable("The AI provider could not be reached")))
    r = await client.post(f"{A}/runs", headers=h, json={"goal": "any goal at all"})
    assert (
        r.status_code == 201
        and r.json()["status"] == "FAILED"
        and r.json()["error"] == "The AI provider could not be reached"
    )


async def test_disabled_without_provider(client, make):
    _, h = await _setup(make)
    assert (await client.get(f"{A}/status", headers=h)).json()["enabled"] is False
    assert (await client.post(f"{A}/runs", headers=h, json={"goal": "any goal at all"})).status_code == 503
    assert (await client.post(f"{A}/translate", headers=h, json={"question": "powershell"})).status_code == 503


async def test_permissions_and_isolation(client, make, llm):
    t, admin = await _setup(make, Role.TENANT_ADMIN)
    llm(Scripted(conclude([])))
    _, viewer = await make.login_as(t, Role.VIEWER)
    assert (await client.post(f"{A}/runs", headers=viewer, json={"goal": "any goal at all"})).status_code == 403
    assert (await client.get(f"{A}/status", headers=viewer)).status_code == 403
    _, analyst = await make.login_as(t, Role.SOC_ANALYST)
    run = (await client.post(f"{A}/runs", headers=analyst, json={"goal": "any goal at all"})).json()
    _, analyst2 = await make.login_as(t, Role.SOC_ANALYST)
    assert (
        await client.get(f"{A}/runs/{run['id']}", headers=analyst2)
    ).status_code == 404  # others' runs are private...
    assert (await client.get(f"{A}/runs/{run['id']}", headers=admin)).status_code == 200  # ...except to admins
    _, hb = await make.login_as(await make.tenant(), Role.TENANT_ADMIN)
    assert (await client.get(f"{A}/runs/{run['id']}", headers=hb)).status_code == 404
    assert (
        await client.post(f"{A}/runs", headers=analyst, json={"goal": "x", "hunt_id": str(uuid.uuid4())})
    ).status_code == 422
    assert (
        await client.post(f"{A}/runs", headers=analyst, json={"goal": "any goal at all", "hunt_id": str(uuid.uuid4())})
    ).status_code == 404


async def test_translate_validates_model_output(client, make, llm):
    _, h = await _setup(make)
    p = llm(Scripted(LLMResponse(text="```\nprocess.name:powershell.exe -user.name:svc_*\n```")))
    r = (await client.post(f"{A}/translate", headers=h, json={"question": "powershell not by service accounts"})).json()
    assert r["query"] == "process.name:powershell.exe -user.name:svc_*"
    assert "process.command_line(text)" in p.calls[0]["system"]
    # invalid first answer is fed back once, then accepted
    llm(Scripted(LLMResponse(text="bogus.field:1"), LLMResponse(text="host.hostname:WS-01")))
    assert (await client.post(f"{A}/translate", headers=h, json={"question": "host WS-01"})).json()[
        "query"
    ] == "host.hostname:WS-01"
    # persistent garbage and UNSUPPORTED are refused, never passed through
    llm(Scripted(LLMResponse(text="bogus.field:1")))
    r = (await client.post(f"{A}/translate", headers=h, json={"question": "something odd"})).json()
    assert r["query"] is None and "valid query" in r["note"]
    llm(Scripted(LLMResponse(text="UNSUPPORTED")))
    assert (await client.post(f"{A}/translate", headers=h, json={"question": "something odd"})).json()["query"] is None


async def test_anthropic_adapter_wire_format(monkeypatch):
    from app.core.config import get_settings

    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"], seen["body"] = request.headers, json.loads(request.content)
        status = seen.get("status", 200)
        return httpx.Response(
            status,
            json={
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 7, "output_tokens": 3},
                "content": [
                    {"type": "text", "text": "hi"},
                    {"type": "tool_use", "id": "t1", "name": "search_events", "input": {"query": "x"}},
                ],
            },
        )

    real = httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    s = get_settings().model_copy(update={"ai_provider": "anthropic", "anthropic_api_key": "k-123"})
    p = providers.build_provider(s)
    assert p is not None and p.name == "anthropic"
    out = await p.complete("sys", [{"role": "user", "content": "q"}], [{"name": "search_events"}])
    assert out.text == "hi" and out.tool_calls[0].input == {"query": "x"} and out.input_tokens == 7
    assert seen["headers"]["x-api-key"] == "k-123" and seen["body"]["system"] == "sys" and seen["body"]["tools"]
    for status in (401, 429, 500):
        seen["status"] = status
        with pytest.raises(ProviderUnavailable) as exc:
            await p.complete("s", [], [])
        assert "k-123" not in str(exc.value)
    assert providers.build_provider(get_settings()) is None  # default config: disabled


async def test_openrouter_adapter_translates_tools_and_results_and_retries_throttling(monkeypatch):
    from app.core.config import get_settings

    sent: list[dict[str, Any]] = []
    statuses = [429, 429, 200]

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append({"auth": request.headers["authorization"], "body": json.loads(request.content)})
        st = statuses.pop(0) if statuses else 200
        if st != 200:
            return httpx.Response(st, json={"error": "throttled"})
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": "ok",
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {"name": "search_events", "arguments": '{"query": "x"}'},
                                },
                                {"id": "c2", "type": "function", "function": {"name": "bad", "arguments": "{not json"}},
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 9, "completion_tokens": 4},
            },
        )

    async def nosleep(_):
        return None

    real = httpx.AsyncClient
    monkeypatch.setattr(providers.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(providers.asyncio, "sleep", nosleep)
    s = get_settings().model_copy(
        update={"ai_provider": "openrouter", "openrouter_api_key": "or-k", "ai_model": "vendor/model"}
    )
    p = providers.build_provider(s)
    assert p is not None and p.name == "openrouter"
    history = [
        {"role": "user", "content": "q"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "t"},
                {"type": "tool_use", "id": "c0", "name": "get_event", "input": {"id": 1}},
            ],
        },
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c0", "content": "res"}]},
    ]
    out = await p.complete(
        "sys", history, [{"name": "search_events", "description": "d", "input_schema": {"type": "object"}}]
    )
    assert len(sent) == 3  # two throttled attempts, then success
    body = sent[-1]["body"]
    assert sent[-1]["auth"] == "Bearer or-k" and body["model"] == "vendor/model"
    assert body["tools"][0]["function"]["parameters"] == {"type": "object"}
    assert [m["role"] for m in body["messages"]] == ["system", "user", "assistant", "tool"]
    assert (
        body["messages"][2]["tool_calls"][0]["function"]["arguments"] == '{"id": 1}'
        and body["messages"][3]["tool_call_id"] == "c0"
    )
    assert (
        out.text == "ok" and out.tool_calls[0].input == {"query": "x"} and out.tool_calls[1].input == {}
    )  # malformed args are not trusted
    assert (out.input_tokens, out.output_tokens, out.stop_reason) == (9, 4, "tool_use")
    statuses[:] = [429] * 10
    with pytest.raises(ProviderUnavailable) as exc:
        await p.complete("s", [], [])
    assert "or-k" not in str(exc.value) and "rate limiting" in str(exc.value)
