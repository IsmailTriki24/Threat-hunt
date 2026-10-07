import pytest

from app.events.search.dsl import QueryParseError, parse
from app.events.search.query import EventQuery


def f(text):
    q, filters = parse(text)
    return q, [(x.field, x.op, x.value, x.negate) for x in filters]


def test_field_expressions():
    assert f("process.name:powershell.exe") == (None, [("process.name", "eq", "powershell.exe", False)])
    assert f('process.command_line:"-enc"')[1] == [("process.command_line", "contains", "-enc", False)]
    assert f("host.hostname:ws-*")[1] == [("host.hostname", "prefix", "ws-", False)]
    assert f("host.hostname:*fin*")[1] == [("host.hostname", "contains", "fin", False)]
    assert f("network.dst_port>=1024")[1] == [("network.dst_port", "gte", 1024, False)]
    assert f("process.name:(cmd.exe|powershell.exe)")[1] == [
        ("process.name", "in", ["cmd.exe", "powershell.exe"], False)
    ]
    assert f("has:network.dst_domain")[1] == [("network.dst_domain", "exists", None, False)]
    assert f("-has:network.dst_domain")[1][0][3] is True
    assert f("-user.name:svc_*")[1] == [("user.name", "prefix", "svc_", True)]
    assert f("NOT user.name:alice")[1] == [("user.name", "eq", "alice", True)]
    assert f("network.dst_ip:203.0.113.0/24")[1][0][2] == "203.0.113.0/24"


def test_free_text_mixed_with_filters():
    q, filters = f('powershell OR cmd "encoded command" host.hostname:ws-01 enc*')
    assert q == 'powershell OR cmd "encoded command" enc*'
    assert filters == [("host.hostname", "eq", "ws-01", False)]
    assert f("NOT whoami")[0] == "NOT whoami"
    assert f("a AND host.hostname:x")[0] == "a"


@pytest.mark.parametrize(
    "text",
    [
        "nope.field:x",
        "tenant_id:abc",
        "has:tenant_id",
        "network.dst_port:abc",
        "network.dst_ip:999.1.1.1",
        "host.hostname:*x",
        "host.hostname:",
        "NOT",
        "a OR host.hostname:x",
        "host.hostname:x OR y",
        "process.name>3",
        "x" * 2001,
        "host.hostname:(" + "a|" * 150 + "b)",
        "raw.x:1",
        "host.hostname:*",
    ],
)
def test_invalid_text_rejected(text):
    with pytest.raises(QueryParseError):
        parse(text)


def test_non_field_colons_are_free_text():
    assert parse("https://evil.example/a")[0] == "https://evil.example/a"


def test_event_query_merges_text_without_mutating_inputs():
    q = EventQuery.model_validate(
        {"q": "foo", "text": "bar host.hostname:a", "filters": [{"field": "user.name", "op": "eq", "value": "x"}]}
    )
    assert q.effective_q() == "(foo) (bar)"
    assert len(q.effective_filters()) == 2 and len(q.filters) == 1
    with pytest.raises(ValueError):
        EventQuery.model_validate({"text": "bad.field:1"})


async def test_text_query_executes_and_endpoint_reports_errors(client, make):
    from app.auth.rbac import Role
    from tests.helpers import ev

    t = await make.tenant()
    await make.index(
        t,
        [
            ev(process={"name": "powershell.exe", "command_line": "powershell -enc AAA"}),
            ev(process={"name": "cmd.exe", "command_line": "cmd /c dir"}, host={"hostname": "WS-02"}),
        ],
    )
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    r = await client.post(
        "/api/v1/events/search", headers=h, json={"text": "process.command_line:enc -host.hostname:ws-02"}
    )
    assert r.json()["total"] == 1
    bad = await client.post("/api/v1/queries/parse", headers=h, json={"text": "nope:1"})
    assert bad.status_code == 400 and "unknown field" in bad.json()["error"]["message"]
    ok = await client.post("/api/v1/queries/parse", headers=h, json={"text": "process.name:cmd.exe hello"})
    assert ok.json()["q"] == "hello" and ok.json()["filters"][0]["field"] == "process.name"
