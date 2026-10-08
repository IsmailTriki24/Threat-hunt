"""Condition tree: validation, local evaluation and a differential test against OpenSearch."""

import pytest

from app.events.schema import Event
from app.events.search.local import glob_match, matches
from app.events.search.query import Condition, EventQuery, TimeRange
from tests.helpers import ev


def F(field, op="eq", value=None, **kw):
    return {"filter": {"field": field, "op": op, "value": value, **kw}}


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"all": []},
        {"any": []},
        {"all": [F("host.hostname", value="a")], "any": [F("host.hostname", value="a")]},
        {"filter": {"field": "nope.x", "op": "eq", "value": "a"}},
        {"filter": {"field": "tenant_id", "op": "eq", "value": "x"}},
        {"filter": {"field": "host.hostname", "op": "wildcard", "value": "*"}},
        {"filter": {"field": "host.hostname", "op": "wildcard", "value": "a" + "*a" * 11}},
        {"filter": {"field": "network.dst_port", "op": "wildcard", "value": "4*"}},
        {"unknown": 1},
    ],
)
def test_invalid_conditions(bad):
    with pytest.raises(ValueError):
        Condition.model_validate(bad)


def test_size_limits():
    node = F("host.hostname", value="a")
    for _ in range(9):
        node = {"not": node}
    with pytest.raises(ValueError, match="too large"):
        EventQuery.model_validate({"where": node})
    wide = {"all": [{"any": [F("host.hostname", value=str(i)) for i in range(100)]} for _ in range(4)]}
    with pytest.raises(ValueError, match="too large"):
        EventQuery.model_validate({"where": wide})


def test_glob_semantics():
    assert glob_match("*\\powershell.exe", "C:\\Windows\\System32\\PowerShell.EXE")
    assert glob_match("power*ll.exe", "powershell.exe") and not glob_match("power*ll.exe", "powershell.exe.bak")
    assert glob_match("a?c", "abc") and not glob_match("a?c", "ac")
    assert glob_match("a\\*c", "a*c") and not glob_match("a\\*c", "abc")
    assert glob_match("*", "") and not glob_match("a*", "")
    assert not glob_match("*" + "a*" * 8 + "b", "a" * 3000)  # pathological pattern stays fast (iterative matcher)


# ---- differential: local evaluator == OpenSearch ------------------------------------------------------
CORPUS = [
    ev(
        1,
        host={"hostname": "WS-FIN-01", "ip": ["10.0.0.5", "10.0.1.5"]},
        user={"name": "Alice", "domain": "CORP"},
        process={
            "name": "PowerShell.exe",
            "pid": 100,
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -NoP -W Hidden -enc SQBFAFgA",
            "parent": {"name": "WINWORD.EXE", "pid": 5},
            "hash": {"sha256": "A" * 64},
        },
        severity=80,
        tags=["Persistence", "demo"],
        action="process_started",
    ),
    ev(
        2,
        event_type="network_connection",
        host={"hostname": "WS-FIN-02"},
        user={"name": "bob"},
        process={"name": "chrome.exe", "pid": 7, "executable": "C:\\Program Files\\Chrome\\chrome.exe"},
        network={
            "src_ip": "10.0.0.6",
            "dst_ip": "203.0.113.45",
            "dst_port": 443,
            "dst_domain": "Cdn.Evil.Example",
            "protocol": "tcp",
            "direction": "outbound",
        },
    ),
    ev(
        3,
        event_type="dns_query",
        host={"hostname": "SRV-DC-01"},
        dns={"question": "evil.example", "answers": ["203.0.113.45", "alias.example"]},
    ),
    ev(
        4,
        event_type="authentication",
        source="windows",
        outcome="failure",
        host={"hostname": "SRV-DC-01"},
        user={"name": "carol"},
        auth={"logon_type": "network", "source_ip": "198.51.100.23"},
        action="logon_failed",
        severity=40,
    ),
    ev(
        5,
        event_type="file_event",
        host={"hostname": "WS-FIN-01"},
        process={"name": "excel.exe"},
        file={"name": "Report.XLSX", "path": "C:\\Users\\Alice\\Documents\\Report.xlsx", "hash": {"md5": "b" * 32}},
    ),
    ev(
        6,
        event_type="registry_event",
        host={"hostname": "WS-FIN-01"},
        registry={"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "value": "c:\\x.exe"},
    ),
    ev(7, host={"hostname": "ws-fin-03"}),
]

CASES = [
    F("host.hostname", value="ws-fin-01"),
    F("host.hostname", "neq", "WS-FIN-01"),
    F("host.hostname", "in", ["WS-FIN-02", "srv-dc-01"]),
    F("host.hostname", "prefix", "ws-fin"),
    F("host.hostname", "contains", "FIN-0"),
    F("host.hostname", "wildcard", "*-fin-0?"),
    F("host.hostname", "wildcard", "WS-*"),
    F("host.hostname", "wildcard", "*dc*"),
    F("host.hostname", value="WS-FIN-01", negate=True),
    F("user.name", value="ALICE"),
    F("user.name", "exists"),
    F("user.name", "not_exists"),
    F("source", value="sysmon"),
    F("source", value="SYSMON"),  # case-sensitive keyword (no normalizer)
    F("event_type", value="dns_query"),
    F("outcome", value="failure"),
    F("action", "prefix", "logon"),
    F("process.name", value="powershell.exe"),
    F("process.parent.name", value="winword.exe"),
    F("process.executable", "wildcard", "*\\powershell.exe"),
    F("process.executable", "wildcard", "*\\WindowsPowerShell\\*"),
    F("process.executable", value="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    F("process.command_line", "contains", "enc"),
    F("process.command_line", "contains", "-w hidden"),
    F("process.command_line", "wildcard", "*-enc *"),
    F("process.command_line", "wildcard", "*-NOP*"),
    F("process.command_line", "prefix", "powershell.exe -nop"),
    F("process.command_line", "contains", "nothing-like-this"),
    F("process.pid", value=100),
    F("process.pid", "gte", 7),
    F("process.pid", "lt", 100),
    F("process.pid", "in", [7, 100]),
    F("severity", "gte", 80),
    F("severity", "lt", 50),
    F("process.hash.sha256", value="a" * 64),
    F("host.ip", value="10.0.0.5"),
    F("host.ip", value="10.0.0.0/24"),
    F("host.ip", "in", ["10.0.1.5", "1.1.1.1"]),
    F("network.dst_ip", value="203.0.113.0/24"),
    F("network.dst_ip", "neq", "203.0.113.45"),
    F("network.dst_port", "gte", 400),
    F("network.dst_domain", value="cdn.evil.example"),
    F("network.dst_domain", "wildcard", "*.evil.example"),
    F("dns.answers", value="203.0.113.45"),
    F("dns.answers", "wildcard", "alias*"),
    F("dns.question", "contains", "vil"),
    F("auth.logon_type", value="network"),
    F("auth.source_ip", value="198.51.100.0/24"),
    F("file.path", "wildcard", "*\\Documents\\*.xlsx"),
    F("file.name", value="report.xlsx"),
    F("file.hash.md5", value="B" * 32),
    F("registry.key", "wildcard", "*\\CurrentVersion\\Run\\*"),
    F("registry.key", "contains", "Run"),
    F("registry.value", value="c:\\x.exe"),
    F("tags", value="persistence"),
    F("tags", "exists"),
    {"all": [F("host.hostname", value="ws-fin-01"), F("process.name", value="powershell.exe")]},
    {"any": [F("dns.question", value="evil.example"), F("severity", "gte", 80)]},
    {"all": [F("host.hostname", "prefix", "ws-"), {"not": F("process.name", value="powershell.exe")}]},
    {"not": {"any": [F("host.hostname", value="ws-fin-01"), F("host.hostname", value="ws-fin-02")]}},
    {
        "all": [
            {"any": [F("process.command_line", "contains", "enc"), F("process.command_line", "contains", "bypass")]},
            {"not": F("user.name", value="bob")},
        ]
    },
]


async def test_local_evaluator_agrees_with_opensearch(make):
    t = await make.tenant()
    await make.index(t, CORPUS)
    backend = make.app.state.search
    docs = [Event.from_input(e, t.id).to_document() for e in CORPUS]
    # Event ids are random per call; align the local docs with what OpenSearch stored.
    stored = (
        await backend.search(
            t.id, EventQuery(limit=50, time_range=TimeRange.last(__import__("datetime").timedelta(hours=1)))
        )
    ).hits
    assert len(stored) == len(CORPUS)
    for i, case in enumerate(CASES):
        cond = Condition.model_validate(case)
        res = await backend.search(
            t.id, EventQuery(where=cond, limit=50, time_range=TimeRange.last(__import__("datetime").timedelta(hours=1)))
        )
        os_ids = {h["id"] for h in res.hits}
        local_ids = {d["id"] for d in stored if matches(cond, d)}
        assert os_ids == local_ids, f"case {i}: {case}\n only-OS={os_ids - local_ids} only-local={local_ids - os_ids}"
    assert docs  # keep the helper referenced
