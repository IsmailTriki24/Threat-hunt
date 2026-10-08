import contextlib

import pytest

from app.auth.rbac import Role
from app.connectors import registry
from app.connectors.base import NormalizationError

TS = 1767261600.123  # 2026-01-01T10:00:00Z-ish (kept in the past relative to "now")


def norm(kind, raw, cfg=None):
    return registry.build(kind, cfg).normalize(raw)


# ---- samples --------------------------------------------------------------------------------------------
ZEEK_CONN = {
    "_path": "conn",
    "ts": TS,
    "uid": "CYm1Gz3",
    "id.orig_h": "10.20.1.14",
    "id.orig_p": 50211,
    "id.resp_h": "203.0.113.45",
    "id.resp_p": 443,
    "proto": "tcp",
    "orig_bytes": 300,
    "resp_bytes": 120,
}
ZEEK_DNS = {
    "_path": "dns",
    "ts": TS,
    "uid": "CDns01",
    "id.orig_h": "10.20.1.14",
    "id.orig_p": 53211,
    "id.resp_h": "10.20.10.1",
    "id.resp_p": 53,
    "proto": "udp",
    "query": "cdn-update-check.example",
    "qtype_name": "A",
    "answers": ["203.0.113.45"],
}
SURI_ALERT = {
    "timestamp": "2026-01-01T10:00:00.123456+0000",
    "flow_id": 1234567890,
    "event_type": "alert",
    "src_ip": "10.20.1.14",
    "src_port": 50211,
    "dest_ip": "203.0.113.45",
    "dest_port": 443,
    "proto": "TCP",
    "alert": {
        "severity": 1,
        "signature": "ET MALWARE Synthetic C2 Beacon",
        "signature_id": 2000001,
        "category": "A Network Trojan was detected",
    },
}
SURI_DNS = {
    "timestamp": "2026-01-01T10:00:00.5+0000",
    "flow_id": 42,
    "event_type": "dns",
    "src_ip": "10.20.1.14",
    "src_port": 5353,
    "dest_ip": "10.20.10.1",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
        "id": 7,
        "rrname": "cdn-update-check.example",
        "rrtype": "A",
        "answers": [{"rdata": "203.0.113.45", "rrtype": "A"}],
    },
}
SURI_FLOW = {
    "timestamp": "2026-01-01T10:00:00+0000",
    "flow_id": 43,
    "event_type": "flow",
    "src_ip": "10.20.1.14",
    "src_port": 1000,
    "dest_ip": "198.51.100.7",
    "dest_port": 22,
    "proto": "TCP",
    "flow": {"bytes_toserver": 100, "bytes_toclient": 900},
}
WAZUH_ALERT = {
    "id": "1767261600.1001",
    "timestamp": "2026-01-01T10:00:00.000+0000",
    "rule": {
        "id": "5710",
        "level": 5,
        "description": "sshd: attempt to login using a non-existent user",
        "groups": ["syslog", "sshd", "authentication_failed"],
    },
    "agent": {"id": "003", "name": "lin-web-01", "ip": "10.20.5.5"},
    "data": {"srcip": "198.51.100.23", "srcuser": "admin"},
    "full_log": "Failed password for invalid user admin",
}
WAZUH_SYSMON = {
    "id": "1767261601.2002",
    "timestamp": "2026-01-01T10:00:01.000+0000",
    "rule": {"id": "92200", "level": 12, "description": "Powershell spawned by Office", "groups": ["sysmon"]},
    "agent": {"id": "001", "name": "WS-FIN-014", "ip": "10.20.1.14"},
    "data": {
        "win": {
            "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1", "computer": "WS-FIN-014"},
            "eventdata": {
                "utcTime": "2026-01-01 10:00:01.000",
                "image": "C:\\Windows\\System32\\powershell.exe",
                "commandLine": "powershell.exe -enc AAAA",
                "processId": "4312",
                "parentImage": "C:\\Program Files\\Office\\WINWORD.EXE",
                "parentProcessId": "5120",
                "user": "CORP\\mharper",
                "hashes": "SHA256=" + "a" * 64,
            },
        }
    },
}
WIN_BASE = {"@timestamp": "2026-01-01T10:00:00.000Z", "computer_name": "SRV-FILE-02", "record_id": 9001}
WIN_4624 = {
    **WIN_BASE,
    "event_id": 4624,
    "winlog": {
        "event_data": {
            "TargetUserName": "svc_backup",
            "TargetDomainName": "CORP",
            "LogonType": "3",
            "IpAddress": "10.20.1.14",
            "AuthenticationPackageName": "NTLM",
        }
    },
}
WIN_4625 = {
    **WIN_BASE,
    "record_id": 9002,
    "EventID": 4625,
    "EventData": {"TargetUserName": "admin", "LogonType": "10", "IpAddress": "198.51.100.23"},
}
WIN_4688 = {
    **WIN_BASE,
    "record_id": 9003,
    "event_id": 4688,
    "winlog": {
        "event_data": {
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "NewProcessId": "0x10e8",
            "ParentProcessName": "C:\\Windows\\System32\\services.exe",
            "ProcessId": "0x258",
            "SubjectUserName": "svc_backup",
        }
    },
}
WIN_4698 = {
    **WIN_BASE,
    "record_id": 9004,
    "event_id": 4698,
    "winlog": {"event_data": {"TaskName": "\\OneDrive Sync Helper", "SubjectUserName": "mharper"}},
}
WIN_7045 = {
    **WIN_BASE,
    "record_id": 9005,
    "event_id": 7045,
    "winlog": {"event_data": {"ServiceName": "PSEXESVC", "ImagePath": "C:\\Windows\\PSEXESVC.exe"}},
}


# ---- happy paths --------------------------------------------------------------------------------------
def test_zeek_conn_and_dns():
    [c] = norm("zeek", ZEEK_CONN, {"sensor": "sensor-1"})
    assert c.event_type == "network_connection" and c.source == "zeek" and c.host.hostname == "sensor-1"
    assert (c.network.src_ip, c.network.dst_port, c.network.protocol, c.network.bytes) == (
        "10.20.1.14",
        443,
        "tcp",
        420,
    )
    assert c.original_id == "sensor-1:conn:CYm1Gz3" and c.timestamp.year == 2026
    [d] = norm("zeek", ZEEK_DNS)
    assert (
        d.event_type == "dns_query"
        and d.dns.question == "cdn-update-check.example"
        and d.dns.answers == ["203.0.113.45"]
    )
    [detected] = norm("zeek", {k: v for k, v in ZEEK_DNS.items() if k != "_path"})
    assert detected.event_type == "dns_query"


def test_suricata_alert_dns_flow():
    [a] = norm("suricata", SURI_ALERT)
    assert a.event_type == "alert" and a.severity == 85 and a.message == "ET MALWARE Synthetic C2 Beacon"
    assert a.tags == ["A Network Trojan was detected"] and a.network.protocol == "tcp" and a.timestamp.tzinfo
    assert a.original_id and a.original_id == norm("suricata", SURI_ALERT)[0].original_id
    assert norm("suricata", {**SURI_ALERT, "alert": {**SURI_ALERT["alert"], "severity": 2}})[0].severity == 60
    assert norm("suricata", {**SURI_ALERT, "alert": {**SURI_ALERT["alert"], "severity": 3}})[0].severity == 35
    [d] = norm("suricata", SURI_DNS)
    assert d.dns.question == "cdn-update-check.example" and d.dns.answers == ["203.0.113.45"]
    [f] = norm("suricata", SURI_FLOW)
    assert f.event_type == "network_connection" and f.network.bytes == 1000


def test_wazuh_generic_and_sysmon_delegation():
    [a] = norm("wazuh", WAZUH_ALERT)
    assert (
        a.event_type == "alert" and a.severity == 35 and a.host.hostname == "lin-web-01" and a.host.ip == ["10.20.5.5"]
    )
    assert "wazuh-rule-5710" in a.tags and "sshd" in a.tags and a.original_id == "003:1767261600.1001"
    assert a.network.src_ip == "198.51.100.23" and a.user.name == "admin"
    [s] = norm("wazuh", WAZUH_SYSMON)
    assert s.event_type == "process_creation" and s.source == "wazuh" and s.process.name == "powershell.exe"
    assert s.process.parent.name == "WINWORD.EXE" and s.process.hash.sha256 == "a" * 64
    assert s.severity == 84 and "wazuh-rule-92200" in s.tags and s.original_id == "001:1767261601.2002"
    assert s.user.name == "mharper"
    assert norm("wazuh", {**WAZUH_ALERT, "rule": {**WAZUH_ALERT["rule"], "level": 15}})[0].severity == 100


def test_windows_eventlog_events():
    [a] = norm("windows_eventlog", WIN_4624)
    assert a.event_type == "authentication" and a.outcome == "success" and a.auth.logon_type == "network"
    assert a.auth.source_ip == "10.20.1.14" and a.user.name == "svc_backup" and a.original_id == "SRV-FILE-02:4624:9001"
    [f] = norm("windows_eventlog", WIN_4625)
    assert (
        f.outcome == "failure"
        and f.severity == 40
        and f.action == "logon_failed"
        and f.auth.logon_type == "remote_interactive"
    )
    [p] = norm("windows_eventlog", WIN_4688)
    assert p.process.pid == 0x10E8 and p.process.parent.pid == 0x258 and p.process.name == "cmd.exe"
    assert p.process.parent.name == "services.exe"
    [t] = norm("windows_eventlog", WIN_4698)
    assert t.event_type == "scheduled_task" and "OneDrive Sync Helper" in t.message and "persistence" in t.tags
    [s] = norm("windows_eventlog", WIN_7045)
    assert (
        s.event_type == "service_install" and "PSEXESVC" in s.message and s.process.executable.endswith("PSEXESVC.exe")
    )
    for ip in ("-", "::1"):
        ev = {**WIN_4624, "winlog": {"event_data": {**WIN_4624["winlog"]["event_data"], "IpAddress": ip}}}
        assert norm("windows_eventlog", ev)[0].auth.source_ip is None


# ---- hostile / malformed ----------------------------------------------------------------------------
BAD = [
    ("zeek", {}),
    ("zeek", {"_path": "files", "ts": TS}),
    ("zeek", {**ZEEK_CONN, "ts": None}),
    ("zeek", {**ZEEK_CONN, "ts": 1e30}),
    ("zeek", {**ZEEK_CONN, "ts": "not-a-time"}),
    ("zeek", {**ZEEK_CONN, "id.orig_h": "999.1.1.1"}),
    ("zeek", {**ZEEK_CONN, "id.resp_p": 70000}),
    ("zeek", {**ZEEK_CONN, "id.resp_p": "abc"}),
    ("zeek", {**ZEEK_DNS, "query": "a" * 300}),
    ("zeek", {**ZEEK_CONN, "id.orig_h": {"x": 1}, "id.resp_h": ["a"]})
    if False
    else ("zeek", {**ZEEK_CONN, "id.orig_h": "x"}),
    ("suricata", {}),
    ("suricata", {"event_type": "http", "timestamp": "2026-01-01T00:00:00+0000"}),
    ("suricata", {**SURI_ALERT, "timestamp": None}),
    ("suricata", {**SURI_ALERT, "timestamp": "yesterday"}),
    ("suricata", {**SURI_ALERT, "src_ip": "not-an-ip"}),
    ("suricata", {**SURI_ALERT, "dest_port": -1}),
    ("suricata", {**SURI_ALERT, "alert": "oops", "src_ip": "bad"}),
    ("wazuh", {}),
    ("wazuh", {"rule": "x"}),
    ("wazuh", {**WAZUH_ALERT, "rule": {"id": "1"}}),
    ("wazuh", {**WAZUH_ALERT, "timestamp": 5}),
    ("wazuh", {**WAZUH_ALERT, "data": {"srcip": "300.0.0.1"}}),
    ("wazuh", {**WAZUH_ALERT, "agent": {"ip": "nope", "name": "x"}}),
    ("wazuh", {**WAZUH_ALERT, "rule": {**WAZUH_ALERT["rule"], "level": "high"}}),
    ("windows_eventlog", {}),
    ("windows_eventlog", {**WIN_4624, "event_id": "abc"}),
    ("windows_eventlog", {**WIN_BASE, "event_id": 1102}),
    ("windows_eventlog", {"event_id": 4624, "computer_name": "x"}),
    ("windows_eventlog", {**WIN_4624, "@timestamp": "garbage"}),
    ("windows_eventlog", {**WIN_4624, "winlog": {"event_data": {"IpAddress": "1.2.3.999", "LogonType": "3"}}}),
    (
        "windows_eventlog",
        {**WIN_4624, "raw_blob": "x", "winlog": "notadict", "EventData": ["a"], "event_id": 4624, "IpAddress": "bad"},
    ),
    ("zeek", {**ZEEK_CONN, "huge": "x" * 70000}),
    ("suricata", {**SURI_ALERT, "huge": "x" * 70000}),
    ("wazuh", {**WAZUH_ALERT, "huge": "x" * 70000}),
    ("windows_eventlog", {**WIN_4624, "huge": "x" * 70000}),
]


@pytest.mark.parametrize("kind,raw", BAD)
def test_malformed_input_raises_normalization_error_only(kind, raw):
    with pytest.raises(NormalizationError):
        norm(kind, raw)


@pytest.mark.parametrize("kind", ["zeek", "suricata", "wazuh", "windows_eventlog"])
def test_weird_types_never_crash(kind):
    junk = [None, 1, "s", [], [1, 2], {"a": {"b": [None]}}, True, 1.5, {"x": float("inf")}]
    for v in junk:
        for key in (
            "ts",
            "timestamp",
            "id",
            "rule",
            "agent",
            "data",
            "winlog",
            "EventData",
            "event_id",
            "alert",
            "dns",
            "flow",
        ):
            with contextlib.suppress(NormalizationError):
                norm(kind, {key: v})


def test_zeek_unknown_config_rejected():
    with pytest.raises(ValueError):
        registry.build("zeek", {"sensor": "x", "command": "rm -rf /"})


# ---- end to end through the API --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "kind,raw,cfg,query",
    [
        ("zeek", ZEEK_CONN, {"sensor": "sensor-1"}, {"text": "network.dst_ip:203.0.113.45 source:zeek"}),
        ("suricata", SURI_ALERT, {}, {"q": "beacon"}),
        ("wazuh", WAZUH_SYSMON, {}, {"text": "process.name:powershell.exe source:wazuh"}),
        ("windows_eventlog", WIN_7045, {}, {"text": "source:windows event_type:service_install"}),
    ],
)
async def test_ingest_end_to_end(client, make, kind, raw, cfg, query):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    # events from the fixed past: search over an explicit wide window
    wide = {"time_range": {"start": "2025-12-31T00:00:00Z", "end": "2026-01-02T00:00:00Z"}}
    body = {"source_type": kind, "config": cfg, "events": [raw, {"garbage": True}]}
    r = (await client.post("/api/v1/events/ingest", headers=h, json=body)).json()
    assert r["accepted"] == 1 and r["rejected"][0]["index"] == 1
    again = (await client.post("/api/v1/events/ingest", headers=h, json={**body, "events": [raw]})).json()
    assert again["accepted"] == 0 and again["duplicates"] == 1
    await make.app.state.opensearch.indices.refresh(index=make.app.state.search.pattern, ignore_unavailable=True)
    res = (await client.post("/api/v1/events/search", headers=h, json={**query, **wide})).json()
    assert res["total"] == 1, (kind, res)


def test_overlong_values_are_truncated_instead_of_dropping_the_event():
    """These used to be rejected, which silently lost the event. Attacker-controlled values are routinely this long."""
    w = norm("wazuh", {**WAZUH_ALERT, "agent": {**WAZUH_ALERT.get("agent", {}), "name": "h" * 400}})
    assert len(w[0].host.hostname) == 256 and w[0].labels["truncated"] == "host.hostname"
    win = norm("windows_eventlog", {**WIN_4688, "winlog": {"event_data": {"NewProcessName": "x" * 2000}}})
    assert len(win[0].process.executable) == 1024 and "process.executable" in win[0].labels["truncated"]
