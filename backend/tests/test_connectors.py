import pytest

from app.auth.rbac import Role
from app.connectors import registry
from app.connectors.base import NormalizationError
from app.events.schema import EventIn

SYSMON_PROC = {
    "EventID": 1,
    "UtcTime": "2026-03-01T10:00:00Z",
    "Computer": "WS-9",
    "User": "CORP\\alice",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -enc AAAA",
    "ProcessId": 4312,
    "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
    "ParentProcessId": 5120,
    "Hashes": "SHA256=" + "A" * 64 + ",MD5=" + "b" * 32,
    "RecordID": 77,
}


def test_sysmon_process_creation():
    [e] = registry.build("sysmon").normalize(SYSMON_PROC)
    assert e.event_type == "process_creation" and e.source == "sysmon"
    assert e.process.name == "powershell.exe" and e.process.parent.name == "WINWORD.EXE"
    assert e.process.hash.sha256 == "a" * 64 and e.process.hash.md5 == "b" * 32
    assert e.user.name == "alice" and e.user.domain == "CORP" and e.host.hostname == "WS-9"
    assert e.original_id == "WS-9:77" and e.raw["EventID"] == 1


def test_sysmon_network_and_dns_and_file():
    c = registry.build("sysmon")
    [n] = c.normalize(
        {
            "EventID": 3,
            "UtcTime": "2026-03-01T10:00:00Z",
            "Computer": "H",
            "Image": "C:\\a\\b.exe",
            "SourceIp": "10.0.0.1",
            "SourcePort": 5555,
            "DestinationIp": "203.0.113.5",
            "DestinationPort": 443,
            "Protocol": "tcp",
            "Initiated": "true",
        }
    )
    assert n.network.dst_ip == "203.0.113.5" and n.network.direction == "outbound"
    [d] = c.normalize(
        {
            "EventID": 22,
            "UtcTime": "2026-03-01T10:00:00Z",
            "Computer": "H",
            "Image": "x.exe",
            "QueryName": "evil.example",
            "QueryResults": "::ffff:203.0.113.5;",
        }
    )
    assert d.dns.question == "evil.example" and d.dns.answers == ["203.0.113.5"]
    [f] = c.normalize(
        {
            "EventID": 11,
            "UtcTime": "2026-03-01T10:00:00Z",
            "Computer": "H",
            "Image": "x.exe",
            "TargetFilename": "C:\\Temp\\a.ps1",
        }
    )
    assert f.file.name == "a.ps1"


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"EventID": "x"},
        {"EventID": 99, "UtcTime": "2026-03-01T10:00:00Z"},
        {"EventID": 1, "UtcTime": "not-a-date"},
        {"EventID": 3, "UtcTime": "2026-03-01T10:00:00Z", "DestinationIp": "999.1.1.1"},
    ],
)
def test_sysmon_rejects_malformed(raw):
    with pytest.raises(NormalizationError):
        registry.build("sysmon").normalize(raw)


def test_generic_json_field_map_and_unknown_target_rejected():
    cfg = {
        "source": "myapp",
        "default_event_type": "authentication",
        "field_map": {"timestamp": "meta.ts", "user.name": "who", "network.src_ip": "ip", "outcome": "result"},
    }
    c = registry.build("generic_json", cfg)
    [e] = c.normalize({"meta": {"ts": "2026-03-01T10:00:00Z"}, "who": "dave", "ip": "10.1.1.1", "result": "failure"})
    assert e.source == "myapp" and e.user.name == "dave" and e.outcome == "failure"
    with pytest.raises(NormalizationError):
        c.normalize({"who": "dave"})  # no timestamp
    bad = registry.build("generic_json", {"field_map": {"timestamp": "t", "tenant_id": "x"}})
    with pytest.raises(NormalizationError):
        bad.normalize({"t": "2026-03-01T10:00:00Z", "x": "other-tenant"})


def test_unknown_connector_and_bad_config():
    with pytest.raises(KeyError):
        registry.build("nope")
    with pytest.raises(ValueError):
        registry.build("generic_json", {"field_map": "not-a-dict"})
    with pytest.raises(ValueError):
        registry.build("sysmon", {"anything": 1})


def test_canonical_schema_validation():
    e = EventIn.model_validate({"timestamp": "2026-03-01T10:00:00", "source": "x", "event_type": "other"})
    assert e.timestamp.tzinfo is not None
    for bad in [
        {"source": "Bad Source!"},
        {"event_type": "weird"},
        {"timestamp": "2999-01-01T00:00:00Z"},
        {"severity": 101},
        {"host": {"ip": ["300.1.1.1"]}},
        {"raw": {"k": "x" * 70000}},
        {"process": {"hash": {"sha256": "zz"}}},
    ]:
        with pytest.raises(ValueError):
            EventIn.model_validate({"timestamp": "2026-03-01T10:00:00Z", "source": "x", "event_type": "other", **bad})


async def test_ingest_sysmon_end_to_end_dedupe_and_partial_failure(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    payload = {"source_type": "sysmon", "events": [SYSMON_PROC, {"EventID": 99}]}
    r = (await client.post("/api/v1/events/ingest", headers=h, json=payload)).json()
    assert r["accepted"] == 1 and r["rejected"][0]["index"] == 1
    again = (await client.post("/api/v1/events/ingest", headers=h, json=payload)).json()
    assert again["accepted"] == 0 and again["duplicates"] == 1  # idempotent re-ingest


async def test_ingest_validation(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    post = lambda body: client.post("/api/v1/events/ingest", headers=h, json=body)  # noqa: E731
    assert (await post({"source_type": "nope", "events": [{}]})).status_code == 400
    assert (await post({"events": []})).status_code == 422
    assert (await post({"events": [{}] * 1001})).status_code == 400
    assert (await post({"source_type": "generic_json", "config": {"field_map": 5}, "events": [{}]})).status_code == 400
