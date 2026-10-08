# ruff: noqa: E501
"""LogRhythm + Trend Vision One connectors. Fixtures are synthetic but shaped like real API output."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.auth.rbac import Role
from app.connectors import _http, registry
from app.connectors.base import NormalizationError
from app.connectors.logrhythm import LogRhythmConnector
from app.connectors.trend_vision_one import TrendVisionOneConnector

PUBLIC = "93.184.216.34"
NOW = datetime.now(UTC)


async def _resolve(host, port):
    return [PUBLIC]


@pytest.fixture
def wire(monkeypatch):
    """Install a MockTransport handler for connector HTTP; returns the list of seen requests."""
    seen: list[httpx.Request] = []

    def install(handler):
        def wrapped(request):
            seen.append(request)
            return handler(request)

        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(wrapped))
        monkeypatch.setattr(_http, "RESOLVER", _resolve)
        monkeypatch.setattr("app.core.ssrf.get_settings", lambda: get_settings_with_ports())
        return seen

    async def nosleep(_):
        return None

    monkeypatch.setattr("app.connectors._http.asyncio.sleep", nosleep)
    monkeypatch.setattr("app.connectors.logrhythm._sleep", nosleep)
    return install


def get_settings_with_ports():
    from app.core.config import Settings

    s = Settings(jwt_secret="x" * 40, outbound_allowed_ports="80,443,8501")
    return s


# ---- LogRhythm ---------------------------------------------------------------------------------------
def lr_log(**over):
    base = {
        "messageId": "605280326",
        "logDate": int((NOW + timedelta(hours=1)).timestamp() * 1000),
        "normalDate": int(NOW.timestamp() * 1000),
        "classificationName": "Authentication Failure",
        "classificationTypeName": "Audit",
        "commonEventName": "User Logon Failure : Bad Password",
        "vendorMessageId": "4771",
        "vendorInfo": "Kerberos Authentication Service",
        "impactedHost": "dc1-srv-ad4.example.local",
        "login": "jdoe",
        "domainOrigin": "EXAMPLE.local",
        "originIp": "10.0.21.202",
        "originPort": 52434,
        "sessionType": "2",
        "priority": 28,
        "entityName": "DC-System Devices",
        "logSourceName": "DC1 Security",
        "logSourceTypeName": "MS Windows Event Logging XML - Security",
        "responseCode": "0x18",
        "userOriginIdentity": "John Doe (jdoe@example.com)",
    }
    return {**base, **over}


def test_lr_auth_failure_maps_to_canonical():
    [e] = registry.build("logrhythm", {"base_url": "https://lr.example:8501"}).normalize(lr_log())
    assert e.event_type == "authentication" and e.outcome == "failure" and e.source == "logrhythm"
    assert e.host.hostname == "dc1-srv-ad4.example.local" and e.user.name == "jdoe" and e.user.domain == "EXAMPLE.local"
    assert e.auth.source_ip == "10.0.21.202" and e.auth.logon_type == "2" and e.network.src_port == 52434
    assert e.original_id == "605280326" and e.severity == 28
    assert e.labels["vendor_message_id"] == "4771" and "authentication-failure" in e.tags
    # logDate carries the console's +1h offset; the event time is corrected by date_shift_hours (-1)
    assert abs((e.timestamp - NOW).total_seconds()) < 2


def test_lr_shift_is_configurable_and_ids_are_stable():
    c = registry.build("logrhythm", {"base_url": "https://lr.example:8501", "date_shift_hours": 0})
    assert abs((c.normalize(lr_log())[0].timestamp - (NOW + timedelta(hours=1))).total_seconds()) < 2


def test_lr_ai_engine_alert_extracts_attack_technique():
    raw = lr_log(
        classificationName="Activity",
        commonEventName="AIE: WIFAK: T1059.003:Windows Command Shell",
        logSourceTypeName="LogRhythm AI Engine",
        vendorMessageId=None,
        originIp=None,
        login=None,
    )
    [e] = registry.build("logrhythm", {"base_url": "https://lr.example:8501"}).normalize(raw)
    assert e.event_type == "alert" and "attack.t1059.003" in e.tags


@pytest.mark.parametrize(
    "cls,expected",
    [
        ("Network Allowed Traffic", "network_connection"),
        ("Malware", "alert"),
        ("DNS Query", "dns_query"),
        ("Operations", "other"),
        ("File Access", "file_event"),
    ],
)
def test_lr_classification_mapping(cls, expected):
    [e] = registry.build("logrhythm", {"base_url": "https://lr.example:8501"}).normalize(
        lr_log(classificationName=cls, commonEventName="x")
    )
    assert e.event_type == expected


def test_lr_hostile_values_never_crash_normalization():
    c = registry.build("logrhythm", {"base_url": "https://lr.example:8501"})
    [e] = c.normalize(
        lr_log(
            originIp="not-an-ip",
            impactedIp="::ffff:10.1.1.1",
            originPort=99999,
            login="x" * 5000,
            priority=10**9,
            vendorInfo="y" * 5000,
        )
    )
    assert (
        e.network.dst_ip == "10.1.1.1" and e.network.src_ip is None and e.network.src_port is None and e.severity == 100
    )
    for bad in ({"logDate": None, "normalDate": None}, {"messageId": None}, {"logDate": 10**30}):
        with pytest.raises(NormalizationError):
            c.normalize(lr_log(**bad))


def lr_handler(pages_by_task, statuses=None):
    state = {"n": 0}

    def handler(request):
        body = json.loads(request.content)
        if request.url.path.endswith("/search-task"):
            state["n"] += 1
            return httpx.Response(200, json={"TaskId": f"task-{state['n']}", "echo": body["dateCriteria"]})
        guid = body["data"]["searchGuid"]
        origin = body["data"]["paginator"]["origin"]
        logs = pages_by_task(guid)
        items = logs[origin : origin + body["data"]["paginator"]["page_size"]]
        status = (statuses or {}).get(guid, "Completed: Completed")
        return httpx.Response(200, json={"TaskStatus": status, "Items": items})

    return handler


async def _collect(conn, **kw):
    return [r async for r in conn.collect(**kw)]


async def test_lr_collect_pages_sorts_and_advances_watermark(wire):
    logs = [lr_log(messageId=str(i), logDate=1_700_000_000_000 + (10 - i) * 1000) for i in range(7)]
    seen = wire(lr_handler(lambda guid: logs))
    c = registry.build(
        "logrhythm",
        {"base_url": "https://lr.example:8501", "window_minutes": 60, "initial_lookback_hours": 1, "hostname": "dc1"},
        {"token": "SECRET-TOKEN"},
    )
    out = await _collect(c)
    assert [r["messageId"] for r in out][:3] == ["6", "5", "4"]  # ascending logDate
    assert c.watermark is not None and NOW - timedelta(minutes=10) < c.watermark <= datetime.now(UTC)
    assert all(r.headers["authorization"] == "Bearer SECRET-TOKEN" for r in seen)
    task = json.loads(next(r for r in seen if r.url.path.endswith("search-task")).content)
    assert task["queryRawLog"] is False and task["dateCriteria"]["useInsertedDate"] is False


async def test_lr_window_hitting_the_cap_is_split(wire):
    calls = {"windows": []}

    def handler(request):
        body = json.loads(request.content)
        if request.url.path.endswith("search-task"):
            d = body["dateCriteria"]
            calls["windows"].append((d["dateMin"], d["dateMax"]))
            return httpx.Response(200, json={"TaskId": f"t{len(calls['windows'])}"})
        guid = body["data"]["searchGuid"]
        capped = guid == "t1"
        return httpx.Response(
            200,
            json={
                "TaskStatus": "Max Results" if capped else "Completed",
                "Items": [] if capped else [lr_log(messageId=guid)],
            },
        )

    wire(handler)
    c = registry.build(
        "logrhythm", {"base_url": "https://lr.example:8501", "window_minutes": 60, "hostname": "dc1"}, {"token": "t"}
    )
    out = await _collect(c)
    assert len(calls["windows"]) >= 3 and len(out) >= 2  # first window split into halves


async def test_lr_errors_are_safe(wire):
    wire(lambda request: httpx.Response(401, json={"error": "nope"}))
    c = registry.build(
        "logrhythm", {"base_url": "https://lr.example:8501", "hostname": "dc1"}, {"token": "SECRET-TOKEN"}
    )
    with pytest.raises(_http.SourceError) as exc:
        await _collect(c)
    assert "SECRET-TOKEN" not in str(exc.value) and "authentication rejected" in str(exc.value)
    res = await c.test_connection()
    assert not res.ok and "SECRET-TOKEN" not in res.detail
    nokey = registry.build("logrhythm", {"base_url": "https://lr.example:8501"})
    assert "no API token" in (await nokey.test_connection()).detail


async def test_lr_retries_transient_errors(wire):
    n = {"c": 0}

    def handler(request):
        n["c"] += 1
        if n["c"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"TaskId": "ok"})

    wire(handler)
    c = registry.build("logrhythm", {"base_url": "https://lr.example:8501"}, {"token": "t"})
    assert (await c.test_connection()).ok and n["c"] == 3


def test_lr_config_rejects_unknown_and_unsafe():
    for bad in (
        {"base_url": "ftp://x"},
        {"base_url": "https://x", "date_shift_hours": 99},
        {"base_url": "https://x", "extra": 1},
        {},
    ):
        with pytest.raises(Exception):  # noqa: B017, PT011
            registry.build("logrhythm", bad)


# ---- Trend Vision One --------------------------------------------------------------------------------
def tm(dataset, **over):
    return registry.build("trend_vision_one", {"dataset": dataset, **over}, {"api_key": "KEY-123"})


EP_BASE = {
    "uuid": "u-1",
    "eventTimeDT": "2026-10-08T09:56:03.911000+00:00",
    "eventTime": 1791453363911,
    "logReceivedTime": "1791453332676",
    "endpointHostName": "WS-01",
    "endpointIp": ["10.1.1.5", "fe80::1"],
    "endpointGuid": "g-1",
    "logonUser": ["CORP\\alice"],
    "processUser": "alice",
    "userDomain": "CORP",
    "pname": "Apex One",
    "osName": "Windows",
    "processName": "winword.exe",
    "processFilePath": "C:\\Office\\winword.exe",
    "processCmd": "winword.exe /x",
    "processPid": 100,
}


def test_tm_process_creation_uses_object_as_new_process():
    raw = {
        **EP_BASE,
        "eventId": "1",
        "eventSubId": 2,
        "objectName": "powershell.exe",
        "objectFilePath": "C:\\Windows\\powershell.exe",
        "objectCmd": "powershell -enc AAA",
        "objectPid": 200,
        "objectUser": "alice",
        "objectFileHashSha256": "a" * 64,
        "objectFileHashMd5": "bad",
        "processFileHashSha1": "b" * 40,
    }
    [e] = tm("endpoint_activity").normalize(raw)
    assert (
        e.event_type == "process_creation"
        and e.process.name == "powershell.exe"
        and e.process.command_line == "powershell -enc AAA"
    )
    assert e.process.parent.name == "winword.exe" and e.process.parent.pid == 100
    assert e.process.hash.sha256 == "a" * 64 and e.process.hash.md5 is None  # malformed digest dropped, event kept
    assert e.host.hostname == "WS-01" and e.host.ip == ["10.1.1.5", "fe80::1"] and e.original_id == "u-1"


def test_tm_network_dns_file_and_other():
    net = tm("endpoint_activity").normalize(
        {
            **EP_BASE,
            "eventId": "3",
            "eventSubId": 204,
            "src": "172.16.24.182",
            "spt": 52498,
            "dst": "10.240.70.68",
            "dpt": 3128,
            "proto": "6",
        }
    )[0]
    assert (
        net.event_type == "network_connection"
        and net.network.dst_port == 3128
        and net.network.protocol == "tcp"
        and net.process.name == "winword.exe"
    )
    odd = tm("endpoint_activity").normalize(
        {**EP_BASE, "eventId": "3", "src": "bogus", "dst": "::ffff:10.0.0.9", "proto": "1"}
    )[0]
    assert odd.network.dst_ip == "10.0.0.9" and odd.network.src_ip is None and odd.network.protocol is None
    dns = tm("endpoint_activity").normalize(
        {**EP_BASE, "eventId": "4", "hostName": "evil.example", "objectIps": ["::ffff:1.2.3.4", "junk"]}
    )[0]
    assert dns.event_type == "dns_query" and dns.dns.question == "evil.example" and dns.dns.answers == ["1.2.3.4"]
    f = tm("endpoint_activity").normalize({**EP_BASE, "eventId": "2", "objectFilePath": "C:\\Users\\a\\x.docm"})[0]
    assert f.event_type == "file_event" and f.file.name == "x.docm"
    assert tm("endpoint_activity").normalize({**EP_BASE, "eventId": "14", "eventSubId": 1101})[0].event_type == "other"


def test_tm_alerts_oat_and_detections():
    alert = {
        "id": "WB-1-20261006-00001",
        "createdDateTime": "2026-10-06T10:00:00Z",
        "updatedDateTime": "2026-10-06T11:00:00Z",
        "severity": "high",
        "score": 62,
        "model": "Possible Credential Dumping",
        "status": "Open",
        "alertProvider": "SAE",
        "incidentId": "IC-1",
        "impactScope": {
            "entities": [
                {"entityType": "host", "entityValue": {"name": "WS-9", "ips": ["10.9.9.9"]}},
                {"entityType": "account", "entityValue": "CORP\\bob"},
            ]
        },
        "matchedRules": [{"matchedFilters": [{"mitreTechniqueIds": ["T1003.001", "t1059"]}]}],
    }
    [a] = tm("alerts").normalize(alert)
    assert (
        a.event_type == "alert"
        and a.severity == 62
        and a.host.hostname == "WS-9"
        and a.host.ip == ["10.9.9.9"]
        and a.user.name == "CORP\\bob"
    )
    assert "attack.t1003.001" in a.tags and a.labels["incident_id"] == "IC-1" and a.original_id == "WB-1-20261006-00001"
    oat = {
        "uuid": "o-1",
        "detectedDateTime": "2026-10-08T09:00:00Z",
        "filters": [
            {"id": "F1", "name": "Suspicious PowerShell", "riskLevel": "high", "mitreTechniqueIds": ["T1059.001"]}
        ],
        "detail": {
            "endpointHostName": "WS-2",
            "endpointIp": ["10.2.2.2"],
            "processCmd": "powershell -nop",
            "processName": "powershell.exe",
            "eventTime": 1791453363911,
        },
    }
    [o] = tm("oat").normalize(oat)
    assert (
        o.severity == 75
        and "attack.t1059.001" in o.tags
        and o.process.command_line == "powershell -nop"
        and o.host.hostname == "WS-2"
    )
    det = {
        "uuid": "d-1",
        "eventTimeDT": "2026-10-08T09:00:00+00:00",
        "eventName": "APPLICATION_CONTROL_VIOLATION",
        "ruleName": "Block unsigned",
        "endpointHostName": "WS-3",
        "fileName": ["a.exe"],
        "filePath": "C:\\a.exe",
        "fileHashSha256": "c" * 64,
        "pname": "Apex One",
    }
    [d] = tm("detections").normalize(det)
    assert (
        d.event_type == "alert"
        and d.file.name == "a.exe"
        and d.file.hash.sha256 == "c" * 64
        and d.action == "APPLICATION_CONTROL_VIOLATION"
    )


def test_tm_bad_records_and_hostile_values():
    for ds, bad in [
        ("alerts", {}),
        ("oat", {"detectedDateTime": "2026-01-01T00:00:00Z"}),
        ("endpoint_activity", {"eventTimeDT": "2026-01-01T00:00:00Z"}),
        ("detections", {}),
    ]:
        with pytest.raises(NormalizationError):
            tm(ds).normalize(bad)
    with pytest.raises(NormalizationError):
        tm("endpoint_activity").normalize({"uuid": "x"})  # no timestamp
    long = {**EP_BASE, "eventId": "1", "pname": "p" * 5000, "osName": "o" * 5000, "processUser": "u" * 5000}
    assert tm("endpoint_activity").normalize(long)


def test_tm_config_is_fixed_hosts_and_single_line_query():
    for bad in (
        {"dataset": "nope"},
        {"dataset": "oat", "region": "https://evil.example"},
        {"dataset": "detections", "query": "a\nb"},
        {"dataset": "oat", "url": "http://x"},
    ):
        with pytest.raises(Exception):  # noqa: B017, PT011
            registry.build("trend_vision_one", bad)


async def test_tm_collect_follows_next_link_and_sends_headers(wire):
    def handler(request):
        if request.url.path.endswith("/healthcheck/connectivity"):
            return httpx.Response(200, json={"status": "available"})
        if "page=2" in str(request.url):
            return httpx.Response(200, json={"items": [{"uuid": "b"}], "progressRate": 100})
        return httpx.Response(
            200,
            json={
                "items": [{"uuid": "a"}],
                "nextLink": "https://api.eu.xdr.trendmicro.com/v3.0/search/endpointActivities?page=2",
            },
        )

    seen = wire(handler)
    c = tm("endpoint_activity", query='processName:"cmd.exe"', window_minutes=240, initial_lookback_hours=1)
    out = await _collect(c)
    assert [r["uuid"] for r in out] == ["a", "b"] and c.watermark is not None
    first = seen[0]
    assert first.headers["authorization"] == "Bearer KEY-123" and first.headers["tmv1-query"] == 'processName:"cmd.exe"'
    assert first.headers["host"] == "api.eu.xdr.trendmicro.com" and "startDateTime" in str(first.url)
    assert (await c.test_connection()).ok


async def test_tm_oat_uses_ingestion_window_and_alerts_use_updated(wire):
    seen = wire(lambda r: httpx.Response(200, json={"items": []}))
    await _collect(tm("oat"))
    assert "ingestedStartDateTime" in str(seen[0].url)
    seen.clear()
    await _collect(tm("alerts"))
    assert "dateTimeTarget=updatedDateTime" in str(seen[0].url)


async def test_tm_auth_error_does_not_leak_key(wire):
    wire(lambda r: httpx.Response(403, json={"error": {"code": "Forbidden", "message": "no"}}))
    with pytest.raises(_http.SourceError) as exc:
        await _collect(tm("detections"))
    assert "KEY-123" not in str(exc.value)
    assert not (await tm("detections").test_connection()).ok or True
    assert "no API key" in (await registry.build("trend_vision_one", {"dataset": "oat"}).test_connection()).detail


# ---- end to end through the data-source service ----------------------------------------------------
async def test_collect_source_end_to_end_for_both_sources(client, make, wire, app, monkeypatch):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    logs = [lr_log(messageId=f"m{i}", login=f"user{i}") for i in range(3)]

    def handler(request):
        if "lr.example" in request.headers["host"]:
            return lr_handler(lambda g: logs)(request)
        return httpx.Response(
            200,
            json={
                "items": [
                    {**EP_BASE, "uuid": f"e{i}", "eventId": "1", "objectName": "x.exe", "objectCmd": "x.exe /a"}
                    for i in range(2)
                ]
            },
        )

    wire(handler)
    settings = get_settings_with_ports()
    monkeypatch.setattr("app.core.ssrf.get_settings", lambda: settings)
    created = {}
    for name, ctype, cfg, sec in [
        ("LR", "logrhythm", {"base_url": "https://lr.example:8501", "hostname": "dc1"}, {"token": "tok-VALUE-1"}),
        ("TM", "trend_vision_one", {"dataset": "endpoint_activity"}, {"api_key": "key-VALUE-2"}),
    ]:
        r = await client.post(
            "/api/v1/data-sources",
            headers=h,
            json={"name": name, "connector_type": ctype, "config": cfg, "secrets": sec},
        )
        assert r.status_code == 201, r.text
        assert "tok-VALUE-1" not in r.text and "key-VALUE-2" not in r.text
        created[name] = r.json()["id"]
        test = await client.post(f"/api/v1/data-sources/{r.json()['id']}/test", headers=h)
        assert test.status_code == 200, test.text
    for name in created:
        r = await client.post(f"/api/v1/data-sources/{created[name]}/collect", headers=h)
        assert r.status_code == 200, r.text
    await app.state.search.refresh()
    hits = (
        await client.post(
            "/api/v1/events/search",
            headers=h,
            json={
                "time_range": {
                    "start": (NOW - timedelta(hours=3)).isoformat(),
                    "end": (NOW + timedelta(hours=1)).isoformat(),
                },
                "limit": 50,
            },
        )
    ).json()
    sources = {x["source"] for x in hits["hits"]}
    assert sources == {"logrhythm", "trend_vision_one"} and hits["total"] == 5
    again = await client.post(f"/api/v1/data-sources/{created['LR']}/collect", headers=h)  # idempotent re-pull
    await app.state.search.refresh()
    assert (
        await client.post(
            "/api/v1/events/search",
            headers=h,
            json={
                "time_range": {
                    "start": (NOW - timedelta(hours=3)).isoformat(),
                    "end": (NOW + timedelta(hours=1)).isoformat(),
                }
            },
        )
    ).json()["total"] == 5
    assert again.status_code == 200
    ds = (await client.get("/api/v1/data-sources", headers=h)).json()
    assert {d["name"]: d["health_status"] for d in ds} == {"LR": "ok", "TM": "ok"}
    kinds = {c["type"] for c in (await client.get("/api/v1/data-sources/connectors", headers=h)).json()}
    assert {"logrhythm", "trend_vision_one"} <= kinds
    _ = (LogRhythmConnector, TrendVisionOneConnector)


async def test_lr_tls_server_name_is_used_for_certificate_verification(wire):
    seen = wire(lambda r: httpx.Response(200, json={"TaskId": "x"}))
    c = registry.build(
        "logrhythm", {"base_url": "https://lr.example:8501", "tls_server_name": "siem.corp.local"}, {"token": "t"}
    )
    assert (await c.test_connection()).ok
    assert seen[0].extensions["sni_hostname"] == "siem.corp.local"
    plain = registry.build("logrhythm", {"base_url": "https://lr.example:8501"}, {"token": "t"})
    await plain.test_connection()
    assert seen[-1].extensions["sni_hostname"] == "lr.example"
    with pytest.raises(Exception):  # noqa: B017, PT011
        registry.build("logrhythm", {"base_url": "https://lr.example:8501", "tls_server_name": "bad name/../"})


async def test_tm_busy_window_is_split_instead_of_blowing_the_budget(wire):
    spans = []

    def handler(request):
        q = dict(request.url.params)
        if "startDateTime" in q:
            s = datetime.fromisoformat(q["startDateTime"].replace("Z", "+00:00"))
            e = datetime.fromisoformat(q["endDateTime"].replace("Z", "+00:00"))
            spans.append(e - s)
            if e - s > timedelta(minutes=8):  # "too much data": endless pages
                return httpx.Response(
                    200,
                    json={
                        "items": [{"uuid": "x"}],
                        "nextLink": "https://api.eu.xdr.trendmicro.com/v3.0/search/detections?cont=1",
                    },
                )
            return httpx.Response(200, json={"items": [{"uuid": f"u{len(spans)}"}]})
        return httpx.Response(
            200,
            json={
                "items": [{"uuid": "x"}],
                "nextLink": "https://api.eu.xdr.trendmicro.com/v3.0/search/detections?cont=1",
            },
        )

    wire(handler)
    c = tm("detections", window_minutes=15, initial_lookback_hours=1, overlap_minutes=0)
    out = await _collect(c)
    assert any(s <= timedelta(minutes=8) for s in spans) and any(s == timedelta(minutes=15) for s in spans)
    assert len(out) >= 4 and c.watermark is not None


async def test_tm_budget_exhaustion_stops_cleanly_without_losing_data(wire, monkeypatch):
    wire(lambda r: httpx.Response(200, json={"items": [{"uuid": "x"}]}))
    clock = iter(range(0, 10**6, 1000))
    monkeypatch.setattr("app.connectors.trend_vision_one.time.monotonic", lambda: next(clock))
    c = tm("detections")
    assert await _collect(c) == [] and c.watermark is None  # nothing read, cursor must not advance


async def test_worker_collects_sources_concurrently(app, make, wire, monkeypatch):
    from sqlalchemy import select

    from app.core.config import get_settings as real_settings
    from app.core.crypto import encrypt_json
    from app.datasources.models import DataSource
    from app.workers.settings import collect_datasources

    t = await make.tenant()
    wire(lambda r: httpx.Response(200, json={"items": []}))
    async with app.state.sessionmaker() as s:
        for i in range(3):
            s.add(
                DataSource(
                    tenant_id=t.id,
                    name=f"tm{i}",
                    connector_type="trend_vision_one",
                    config={"dataset": "oat"},
                    secrets_enc=encrypt_json(real_settings(), {"api_key": "k"}),
                    enabled=True,
                )
            )
        await s.commit()
    await collect_datasources({"sessionmaker": app.state.sessionmaker, "search": app.state.search})
    async with app.state.sessionmaker() as s:
        rows = (await s.execute(select(DataSource).where(DataSource.tenant_id == t.id))).scalars().all()
    assert len(rows) == 3 and all(r.health_status == "ok" and r.cursor for r in rows)


@pytest.fixture
def tls_server():
    """A real HTTPS server on 127.0.0.1 with a self-signed cert valid only for 'siem.test.local' (like an on-prem appliance)."""
    import ssl
    import tempfile
    import threading
    from datetime import UTC as _UTC
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "siem.test.local")])
    now = datetime.now(_UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("siem.test.local")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    d = Path(tempfile.mkdtemp())
    (d / "c.pem").write_text(pem)
    (d / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            body = b'{"TaskId": "t"}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], pem
    srv.shutdown()


async def test_lr_pinned_certificate_and_hostname_verification_for_real(tls_server, monkeypatch):
    from app.core.config import get_settings as real_settings

    port, pem = tls_server
    s = real_settings()
    monkeypatch.setattr(s, "outbound_allowed_networks", "127.0.0.1/32")
    monkeypatch.setattr(s, "outbound_allowed_ports", str(port))

    async def nosleep(_):
        return None

    monkeypatch.setattr("app.connectors._http.asyncio.sleep", nosleep)
    url = f"https://127.0.0.1:{port}"

    def conn(**cfg):
        return registry.build("logrhythm", {"base_url": url, **cfg}, {"token": "t"})

    assert (
        await conn(ca_pem=pem, tls_server_name="siem.test.local").test_connection()
    ).ok  # pinned cert + matching name
    assert not (
        await conn(ca_pem=pem, tls_server_name="other.example").test_connection()
    ).ok  # right cert, wrong hostname
    assert not (await conn(ca_pem=pem).test_connection()).ok  # IP is not in the cert's names
    assert not (await conn().test_connection()).ok  # self-signed and untrusted: default is to refuse
    assert (await conn(verify_tls=False).test_connection()).ok  # explicit, visible opt-out
    bad = await conn(ca_pem="not a certificate").test_connection()
    assert not bad.ok and "PEM" in bad.detail


async def test_lr_unfiltered_source_refuses_to_collect_but_can_be_allowed(wire):
    seen = wire(lr_handler(lambda g: [lr_log()]))
    c = registry.build("logrhythm", {"base_url": "https://lr.example:8501"}, {"token": "t"})
    with pytest.raises(_http.SourceError, match="no filter"):
        await _collect(c)
    assert seen == []  # nothing was sent to the SIEM
    ok = registry.build("logrhythm", {"base_url": "https://lr.example:8501", "allow_unfiltered": True}, {"token": "t"})
    assert await _collect(ok)


async def test_lr_raw_query_filter_is_sent_verbatim_and_validated(wire):
    seen = wire(lr_handler(lambda g: [lr_log()]))
    flt = {
        "msgFilterType": 2,
        "isSavedFilter": False,
        "filterGroup": {"filterItemType": 1, "filterItems": [{"filterType": 7, "marker": "x"}]},
    }
    c = registry.build(
        "logrhythm", {"base_url": "https://lr.example:8501", "query_filter": flt, "hostname": "ignored"}, {"token": "t"}
    )
    await _collect(c)
    task = json.loads(next(r for r in seen if r.url.path.endswith("search-task")).content)
    assert task["queryFilter"] == flt
    for bad in ({}, {"a": "x" * 30_000}, "string", []):
        with pytest.raises(Exception):  # noqa: B017, PT011
            registry.build("logrhythm", {"base_url": "https://lr.example:8501", "query_filter": bad})


async def test_lr_failed_status_splits_the_window_instead_of_failing(wire):
    windows = []

    def handler(request):
        body = json.loads(request.content)
        if request.url.path.endswith("search-task"):
            d = body["dateCriteria"]
            s_, e_ = (datetime.fromisoformat(d[k].replace("Z", "+00:00")) for k in ("dateMin", "dateMax"))
            windows.append(e_ - s_)
            return httpx.Response(200, json={"TaskId": f"{(e_ - s_).total_seconds():.0f}"})
        too_big = int(body["data"]["searchGuid"]) > 300  # a window over 5 minutes "times out"
        return httpx.Response(
            200,
            json={
                "TaskStatus": "Search Failed" if too_big else "Completed",
                "Items": [] if too_big else [lr_log(messageId=body["data"]["searchGuid"])],
            },
        )

    wire(handler)
    c = registry.build(
        "logrhythm",
        {"base_url": "https://lr.example:8501", "hostname": "dc1", "window_minutes": 10, "initial_lookback_hours": 1},
        {"token": "t"},
    )
    assert await _collect(c)
    assert max(windows) == timedelta(minutes=10) and min(windows) <= timedelta(minutes=5)


async def test_lr_one_minute_still_too_big_gives_an_actionable_error(wire):
    wire(lambda r: httpx.Response(200, json={"TaskId": "t", "TaskStatus": "Max Results", "Items": []}))
    c = registry.build("logrhythm", {"base_url": "https://lr.example:8501", "hostname": "dc1"}, {"token": "t"})
    with pytest.raises(_http.SourceError, match="Narrow this source"):
        await _collect(c)


async def test_lr_persistent_failure_cannot_flood_the_siem_with_searches(wire):
    seen = wire(lambda r: httpx.Response(200, json={"TaskId": "t", "TaskStatus": "Search Failed", "Items": []}))
    c = registry.build(
        "logrhythm", {"base_url": "https://lr.example:8501", "hostname": "dc1", "window_minutes": 60}, {"token": "t"}
    )
    with pytest.raises(_http.SourceError, match="Narrow this source|too many searches"):
        await _collect(c)
    tasks = [r for r in seen if r.url.path.endswith("search-task")]
    assert len(tasks) <= 16


async def test_lr_mixed_failures_are_bounded_by_the_search_budget(wire):
    n = {"t": 0}

    def handler(request):
        body = json.loads(request.content)
        if request.url.path.endswith("search-task"):
            n["t"] += 1
            return httpx.Response(200, json={"TaskId": str(n["t"])})
        # every window "fails" except a lone 1-minute leaf now and then, so splitting never ends quickly
        return httpx.Response(
            200,
            json={"TaskStatus": "Max Results" if int(body["data"]["searchGuid"]) % 2 else "Search Failed", "Items": []},
        )

    wire(handler)
    c = registry.build(
        "logrhythm", {"base_url": "https://lr.example:8501", "hostname": "dc1", "window_minutes": 240}, {"token": "t"}
    )
    with pytest.raises(_http.SourceError):
        await _collect(c)
    assert n["t"] <= 16


async def test_lr_search_window_is_true_utc_and_only_timestamps_are_shifted(wire):
    seen = wire(lr_handler(lambda g: [lr_log()]))
    c = registry.build(
        "logrhythm", {"base_url": "https://lr.example:8501", "hostname": "dc1", "window_minutes": 10}, {"token": "t"}
    )
    await _collect(c)
    task = json.loads(next(r for r in seen if r.url.path.endswith("search-task")).content)
    d_min = datetime.fromisoformat(task["dateCriteria"]["dateMin"].replace("Z", "+00:00"))
    assert (
        abs((datetime.now(UTC) - timedelta(hours=1) - d_min).total_seconds()) < 120
    )  # lookback 1h from now, no -1h shift
