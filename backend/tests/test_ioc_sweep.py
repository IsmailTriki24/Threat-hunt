# ruff: noqa: E501
"""The continuous indicator sweep: only logs that contain a validated indicator are kept, progress is exact (cursor, queue, errors), hits land in
the indicator's case, and the optional high-value-only collection filter."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select, update

from app.auth.rbac import Role
from app.connectors import _http
from app.connectors.logrhythm import LogRhythmConnector
from app.core.config import get_settings
from app.datasources.models import DataSource
from app.iochunt import runner, sweep
from app.iochunt.models import Ioc, IocHunt, IocMatch, IocSweep
from tests import fake_console
from tests.test_logrhythm_ioc import FT_URL, lr_log, make_siem

API = "/api/v1/ioc"
NOW = datetime.now(UTC).replace(microsecond=0)
C2 = "198.51.100.101"


async def _resolve(host, port):
    return ["93.184.216.34"]


@pytest.fixture
def wire(monkeypatch):
    def install(handler):
        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(handler))
        monkeypatch.setattr(_http, "RESOLVER", _resolve)
        fake_console.install(monkeypatch, handler)

    async def nosleep(_):
        return None

    monkeypatch.setattr("app.connectors._http.asyncio.sleep", nosleep)
    monkeypatch.setattr("app.connectors.logrhythm_console._sleep", nosleep)
    return install


def empty_siem(request):
    if request.url.path.endswith("search-task"):
        return httpx.Response(200, json={"TaskId": "t"})
    return httpx.Response(200, json={"TaskStatus": "Completed", "Items": []})


def _config(config, connector, siem, fast=False):
    cfg = dict(config or ({"base_url": "https://lr.example", "hostname": "dc1"} if connector == "logrhythm" else {}))
    if connector == "logrhythm" and not siem:
        cfg.setdefault("siem_behaviours", False)  # built-in behaviours have their own tests
    if not fast:
        cfg.setdefault("sweep_hot_size", 0)  # the fast lane has its own tests
        cfg.setdefault("sweep_hot_ioas", 0)
    return cfg


async def _setup(
    client, make, app, wire, values, *, config=None, connector="logrhythm", secrets=None, siem=False, fast=False
):
    """A tenant with a SIEM source and validated, already-hunted (so they own a case) indicators."""
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    wire(empty_siem)
    r = await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "siem",
            "connector_type": connector,
            "config": _config(config, connector, siem, fast),
            "secrets": secrets or {"token": "T"},
            "enabled": False,
        },
    )
    assert r.status_code == 201, r.text
    ids = []
    for v in values:
        ids.append((await client.post(f"{API}/iocs", headers=h, json={"type": "ip", "value": v})).json()["id"])
    assert (await client.post(f"{API}/iocs/validate", headers=h, json={"ioc_ids": ids})).status_code == 201
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())
    async with app.state.sessionmaker() as db:
        ds = (await db.execute(select(DataSource).where(DataSource.tenant_id == t.id))).scalars().one()
        db.add(IocSweep(tenant_id=t.id, data_source_id=ds.id, cursor=NOW - timedelta(minutes=20), queue=[], members=[]))
        await db.commit()
    return t, h, ds


async def _tick(app, ds, now=NOW):
    async with app.state.sessionmaker() as db:
        fresh = await db.get(DataSource, ds.id)
        out = await sweep.sweep_source(db, app.state.search, get_settings(), fresh, now=now)
    return out


async def _state(app, ds):
    async with app.state.sessionmaker() as db:
        return (await db.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id))).scalar_one()


async def _case_of(client, h, t, app):
    async with app.state.sessionmaker() as db:
        case_id = (await db.execute(select(Ioc.case_id).where(Ioc.tenant_id == t.id))).scalars().first()
    return (await client.get(f"/api/v1/cases/{case_id}", headers=h)).json(), case_id


async def test_a_sweep_keeps_only_logs_that_contain_an_indicator_and_files_them_in_the_case(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    case, case_id = await _case_of(client, h, t, app)
    assert case["status"] == "CLOSED"  # hunted before: nothing was found
    handler, seen = make_siem(
        [
            lr_log(
                1, originIp=C2, impactedHost="srv9.corp.example"
            ),  # another host than the DC: the whole SIEM is searched
            lr_log(2, originIp="198.51.100.250"),
        ]
    )
    wire(handler)
    out = await _tick(app, ds)
    assert out["hits"] == 1 and out["error"] == "" and out["pending"] == 0
    assert "hostname" not in str(seen[0])  # not limited to the DC
    st = await _state(app, ds)
    assert st.status == "ok" and st.window_end is None and st.queue == [] and st.cursor > NOW - timedelta(minutes=10)
    case = (await client.get(f"/api/v1/cases/{case_id}", headers=h)).json()
    assert (
        case["status"] == "INVESTIGATING" and case["evidence_count"] == 1
    )  # reopened, the one matching log is evidence
    got = (
        await client.post(
            "/api/v1/events/search",
            headers=h,
            json={
                "text": "host.hostname:srv9.corp.example",
                "time_range": {
                    "start": (NOW - timedelta(days=1)).isoformat(),
                    "end": (NOW + timedelta(hours=3)).isoformat(),
                },
            },
        )
    ).json()
    other = (
        await client.post(
            "/api/v1/events/search",
            headers=h,
            json={
                "text": "network.src_ip:198.51.100.250",
                "time_range": {
                    "start": (NOW - timedelta(days=1)).isoformat(),
                    "end": (NOW + timedelta(hours=3)).isoformat(),
                },
            },
        )
    ).json()
    assert got["total"] == 1 and other["total"] == 0  # the unrelated log was never stored
    acts = (await client.get(f"/api/v1/cases/{case_id}/activity", headers=h)).json()
    assert any("Indicator sweep" in (a.get("message") or a.get("body") or str(a)) for a in acts)
    async with app.state.sessionmaker() as db:
        full = await db.scalar(
            select(func.count()).select_from(IocHunt).where(IocHunt.tenant_id == t.id, IocHunt.mode == "rehunt")
        )
        ioc_hunted = await db.scalar(select(Ioc.last_hunted_at).where(Ioc.tenant_id == t.id))
    assert full == 1
    # a sweep is not a full re-hunt: the indicator stays due for the 6-hourly one
    async with app.state.sessionmaker() as db:
        await db.execute(update(Ioc).where(Ioc.tenant_id == t.id).values(last_hunted_at=NOW - timedelta(hours=7)))
        await db.commit()
    await _tick(app, ds, NOW + timedelta(minutes=5))
    async with app.state.sessionmaker() as db:
        assert await db.scalar(select(Ioc.last_hunted_at).where(Ioc.tenant_id == t.id)) == NOW - timedelta(hours=7)
    assert ioc_hunted is not None


async def test_the_same_log_is_never_reported_twice_and_a_quiet_tick_stores_nothing(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    handler, _ = make_siem([lr_log(1, originIp=C2)])
    wire(handler)
    await _tick(app, ds)
    await _tick(app, ds, NOW + timedelta(minutes=5))  # the overlap returns the same log again
    async with app.state.sessionmaker() as db:
        matches = await db.scalar(select(func.count()).select_from(IocMatch).where(IocMatch.tenant_id == t.id))
        sweeps = await db.scalar(
            select(func.count())
            .select_from(IocHunt)
            .where(IocHunt.tenant_id == t.id, IocHunt.signals["sweep"].as_boolean())
        )
    assert matches == 1 and sweeps == 1  # no second record for a known event
    wire(empty_siem)
    out = await _tick(app, ds, NOW + timedelta(minutes=10))
    assert out["hits"] == 0
    async with app.state.sessionmaker() as db:
        assert await db.scalar(select(func.count()).select_from(IocMatch).where(IocMatch.tenant_id == t.id)) == 1


async def test_a_siem_error_never_moves_the_cursor_and_the_next_tick_resumes(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    before = (await _state(app, ds)).cursor
    wire(lambda request: httpx.Response(500, json={"error": "down"}))
    out = await _tick(app, ds)
    st = await _state(app, ds)
    assert (
        out["error"]
        and st.status == "error"
        and st.cursor == before
        and st.window_end is not None
        and len(st.queue) == 1
    )
    assert st.lock_until is None
    wire(empty_siem)
    out = await _tick(app, ds, NOW + timedelta(minutes=1))
    st = await _state(app, ds)
    assert out["error"] == "" and st.status == "ok" and st.cursor > before and st.queue == []


async def test_indicators_are_worked_through_in_chunks_before_the_window_closes(client, make, app, wire):
    values = [f"198.51.100.{i}" for i in range(110, 115)]
    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        values,
        config={"base_url": "https://lr.example", "hostname": "dc1", "ioc_search_max": 2},
    )
    handler, seen = make_siem([])
    wire(handler)
    out = await _tick(app, ds)
    assert out["pending"] == 0 and len(seen) >= 3  # 5 indicators, 2 per search
    sent = {v["value"] for f in seen for it in f["filterGroup"]["filterItems"][0]["filterItems"] for v in it["values"]}
    assert set(values) <= sent
    assert (await _state(app, ds)).cursor > NOW - timedelta(minutes=10)


async def test_an_indicator_validated_mid_window_is_searched_over_the_same_window(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    # a window is in flight and fully searched, but the second indicator joined after it was built
    late = (await client.post(f"{API}/iocs", headers=h, json={"type": "ip", "value": "198.51.100.77"})).json()["id"]
    await client.post(f"{API}/iocs/validate", headers=h, json={"ioc_ids": [late]})
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())
    async with app.state.sessionmaker() as db:
        first = str((await db.execute(select(Ioc.id).where(Ioc.tenant_id == t.id, Ioc.value == C2))).scalar_one())
        st = (await db.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id))).scalar_one()
        st.window_end, st.queue, st.members = NOW - timedelta(minutes=10), [], [first]
        await db.commit()
    handler, seen = make_siem([lr_log(1, originIp="198.51.100.77")])
    wire(handler)
    out = await _tick(app, ds)
    first_search = {v["value"] for it in seen[0]["filterGroup"]["filterItems"][0]["filterItems"] for v in it["values"]}
    assert (
        first_search == {"198.51.100.77"} and out["hits"] == 1
    )  # the late joiner alone, over the window already in flight


async def test_a_source_with_the_sweep_switched_off_is_not_searched(client, make, app, wire):
    t, h, ds = await _setup(
        client, make, app, wire, [C2], config={"base_url": "https://lr.example", "hostname": "dc1", "ioc_sweep": False}
    )
    handler, seen = make_siem([lr_log(1, originIp=C2)])
    wire(handler)
    assert await _tick(app, ds) is None and not seen
    assert (await _state(app, ds)).status == "off"


async def test_trend_search_datasets_are_swept_even_when_not_ingested(client, make, app, wire):
    def handler(request):
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "uuid": "u-1",
                        "eventId": "3",
                        "eventSubId": 204,
                        "eventTimeDT": (NOW - timedelta(minutes=8)).isoformat(),
                        "endpointHostName": "WS-77",
                        "endpointIp": ["10.7.7.7"],
                        "src": "10.7.7.7",
                        "dst": C2,
                        "spt": 5000,
                        "dpt": 443,
                        "proto": "6",
                        "processName": "evil.exe",
                    },
                    {
                        "uuid": "u-2",
                        "eventId": "3",
                        "eventSubId": 204,
                        "eventTimeDT": NOW.isoformat(),
                        "src": "10.7.7.7",
                        "dst": "192.0.2.1",
                    },
                ],
                "progressRate": 100,
            },
        )

    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        [C2],
        config={"dataset": "endpoint_activity"},
        connector="trend_vision_one",
        secrets={"api_key": "K"},
    )
    wire(handler)
    out = await _tick(app, ds)
    assert out["hits"] == 1 and out["error"] == ""
    assert (await _state(app, ds)).status == "ok"
    case, _ = await _case_of(client, h, t, app)
    assert case["status"] == "INVESTIGATING" and case["evidence_count"] == 1


async def test_datasets_without_a_query_surface_are_not_swept(client, make, app, wire):
    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        [C2],
        config={"dataset": "alerts"},
        connector="trend_vision_one",
        secrets={"api_key": "K"},
    )
    assert await _tick(app, ds) is None


async def test_two_workers_never_sweep_the_same_source_at_once(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    async with app.state.sessionmaker() as db:
        await db.execute(
            update(IocSweep).where(IocSweep.data_source_id == ds.id).values(lock_until=NOW + timedelta(minutes=5))
        )
        await db.commit()
    handler, seen = make_siem([])
    wire(handler)
    assert await _tick(app, ds) is None and not seen


# ---- high-value-only collection ----------------------------------------------------------------------
async def test_collection_can_keep_only_listed_vendor_message_ids():
    conn = LogRhythmConnector.__new__(LogRhythmConnector)
    from app.connectors.logrhythm import LogRhythmConfig

    conn.config = LogRhythmConfig(
        base_url="https://lr.example", hostname="dc1", collect_vendor_message_ids=["4624", "4768"]
    )
    conn.secrets, conn.watermark, conn._filter_override = {"token": "T"}, None, None

    async def fake(start, end, budget=None):
        return [
            {"messageId": "a", "logDate": 1, "vendorMessageId": "4624"},
            {"messageId": "b", "logDate": 2, "vendorMessageId": "5156"},
            {"messageId": "c", "logDate": 3, "vendorMessageId": "4768"},
        ]

    conn._search_window = fake  # type: ignore[method-assign]
    kept = [r async for r in conn.collect(since=NOW - timedelta(minutes=30), limit=100)]
    assert {r["messageId"] for r in kept} == {"a", "c"}
    assert json.dumps(conn.watermark.isoformat())  # the watermark still advanced over the dropped logs


# ---- status on the data sources API ----------------------------------------------------------------------
async def test_the_data_source_api_reports_the_sweep_status(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    wire(make_siem([lr_log(1, originIp=C2)])[0])
    await _tick(app, ds)
    rows = (await client.get("/api/v1/data-sources", headers=h)).json()
    sw = rows[0]["sweep"]
    assert (
        sw["status"] == "ok"
        and sw["iocs_total"] == 1
        and sw["pending"] == 0
        and sw["hits_total"] == 1
        and sw["cursor"]
        and sw["last_ok_at"]
    )
    one = (await client.get(f"/api/v1/data-sources/{ds.id}", headers=h)).json()
    assert one["sweep"]["status"] == "ok"
    # a source not swept yet says so; a push source and a dataset with no query surface have no sweep at all
    await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "fresh",
            "connector_type": "logrhythm",
            "config": {"base_url": "https://lr.example", "hostname": "dc2"},
            "secrets": {"token": "T"},
            "enabled": False,
        },
    )
    await client.post(
        "/api/v1/data-sources", headers=h, json={"name": "push", "connector_type": "sysmon", "config": {}}
    )
    await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "alerts",
            "connector_type": "trend_vision_one",
            "config": {"dataset": "alerts"},
            "secrets": {"api_key": "K"},
            "enabled": False,
        },
    )
    by = {r["name"]: r for r in (await client.get("/api/v1/data-sources", headers=h)).json()}
    assert by["fresh"]["sweep"]["status"] == "pending" and by["push"]["sweep"] is None and by["alerts"]["sweep"] is None


# ---- behaviours (IOAs) --------------------------------------------------------------------------------
from app.connectors.logrhythm import (  # noqa: E402
    FT_COMMAND,
    FT_LOGIN,
    FT_PROCESS,
    FT_SIP,
    FT_VENDOR_MSG_ID,
    _normalize,
    ioa_searches,
)
from app.events.search.query import Condition  # noqa: E402
from app.iochunt.ioa_catalog import ALL, F, cmd_has, name_in  # noqa: E402
from app.iochunt.models import SignalMatch, Threat, ThreatIoa  # noqa: E402

PS_ENC = ALL(name_in("powershell.exe"), cmd_has("enc", "encodedcommand"))


def _items(flt):
    return flt["filterGroup"]["filterItems"][0]["filterItems"]


def test_a_behaviour_compiles_to_anded_verified_logrhythm_searches():
    searches, unsearchable = ioa_searches(Condition.model_validate(PS_ENC))
    assert unsearchable == 0 and len(searches) == 2  # one search per alternative of the command-line list
    for flt in searches:
        assert flt["filterGroup"]["filterItems"][0]["fieldOperator"] == 1  # And: the items narrow each other
        its = _items(flt)
        assert {i["filterType"] for i in its} == {FT_PROCESS, FT_COMMAND}
        proc = next(i for i in its if i["filterType"] == FT_PROCESS)["values"][0]["value"]
        assert proc == {"matchType": 1, "value": "%powershell.exe"}  # suffix: LogRhythm may hold the full path
    cmds = {
        next(i for i in _items(f) if i["filterType"] == FT_COMMAND)["values"][0]["value"]["value"] for f in searches
    }
    assert cmds == {"%enc%", "%encodedcommand%"}


def test_conditions_logrhythm_cannot_express_are_dropped_from_the_search_and_reported():
    # parent process, ports and negations are not verified filters: only the process name narrows the search; the rest is checked locally
    cond = Condition.model_validate(
        ALL(
            name_in("cmd.exe"),
            F("process.parent.name", "in", ["winword.exe"]),
            {"not": F("user.name", "eq", "svc")},
        )
    )
    searches, unsearchable = ioa_searches(cond)
    assert len(searches) == 1 and unsearchable == 0 and {i["filterType"] for i in _items(searches[0])} == {FT_PROCESS}
    # nothing expressible at all: not searchable, and it says so rather than searching everything
    none = ioa_searches(Condition.model_validate(F("process.parent.name", "in", ["winword.exe"])))
    assert none == ([], 1)
    # ips, users and event ids that ARE verified become filters
    ips = ioa_searches(
        Condition.model_validate(ALL(F("network.src_ip", "in", ["203.0.113.5"]), F("user.name", "eq", "bob")))
    )[0]
    assert {i["filterType"] for i in _items(ips[0])} == {FT_SIP, FT_LOGIN}
    assert FT_VENDOR_MSG_ID == 37


def test_logrhythm_logs_carry_the_command_line_and_parent_for_the_local_check():
    raw = {
        "logDate": 1760000000000,
        "messageId": "m1",
        "process": "C:\\Windows\\System32\\PowerShell.exe",
        "command": "powershell -enc AAAA",
        "parentProcessName": "WINWORD.EXE",
        "classificationName": "Other",
    }
    ev = _normalize(raw, 0)[0]
    assert (
        ev.process.name == "PowerShell.exe"
        and ev.process.command_line == "powershell -enc AAAA"
        and ev.process.parent.name == "WINWORD.EXE"
    )


async def _threat_with_ioa(app, t, case_id, condition, **kw):
    async with app.state.sessionmaker() as db:
        th = Threat(
            tenant_id=t.id,
            key=f"k{uuid.uuid4().hex[:6]}",
            name="Test threat",
            kind="malware",
            status="VALIDATED",
            case_id=case_id,
        )
        db.add(th)
        await db.flush()
        ioa = ThreatIoa(
            tenant_id=t.id,
            threat_id=th.id,
            name="PowerShell encoded command",
            technique_id="T1059.001",
            condition=condition,
            severity="HIGH",
            source="manual",
            **kw,
        )
        db.add(ioa)
        await db.commit()
        return th, ioa


async def test_a_logrhythm_sweep_finds_a_behaviour_anywhere_and_rejects_logs_the_loose_search_returned(
    client, make, app, wire
):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    _, case_id = await _case_of(client, h, t, app)
    await _threat_with_ioa(app, t, case_id, PS_ENC)
    logs = [
        lr_log(
            1,
            process="C:\\Windows\\System32\\PowerShell.exe",
            command="powershell.exe -enc AAAA",
            impactedHost="ws-77.corp.example",
        ),
        lr_log(
            2,
            process="powershell.exe",
            command="powershell.exe -nop -file backup.ps1",
            impactedHost="ws-78.corp.example",
        ),  # same process, not the behaviour
    ]
    handler, seen = make_siem(logs)
    wire(handler)
    out = await _tick(app, ds)
    assert out["error"] == "" and out["pending"] == 0 and out["hits"] == 1
    assert any(
        FT_PROCESS in {i["filterType"] for i in _items(f)} and FT_COMMAND in {i["filterType"] for i in _items(f)}
        for f in seen
    )
    async with app.state.sessionmaker() as db:
        sig = (await db.execute(select(SignalMatch).where(SignalMatch.tenant_id == t.id))).scalars().all()
    assert (
        len(sig) == 1 and sig[0].kind == "ioa" and sig[0].host == "ws-77.corp.example"
    )  # the decoy was rejected by the local check
    case = (await client.get(f"/api/v1/cases/{case_id}", headers=h)).json()
    assert (
        case["status"] == "INVESTIGATING" and case["evidence_count"] == 1
    )  # a lone behaviour is a lead (MEDIUM), not a verdict
    acts = (await client.get(f"/api/v1/cases/{case_id}/activity", headers=h)).json()
    assert any("PowerShell encoded command" in str(a) for a in acts)
    st = (await client.get("/api/v1/data-sources", headers=h)).json()[0]["sweep"]
    assert st["ioas_total"] == 1 and st["iocs_total"] == 1
    # an event already reported is not reported again
    out2 = await _tick(app, ds, NOW + timedelta(minutes=5))
    async with app.state.sessionmaker() as db:
        assert len((await db.execute(select(SignalMatch).where(SignalMatch.tenant_id == t.id))).scalars().all()) == 1
    assert out2["error"] == ""


async def test_a_behaviour_logrhythm_cannot_search_is_not_queued(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    _, case_id = await _case_of(client, h, t, app)
    await _threat_with_ioa(app, t, case_id, F("process.parent.name", "in", ["winword.exe"]))
    handler, seen = make_siem([])
    wire(handler)
    await _tick(app, ds)
    assert (await _state(app, ds)).ioas_total == 0


async def test_trend_behaviours_are_swept_with_their_vendor_query_and_verified(client, make, app, wire):
    sent = []

    def handler(request):
        sent.append(request.headers.get("tmv1-query", ""))
        base = {
            "eventId": "1",
            "eventSubId": 101,
            "eventTimeDT": (NOW - timedelta(minutes=8)).isoformat(),
            "endpointHostName": "WS-77",
            "endpointIp": ["10.7.7.7"],
        }
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        **base,
                        "uuid": "p1",
                        "objectName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "objectCmd": "powershell.exe -enc AAAA",
                        "processName": "C:\\x\\winword.exe",
                    },
                    {
                        **base,
                        "uuid": "p2",
                        "objectName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "objectCmd": "powershell.exe -nop",
                        "processName": "C:\\x\\explorer.exe",
                    },
                ],
                "progressRate": 100,
            },
        )

    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        [C2],
        config={"dataset": "endpoint_activity"},
        connector="trend_vision_one",
        secrets={"api_key": "K"},
    )
    _, case_id = await _case_of(client, h, t, app)
    await _threat_with_ioa(
        app, t, case_id, PS_ENC, trend_query='eventId:1 AND objectName:"*\\powershell.exe" AND objectCmd:"*enc*"'
    )
    wire(handler)
    out = await _tick(app, ds)
    assert out["error"] == "" and out["hits"] == 1 and any("objectCmd" in q and "powershell" in q for q in sent)
    async with app.state.sessionmaker() as db:
        sig = (await db.execute(select(SignalMatch).where(SignalMatch.tenant_id == t.id))).scalars().all()
    assert len(sig) == 1 and sig[0].host == "WS-77"
    assert (await _state(app, ds)).ioas_total == 1


async def test_a_restarted_worker_frees_the_sweep_locks_a_dead_one_left(client, make, app, wire):
    t, h, ds = await _setup(client, make, app, wire, [C2])
    async with app.state.sessionmaker() as db:
        await db.execute(
            update(IocSweep).where(IocSweep.data_source_id == ds.id).values(lock_until=NOW + timedelta(minutes=9))
        )
        await db.commit()
    assert await _tick(app, ds) is None  # locked
    assert await sweep.release_locks(app.state.sessionmaker) >= 1
    wire(empty_siem)
    assert await _tick(app, ds) is not None


# ---- the fast lane --------------------------------------------------------------------------------------
from app.iochunt.sweep import hot_score  # noqa: E402


def _ioc(**kw):
    from app.iochunt.models import Ioc as _I

    return _I(
        type=kw.pop("type", "ip"),
        value="203.0.113.5",
        source=kw.pop("source", "abuse.ch ThreatFox"),
        confidence=kw.pop("confidence", 99),
        seen_count=kw.pop("seen_count", 0),
        threat_type=kw.pop("threat_type", ""),
        first_seen=NOW,
        last_seen=kw.pop("last_seen", NOW),
    )


def test_hotness_ranks_seen_then_own_intel_then_live_infrastructure_then_freshness_and_ignores_confidence():
    old = NOW - timedelta(days=9)
    seen = hot_score(_ioc(seen_count=1, last_seen=old, threat_type="payload"), NOW)
    own = hot_score(_ioc(source="manual", last_seen=old), NOW)
    c2_fresh = hot_score(_ioc(threat_type="botnet_cc"), NOW)
    c2_old = hot_score(_ioc(threat_type="botnet_cc", last_seen=old), NOW)
    payload_fresh = hot_score(_ioc(threat_type="payload_delivery"), NOW)
    stale_hash = hot_score(_ioc(type="sha256", threat_type="payload", last_seen=old), NOW)
    assert seen > own > c2_fresh > c2_old > payload_fresh > stale_hash
    assert hot_score(_ioc(confidence=100, last_seen=old), NOW) == hot_score(
        _ioc(confidence=10, last_seen=old), NOW
    )  # saturated feed confidence says nothing
    assert (
        c2_old >= 300 > payload_fresh
    )  # only seen / own-intel / live-infrastructure indicators qualify for the fast lane


async def test_the_fast_lane_searches_only_the_hottest_indicators_and_stays_close_to_real_time(client, make, app, wire):
    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"],
        fast=True,
        config={"base_url": "https://lr.example", "hostname": "dc1", "sweep_hot_size": 2, "sweep_hot_ioas": 0},
    )
    async with app.state.sessionmaker() as db:
        rows = (await db.execute(select(Ioc).where(Ioc.tenant_id == t.id).order_by(Ioc.value))).scalars().all()
        for r, (role, age) in zip(
            rows, (("botnet_cc", 0), ("botnet_cc", 5), ("payload", 0), ("payload", 9)), strict=True
        ):
            r.threat_type, r.last_seen = role, NOW - timedelta(days=age)
        db.add(
            IocSweep(
                tenant_id=t.id,
                data_source_id=ds.id,
                lane="fast",
                cursor=NOW - timedelta(minutes=20),
                queue=[],
                members=[],
            )
        )
        full = (
            await db.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id, IocSweep.lane == "full"))
        ).scalar_one()
        full.cursor = NOW - timedelta(hours=30)  # the full lane is far behind
        await db.commit()
    handler, seen = make_siem([lr_log(1, originIp="198.51.100.10", impactedHost="srv9.corp.example")])
    wire(handler)
    out = await _tick(app, ds)
    assert out["error"] == "" and out["hits"] == 1  # found once even though both lanes search it
    first = {v["value"] for it in seen[0]["filterGroup"]["filterItems"][0]["filterItems"] for v in it["values"]}
    assert first == {"198.51.100.10", "198.51.100.11"}  # the two hottest (live C2, freshest first), nothing else
    async with app.state.sessionmaker() as db:
        fast = (
            await db.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id, IocSweep.lane == "fast"))
        ).scalar_one()
        full = (
            await db.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id, IocSweep.lane == "full"))
        ).scalar_one()
    assert fast.status == "ok" and fast.cursor > NOW - timedelta(minutes=10) and fast.iocs_total == 2
    assert full.cursor <= NOW - timedelta(
        hours=24
    )  # the full lane is still working through its backlog, the fast lane is not held back by it
    sent = {v["value"] for f in seen for it in f["filterGroup"]["filterItems"][0]["filterItems"] for v in it["values"]}
    assert {"198.51.100.12", "198.51.100.13"} <= sent  # the full lane still covers the cold ones
    case, _ = await _case_of(client, h, t, app)
    assert case["status"] == "INVESTIGATING" and case["evidence_count"] == 1
    sw = (await client.get("/api/v1/data-sources", headers=h)).json()[0]["sweep"]
    assert sw["fast"]["status"] == "ok" and sw["fast"]["iocs_total"] == 2 and sw["iocs_total"] == 4


async def test_a_failing_fast_lane_does_not_stop_the_full_lane_and_the_fast_lane_can_be_switched_off(
    client, make, app, wire
):
    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        ["198.51.100.10"],
        fast=True,
        config={"base_url": "https://lr.example", "hostname": "dc1", "sweep_hot_size": 5, "sweep_hot_ioas": 0},
    )
    async with app.state.sessionmaker() as db:
        await db.execute(update(Ioc).where(Ioc.tenant_id == t.id).values(threat_type="botnet_cc"))
        db.add(
            IocSweep(
                tenant_id=t.id,
                data_source_id=ds.id,
                lane="fast",
                cursor=NOW - timedelta(minutes=20),
                queue=[],
                members=[],
            )
        )
        await db.commit()
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(500, json={}) if len(calls) <= 6 else empty_siem(request)  # outlasts the client's retries

    wire(handler)
    out = await _tick(app, ds)
    assert out["error"]  # the fast lane failed ...
    async with app.state.sessionmaker() as db:
        lanes = {
            r.lane: r for r in (await db.execute(select(IocSweep).where(IocSweep.data_source_id == ds.id))).scalars()
        }
    assert lanes["fast"].status == "error" and lanes["full"].status in (
        "ok",
        "partial",
        "error",
    )  # ... and the full lane ran on its own
    assert "full" in lanes
    # switching it off: no fast lane in the status any more
    t2, h2, ds2 = await _setup(client, make, app, wire, ["198.51.100.10"])
    assert (await client.get("/api/v1/data-sources", headers=h2)).json()[0]["sweep"]["fast"] is None


async def test_exact_url_searches_are_budgeted_per_tick_not_repeated_for_every_chunk(client, make, app, wire):
    urls = [f"http://host{i}.evil.example/payload{i}.bin" for i in range(12)]
    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        [C2],
        config={"base_url": "https://lr.example", "hostname": "dc1", "ioc_search_max": 4, "sweep_url_patterns": 3},
    )
    async with app.state.sessionmaker() as db:
        from app.iochunt.models import Ioc as _I

        case_id = (await db.execute(select(_I.case_id).where(_I.tenant_id == t.id))).scalars().first()
        for u in urls:
            db.add(
                _I(
                    tenant_id=t.id,
                    type="url",
                    value=u,
                    source="t",
                    confidence=90,
                    first_seen=NOW,
                    last_seen=NOW,
                    status="VALIDATED",
                    case_id=case_id,
                )
            )
        await db.commit()
    handler, seen = make_siem([])
    wire(handler)
    out = await _tick(app, ds)
    assert out["error"] == "" and out["pending"] == 0
    url_searches = [
        f for f in seen if any(i["filterType"] == FT_URL for i in f["filterGroup"]["filterItems"][0]["filterItems"])
    ]
    assert len(url_searches) == 3  # the whole tick spends 3, however many chunks the 12 URLs were split into
    assert len(seen) > 4  # (the host searches still covered every URL)
