# ruff: noqa: E501, F811
"""The live SIEM search page: queries go to LogRhythm / Trend, every result is re-checked locally, and nothing is stored until an event is opened."""

import json
from datetime import UTC, datetime, timedelta

import httpx

from app.auth.rbac import Role
from app.connectors.logrhythm import FT_LOGIN, FT_PROCESS
from app.events import siem_query as sq
from app.events.search.query import Filter
from tests.test_ioc_sweep import empty_siem, wire  # noqa: F401, F811
from tests.test_logrhythm_ioc import lr_log, make_siem

API = "/api/v1/events"
NOW = datetime.now(UTC).replace(microsecond=0)
RANGE = {"start": (NOW - timedelta(hours=1)).isoformat(), "end": (NOW + timedelta(minutes=5)).isoformat()}
STORED = {"start": (NOW - timedelta(days=1)).isoformat(), "end": (NOW + timedelta(hours=3)).isoformat()}


async def _env(client, make, app, wire, *, handler=None, trend=None, lr=True):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SUPER_ADMIN)
    wire(handler or empty_siem)
    if lr:
        r = await client.post(
            f"{API.replace('/events', '')}/data-sources",
            headers=h,
            json={
                "name": "LogRhythm SIEM",
                "connector_type": "logrhythm",
                "config": {"base_url": "https://lr.example", "hostname": "dc1"},
                "secrets": {"token": "T"},
                "enabled": False,
            },
        )
        assert r.status_code == 201, r.text
    if trend:
        r = await client.post(
            "/api/v1/data-sources",
            headers=h,
            json={
                "name": f"Trend {trend}",
                "connector_type": "trend_vision_one",
                "config": {"dataset": trend},
                "secrets": {"api_key": "K"},
                "enabled": False,
            },
        )
        assert r.status_code == 201, r.text
    return t, h


async def _q(client, h, **body):
    r = await client.post(f"{API}/siem-query", headers=h, json={"time_range": RANGE, **body})
    assert r.status_code == 200, r.text
    return r.json()


async def _stored(client, h, text):
    return (await client.post(f"{API}/search", headers=h, json={"q": text, "time_range": STORED})).json()["total"]


# ---- parsing and local verification ----------------------------------------------------------------------
def test_free_text_understands_phrases_negation_and_alternatives():
    alts = sq.parse_text('powershell -chrome "encoded command" OR cmd.exe NOT calc')
    assert [(a.pos, a.neg) for a in alts] == [(["powershell", "encoded command"], ["chrome"]), (["cmd.exe"], ["calc"])]


def test_every_result_must_satisfy_the_whole_query_locally():
    from app.events.search.query import EventQuery

    q = EventQuery(q="powershell -chrome", filters=[Filter(field="user.name", op="eq", value="bob")])
    parsed = sq.parse(q)
    ok = {"user": {"name": "bob"}, "process": {"name": "powershell.exe", "command_line": "powershell -enc AAA"}}
    assert sq.accepts(parsed, ok)
    assert not sq.accepts(parsed, {**ok, "user": {"name": "alice"}})  # filter
    assert not sq.accepts(
        parsed, {**ok, "process": {"name": "powershell.exe", "command_line": "powershell chrome"}}
    )  # negated word
    assert not sq.accepts(parsed, {"user": {"name": "bob"}, "process": {"name": "cmd.exe"}})  # missing word


# ---- the search ------------------------------------------------------------------------------------------
async def test_an_indicator_search_goes_to_the_siem_and_shows_only_logs_that_really_contain_it_without_storing_anything(
    client, make, app, wire
):
    logs = [
        lr_log(1, originIp="203.0.113.5", impactedHost="srv9.corp.example"),
        lr_log(2, originIp="203.0.113.50"),
        lr_log(3, note="mentions 203.0.113.5.5 only"),
    ]
    handler, seen = make_siem(logs)
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="203.0.113.5")
    assert out["total"] == 1 and out["hits"][0]["host"]["hostname"] == "srv9.corp.example" and out["search_id"]
    src = out["sources"][0]
    assert src["kind"] == "logrhythm" and src["status"] == "ok" and src["matched"] == 1 and src["scanned"] >= 1 and seen
    assert any("203.0.113.5" in s for s in src["searched"])
    assert out["origins"] == {out["hits"][0]["id"]: src["id"]}  # every result says which source returned it
    assert await _stored(client, h, "srv9.corp.example") == 0  # nothing was stored


async def test_filters_become_verified_logrhythm_searches_and_the_rest_is_checked_locally(client, make, app, wire):
    logs = [
        lr_log(
            1,
            process="C:\\Windows\\System32\\PowerShell.exe",
            command="powershell -enc AAAA",
            login="bob",
            impactedHost="ws-1",
        ),
        lr_log(2, process="powershell.exe", command="powershell -nop", login="alice", impactedHost="ws-2"),
    ]
    handler, seen = make_siem(logs)
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, text="process.name:powershell.exe user.name:bob")
    assert [x["host"]["hostname"] for x in out["hits"]] == [
        "ws-1"
    ]  # alice's log came back from the loose search and was dropped
    kinds = {i["filterType"] for f in seen for i in f["filterGroup"]["filterItems"][0]["filterItems"]}
    assert FT_PROCESS in kinds and FT_LOGIN in kinds


async def test_a_bare_word_is_one_search_of_the_raw_log_text(client, make, app, wire):
    logs = [
        lr_log(1, process="backup.exe", command="backup.exe /full", impactedHost="srv-1"),
        lr_log(2, url="/x/backup/run", command="GET", impactedHost="web-1"),
        lr_log(3, process="other.exe", impactedHost="srv-3"),
    ]
    handler, seen = make_siem(logs)
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="backup")
    assert {x["host"]["hostname"] for x in out["hits"]} == {"srv-1", "web-1"}
    kinds = {i["filterType"] for f in seen for i in f["filterGroup"]["filterItems"][0]["filterItems"]}
    assert kinds == {35}  # one search on the raw log text (it holds the process, command line, user, URL...), not nine
    assert len(seen) == 1
    assert any("looked for in the raw log text" in n for n in out["sources"][0]["skipped"])


async def test_a_word_found_only_in_the_raw_log_text_is_kept_because_the_siem_vouches_for_it(client, make, app, wire):
    # the raw text never comes back, so the normalized log has no trace of the word; only the Message (35) search can have found it
    logs = [
        lr_log(1, impactedHost="dc-1", rawText="status 0xC000006A"),
        lr_log(2, impactedHost="dc-2", rawText="status 0x0"),
    ]
    handler, seen = make_siem(logs)
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="0xC000006A")
    assert {x["host"]["hostname"] for x in out["hits"]} == {"dc-1"}


async def test_a_user_agent_or_firewall_action_is_found_by_a_bare_word(client, make, app, wire):
    logs = [
        lr_log(1, impactedHost="fw-1", userAgent="DNS over HTTPS"),
        lr_log(2, impactedHost="fw-2", userAgent="curl/8"),
    ]
    handler, seen = make_siem(logs)
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q='"DNS over HTTPS"')
    assert {x["host"]["hostname"] for x in out["hits"]} == {"fw-1"}


async def test_browse_lists_every_log_of_the_range_and_can_be_narrowed_to_entities(client, make, app, wire):
    logs = [
        lr_log(1, impactedHost="a-1", entityId=7),
        lr_log(2, impactedHost="b-1", entityId=9),
        lr_log(3, impactedHost="c-1", entityId=2, impactedEntityId=7),
    ]
    handler, seen = make_siem(logs)
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, browse=True)
    assert out["empty_query"] is False and {x["host"]["hostname"] for x in out["hits"]} == {"a-1", "b-1", "c-1"}
    assert {35} == {i["filterType"] for f in seen for i in f["filterGroup"]["filterItems"][0]["filterItems"]}
    seen.clear()
    out = await _q(client, h, browse=True, entity_ids=[7])
    assert {x["host"]["hostname"] for x in out["hits"]} == {"a-1", "c-1"}  # the entity filter is re-checked locally
    assert {35, 6} == {i["filterType"] for f in seen for i in f["filterGroup"]["filterItems"][0]["filterItems"]}


def _alarm(i, rule, **event):
    when = NOW.strftime("%Y-%m-%dT%H:%M:%S.000")
    return {
        "alarmId": i,
        "alarmRuleName": rule,
        "alarmStatus": 0,
        "entityName": "Global Entity",
        "dateInserted": when,
        "associatedCases": [],
    }, [{"commonEventName": rule, "priority": 40, "classificationName": "Reconnaissance", **event}]


async def test_alarms_are_searched_with_the_logs_behind_them_raw_text_included(client, make, app, wire):
    handler, seen = make_siem([])
    handler.alarms = [
        _alarm(
            1, "AIE: port scan horizontal", originIP="45.148.10.188", logMessage="<aie>scan from 45.148.10.188</aie>"
        ),
        _alarm(
            2,
            "LogRhythm Agent Heartbeat Missed",
            impactedHostName="poste_test",
            logMessage="heartbeat missed 0xABCD1234",
        ),
    ]
    t, h = await _env(client, make, app, wire, handler=handler)
    by_rule = await _q(client, h, q="port scan")  # a word in the rule name
    assert [x["action"] for x in by_rule["hits"]] == ["AIE: port scan horizontal"] and by_rule["hits"][0][
        "event_type"
    ] == "alert"
    by_ip = await _q(client, h, q="45.148.10.188")  # an indicator in the logs behind the alarm
    assert [x["original_id"] for x in by_ip["hits"]] == ["alarm-1"]
    by_raw = await _q(client, h, q="0xABCD1234")  # a string only in the raw log text
    assert [x["original_id"] for x in by_raw["hits"]] == ["alarm-2"]
    assert "alarms" in by_raw["sources"][0]["searched"]
    assert (await _q(client, h, q="nothing-like-this"))["hits"] == []


async def test_an_alarm_api_failure_is_reported_and_does_not_fail_the_log_search(client, make, app, wire):
    handler, seen = make_siem([lr_log(1, process="backup.exe", impactedHost="srv-1")])

    def failing(request):
        if "/lr-alarm-api/" in request.url.path:
            return httpx.Response(500, json={})
        return handler(request)

    failing.results = handler.results
    t, h = await _env(client, make, app, wire, handler=failing)
    out = await _q(client, h, q="backup")
    assert [x["host"]["hostname"] for x in out["hits"]] == ["srv-1"]
    assert any("Alarms could not be read" in n for n in out["sources"][0]["skipped"])


async def test_the_scopes_endpoint_lists_the_entities_and_log_source_types_a_browse_can_be_narrowed_to(
    client, make, app, wire
):
    handler, seen = make_siem([])
    t, h = await _env(client, make, app, wire, handler=handler)
    r = await client.get(f"{API}/siem-scopes", headers=h)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["entities"] == [{"id": 7, "name": "Wifak-Datacenter/DC-System Devices"}]  # retired entities are left out
    assert (
        out["source_types"]
        == [
            {"id": 86, "name": "Cisco Router", "sources": 1},
            {"id": 1000639, "name": "Win Sec", "sources": 2},
        ]
        and out["errors"] == []
    )


async def test_an_empty_search_does_not_browse_the_siem_and_missing_sources_are_said(client, make, app, wire):
    handler, seen = make_siem([lr_log(1)])
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h)
    assert out["empty_query"] is True and out["total"] == 0 and not seen
    t2, h2 = await _env(client, make, app, wire, lr=False)
    assert (await _q(client, h2, q="203.0.113.5"))["no_sources"] is True


async def test_the_window_is_limited_and_a_failing_source_is_reported_without_hiding_the_other(client, make, app, wire):
    def handler(request):
        if request.url.host == "lr.example":
            return httpx.Response(500, json={})
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "uuid": "u1",
                        "eventId": "3",
                        "eventSubId": 204,
                        "eventTimeDT": (NOW - timedelta(minutes=3)).isoformat(),
                        "endpointHostName": "WS-77",
                        "src": "10.7.7.7",
                        "dst": "203.0.113.5",
                        "processName": "evil.exe",
                    }
                ],
                "progressRate": 100,
            },
        )

    t, h = await _env(client, make, app, wire, handler=handler, trend="endpoint_activity")
    wide = {"start": (NOW - timedelta(days=60)).isoformat(), "end": NOW.isoformat()}
    r = await client.post(f"{API}/siem-query", headers=h, json={"q": "203.0.113.5", "time_range": wide})
    out = r.json()
    by = {s["kind"]: s for s in out["sources"]}
    assert by["logrhythm"]["status"] == "error" and by["trend:endpoint_activity"]["status"] == "ok"
    assert (
        out["total"] == 1
        and out["hits"][0]["host"]["hostname"] == "WS-77"
        and "at most the last 14 days" in out["note"]
    )
    assert out["origins"][out["hits"][0]["id"]] == by["trend:endpoint_activity"]["id"]


# ---- nothing is stored until an event is opened ----------------------------------------------------------
async def test_opening_an_event_imports_only_that_event_and_a_held_result_expires(client, make, app, wire):
    handler, _ = make_siem(
        [lr_log(1, originIp="203.0.113.5", impactedHost="srv9"), lr_log(2, originIp="203.0.113.5", impactedHost="srv8")]
    )
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="203.0.113.5")
    a, b = out["hits"][0]["id"], out["hits"][1]["id"]
    assert (await client.get(f"{API}/{a}", headers=h)).status_code == 404  # not stored yet
    imp = await client.post(f"{API}/siem-import", headers=h, json={"search_id": out["search_id"], "ids": [a]})
    assert imp.status_code == 200 and imp.json()["imported"] == 1
    assert (await client.get(f"{API}/{a}", headers=h)).status_code == 200
    assert (await client.get(f"{API}/{b}", headers=h)).status_code == 404  # the other result is still only a result
    again = await client.post(f"{API}/siem-import", headers=h, json={"search_id": out["search_id"], "ids": [a]})
    assert again.json()["imported"] == 0 and again.json()["duplicates"] == 1  # idempotent
    await app.state.redis.delete(sq.cache_key(t.id, out["search_id"]))
    gone = await client.post(f"{API}/siem-import", headers=h, json={"search_id": out["search_id"], "ids": [b]})
    assert gone.json()["expired"] == 1 and gone.json()["imported"] == 0


async def test_another_tenant_cannot_import_a_held_result(client, make, app, wire):
    handler, _ = make_siem([lr_log(1, originIp="203.0.113.5", impactedHost="srv9")])
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="203.0.113.5")
    other = await make.tenant()
    _, h2 = await make.login_as(other, Role.SUPER_ADMIN)
    r = await client.post(
        f"{API}/siem-import", headers=h2, json={"search_id": out["search_id"], "ids": [out["hits"][0]["id"]]}
    )
    assert r.json()["imported"] == 0 and r.json()["expired"] == 1


async def test_sources_listing_and_permissions(client, make, app, wire):
    t, h = await _env(client, make, app, wire, trend="endpoint_activity")
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
    srcs = (await client.get(f"{API}/siem-sources", headers=h)).json()
    assert {s["kind"] for s in srcs} == {
        "logrhythm",
        "trend:endpoint_activity",
    }  # a dataset with no query surface is not offered
    viewer = await make.user(t, Role.VIEWER)
    assert (await client.get(f"{API}/siem-sources", headers=make.headers(viewer, t))).status_code == 200
    assert (
        await client.post(f"{API}/siem-query", headers=make.headers(viewer, t), json={"q": "x", "time_range": RANGE})
    ).status_code == 200
    assert (await client.post(f"{API}/siem-query", json={"q": "x"})).status_code == 401


async def test_a_word_in_the_vendors_own_fields_of_an_authentication_log_is_found(client, make, app, wire):
    # LogRhythm keeps the Kerberos service (krbtgt) in `process` of Windows authentication logs: a real hit that must not be dropped by the local check
    handler, _ = make_siem(
        [
            lr_log(
                1,
                process="krbtgt",
                command="0x40810010",
                classificationName="Authentication Failure",
                vendorMessageId="4771",
                login="bob",
                impactedHost="dc1",
            )
        ]
    )
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="krbtgt")
    assert out["total"] == 1 and out["hits"][0]["process"]["name"] == "krbtgt"
    out2 = await _q(client, h, text="process.name:krbtgt")
    assert out2["total"] == 1


# ---- more than one page: the whole result is held server-side and fetched page by page ---------------------------------------------------
def _many(n, ip="203.0.113.5"):
    return [lr_log(i, originIp=ip, logDate=1_700_000_000_000 + i * 1000) for i in range(1, n + 1)]


async def _hits(client, h, sid, offset, limit=500):
    r = await client.get(f"{API}/siem-query/{sid}/hits", headers=h, params={"offset": offset, "limit": limit})
    assert r.status_code == 200, r.text
    return r.json()


async def test_a_result_larger_than_a_page_is_fetched_page_by_page_without_gaps_or_duplicates(client, make, app, wire):
    handler, _ = make_siem(_many(1200))
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="203.0.113.5")
    assert out["total"] == 1200 and len(out["hits"]) == 500 and out["truncated"] is False
    assert (
        out["found"] == 1200 and out["found_at_least"] is False
    )  # the SIEM's own count, exact because nothing was cut
    sid = out["search_id"]
    p2, p3 = await _hits(client, h, sid, 500), await _hits(client, h, sid, 1000)
    assert (len(p2["hits"]), len(p3["hits"]), p3["total"], p3["expired"]) == (500, 200, 1200, False)
    pages = [*out["hits"], *p2["hits"], *p3["hits"]]
    assert len({e["id"] for e in pages}) == 1200  # every event exactly once
    stamps = [e["timestamp"] for e in pages]
    assert stamps == sorted(stamps, reverse=True)  # one newest-first order across the pages
    origins = {**out["origins"], **p2["origins"], **p3["origins"]}
    assert all(e["id"] in origins for e in pages)  # each page says which SIEM returned its events
    assert (await _hits(client, h, sid, 1200))["hits"] == []  # past the end is empty, not an error


async def test_an_event_from_a_later_page_can_still_be_opened_and_added_to_a_case(client, make, app, wire):
    handler, _ = make_siem(_many(700))
    t, h = await _env(client, make, app, wire, handler=handler)
    out = await _q(client, h, q="203.0.113.5")
    late = (await _hits(client, h, out["search_id"], 600, 1))["hits"][0]["id"]
    r = await client.post(f"{API}/siem-import", headers=h, json={"search_id": out["search_id"], "ids": [late]})
    assert r.status_code == 200 and r.json()["imported"] == 1 and r.json()["expired"] == 0
    assert (
        await client.get(f"{API}/{late}", headers=h)
    ).status_code == 200  # stored now: the drawer, pivots and cases work


async def test_a_held_result_expires_and_is_never_readable_by_another_tenant(client, make, app, wire):
    handler, _ = make_siem(_many(60))
    t, h = await _env(client, make, app, wire, handler=handler)
    sid = (await _q(client, h, q="203.0.113.5"))["search_id"]
    assert (await _hits(client, h, sid, 0))["expired"] is False
    other = await make.tenant()
    _, h2 = await make.login_as(other, Role.SUPER_ADMIN)
    stolen = await _hits(client, h2, sid, 0)
    assert stolen["expired"] is True and stolen["hits"] == []  # the key carries the tenant: another tenant sees nothing
    assert (await _hits(client, h, "0" * 32, 0))["expired"] is True  # unknown / expired id
    bad = await client.get(f"{API}/siem-query/not-an-id/hits", headers=h)
    assert bad.status_code == 422  # only a 32-character hex id is accepted


async def test_the_read_and_hold_limits_are_explicit_and_say_the_result_is_cut(client, make, app, wire):
    from app.core.config import get_settings

    handler, _ = make_siem(_many(1200))
    t, h = await _env(client, make, app, wire, handler=handler)
    q = sq.SiemQuery.model_validate({"q": "203.0.113.5", "time_range": RANGE})
    async with app.state.sessionmaker() as db:
        out = await sq.search(db, app.state.redis, get_settings(), t.id, q, read_cap=300, hold_max=250, page_size=100)
    assert len(out["hits"]) == 100 and out["total"] == 250  # a page of the 250 held
    assert out["truncated"] is True  # the SIEM had more than was read
    assert out["found"] == 1200 and out["found_at_least"] is True  # ... and says how much more
    assert out["sources"][0]["found"] == 1200 and out["sources"][0]["capped"] is True
    async with app.state.sessionmaker() as db:  # page_size=None (the AI agent) = everything held in `hits`
        everything = await sq.search(db, None, get_settings(), t.id, q, read_cap=300, hold_max=250, page_size=None)
    assert len(everything["hits"]) == 250


def test_held_results_are_packed_and_an_older_plain_list_is_still_readable():
    docs = [{"id": f"e{i}", "message": "x" * 200} for i in range(50)]
    packed = sq._pack({"docs": docs, "origins": {"e1": "src"}})
    assert (
        packed.startswith("z:") and len(packed) < len(str(docs)) / 3
    )  # compressed: ten thousand events do not sit in Redis as 35 MB
    assert sq._unpack(packed) == {"docs": docs, "origins": {"e1": "src"}}
    assert sq._unpack(json.dumps(docs)) == {"docs": docs, "origins": {}}  # a result held by the previous version


async def test_the_logs_behind_an_alarm_are_fetched_once_for_many_searches(client, make, app, wire):
    handler, seen = make_siem([])
    handler.alarms = [_alarm(1, "AIE: port scan horizontal", originIP="45.148.10.188"), _alarm(2, "Heartbeat Missed")]
    fetched = []

    def counting(request):
        if request.url.path.endswith("/events"):
            fetched.append(request.url.path)
        return handler(request)

    counting.results = handler.results
    t, h = await _env(client, make, app, wire, handler=counting)
    for q in ("port scan", "45.148.10.188", "heartbeat"):  # three searches over the same window
        await _q(client, h, q=q)
    assert (
        sorted(fetched) == sorted({*fetched}) and len(fetched) == 2
    )  # one request per alarm, not one per alarm per search
