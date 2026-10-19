# ruff: noqa: E501, F811
"""The live SIEM search page: queries go to LogRhythm / Trend, every result is re-checked locally, and nothing is stored until an event is opened."""

from datetime import UTC, datetime, timedelta

import httpx

from app.auth.rbac import Role
from app.connectors.logrhythm import FT_COMMAND, FT_LOGIN, FT_PROCESS, FT_URL
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
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
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


async def test_a_bare_word_is_looked_for_in_process_command_user_host_url_reason_and_object(client, make, app, wire):
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
    assert {FT_PROCESS, FT_COMMAND, FT_LOGIN, FT_URL, 149, 34, 35} <= kinds
    assert {154, 144, 141} <= {
        i["filterType"] for f in seen for i in f["filterGroup"]["filterItems"][0]["filterItems"]
    }  # the hunting fields, OR-ed in one search
    assert any(
        "process, command line, user, host, URL, reason, object and the raw log text" in n
        for n in out["sources"][0]["skipped"]
    )


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
    _, h2 = await make.login_as(other, Role.TENANT_ADMIN)
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
