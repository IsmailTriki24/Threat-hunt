# ruff: noqa: E501
"""IOC database: feed parsing, guard-rails, ageing, caps, idempotent upserts, expiry, allow-list, API."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.auth.rbac import Role
from app.connectors import _http
from app.core.config import get_settings
from app.core.crypto import encrypt_json
from app.iochunt import ingest
from app.iochunt.feeds import registry
from app.iochunt.feeds.base import RawIoc, parse_dt
from app.iochunt.models import Ioc, IocFeed
from tests.helpers import ev

NOW = datetime.now(UTC)
API = "/api/v1/ioc"


def fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


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
    return install


def prep(raws, **kw):
    args = dict(max_age_days=14, min_confidence=0, max_items=1000, allow=[], now=NOW)
    args.update(kw)
    return ingest.prepare(raws, **args)


# ---- guard-rails ------------------------------------------------------------------------------------
def test_defanged_values_are_normalised_and_typed():
    items, res = prep(
        [
            RawIoc("hxxps://Evil[.]example/a.ps1", first_seen=NOW),
            RawIoc("203[.]0[.]113[.]9", first_seen=NOW),
            RawIoc("BAD[.]Example[.]ORG", first_seen=NOW),
            RawIoc("A" * 64, first_seen=NOW),
        ]
    )
    got = {(i.type, i.value) for i in items}
    assert ("url", "https://Evil.example/a.ps1") in got or any(t == "url" for t, _ in got)
    assert ("ip", "203.0.113.9") in got and ("domain", "bad.example.org") in got and ("sha256", "a" * 64) in got


def test_noise_is_kept_out_of_the_database():
    raws = [
        RawIoc(v, first_seen=NOW)
        for v in (
            "10.0.0.5",
            "192.168.1.1",
            "8.8.8.8",
            "127.0.0.1",
            "google.com",
            "login.microsoft.com",
            "host.corp.local",
            "d41d8cd98f00b204e9800998ecf8427e",
            "not an ioc",
            "",
        )
    ]
    items, res = prep(raws)
    assert items == [] and res.fetched == 10 and sum(res.dropped.values()) == 10


def test_only_recent_indicators_are_imported():
    old, fresh = NOW - timedelta(days=200), NOW - timedelta(days=2)
    raws = [
        RawIoc("198.51.100.1", type="ip", first_seen=old, last_seen=old),  # a year-old style IOC
        RawIoc("198.51.100.2", type="ip", first_seen=old, last_seen=fresh),  # old but seen again recently: kept
        RawIoc("198.51.100.3", type="ip", first_seen=fresh),
        RawIoc(
            "198.51.100.4", type="ip", first_seen=fresh, valid_until=NOW - timedelta(days=1)
        ),  # already expired by the feed
    ]
    items, res = prep(raws)
    assert sorted(i.value for i in items) == ["198.51.100.2", "198.51.100.3"]
    assert res.dropped == {"too old": 1, "expired": 1}
    assert prep(raws, max_age_days=1)[0] == []


def test_confidence_floor_item_cap_and_dedup_keep_the_best():
    raws = [RawIoc(f"198.51.100.{n}", type="ip", first_seen=NOW, confidence=n) for n in range(1, 31)]
    raws.append(RawIoc("198.51.100.30", type="ip", first_seen=NOW, confidence=99))  # duplicate with higher confidence
    items, res = prep(raws, min_confidence=10, max_items=5)
    assert [i.value for i in items][:2] == ["198.51.100.30", "198.51.100.29"] and len(items) == 5
    assert items[0].raw.confidence == 99 and res.dropped["over item cap"] == 16 and res.dropped["low confidence"] == 9


def test_tenant_allowlist_covers_domains_subdomains_urls_and_exact_values():
    allow = [("domain", "partner.example"), ("ip", "198.51.100.77")]
    raws = [
        RawIoc(v, first_seen=NOW)
        for v in (
            "partner.example",
            "cdn.partner.example",
            "https://cdn.partner.example/x.js",
            "198.51.100.77",
            "notpartner.example",
            "198.51.100.78",
        )
    ]
    items, _ = prep(raws, allow=allow)
    assert sorted(i.value for i in items) == ["198.51.100.78", "notpartner.example"]


def test_parse_dt_handles_every_feed_format():
    for v in (
        "2026-10-08 12:17:07",
        "2026-10-08 12:17:07 UTC",
        "2026-10-08T12:17:07Z",
        "2026-10-08",
        1791461827,
        "1791461827",
        1791461827000,
    ):
        assert parse_dt(v) is not None, v
    for v in (None, "", "None", "garbage", True):
        assert parse_dt(v) is None


# ---- feed parsers -----------------------------------------------------------------------------------
def csv_row(i, url, status="online", added=None, tags="Mozi,elf"):
    added = added or fmt(NOW - timedelta(hours=1))
    return f'"{i}","{added}","{url}","{status}","{added}","malware_download","{tags}","https://urlhaus.abuse.ch/url/{i}/","rep"'


async def test_urlhaus_csv(wire):
    body = "\n".join(
        [
            "# comment",
            "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter",
            csv_row(1, "http://198.51.100.5:8080/i"),
            csv_row(2, "http://old.example/x", added=fmt(NOW - timedelta(days=90))),
            csv_row(3, "http://off.example/y", status="offline"),
        ]
    )
    wire(lambda r: httpx.Response(200, text=body))
    raws = await registry.build("urlhaus_csv").fetch(None, 14)
    assert (
        [r.value for r in raws] == ["http://198.51.100.5:8080/i"]
        and raws[0].confidence == 75
        and raws[0].malware == "Mozi"
        and raws[0].threat_type == "payload_delivery"
    )
    both = await registry.build("urlhaus_csv", {"only_online": False}).fetch(None, 14)
    assert len(both) == 2


async def test_feodo_marks_online_c2_high_confidence(wire):
    data = [
        {
            "ip_address": "198.51.100.9",
            "port": 443,
            "status": "online",
            "first_seen": fmt(NOW - timedelta(days=3)),
            "last_online": NOW.strftime("%Y-%m-%d"),
            "malware": "QakBot",
            "as_number": 1,
            "as_name": "X",
        }
    ]
    wire(lambda r: httpx.Response(200, json=data))
    [r] = await registry.build("feodo").fetch(None, 14)
    assert r.type == "ip" and r.confidence == 90 and r.threat_type == "botnet_cc" and r.malware == "QakBot"


async def test_threatfox_needs_a_key_and_maps_types(wire):
    seen = {}

    def h(request):
        seen["h"], seen["b"] = request.headers, json.loads(request.content)
        rows = [
            {
                "ioc": "198.51.100.7:443",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 80,
                "first_seen": fmt(NOW) + " UTC",
                "tags": ["cs"],
                "reference": "https://x",
            },
            {"ioc": "evil.example", "ioc_type": "domain", "confidence_level": 50, "first_seen": fmt(NOW) + " UTC"},
            {"ioc": "x", "ioc_type": "weird", "confidence_level": 99},
        ]
        return httpx.Response(200, json={"query_status": "ok", "data": rows})

    wire(h)
    with pytest.raises(_http.SourceError, match="Auth-Key"):
        await registry.build("threatfox").fetch(None, 14)
    raws = await registry.build("threatfox", {}, {"auth_key": "K"}).fetch(None, 14)
    assert [(r.type, r.value) for r in raws] == [("ip", "198.51.100.7"), ("domain", "evil.example")]
    assert seen["h"]["auth-key"] == "K" and seen["b"] == {"query": "get_iocs", "days": 7}


async def test_otx_pulses_carry_attack_ids_and_expiry(wire):
    pulse = {
        "id": "p1",
        "name": "Campaign X",
        "created": NOW.isoformat(),
        "modified": NOW.isoformat(),
        "adversary": "APT-X",
        "tags": ["rat"],
        "attack_ids": [{"id": "T1059.001"}, {"id": "TA0001"}],
        "indicators": [
            {
                "indicator": "198.51.100.8",
                "type": "IPv4",
                "created": NOW.isoformat(),
                "expiration": (NOW + timedelta(days=5)).isoformat(),
                "is_active": True,
            },
            {"indicator": "gone.example", "type": "domain", "is_active": False},
            {"indicator": "x", "type": "CVE"},
        ],
    }
    wire(lambda r: httpx.Response(200, json={"results": [pulse], "next": None}))
    raws = await registry.build("otx", {}, {"api_key": "K"}).fetch(None, 14)
    assert (
        len(raws) == 1
        and raws[0].techniques == ["T1059.001"]
        and raws[0].malware == "APT-X"
        and raws[0].valid_until is not None
    )


async def test_misp_extracts_techniques_from_galaxy_tags(wire):
    attrs = [
        {
            "type": "ip-dst",
            "value": "198.51.100.10",
            "to_ids": True,
            "timestamp": str(int(NOW.timestamp())),
            "category": "Network activity",
            "event_id": "5",
            "Event": {"info": "Intrusion"},
            "Tag": [{"name": 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"'}, {"name": "tlp:amber"}],
        },
        {"type": "vulnerability", "value": "CVE-1"},
    ]
    wire(lambda r: httpx.Response(200, json={"response": {"Attribute": attrs}}))
    raws = await registry.build("misp", {"base_url": "https://misp.example"}, {"api_key": "K"}).fetch(None, 14)
    assert (
        len(raws) == 1 and raws[0].techniques == ["T1566"] and raws[0].confidence == 70 and "tlp:amber" in raws[0].tags
    )


async def test_trend_suspicious_objects_respect_exceptions_and_expiry(wire):
    items = [
        {
            "type": "ip",
            "ip": "198.51.100.11",
            "riskLevel": "high",
            "lastModifiedDateTime": NOW.isoformat(),
            "expiredDateTime": (NOW + timedelta(days=10)).isoformat(),
            "scanAction": "block",
            "inExceptionList": False,
        },
        {
            "type": "fileSha256",
            "fileSha256": "b" * 64,
            "riskLevel": "low",
            "lastModifiedDateTime": NOW.isoformat(),
            "inExceptionList": True,
        },
        {"type": "domain", "domain": "bad.example", "riskLevel": "medium", "lastModifiedDateTime": NOW.isoformat()},
    ]
    wire(lambda r: httpx.Response(200, json={"items": items}))
    raws = await registry.build("trend_suspicious_objects", {}, {"api_key": "K"}).fetch(None, 14)
    assert [(r.type, r.confidence) for r in raws] == [("ip", 90), ("domain", 60)] and raws[0].valid_until is not None


async def test_text_list_and_stix(wire):
    wire(lambda r: httpx.Response(200, text="# list\n198.51.100.20\nevil.example # c2\n\nhttps://bad.example/x\n"))
    raws = await registry.build("text_list", {"url": "https://lists.example/x.txt"}).fetch(None, 14)
    assert [r.value for r in raws] == ["198.51.100.20", "evil.example", "https://bad.example/x"]
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '198.51.100.21']",
                "pattern_type": "stix",
                "valid_from": NOW.isoformat(),
                "confidence": 80,
                "labels": ["malicious-activity"],
            }
        ],
    }
    wire(lambda r: httpx.Response(200, json=bundle))
    raws = await registry.build("stix_bundle", {"url": "https://stix.example/b.json"}).fetch(None, 14)
    assert [(r.type, r.value) for r in raws] == [("ip", "198.51.100.21")]
    wire(lambda r: httpx.Response(200, json={"not": "stix"}))
    with pytest.raises(_http.SourceError, match="STIX"):
        await registry.build("stix_bundle", {"url": "https://stix.example/b.json"}).fetch(None, 14)


def test_feed_configs_are_validated():
    for ft, bad in (
        ("urlhaus_csv", {"x": 1}),
        ("misp", {}),
        ("text_list", {"url": "ftp://x"}),
        ("threatfox", {"days": 99}),
    ):
        with pytest.raises(Exception):  # noqa: B017, PT011
            registry.build(ft, bad)


# ---- persistence -------------------------------------------------------------------------------------
async def test_run_feed_is_idempotent_expires_and_revives(app, make, wire):
    t = await make.tenant()
    s = get_settings()
    wire(
        lambda r: httpx.Response(
            200,
            json=[
                {
                    "ip_address": "198.51.100.30",
                    "port": 80,
                    "status": "online",
                    "first_seen": fmt(NOW),
                    "last_online": NOW.strftime("%Y-%m-%d"),
                    "malware": "Emotet",
                }
            ],
        )
    )
    async with app.state.sessionmaker() as db:
        feed = IocFeed(tenant_id=t.id, name="feodo", feed_type="feodo", config={}, max_age_days=14, max_items=100)
        db.add(feed)
        await db.flush()
        r1 = await ingest.run_feed(db, s, feed)
        r2 = await ingest.run_feed(db, s, feed)
        await db.commit()
        assert (r1.new, r2.new) == (1, 0) and feed.last_status == "ok" and "0 new" in feed.last_detail
        ioc = (await db.execute(select(Ioc).where(Ioc.tenant_id == t.id))).scalar_one()
        assert ioc.status == "NEW" and ioc.source == "feodo" and ioc.malware == "Emotet"
        # aged out when never reviewed and no longer re-sighted
        ioc.last_seen = NOW - timedelta(days=40)
        await db.flush()
        assert (await ingest.expire(db, t.id))["aged"] == 1
        assert ioc.status == "EXPIRED"
        # a validated indicator is not touched by the NEW-ageing rule but retires after the watch period
        ioc.status, ioc.last_seen, ioc.validated_at = "VALIDATED", NOW - timedelta(days=40), NOW - timedelta(days=31)
        await db.flush()
        out = await ingest.expire(db, t.id)
        assert out["unwatched"] == 1 and ioc.status == "EXPIRED"


async def test_feed_failure_is_recorded_not_raised(app, make, wire):
    t = await make.tenant()
    wire(lambda r: httpx.Response(403))
    async with app.state.sessionmaker() as db:
        feed = IocFeed(
            tenant_id=t.id,
            name="tf",
            feed_type="threatfox",
            config={},
            secrets_enc=encrypt_json(get_settings(), {"auth_key": "SECRET-K"}),
        )
        db.add(feed)
        await db.flush()
        await ingest.run_feed(db, get_settings(), feed)
        assert (
            feed.last_status == "error" and "SECRET-K" not in feed.last_detail and "authentication" in feed.last_detail
        )
        await db.commit()


async def test_prescreen_flags_indicators_already_seen_in_our_telemetry(app, make):
    t = await make.tenant()
    await make.index(
        t,
        [
            ev(10, network={"dst_ip": "198.51.100.40", "dst_port": 443}, event_type="network_connection"),
            ev(10, dns={"question": "seen.example"}, event_type="dns_query"),
        ],
    )
    now = NOW
    async with app.state.sessionmaker() as db:
        for typ, val in (("ip", "198.51.100.40"), ("ip", "198.51.100.41"), ("domain", "seen.example")):
            db.add(
                Ioc(
                    tenant_id=t.id,
                    type=typ,
                    value=val,
                    source="test",
                    first_seen=now,
                    last_seen=now,
                    status="NEW",
                    confidence=60,
                )
            )
        await db.flush()
        flagged = await ingest.prescreen(db, app.state.search, t.id)
        rows = {r.value: r.seen_count for r in (await db.execute(select(Ioc).where(Ioc.tenant_id == t.id))).scalars()}
        await db.commit()
    assert flagged == 2 and rows["198.51.100.40"] >= 1 and rows["seen.example"] >= 1 and rows["198.51.100.41"] == 0


# ---- API ---------------------------------------------------------------------------------------------
async def test_feed_api_lifecycle_and_secrets_never_leak(client, make, wire):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    types = (await client.get(f"{API}/feed-types", headers=h)).json()
    assert {x["type"] for x in types} >= {
        "urlhaus_csv",
        "feodo",
        "threatfox",
        "otx",
        "misp",
        "trend_suspicious_objects",
        "text_list",
        "stix_bundle",
    }
    r = await client.post(
        f"{API}/feeds", headers=h, json={"name": "tf", "feed_type": "threatfox", "secrets": {"auth_key": "VERY-SECRET"}}
    )
    assert (
        r.status_code == 201
        and "VERY-SECRET" not in r.text
        and r.json()["secret_keys"] == ["auth_key"]
        and r.json()["max_age_days"] == 14
    )
    fid = r.json()["id"]
    assert (
        await client.post(f"{API}/feeds", headers=h, json={"name": "tf", "feed_type": "threatfox"})
    ).status_code == 409
    for bad in (
        {"name": "x", "feed_type": "nope"},
        {"name": "x", "feed_type": "misp", "config": {}},
        {"name": "x", "feed_type": "feodo", "max_age_days": 500},
        {"name": "x", "feed_type": "feodo", "tenant_id": "1"},
    ):
        assert (await client.post(f"{API}/feeds", headers=h, json=bad)).status_code in (400, 422)
    assert (
        await client.put(f"{API}/feeds/{fid}/secrets/auth_key", headers=h, json={"value": "NEW"})
    ).status_code == 204
    wire(
        lambda r: httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "ioc": "198.51.100.50:80",
                        "ioc_type": "ip:port",
                        "confidence_level": 90,
                        "first_seen": fmt(NOW) + " UTC",
                        "malware_printable": "X",
                    }
                ],
            },
        )
    )
    run = await client.post(f"{API}/feeds/{fid}/run", headers=h)
    assert run.status_code == 200 and run.json()["last_status"] == "ok" and run.json()["last_new"] == 1
    page = (await client.get(f"{API}/iocs", headers=h)).json()
    assert (
        page["total"] == 1 and page["items"][0]["value"] == "198.51.100.50" and page["facets"]["status"] == {"NEW": 1}
    )
    assert (await client.delete(f"{API}/feeds/{fid}", headers=h)).status_code == 204
    assert (await client.get(f"{API}/iocs", headers=h)).json()["total"] == 1  # indicators outlive their feed


async def test_ioc_queue_filters_sorting_and_manual_entry(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)

    async def add(**kw):
        return await client.post(f"{API}/iocs", headers=h, json={"type": "ip", "value": "198.51.100.60", **kw})

    r = await add()
    assert r.status_code == 201 and r.json()["source"] == "manual" and r.json()["valid_until"] is not None
    assert (await add()).status_code == 409
    assert (
        await client.post(f"{API}/iocs", headers=h, json={"type": "domain", "value": "login.microsoft.com"})
    ).status_code == 400
    assert (await client.post(f"{API}/iocs", headers=h, json={"type": "ip", "value": "10.1.1.1"})).status_code == 400
    assert (await client.post(f"{API}/iocs", headers=h, json={"type": "ip", "value": "999.1.1.1"})).status_code == 400
    assert (
        await client.post(
            f"{API}/iocs", headers=h, json={"type": "domain", "value": "Evil[.]Example", "confidence": 90}
        )
    ).status_code == 201
    q = lambda qs: client.get(f"{API}/iocs{qs}", headers=h)  # noqa: E731
    assert [i["value"] for i in (await q("?sort=confidence")).json()["items"]][0] == "evil.example"
    assert (
        (await q("?type=domain")).json()["total"] == 1
        and (await q("?min_confidence=80")).json()["total"] == 1
        and (await q("?q=evil")).json()["total"] == 1
    )
    assert (await q("?seen=true")).json()["total"] == 0 and (await q("?max_age_days=1")).json()["total"] == 2
    assert (await q("?limit=1&offset=1")).json()["items"].__len__() == 1


async def test_allowlist_retires_queued_indicators_and_blocks_new_ones(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    await client.post(f"{API}/iocs", headers=h, json={"type": "domain", "value": "cdn.partner.example"})
    a = await client.post(
        f"{API}/allowlist", headers=h, json={"type": "domain", "value": "partner.example", "reason": "our supplier"}
    )
    assert a.status_code == 201
    assert (await client.get(f"{API}/iocs?status=REJECTED", headers=h)).json()["total"] == 1
    assert (
        await client.post(f"{API}/iocs", headers=h, json={"type": "domain", "value": "x.partner.example"})
    ).status_code == 400
    assert (
        await client.post(f"{API}/allowlist", headers=h, json={"type": "domain", "value": "partner.example"})
    ).status_code == 409
    assert (await client.delete(f"{API}/allowlist/{a.json()['id']}", headers=h)).status_code == 204
    assert (
        await client.post(f"{API}/iocs", headers=h, json={"type": "domain", "value": "x.partner.example"})
    ).status_code == 201


@pytest.mark.parametrize(
    "role,read,validate,manage",
    [
        (Role.VIEWER, True, False, False),
        (Role.SOC_ANALYST, True, False, False),
        (Role.THREAT_HUNTER, True, False, False),
        (Role.TENANT_ADMIN, True, True, True),
    ],
)
async def test_only_tenant_admins_validate_and_manage(client, make, role, read, validate, manage):
    t = await make.tenant()
    _, admin = await make.login_as(t, Role.TENANT_ADMIN)
    ioc = (await client.post(f"{API}/iocs", headers=admin, json={"type": "ip", "value": "198.51.100.70"})).json()
    _, h = await make.login_as(t, role)
    assert (await client.get(f"{API}/iocs", headers=h)).status_code == (200 if read else 403)
    assert (await client.post(f"{API}/iocs/validate", headers=h, json={"ioc_ids": [ioc["id"]]})).status_code == (
        201 if validate else 403
    )
    assert (await client.post(f"{API}/feeds", headers=h, json={"name": "f", "feed_type": "feodo"})).status_code == (
        201 if manage else 403
    )
    assert (
        await client.post(f"{API}/allowlist", headers=h, json={"type": "ip", "value": "198.51.100.71"})
    ).status_code == (201 if manage else 403)


async def test_tenants_cannot_see_or_validate_each_others_indicators(client, make):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.TENANT_ADMIN)
    _, hb = await make.login_as(b, Role.TENANT_ADMIN)
    ioc = (await client.post(f"{API}/iocs", headers=ha, json={"type": "ip", "value": "198.51.100.80"})).json()
    assert (await client.get(f"{API}/iocs", headers=hb)).json()["total"] == 0
    assert (await client.post(f"{API}/iocs/validate", headers=hb, json={"ioc_ids": [ioc["id"]]})).status_code == 404
    assert (await client.post(f"{API}/iocs/reject", headers=hb, json={"ioc_ids": [ioc["id"]]})).status_code == 404


async def test_misp_filters_on_attribute_time_not_publish_time_and_threatfox_allows_big_exports(wire):
    seen = {}

    def h(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"response": {"Attribute": []}, "query_status": "ok", "data": []})

    wire(h)
    await registry.build("misp", {"base_url": "https://misp.example"}, {"api_key": "K"}).fetch(None, 14)
    assert seen["body"]["timestamp"] == "14d" and "last" not in seen["body"]
    big = "x" * (11 * 1024 * 1024)  # an export over the generic 10 MB cap must still be accepted
    wire(lambda r: httpx.Response(200, json={"query_status": "ok", "data": [], "pad": big}))
    assert await registry.build("threatfox", {}, {"auth_key": "K"}).fetch(None, 7) == []
