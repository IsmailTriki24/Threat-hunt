# ruff: noqa: E501
"""LogRhythm IOC search: verified filter shapes, batching, URL handling, attribution and limits. The mock SIEM rejects what the live one rejects."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.auth.rbac import Role
from app.connectors import _http, registry
from app.connectors.logrhythm import FT_HASH, FT_HOSTNAME, FT_IP, FT_SENDER, FT_URL, ioc_query_filter
from app.core.config import get_settings
from app.core.crypto import encrypt_json
from app.datasources.models import DataSource
from app.iochunt import hunting
from app.iochunt.models import Ioc

NOW = datetime.now(UTC)


async def _resolve(host, port):
    return ["93.184.216.34"]


def ioc(typ, value, **kw):
    return Ioc(
        id=uuid.uuid4(),
        type=typ,
        value=value,
        source="t",
        confidence=kw.pop("confidence", 70),
        seen_count=kw.pop("seen_count", 0),
        first_seen=NOW,
        last_seen=NOW,
        **kw,
    )


def items_of(flt):
    return flt["filterGroup"]["filterItems"][0]["filterItems"]


# ---- filter shapes (each verified on a production LogRhythm) --------------------------------------------
def test_ip_filter_uses_ip_value_type_with_plain_strings_and_one_or_group():
    f = ioc_query_filter("ip", ["203.0.113.5", "198.51.100.7", "203.0.113.5"])
    grp = f["filterGroup"]["filterItems"][0]
    assert grp["filterItemType"] == 1 and grp["fieldOperator"] == 2 and f["msgFilterType"] == 2  # Or
    [it] = grp["filterItems"]
    assert it["filterType"] == FT_IP and [v["value"] for v in it["values"]] == [
        "203.0.113.5",
        "198.51.100.7",
    ]  # de-duplicated, order kept
    assert all(
        v["valueType"] == 5 and isinstance(v["value"], str) for v in it["values"]
    )  # a string-typed IP makes the live search fail


def test_domain_hash_and_email_filters():
    dom = items_of(ioc_query_filter("domain", ["evil.example", "bad.example"]))
    assert [i["filterType"] for i in dom] == [FT_HOSTNAME, FT_HOSTNAME]  # exact host, then anything under it
    assert [v["value"] for v in dom[0]["values"]] == [
        {"matchType": 0, "value": "evil.example"},
        {"matchType": 0, "value": "bad.example"},
    ]
    assert [v["value"]["value"] for v in dom[1]["values"]] == ["%.evil.example", "%.bad.example"] and dom[1]["values"][
        0
    ]["value"]["matchType"] == 1
    h = items_of(ioc_query_filter("sha256", ["A" * 64]))[0]
    assert h["filterType"] == FT_HASH and [v["value"]["value"] for v in h["values"]] == [
        "a" * 64,
        "A" * 64,
    ]  # both cases: LogRhythm's casing is not known
    em = items_of(ioc_query_filter("email", ["x@evil.example"]))
    assert [i["filterType"] for i in em] == [FT_SENDER, 32]


def test_url_pattern_search_takes_exactly_one_value_because_the_live_api_fails_otherwise():
    [it] = items_of(ioc_query_filter("url_pattern", ["https://evil.example/a/b.exe"]))
    assert it["filterType"] == FT_URL and it["values"][0]["value"] == {
        "matchType": 1,
        "value": "%evil.example/a/b.exe%",
    }  # scheme dropped
    with pytest.raises(ValueError):
        ioc_query_filter("url_pattern", ["http://a.example/x", "http://b.example/y"])
    for bad in ("nope", "url"):
        with pytest.raises(ValueError):
            ioc_query_filter(bad, ["x"])
    with pytest.raises(ValueError):
        ioc_query_filter("ip", [])
    # no builder may ever put more than one URL-pattern item into a group
    for kind, vals in (
        ("domain", ["a.example", "b.example", "c.example"]),
        ("ip", ["1.1.1.1"]),
        ("sha1", ["a" * 40]),
        ("email", ["a@b.example"]),
    ):
        assert sum(1 for i in items_of(ioc_query_filter(kind, vals)) if i["filterType"] == FT_URL) == 0


# ---- the mock SIEM ---------------------------------------------------------------------------------------
def make_siem(logs):
    """Behaves like the live API where it matters: IP values must be plain strings; a group with several URL items fails; a log is returned if
    any filter value (or pattern) occurs in it."""
    seen = []

    def handler(request):
        body = json.loads(request.content)
        if request.url.path.endswith("search-task"):
            flt = body["queryFilter"]
            seen.append(flt)
            urls = [i for i in items_of(flt) if i["filterType"] == FT_URL]
            bad = len(urls) > 1 or any(
                v["valueType"] == 5 and not isinstance(v["value"], str) for i in items_of(flt) for v in i["values"]
            )
            hit = []
            for i in items_of(flt):
                for v in i["values"]:
                    val = v["value"]["value"] if isinstance(v["value"], dict) else v["value"]
                    needle = str(val).strip("%").lstrip(".").lower()
                    hit += [lg for lg in logs if needle and any(needle in str(x).lower() for x in lg.values())]
            tid = f"fail-{len(seen)}" if bad else f"ok-{len(seen)}"
            handler.results[tid] = list({id(x): x for x in hit}.values())
            return httpx.Response(200, json={"TaskId": tid})
        guid = body["data"]["searchGuid"]
        origin = body["data"]["paginator"]["origin"]
        if guid.startswith("fail"):
            return httpx.Response(200, json={"TaskStatus": "Search Failed", "Items": []})
        res = handler.results[guid]
        return httpx.Response(200, json={"TaskStatus": "Completed", "Items": res[origin : origin + 500]})

    handler.results = {}
    return handler, seen


def lr_log(i, **kw):
    base = {
        "messageId": f"m{i}",
        "logDate": int((NOW + timedelta(hours=1)).timestamp() * 1000),
        "classificationName": "Network Allowed Traffic",
        "commonEventName": "Connection",
        "priority": 20,
        "impactedHost": "srv1.corp.example",
        "login": "svc",
    }
    return {**base, **kw}


@pytest.fixture
async def setup(app, make, monkeypatch):
    async def nosleep(_):
        return None

    monkeypatch.setattr("app.connectors._http.asyncio.sleep", nosleep)
    monkeypatch.setattr("app.connectors.logrhythm._sleep", nosleep)
    monkeypatch.setattr(_http, "RESOLVER", _resolve)
    t = await make.tenant()

    async def install(handler, config=None):
        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(handler))
        async with app.state.sessionmaker() as db:
            db.add(
                DataSource(
                    tenant_id=t.id,
                    name=f"lr-{uuid.uuid4().hex[:6]}",
                    connector_type="logrhythm",
                    config={"base_url": "https://lr.example", "hostname": "dc1", **(config or {})},
                    secrets_enc=encrypt_json(get_settings(), {"token": "T"}),
                    enabled=False,
                )
            )
            await db.commit()

    return t, install


async def run_search(app, t, iocs):
    end = NOW
    async with app.state.sessionmaker() as db:
        return await hunting.search_logrhythm(
            db, app.state.search, get_settings(), t.id, iocs, end - timedelta(days=1), end
        )


async def test_indicators_are_batched_by_type_and_attributed_from_the_log_itself(app, setup):
    t, install = setup
    logs = [
        lr_log(1, originIp="203.0.113.5"),
        lr_log(2, impactedIp="198.51.100.7", url="http://x/y"),
        lr_log(3, originHost="host.evil.example"),
        lr_log(4, originIp="203.0.113.50"),
        lr_log(5, note="mentions 1.2.3.4.5 only"),
    ]
    handler, seen = make_siem(logs)
    await install(handler)
    ips = [
        ioc("ip", "203.0.113.5", tenant_id=t.id),
        ioc("ip", "198.51.100.7", tenant_id=t.id),
        ioc("ip", "192.0.2.99", tenant_id=t.id),
    ]
    dom = ioc("domain", "evil.example", tenant_id=t.id)
    res = await run_search(app, t, [*ips, dom])
    cov = res.coverage[0]
    assert (
        cov.status == "ok" and cov.iocs_searched == 4 and len(seen) == 3
    )  # all IPs in ONE search, domains in another, plus one exact-URL search for the domain (proxy logs)
    assert sum(1 for f in seen if items_of(f)[0]["filterType"] == FT_IP) == 1
    got = {(h.ioc.value, h.field) for h in res.hits}
    assert (
        ("203.0.113.5", "logrhythm:originIp") in got
        and ("198.51.100.7", "logrhythm:impactedIp") in got
        and ("evil.example", "logrhythm:originHost") in got
    )
    assert not any(
        h.ioc.value == "203.0.113.50" or h.ioc.value == "192.0.2.99" for h in res.hits
    )  # a look-alike address is not a match
    assert all(h.source == "logrhythm" and h.doc["source"] == "logrhythm" for h in res.hits)


async def test_urls_are_searched_through_their_host_and_must_appear_in_full(app, setup):
    t, install = setup
    logs = [
        lr_log(1, originIp="203.0.113.9", url="http://203.0.113.9:8080/bin/payload.sh"),
        lr_log(2, originIp="203.0.113.9", url="http://203.0.113.9:8080/other"),
        lr_log(3, originHost="dl.evil.example", url="https://dl.evil.example/a.exe"),
    ]
    handler, seen = make_siem(logs)
    await install(handler)
    u1 = ioc("url", "http://203.0.113.9:8080/bin/payload.sh", tenant_id=t.id)
    u2 = ioc("url", "https://dl.evil.example/a.exe", tenant_id=t.id)
    u3 = ioc("url", "https://dl.evil.example/never-seen.exe", tenant_id=t.id)
    res = await run_search(app, t, [u1, u2, u3])
    hits = {(h.ioc.value, h.doc["id"] and h.ioc.id == h.ioc.id) for h in res.hits}
    assert {h.ioc.value for h in res.hits} == {
        u1.value,
        u2.value,
    }  # u3 shares a host with a hit but its path never appears
    kinds = [items_of(f)[0]["filterType"] for f in seen]
    assert (
        FT_IP in kinds and FT_HOSTNAME in kinds and kinds.count(FT_URL) == 3
    )  # host batches + one exact-URL search each (never two URL items together)
    assert all(sum(1 for i in items_of(f) if i["filterType"] == FT_URL) <= 1 for f in seen)
    assert hits


async def test_url_pattern_searches_are_capped_and_the_report_says_so(app, setup):
    t, install = setup
    handler, seen = make_siem([lr_log(1)])
    await install(handler, {"url_pattern_max": 2})
    urls = [ioc("url", f"http://host{i}.evil.example/p{i}", tenant_id=t.id) for i in range(5)]
    res = await run_search(app, t, urls)
    assert sum(1 for f in seen if items_of(f)[0]["filterType"] == FT_URL) == 2
    assert "only the top 2 also by exact URL" in res.coverage[0].detail and res.coverage[0].status == "ok"


async def test_a_large_hunt_is_truncated_by_priority_and_flagged(app, setup):
    t, install = setup
    handler, seen = make_siem([lr_log(1)])
    await install(handler, {"ioc_search_max": 3, "ioc_batch": 2})
    many = [
        ioc("ip", f"203.0.113.{n}", tenant_id=t.id, confidence=10 + n, seen_count=5 if n == 1 else 0)
        for n in range(1, 8)
    ]
    res = await run_search(app, t, many)
    cov = res.coverage[0]
    assert (
        cov.status == "truncated"
        and cov.iocs_searched == 3
        and "3 of 7 indicators searched (highest priority first)" in cov.detail
    )
    searched = [v["value"] for f in seen for i in items_of(f) for v in i["values"]]
    assert (
        "203.0.113.1" in searched
        and "203.0.113.7" in searched
        and "203.0.113.6" in searched
        and "203.0.113.2" not in searched
    )  # seen-in-telemetry first, then confidence
    assert len(seen) == 2  # batches of two


async def test_types_without_a_logrhythm_filter_are_named_and_never_crash(app, setup):
    t, install = setup
    handler, seen = make_siem([lr_log(1)])
    await install(handler)
    res = await run_search(
        app, t, [ioc("ip", "203.0.113.5", tenant_id=t.id), ioc("certificate", "a" * 64, tenant_id=t.id)]
    )
    assert "no LogRhythm filter for: certificate" in res.coverage[0].detail and res.coverage[0].iocs_searched == 1


async def test_hash_and_email_batches_and_error_handling(app, setup):
    t, install = setup
    logs = [
        lr_log(1, hash="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
        lr_log(2, sender="a@evil.example"),
    ]
    handler, seen = make_siem(logs)
    await install(handler)
    res = await run_search(
        app,
        t,
        [
            ioc("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", tenant_id=t.id),
            ioc("email", "a@evil.example", tenant_id=t.id),
        ],
    )
    assert {h.ioc.type for h in res.hits} == {
        "sha256",
        "email",
    }  # the hash matched although LogRhythm stores it upper-case
    # an upstream failure is reported as a coverage error, not an exception
    await install(lambda r: httpx.Response(401, json={"error": "no"}))
    async with app.state.sessionmaker() as db:
        for ds in (await db.execute(select(DataSource).where(DataSource.tenant_id == t.id))).scalars():
            ds.name = ds.name  # (keep both sources; the second one fails)
    res2 = await run_search(app, t, [ioc("ip", "203.0.113.5", tenant_id=t.id)])
    assert any(c.status == "error" and "authentication rejected" in c.detail for c in res2.coverage)


def test_config_options_validate():
    c = registry.build("logrhythm", {"base_url": "https://lr.example"})
    assert (
        c.cfg.ioc_search is True
        and c.cfg.ioc_search_max == 200
        and c.cfg.ioc_batch == 25
        and c.cfg.url_pattern_max == 10
    )
    for bad in ({"ioc_batch": 0}, {"ioc_search_max": 99999}, {"url_pattern_max": -1}):
        with pytest.raises(Exception):  # noqa: B017, PT011
            registry.build("logrhythm", {"base_url": "https://lr.example", **bad})
    _ = Role
