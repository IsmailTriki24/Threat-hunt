# ruff: noqa: E501
"""Whole-SIEM search: every interactive search also asks LogRhythm for the indicators it contains, imports what matches, and says honestly what
it could and could not do. The mock SIEM is the same one that mirrors the live Search API for IOC hunts."""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.auth.rbac import Role
from app.connectors import _http
from app.core.config import get_settings
from app.core.crypto import encrypt_json
from app.datasources.models import DataSource
from app.events.search.query import EventQuery
from app.events.siem_search import classify, plan_for, plan_for_indicator
from tests import fake_console
from tests.test_logrhythm_ioc import lr_log, make_siem

API = "/api/v1/events"
NOW = datetime.now(UTC)


async def _resolve(host, port):
    return ["93.184.216.34"]


# ---- planning: what in a search can be asked of the SIEM ---------------------------------------------
def q(text=None, **kw):
    return EventQuery(text=text, **kw)


def test_indicator_filters_and_bare_indicators_become_siem_terms():
    p = plan_for(q("network.dst_ip:(51.89.20.151|8.8.8.8) dns.question:Evil.Example"))
    assert p.terms == {"ip": ["51.89.20.151", "8.8.8.8"], "domain": ["evil.example"]}
    p = plan_for(EventQuery(q="beacon 185.220.101.5 evil.example " + "a" * 64 + " ana@evil.example"))
    assert p.terms == {
        "ip": ["185.220.101.5"],
        "domain": ["evil.example"],
        "sha256": ["a" * 64],
        "email": ["ana@evil.example"],
    }
    assert plan_for(q("host.hostname:DC1-SRV-AD4")).terms == {"hostname": ["dc1-srv-ad4"]}
    assert plan_for(q("process.hash.md5:" + "c" * 32 + " file.hash.sha256:" + "d" * 64)).terms == {
        "md5": ["c" * 32],
        "sha256": ["d" * 64],
    }


def test_what_the_siem_cannot_be_asked_is_reported_and_kept_as_a_local_filter():
    p = plan_for(q("network.dst_ip:8.8.8.8 process.name:cmd.exe network.dst_port>=1024"))
    assert p.terms == {"ip": ["8.8.8.8"]}
    assert {f.field for f in p.rest} == {"process.name", "network.dst_port"}
    assert p.skipped and "process.name" in p.skipped[0] and "network.dst_port" in p.skipped[0]
    assert plan_for(q("powershell -enc")).terms == {}
    assert plan_for(q("-network.dst_ip:8.8.8.8")).terms == {}  # a negation is not something to search for


def test_values_are_deduplicated_and_capped_and_classification_is_strict():
    p = plan_for(q("network.dst_ip:(" + "|".join(f"10.0.0.{i}" for i in range(1, 101)) + ")"))
    assert len(p.terms["ip"]) == 50
    assert plan_for(q("network.dst_ip:8.8.8.8 network.src_ip:8.8.8.8")).terms == {"ip": ["8.8.8.8"]}
    assert [
        classify(x)
        for x in ("8.8.8.8", "a" * 40, "x@y.example", "sub.evil.example", "powershell", "999.1.1.1", "a" * 63)
    ] == ["ip", "sha1", "email", "domain", None, None, None]
    assert plan_for_indicator("ip", "1.2.3.4").terms == {"ip": ["1.2.3.4"]}


# ---- the endpoint against a mock SIEM -------------------------------------------------------------------
@pytest.fixture
async def siem(app, make, monkeypatch):
    async def nosleep(_):
        return None

    monkeypatch.setattr("app.connectors._http.asyncio.sleep", nosleep)
    monkeypatch.setattr("app.connectors.logrhythm_console._sleep", nosleep)
    monkeypatch.setattr(_http, "RESOLVER", _resolve)

    async def install(tenant, handler, *, enabled=True, config=None):
        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(handler))
        fake_console.install(monkeypatch, handler)
        async with app.state.sessionmaker() as db:
            db.add(
                DataSource(
                    tenant_id=tenant.id, name=f"lr-{uuid.uuid4().hex[:6]}", connector_type="logrhythm", enabled=enabled,
                    config={"base_url": "https://lr.example", "hostname": "dc1-only", **(config or {})},
                    secrets_enc=encrypt_json(get_settings(), {"token": "T"}),
                )
            )  # fmt: skip
            await db.commit()

    return install


async def search(client, h, text, **kw):
    body = {"text": text, **kw}
    return await client.post(f"{API}/siem-search", headers=h, json=body)


LOGS = [
    lr_log(1, impactedIp="51.89.20.151", originIp="10.240.136.2", commonEventName="AIE: C2: Blacklisted Egress Port"),
    lr_log(2, impactedIp="51.89.20.151", originIp="10.240.137.20", commonEventName="AIE: C2: Blacklisted Egress Port"),
    lr_log(3, impactedIp="51.89.20.152", originIp="10.0.0.9"),  # a neighbour address: must not match
    lr_log(4, note="mentions 51.89.20.1510 only"),  # a longer number: must not match
]


async def test_a_search_asks_the_whole_siem_and_imports_what_really_contains_the_indicator(client, make, siem):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    handler, seen = make_siem(LOGS)
    await siem(t, handler)
    r = await search(
        client,
        h,
        "network.dst_ip:51.89.20.151",
        time_range={"start": (NOW - timedelta(days=2)).isoformat(), "end": NOW.isoformat()},
    )
    body = r.json()
    assert r.status_code == 200 and body["status"] == "ok" and body["configured"] is True
    assert body["matched"] == 2 and body["imported"] == 2 and body["duplicates"] == 0
    assert body["searched"] == [
        {"kind": "ip", "values": ["51.89.20.151"], "logs": 3}
    ]  # LogRhythm returned 3; attribution kept the 2 that really contain it
    assert (
        len(seen) == 1
    )  # exactly one SIEM search, built with the verified IP filter, with no host restriction (the connector's hostname filter is NOT applied)
    assert "dc1-only" not in str(seen[0])
    assert len(body["samples"]) == 2 and all(
        set(x) == {"id", "timestamp", "summary", "host"} for x in body["samples"]
    )  # enough to show and link them
    # the imported logs are now ordinary events
    local = (
        await client.post(
            f"{API}/search",
            headers=h,
            json={
                "filters": [{"field": "source", "op": "eq", "value": "logrhythm"}],
                "time_range": {
                    "start": (NOW - timedelta(days=2)).isoformat(),
                    "end": (NOW + timedelta(hours=3)).isoformat(),
                },
            },
        )
    ).json()
    assert local["total"] == 2
    # searching again is idempotent: collection and search can never duplicate each other
    again = (
        await search(
            client,
            h,
            "network.dst_ip:51.89.20.151",
            time_range={"start": (NOW - timedelta(days=2)).isoformat(), "end": NOW.isoformat()},
        )
    ).json()
    assert again["matched"] == 2 and again["imported"] == 0 and again["duplicates"] == 2


async def test_remaining_filters_narrow_the_results_locally(client, make, siem):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    handler, _ = make_siem(LOGS)
    await siem(t, handler)
    body = (
        await search(
            client,
            h,
            "network.dst_ip:51.89.20.151 user.name:nobody-has-this",
            time_range={"start": (NOW - timedelta(days=2)).isoformat(), "end": NOW.isoformat()},
        )
    ).json()
    assert body["status"] == "ok" and body["matched"] == 0 and body["imported"] == 0
    assert "user.name" in body["skipped"][0]  # said, not silently dropped


async def test_a_search_with_nothing_to_look_up_does_not_touch_the_siem(client, make, siem):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    handler, seen = make_siem(LOGS)
    await siem(t, handler)
    body = (await search(client, h, "powershell -enc")).json()
    assert body["status"] == "not_applicable" and "IP addresses, domains, hashes" in body["detail"] and seen == []


async def test_unconfigured_disabled_and_switched_off_sources_are_reported_not_queried(client, make, siem):
    none = await make.tenant()
    _, h0 = await make.login_as(none, Role.SOC_ANALYST)
    r = (await search(client, h0, "network.dst_ip:8.8.8.8")).json()
    assert r["configured"] is False and r["status"] == "unconfigured"
    for kw, status in (({"enabled": False}, "unconfigured"), ({"config": {"siem_search": False}}, "disabled")):
        t = await make.tenant()
        _, h = await make.login_as(t, Role.SOC_ANALYST)
        handler, seen = make_siem(LOGS)
        await siem(t, handler, **kw)
        assert (await search(client, h, "network.dst_ip:8.8.8.8")).json()["status"] == status and seen == []


async def test_a_siem_failure_is_a_clean_status_not_a_500(client, make, siem):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    await siem(t, lambda request: httpx.Response(503, json={"error": "down"}))
    r = await search(client, h, "network.dst_ip:8.8.8.8")
    assert r.status_code == 200 and r.json()["status"] == "error" and r.json()["detail"] and "Traceback" not in r.text


async def test_the_siem_window_is_capped_and_says_so(client, make, siem):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    handler, _ = make_siem(LOGS)
    await siem(t, handler)
    body = (
        await search(
            client,
            h,
            "network.dst_ip:51.89.20.151",
            time_range={"start": (NOW - timedelta(days=60)).isoformat(), "end": NOW.isoformat()},
        )
    ).json()
    assert "at most the last 14 days" in body["detail"]
    assert (datetime.fromisoformat(body["window"]["end"]) - datetime.fromisoformat(body["window"]["start"])).days == 14


async def test_lookup_of_a_single_indicator_for_the_investigation_panel(client, make, siem):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    handler, _ = make_siem(LOGS)
    await siem(t, handler)
    r = await client.post(
        f"{API}/siem-lookup",
        headers=h,
        json={
            "kind": "ip",
            "value": "51.89.20.151",
            "time_range": {"start": (NOW - timedelta(days=2)).isoformat(), "end": NOW.isoformat()},
        },
    )
    assert r.status_code == 200 and r.json()["matched"] == 2
    for bad in (
        {"kind": "process", "value": "x"},
        {"kind": "ip", "value": ""},
        {"kind": "ip", "value": "x" * 600},
        {"kind": "ip", "value": "1.2.3.4", "extra": 1},
    ):
        assert (await client.post(f"{API}/siem-lookup", headers=h, json=bad)).status_code == 422


async def test_authorisation_audit_and_tenant_isolation(client, make, siem):
    a, b = await make.tenant(), await make.tenant()
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    admin = (await make.login_as(a, Role.TENANT_ADMIN))[1]
    _, hb = await make.login_as(b, Role.SOC_ANALYST)
    handler, _ = make_siem(LOGS)
    await siem(a, handler)
    assert (await client.post(f"{API}/siem-search", json={"text": "network.dst_ip:8.8.8.8"})).status_code == 401
    await search(
        client,
        ha,
        "network.dst_ip:51.89.20.151",
        time_range={"start": (NOW - timedelta(days=2)).isoformat(), "end": NOW.isoformat()},
    )
    rows = (await client.get("/api/v1/audit", headers=admin, params={"action": "event.siem_search"})).json()
    assert rows and rows[0]["details"]["terms"] == {"ip": ["51.89.20.151"]} and rows[0]["details"]["matched"] == 2
    # tenant B has no LogRhythm source and cannot use A's, nor see what A imported
    assert (await search(client, hb, "network.dst_ip:51.89.20.151")).json()["configured"] is False
    seen_b = (
        await client.post(
            f"{API}/search",
            headers=hb,
            json={
                "filters": [{"field": "source", "op": "eq", "value": "logrhythm"}],
                "time_range": {
                    "start": (NOW - timedelta(days=2)).isoformat(),
                    "end": (NOW + timedelta(hours=3)).isoformat(),
                },
            },
        )
    ).json()
    assert seen_b["total"] == 0
