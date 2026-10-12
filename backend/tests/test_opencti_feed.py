# ruff: noqa: E501
"""OpenCTI feed adapter: GraphQL request shape, STIX-pattern parsing, provenance, paging and failure handling (mocked transport)."""

import json
from datetime import UTC, datetime

import httpx
import pytest

from app.connectors import _http
from app.connectors._http import SourceError
from app.iochunt import ingest
from app.iochunt.feeds import registry

NOW = datetime.now(UTC)


async def _resolve(host, port):
    return ["93.184.216.34"]


@pytest.fixture
def wire(monkeypatch):
    def install(handler):
        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(handler))
        monkeypatch.setattr(_http, "RESOLVER", _resolve)

    return install


def node(id_, pattern, **kw):
    return {
        "node": {
            "id": id_,
            "name": "n",
            "description": "C2 server",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": "2026-10-10T08:00:00.000Z",
            "valid_until": None,
            "created": "2026-10-09T08:00:00.000Z",
            "modified": "2026-10-11T09:30:00.000Z",
            "confidence": 60,
            "x_opencti_score": 85,
            "indicator_types": ["malicious-activity"],
            "objectLabel": [{"value": "emotet"}, {"value": "T1071"}],
            **kw,
        }
    }


def page(edges, end=None):
    return {"data": {"indicators": {"pageInfo": {"endCursor": end, "hasNextPage": bool(end)}, "edges": edges}}}


def build(**cfg):
    return registry.build("opencti", {"base_url": "https://cti.example", **cfg}, {"api_key": "TOKEN"})


async def test_query_is_authenticated_bounded_and_excludes_revoked(wire):
    seen = {}

    def h(request):
        seen["url"], seen["auth"], seen["body"] = (
            str(request.url),
            request.headers["authorization"],
            json.loads(request.content),
        )
        return httpx.Response(200, json=page([]))

    wire(h)
    assert await build().fetch(None, 14) == []
    assert seen["url"].endswith("/graphql") and seen["auth"] == "Bearer TOKEN"
    flt = seen["body"]["variables"]["filters"]["filters"]
    assert {"key": ["revoked"], "values": ["false"], "operator": "eq"} in flt
    modified = next(f for f in flt if f["key"] == ["modified"])
    assert modified["operator"] == "gt" and modified["values"][0] < NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert seen["body"]["variables"]["first"] == 200


async def test_stix_patterns_become_typed_indicators_with_provenance(wire):
    wire(
        lambda r: httpx.Response(
            200,
            json=page(
                [
                    node("a1", "[ipv4-addr:value = '185.220.101.5']"),
                    node("a2", "[domain-name:value = 'bad.example']"),
                    node("a3", "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"),
                    node(
                        "a4", "[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'x.example']"
                    ),  # compound: not one indicator
                    node("a5", "rule x { condition: true }", pattern_type="yara"),  # not STIX
                ]
            ),
        )
    )
    raws = await build().fetch(None, 14)
    assert [(r.type, r.value) for r in raws] == [
        ("ip", "185.220.101.5"),
        ("domain", "bad.example"),
        ("sha256", "a" * 64),
    ]
    r = raws[0]
    assert r.confidence == 85 and r.threat_type == "malicious-activity" and r.description == "C2 server"
    assert r.first_seen.isoformat().startswith("2026-10-10T08:00") and r.last_seen.isoformat().startswith(
        "2026-10-11T09:30"
    )
    assert r.reference == "https://cti.example/dashboard/observations/indicators/a1"
    assert r.tags[0] == "opencti" and "emotet" in r.tags and r.techniques == ["T1071"]


async def test_score_falls_back_to_confidence_and_is_clamped(wire):
    wire(
        lambda r: httpx.Response(
            200,
            json=page(
                [
                    node("a", "[ipv4-addr:value = '8.8.8.8']", x_opencti_score=None, confidence=70),
                    node("b", "[ipv4-addr:value = '8.8.4.4']", x_opencti_score=500),
                ]
            ),
        )
    )
    assert [r.confidence for r in await build().fetch(None, 14)] == [70, 100]


async def test_pages_are_followed_up_to_the_cap(wire):
    calls = []

    def h(request):
        body = json.loads(request.content)
        calls.append(body["variables"]["after"])
        n = len(calls)
        return httpx.Response(200, json=page([node(f"i{n}", f"[ipv4-addr:value = '8.8.8.{n}']")], end=f"c{n}"))

    wire(h)
    raws = await build(max_pages=3).fetch(None, 14)
    assert calls == [None, "c1", "c2"] and len(raws) == 3  # stops at max_pages even though the server has more


async def test_failures_are_clear_and_never_leak_the_token(wire):
    with pytest.raises(SourceError, match="no OpenCTI API token"):
        await registry.build("opencti", {"base_url": "https://cti.example"}, {}).fetch(None, 14)
    wire(lambda r: httpx.Response(200, json={"errors": [{"message": "FORBIDDEN_ACCESS"}], "data": None}))
    with pytest.raises(SourceError, match="rejected the query") as e:
        await build().fetch(None, 14)
    assert "TOKEN" not in str(e.value)
    wire(lambda r: httpx.Response(200, json={"data": {"unexpected": 1}}))
    with pytest.raises(SourceError, match="unexpected OpenCTI response"):
        await build().fetch(None, 14)
    wire(lambda r: httpx.Response(401, json={"error": "nope"}))
    with pytest.raises(SourceError):
        await build().fetch(None, 14)


async def test_shared_guard_rails_apply_to_opencti_indicators(wire):
    wire(
        lambda r: httpx.Response(
            200,
            json=page(
                [
                    node("a", "[ipv4-addr:value = '185.220.101.5']"),
                    node("b", "[ipv4-addr:value = '185.220.101.5']"),  # duplicate
                    node("c", "[ipv4-addr:value = '10.1.2.3']"),  # private: never an external indicator
                    node("d", "[domain-name:value = 'allowed.example']"),
                ]
            ),
        )
    )
    raws = await build().fetch(None, 14)
    items, res = ingest.prepare(
        raws, max_age_days=14, min_confidence=0, max_items=1000, allow=[("domain", "allowed.example")], now=NOW
    )
    assert [(i.type, i.value) for i in items] == [("ip", "185.220.101.5")]
    assert (
        sum(res.dropped.values()) >= 2
    )  # the private address and the allow-listed domain are dropped by the shared guard-rails


def test_feed_is_registered_with_its_secret_and_config_contract():
    cls = registry.FEEDS["opencti"]
    assert cls.needs_secret and cls.secret_names == ["api_key"]
    with pytest.raises(ValueError, match="base_url"):
        registry.build("opencti", {})
    with pytest.raises(ValueError):
        registry.build("opencti", {"base_url": "https://cti.example", "unknown": 1})
