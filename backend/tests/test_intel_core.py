from datetime import UTC, datetime, timedelta

import pytest

from app.intel import stix, types
from app.intel.providers.base import Context
from app.intel.providers.heuristics import HeuristicsProvider
from app.intel.scoring import Signal, score


# ---- scoring ------------------------------------------------------------------------------------------
def test_no_signals_is_unknown_not_benign():
    assert score([]) == (0, "unknown", [])


def test_corroboration_raises_score_and_single_weak_source_cannot_convict():
    one = score([Signal("otx", "malicious", 70)])
    two = score([Signal("otx", "malicious", 70), Signal("threatfox", "malicious", 80)])
    assert one[1] != "malicious" and two[0] > one[0] and two[1] == "malicious"
    assert score([Signal("heuristics", "suspicious", 55)])[1] == "unknown"


def test_watchlist_dominates_and_benign_dampens():
    assert score([Signal("watchlist", "malicious", 90)])[1] == "malicious"
    s, v, _ = score(
        [Signal("watchlist", "benign", 90), Signal("otx", "malicious", 70), Signal("virustotal", "malicious", 70)]
    )
    assert s <= 10 and v == "benign"
    damp, _, _ = score([Signal("virustotal", "benign", 80), Signal("otx", "malicious", 70)])
    assert damp < score([Signal("otx", "malicious", 70)])[0]


def test_breakdown_explains_every_signal_and_scores_are_bounded():
    s, _, b = score(
        [Signal("misp", "malicious", 500), Signal("urlhaus", "malicious", 100), Signal("virustotal", "malicious", -5)]
    )
    assert 0 <= s <= 100 and {x["provider"] for x in b} == {"misp", "urlhaus", "virustotal"}
    assert all("contribution" in x and "weight" in x for x in b)


# ---- types ------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("203.0.113.5", "ip"),
        ("a" * 64, "sha256"),
        ("b" * 40, "sha1"),
        ("c" * 32, "md5"),
        ("https://x.example/a", "url"),
        ("a@b.example", "email"),
        ("evil.example", "domain"),
        ("not a thing", None),
        ("999.1.1.1", None),
    ],
)
def test_detect_type(value, expected):
    assert types.detect_type(value) == expected


def test_named_and_certificate_normalisation():
    assert types.normalize("malware", "  Emotet ") == "emotet"
    assert types.normalize("threat_actor", "<script>") is None
    assert types.normalize("certificate", "AA:" * 31 + "AA") == "aa" * 32
    assert types.normalize("certificate", "xyz") is None


# ---- heuristics (offline) --------------------------------------------------------------------------------
async def h(type_, value):
    return await HeuristicsProvider().lookup(Context({}, {}), type_, value)


async def test_heuristics_signals_never_claim_malicious():
    for t, v in [
        ("domain", "xn--pple-43d.com"),
        ("domain", "qzxjvkwpmtbh7r4n2.top"),
        ("url", "http://203.0.113.5/payload.exe"),
        ("url", "http://good.example@evil.example/"),
        ("domain", "a.b.c.d.e.f.example.xyz"),
    ]:
        r = await h(t, v)
        assert r.status == "ok" and r.verdict == "suspicious" and r.confidence <= 60, (v, r)
    assert (await h("domain", "example.com")).status == "not_found"
    assert (await h("ip", "10.0.0.5")).verdict == "benign"
    assert (await h("ip", "203.0.113.5")).status == "not_found"
    assert (await h("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).verdict == "benign"


# ---- STIX ------------------------------------------------------------------------------------------------
def test_stix_patterns():
    assert stix.patterns("[ipv4-addr:value = '203.0.113.5']") == [("ip", "203.0.113.5")]
    assert stix.patterns("[domain-name:value = 'a.example' OR url:value = 'http://a.example/x']") == [
        ("domain", "a.example"),
        ("url", "http://a.example/x"),
    ]
    assert stix.patterns("[file:hashes.'SHA-256' = '" + "a" * 64 + "']") == [("sha256", "a" * 64)]
    assert stix.patterns("[file:hashes.MD5 = '" + "b" * 32 + "']") == [("md5", "b" * 32)]
    assert stix.patterns("[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'x.example']") == []
    assert stix.patterns("[process:name = 'x']") == []
    assert stix.patterns("[" + "a" * 3000 + "]") == []


def test_stix_parse_filters_expired_invalid_and_builds_relations():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    objs = [
        {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": "[ipv4-addr:value = '203.0.113.5']",
            "labels": ["malicious-activity"],
            "confidence": 85,
        },
        {
            "type": "indicator",
            "id": "indicator--2",
            "pattern": "[domain-name:value = 'old.example']",
            "valid_until": (now - timedelta(days=1)).isoformat(),
        },
        {"type": "indicator", "id": "indicator--3", "pattern": "[ipv4-addr:value = '999.1.1.1']"},
        {
            "type": "indicator",
            "id": "indicator--4",
            "pattern": "[domain-name:value = 'ok.example']",
            "labels": ["benign"],
        },
        {"type": "malware", "id": "malware--1", "name": "Emotet"},
        {"type": "malware", "id": "malware--2", "name": "<img onerror=x>"},
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "indicates",
            "source_ref": "indicator--1",
            "target_ref": "malware--1",
        },
        {
            "type": "relationship",
            "id": "relationship--2",
            "relationship_type": "weird",
            "source_ref": "a",
            "target_ref": "b",
        },
        "garbage",
        {"no": "id"},
        {"type": "indicator", "id": "indicator--5", "pattern": 5},
    ]
    p = stix.parse(objs, now)
    assert [(i.type, i.value, i.verdict, i.confidence) for i in p.indicators] == [
        ("ip", "203.0.113.5", "malicious", 85),
        ("domain", "ok.example", "benign", 60),
    ]
    assert p.named == [("malware--1", "malware", "emotet")]
    assert p.relations == [("indicator--1", "malware--1", "indicates")]
    assert p.skipped >= 4
