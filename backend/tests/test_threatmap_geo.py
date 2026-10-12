"""IP classification, geolocation providers and search parsing: pure logic, no services needed."""

import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.threatmap.countries import COUNTRY_NAMES
from app.threatmap.geo import (
    CachedGeo,
    GeoPoint,
    MmdbProvider,
    NullProvider,
    build_provider,
    classify_ip,
    classify_with_own,
    is_internal,
    is_public,
)
from app.threatmap.service import event_severity, interval_for, ioc_severity, parse_search


@pytest.mark.parametrize(
    ("ip", "cls"),
    [
        ("8.8.8.8", "public"),
        ("185.220.101.5", "public"),
        ("2606:4700:4700::1111", "public"),
        ("10.1.2.3", "private"),
        ("172.16.8.106", "private"),
        ("192.168.0.1", "private"),
        ("fd00::1", "private"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.10.10", "link_local"),
        ("fe80::1", "link_local"),
        ("100.64.0.9", "cgnat"),
        ("224.0.0.5", "multicast"),
        ("0.0.0.0", "unspecified"),  # noqa: S104
        ("203.0.113.45", "reserved"),  # TEST-NET-3 documentation range: never geolocated
        ("198.51.100.7", "reserved"),
        ("240.0.0.1", "reserved"),
        ("::ffff:10.0.0.1", "private"),  # IPv4-mapped IPv6 is classified by its IPv4 address
        ("::ffff:8.8.8.8", "public"),
        ("not-an-ip", "invalid"),
        ("", "invalid"),
        (None, "invalid"),
        ("999.1.1.1", "invalid"),
    ],
)
def test_classify_ip(ip, cls):
    assert classify_ip(ip) == cls


def test_public_and_internal_predicates():
    assert is_public("8.8.8.8") and not is_public("10.0.0.1") and not is_public("203.0.113.1")
    assert is_internal("10.0.0.1") and is_internal("100.64.1.1") and not is_internal("8.8.8.8")
    assert not is_internal("203.0.113.1")  # reserved is neither public nor a local network


def test_own_address_space_is_not_remote():
    own = [ipaddress.ip_network("41.231.0.0/16"), ipaddress.ip_network("2001:db8::/32")]
    assert classify_with_own("41.231.5.5", own) == "own"
    assert classify_with_own("8.8.8.8", own) == "public"
    assert classify_with_own("10.0.0.1", own) == "private"
    assert classify_with_own("41.231.5.5", []) == "public"


class _Counting:
    name = "count"

    def __init__(self):
        self.calls = 0

    def lookup(self, ip):
        self.calls += 1
        return (
            GeoPoint("DE", "Germany", "EU", "Berlin", "", 52.5, 13.4, 64496, "Example AS") if ip == "8.8.8.8" else None
        )

    def info(self):
        return {"provider": "count"}


def test_lookups_are_cached_including_misses():
    p = _Counting()
    g = CachedGeo(p)
    for _ in range(5):
        assert g.lookup("8.8.8.8").country == "DE"
        assert g.lookup("1.1.1.1") is None
    assert p.calls == 2  # one resolution per distinct address, hit or miss


def test_provider_failure_never_breaks_a_request():
    class Boom(_Counting):
        def lookup(self, ip):
            raise RuntimeError("corrupt record")

    assert CachedGeo(Boom()).lookup("8.8.8.8") is None


def test_null_provider_and_missing_database_degrade_to_no_locations(tmp_path):
    assert NullProvider().lookup("8.8.8.8") is None
    assert build_provider("none", "x", "").info()["available"] is False
    p = build_provider("mmdb", str(tmp_path / "missing.mmdb"), "")
    assert isinstance(p, NullProvider)  # configured but absent: no crash, no invented data
    with pytest.raises(ValueError, match="unknown GEOIP_PROVIDER"):
        build_provider("bogus", "x", "")


_DB = Path(__file__).resolve().parents[2] / "data" / "geoip" / "dbip-city-lite.mmdb"


@pytest.mark.skipif(not _DB.is_file(), reason="GeoIP database not installed (scripts/fetch-geoip.sh)")
def test_mmdb_provider_resolves_public_and_refuses_private():
    asn = _DB.with_name("dbip-asn-lite.mmdb")
    p = MmdbProvider(str(_DB), str(asn))
    g = p.lookup("8.8.8.8")
    assert g and g.country == "US" and g.lat is not None and g.continent == "NA"
    if asn.is_file():
        assert g.asn == 15169
    for private in ("10.0.0.1", "127.0.0.1", "203.0.113.45", "192.168.1.1"):
        assert p.lookup(private) is None
    assert p.info()["attribution"]  # DB-IP requires attribution


def test_search_is_classified_before_it_is_used():
    names = COUNTRY_NAMES
    assert parse_search("8.8.8.8", names).ip == "8.8.8.8"
    assert parse_search("45.9.148.0/24", names).cidr is not None
    assert parse_search("AS15169", names).asn == 15169
    assert parse_search("15169", names).asn == 15169
    assert parse_search("de", names).country == "DE"
    assert parse_search("Germany", names).country == "DE"
    assert parse_search("12", names).text == "12"  # too short to be an AS number
    t = parse_search("Cobalt Strike", names)
    assert t.text == "cobalt strike" and t.ip is None and t.asn is None
    assert parse_search("", names).text == ""


def test_severity_mapping():
    assert [event_severity(n) for n in (0, 19, 20, 40, 60, 80, 100)] == [
        "info",
        "info",
        "low",
        "medium",
        "high",
        "critical",
        "critical",
    ]
    assert ioc_severity(90, None) == "high" and ioc_severity(70, None) == "medium" and ioc_severity(30, None) == "low"
    assert ioc_severity(10, "CRITICAL") == "critical"  # the linked threat's severity wins
    assert ioc_severity(95, "bogus") == "high"


def test_timeline_bucket_size_follows_the_range():
    end = datetime(2026, 10, 12, tzinfo=UTC)
    assert interval_for(end - timedelta(hours=1), end)[0] == "5m"
    assert interval_for(end - timedelta(hours=24), end)[0] == "1h"
    assert interval_for(end - timedelta(days=7), end)[0] == "6h"
    assert interval_for(end - timedelta(days=30), end)[0] == "1d"
    assert interval_for(end - timedelta(days=90), end)[0] == "7d"
