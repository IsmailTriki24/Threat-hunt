# ruff: noqa: E501
"""Contract between the UI's generated search links and the hunt query language.

The frontend (global search, threat-map "Investigate", etc.) builds `/events?lang=1&q=<field>:<value>` links. The language has no cross-field OR, so
each link must be one valid single-field term. These are the exact patterns of frontend/src/lib/global-search.ts; if the grammar changes or a field is
renamed, this test fails instead of the UI silently linking to a 422."""

import pytest

from app.events.search import dsl

# (field, sample value) for every scope in lib/global-search.ts SCOPES, with the quoting pivotTerm applies
SCOPES = [
    ("network.dst_ip", "185.220.101.5"), ("network.src_ip", "185.220.101.5"), ("auth.source_ip", "185.220.101.5"), ("host.ip", "185.220.101.5"),
    ("network.dst_ip", "2606:4700:4700::1111"),
    ("process.hash.sha256", "a" * 64), ("file.hash.sha256", "a" * 64), ("process.hash.sha1", "b" * 40), ("process.hash.md5", "c" * 32),
    ("network.dst_domain", "sub.evil-site.example"), ("dns.question", "evil.example"),
]  # fmt: skip


@pytest.mark.parametrize(("field", "value"), SCOPES)
def test_every_ui_scope_is_a_valid_single_field_query(field, value):
    text, filters = dsl.parse(f"{field}:{value}")
    assert text is None
    assert len(filters) == 1 and filters[0].field == field and filters[0].op == "eq"
    assert str(filters[0].value) == value


def test_cross_field_or_is_rejected_which_is_why_the_ui_offers_one_search_per_role():
    with pytest.raises(dsl.QueryParseError, match="OR works between free-text terms only"):
        dsl.parse("network.src_ip:1.2.3.4 OR network.dst_ip:1.2.3.4")


def test_same_field_alternatives_are_the_supported_way_to_widen():
    _, filters = dsl.parse("network.dst_ip:(1.2.3.4|5.6.7.8)")
    assert len(filters) == 1 and filters[0].op == "in"
