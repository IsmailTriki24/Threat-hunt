from datetime import UTC, datetime, timedelta

import pytest

from app.auth.rbac import Role
from app.events.search.opensearch import OpenSearchBackend, pick_interval
from app.events.search.query import EventQuery, TimeRange
from tests.helpers import ev


@pytest.fixture
async def data(make):
    t = await make.tenant()
    await make.index(
        t,
        [
            ev(
                1,
                host={"hostname": "WS-01", "ip": ["10.0.0.5"]},
                user={"name": "Alice"},
                process={"name": "powershell.exe", "pid": 100, "command_line": r"powershell.exe -NoP -enc SQBFAFgA"},
            ),
            ev(
                2,
                host={"hostname": "WS-02", "ip": ["10.0.1.9"]},
                user={"name": "bob"},
                process={"name": "cmd.exe", "pid": 200, "command_line": "cmd.exe /c whoami"},
            ),
            ev(
                3,
                event_type="network_connection",
                host={"hostname": "WS-01"},
                user={"name": "bob"},
                network={"src_ip": "10.0.0.5", "dst_ip": "203.0.113.45", "dst_port": 443, "dst_domain": "evil.example"},
            ),
            ev(
                4,
                event_type="authentication",
                source="windows",
                outcome="failure",
                host={"hostname": "DC-01"},
                auth={"logon_type": "network", "source_ip": "198.51.100.23"},
                user={"name": "carol"},
            ),
            ev(60 * 30, host={"hostname": "OLD-01"}),  # 30h ago: outside the default 24h window
        ],
    )
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    return h


async def search(client, h, **body):
    r = await client.post("/api/v1/events/search", headers=h, json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def test_default_window_is_24h(client, data):
    r = await search(client, data)
    assert r["total"] == 4


async def test_explicit_time_range(client, data):
    now = datetime.now(UTC)
    r = await search(
        client, data, time_range={"start": (now - timedelta(hours=48)).isoformat(), "end": now.isoformat()}
    )
    assert r["total"] == 5


async def test_full_text_matches_command_line_tokens(client, data):
    assert (await search(client, data, q="enc"))["total"] == 1
    assert (await search(client, data, q="powershell"))["total"] == 1
    assert (await search(client, data, q="whoami"))["hits"][0]["host"]["hostname"] == "WS-02"
    assert (await search(client, data, q="powershell AND whoami"))["total"] == 0
    assert (await search(client, data, q="powershell OR whoami"))["total"] == 2
    assert (await search(client, data, q="power*"))["total"] == 1


async def test_filters_are_case_insensitive_and_typed(client, data):
    f = lambda **k: {"filters": [k]}  # noqa: E731
    assert (await search(client, data, **f(field="host.hostname", op="eq", value="ws-01")))["total"] == 2
    assert (await search(client, data, **f(field="user.name", op="eq", value="ALICE")))["total"] == 1
    assert (await search(client, data, **f(field="process.name", op="in", value=["cmd.exe", "powershell.exe"])))[
        "total"
    ] == 2
    assert (await search(client, data, **f(field="host.hostname", op="neq", value="WS-01")))["total"] == 2
    assert (await search(client, data, **f(field="host.hostname", op="prefix", value="ws-")))["total"] == 3
    assert (await search(client, data, **f(field="process.command_line", op="contains", value="whoami")))["total"] == 1
    assert (await search(client, data, **f(field="network.dst_port", op="gte", value=400)))["total"] == 1
    assert (await search(client, data, **f(field="network.dst_ip", op="eq", value="203.0.113.0/24")))["total"] == 1
    assert (await search(client, data, **f(field="host.ip", op="eq", value="10.0.0.0/16")))["total"] == 2
    assert (await search(client, data, **f(field="network.dst_domain", op="exists")))["total"] == 1
    assert (await search(client, data, **f(field="network.dst_domain", op="not_exists")))["total"] == 3
    assert (await search(client, data, **f(field="outcome", op="eq", value="failure")))["total"] == 1


async def test_sorting_and_pagination(client, data):
    asc = await search(client, data, sort=[{"field": "timestamp", "order": "asc"}], limit=2)
    assert asc["total"] == 4 and len(asc["hits"]) == 2
    ts = [h["timestamp"] for h in asc["hits"]]
    assert ts == sorted(ts)
    page2 = await search(client, data, sort=[{"field": "timestamp", "order": "asc"}], limit=2, offset=2)
    assert {h["id"] for h in page2["hits"]}.isdisjoint({h["id"] for h in asc["hits"]})
    by_host = await search(client, data, sort=[{"field": "host.hostname", "order": "asc"}])
    assert by_host["hits"][0]["host"]["hostname"] == "DC-01"


async def test_aggregations(client, data):
    r = await search(
        client,
        data,
        limit=1,
        aggregations=[
            {"name": "by_host", "field": "host.hostname"},
            {"name": "by_type", "field": "event_type"},
            {"name": "over_time", "type": "date_histogram"},
        ],
    )
    hosts = {b["key"]: b["count"] for b in r["aggregations"]["by_host"]["buckets"]}
    assert hosts == {"ws-01": 2, "ws-02": 1, "dc-01": 1}
    assert sum(b["count"] for b in r["aggregations"]["over_time"]["buckets"]) == 4
    assert {b["key"] for b in r["aggregations"]["by_type"]["buckets"]} == {
        "process_creation",
        "network_connection",
        "authentication",
    }


async def test_raw_is_excluded_from_list_and_present_in_detail(client, make):
    t = await make.tenant()
    await make.index(t, [ev(raw={"Hashes": "SHA256=abc"})])
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    hit = (await search(client, h))["hits"][0]
    assert "raw" not in hit
    detail = (await client.get(f"/api/v1/events/{hit['id']}", headers=h)).json()
    assert detail["event"]["raw"] == {"Hashes": "SHA256=abc"}
    entities = {(p["entity"], p["field"]) for p in detail["pivots"]}
    assert ("host", "host.hostname") in entities and ("user", "user.name") in entities and ("ip", "host.ip") in entities


async def test_get_event_rejects_malformed_ids(client, data):
    for bad in ["x", "..%2f..", "A" * 32, "a" * 33]:
        assert (await client.get(f"/api/v1/events/{bad}", headers=data)).status_code == 404


async def test_empty_index_returns_empty_not_error(client, make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.VIEWER)
    r = await search(client, h, q="anything")
    assert r["total"] == 0 and r["hits"] == []


# ---- validation: the query model is the injection boundary ------------------------------------
@pytest.mark.parametrize(
    "body",
    [
        {"filters": [{"field": "process.name.keyword", "op": "eq", "value": "x"}]},  # not in registry
        {"filters": [{"field": "raw.anything", "op": "eq", "value": "x"}]},
        {"filters": [{"field": "host.hostname", "op": "script", "value": "x"}]},
        {"filters": [{"field": "host.hostname", "op": "gt", "value": "x"}]},  # op/kind mismatch
        {"filters": [{"field": "network.dst_port", "op": "eq", "value": "80; DROP"}]},
        {"filters": [{"field": "network.dst_ip", "op": "eq", "value": "not-an-ip"}]},
        {"filters": [{"field": "host.hostname", "op": "eq", "value": {"$ne": 1}}]},
        {"filters": [{"field": "host.hostname", "op": "in", "value": "single"}]},
        {"sort": [{"field": "process.command_line"}]},  # not sortable
        {"sort": [{"field": "_script"}]},
        {"aggregations": [{"name": "a", "field": "process.command_line"}]},  # not aggregatable
        {"aggregations": [{"name": "Bad Name!", "field": "host.hostname"}]},
        {"limit": 201},
        {"limit": 0},
        {"offset": 10000, "limit": 1},
        {"offset": -1},
        {"q": "x" * 513},
        {"query": {"match_all": {}}},  # raw DSL not accepted
        {"time_range": {"start": "2026-01-02T00:00:00Z", "end": "2026-01-01T00:00:00Z"}},
    ],
)
async def test_invalid_queries_rejected(client, data, body):
    r = await client.post("/api/v1/events/search", headers=data, json=body)
    assert r.status_code == 422, (body, r.text)


@pytest.mark.parametrize(
    "q",
    [
        '"}}]}} , {"match_all": {}',
        "\\",
        '"',
        "(((",
        "a" * 500,
        "-",
        "+++",
        "foo:bar",
        "_exists_:raw",
        "/regex.*(a+)+$/",
        "power~2",
        "*:*",
        "NOT",
        "process.name:*",
        "{{script}}",
    ],
)
async def test_hostile_free_text_never_errors_or_escapes_scope(client, data, q):
    r = await client.post("/api/v1/events/search", headers=data, json={"q": q})
    assert r.status_code == 200, (q, r.text)
    assert r.json()["total"] <= 4


async def test_wildcard_characters_in_contains_are_literal(client, data):
    r = await search(client, data, filters=[{"field": "host.hostname", "op": "contains", "value": "*"}])
    assert r["total"] == 0
    r = await search(client, data, filters=[{"field": "host.hostname", "op": "contains", "value": "?"}])
    assert r["total"] == 0


async def test_error_responses_do_not_leak_internals(client, data):
    r = await client.post("/api/v1/events/search", headers=data, json={"limit": "abc"})
    body = r.json()["error"]
    assert "input" not in str(body) and "Traceback" not in str(body)


# ---- compiler unit tests ------------------------------------------------------------------------
def test_compiled_query_keeps_tenant_filter_outside_user_clauses(app):
    import uuid

    backend: OpenSearchBackend = app.state.search
    tid = uuid.uuid4()
    body = backend.compile(
        tid, EventQuery.model_validate({"q": "x", "filters": [{"field": "host.hostname", "op": "neq", "value": "a"}]})
    )
    top = body["query"]["bool"]["filter"]
    assert top[0] == {"term": {"tenant_id": str(tid)}}
    assert "should" not in body["query"]["bool"] and "must_not" not in body["query"]["bool"]
    assert body["query"]["bool"]["filter"][2]["bool"]["must_not"]


def test_histogram_interval_scales_with_range():
    assert pick_interval(TimeRange.last(timedelta(hours=1))) == "1m"
    assert pick_interval(TimeRange.last(timedelta(hours=24))) == "30m"
    assert pick_interval(TimeRange.last(timedelta(days=45))) == "1d"


def test_query_translation_preserves_quotes():
    from app.events.search.opensearch import translate_query

    assert translate_query("a AND b OR c") == "a b | c"
    assert translate_query("NOT whoami powershell") == "-whoami powershell"
    assert translate_query('"x OR y" and') == '"x OR y" and'
