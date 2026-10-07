import httpx
import pytest
import sqlalchemy as sa

from app.auth.rbac import Role
from app.intel.models import IntelProvider
from app.intel.providers import base
from tests.helpers import ev

I = "/api/v1/intel"  # noqa: E741
C2 = "203.0.113.45"


@pytest.fixture
def remote(monkeypatch):
    state = {"handler": lambda r: httpx.Response(404), "requests": []}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        return state["handler"](request)

    async def resolve(host, port):
        return {"internal.example": ["10.1.1.1"]}.get(host, ["93.184.216.34"])

    monkeypatch.setattr(base, "HTTP_TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(base, "RESOLVER", resolve)
    return state


async def _admin(make):
    t = await make.tenant()
    _, h = await make.login_as(t, Role.TENANT_ADMIN)
    return t, h


async def test_lookup_works_with_no_credentials_and_makes_no_network_calls(client, make, remote):
    t, h = await _admin(make)
    r = await client.post(f"{I}/lookup", headers=h, json={"value": "qzxjvkwpmtbh7r4n2.top"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["entity"]["type"] == "domain" and d["entity"]["verdict"] == "unknown"  # one weak heuristic never convicts
    assert {o["provider"] for o in d["observations"]} == {"heuristics", "watchlist"} - {"watchlist"} or d[
        "observations"
    ][0]["provider"] == "heuristics"
    skipped = {s["provider"]: s["reason"] for s in d["coverage"]["skipped"]}
    assert skipped["virustotal"] == "disabled" and "otx" in skipped
    assert remote["requests"] == []


async def test_watchlist_override_changes_verdict_and_is_explained(client, make):
    t, h = await _admin(make)
    e = (await client.post(f"{I}/lookup", headers=h, json={"value": C2})).json()["entity"]
    upd = await client.patch(
        f"{I}/entities/{e['id']}",
        headers=h,
        json={"watch_verdict": "malicious", "watch_confidence": 95, "notes": "seen in IR-42"},
    )
    d = upd.json()
    assert d["entity"]["verdict"] == "malicious" and d["entity"]["score"] >= 90
    assert any(b["provider"] == "watchlist" and b["contribution"] > 0 for b in d["score_breakdown"])
    cleared = (await client.patch(f"{I}/entities/{e['id']}", headers=h, json={"clear_watch": True})).json()
    assert cleared["entity"]["verdict"] in ("unknown", "benign") and cleared["entity"]["watch_verdict"] is None


async def test_configured_providers_are_used_corroborate_and_secrets_are_protected(client, make, remote, db):
    t, h = await _admin(make)
    remote["handler"] = lambda r: (
        httpx.Response(
            200, json={"query_status": "ok", "data": [{"malware_printable": "Cobalt Strike", "confidence_level": 90}]}
        )
        if "threatfox" in r.headers["host"]
        else httpx.Response(
            200, json={"pulse_info": {"count": 5, "pulses": [{"name": "p", "adversary": "APT-Fictional"}]}}
        )
        if "otx" in r.headers["host"]
        else httpx.Response(404)
    )
    put = await client.put(
        f"{I}/providers/threatfox", headers=h, json={"enabled": True, "secrets": {"auth_key": "SECRET-TF-KEY"}}
    )
    assert put.status_code == 200 and put.json()["configured"] is True and "SECRET-TF" not in put.text
    await client.put(f"{I}/providers/otx", headers=h, json={"enabled": True, "secrets": {"api_key": "SECRET-OTX"}})
    d = (await client.post(f"{I}/lookup", headers=h, json={"value": C2})).json()
    assert d["entity"]["verdict"] == "malicious" and d["coverage"]["answered"] >= 2
    assert {o["provider"] for o in d["observations"]} >= {"threatfox", "otx", "heuristics"}
    rel = {(r["kind"], r["other"]["type"], r["other"]["value"]) for r in d["relations"]}
    assert ("indicates", "malware", "cobalt strike") in rel and (
        "attributed-to",
        "threat_actor",
        "apt-fictional",
    ) in rel
    row = (
        await db.execute(
            sa.select(IntelProvider).where(IntelProvider.tenant_id == t.id, IntelProvider.provider == "threatfox")
        )
    ).scalar_one()
    assert b"SECRET-TF" not in bytes(row.secrets_enc)
    assert "SECRET" not in (await client.get(f"{I}/providers", headers=h)).text
    # cached: a second lookup makes no new calls; refresh=true does
    n = len(remote["requests"])
    await client.post(f"{I}/lookup", headers=h, json={"value": C2})
    assert len(remote["requests"]) == n
    await client.post(f"{I}/lookup", headers=h, json={"value": C2, "refresh": True})
    assert len(remote["requests"]) > n


async def test_failing_provider_degrades_gracefully(client, make, remote):
    t, h = await _admin(make)
    await client.put(f"{I}/providers/virustotal", headers=h, json={"enabled": True, "secrets": {"api_key": "K"}})
    await client.put(f"{I}/providers/urlhaus", headers=h, json={"enabled": True, "secrets": {"auth_key": "K"}})

    def handler(r):
        if "virustotal" in r.headers["host"]:
            raise httpx.ConnectError("boom")
        return httpx.Response(500)

    remote["handler"] = handler
    r = await client.post(f"{I}/lookup", headers=h, json={"value": "evil.example"})
    assert r.status_code == 200
    d = r.json()
    assert d["coverage"]["failed"] == 2 and d["entity"]["verdict"] == "unknown"
    errs = {o["provider"]: o["summary"] for o in d["observations"] if o["status"] == "error"}
    assert "network error" in errs["virustotal"] and "HTTP 500" in errs["urlhaus"]
    assert "boom" not in r.text


async def test_provider_config_validation_and_permissions(client, make):
    t, h = await _admin(make)
    _, analyst = await make.login_as(t, Role.SOC_ANALYST)
    _, viewer = await make.login_as(t, Role.VIEWER)
    assert (
        await client.put(
            f"{I}/providers/misp", headers=h, json={"config": {"url": "ftp://x"}, "secrets": {"api_key": "k"}}
        )
    ).status_code == 400
    assert (
        await client.put(
            f"{I}/providers/misp", headers=h, json={"config": {"url": "https://misp.example.org", "evil": 1}}
        )
    ).status_code == 400
    assert (await client.put(f"{I}/providers/otx", headers=h, json={"secrets": {"wrong": "k"}})).status_code == 400
    assert (
        await client.put(f"{I}/providers/heuristics", headers=h, json={})
    ).status_code == 404  # offline: not configurable
    assert (await client.put(f"{I}/providers/nope", headers=h, json={})).status_code == 404
    for hdr, code in ((analyst, 403), (viewer, 403)):
        assert (
            await client.put(f"{I}/providers/otx", headers=hdr, json={"secrets": {"api_key": "k"}})
        ).status_code == code
        assert (await client.post(f"{I}/providers/otx/test", headers=hdr)).status_code == code
        assert (await client.post(f"{I}/taxii/pull", headers=hdr)).status_code == code
    assert (await client.get(f"{I}/providers", headers=viewer)).status_code == 200
    assert (await client.post(f"{I}/lookup", headers=viewer, json={"value": C2})).status_code == 403
    assert (await client.post(f"{I}/lookup", headers=analyst, json={"value": C2})).status_code == 200
    assert (await client.post(f"{I}/lookup", headers=analyst, json={"value": "not an indicator!"})).status_code == 400
    assert (
        await client.post(f"{I}/lookup", headers=analyst, json={"value": C2, "providers": ["bogus"]})
    ).status_code == 400


async def test_provider_test_endpoint_reports_auth_failure_and_ssrf_block(client, make, remote):
    t, h = await _admin(make)
    await client.put(f"{I}/providers/otx", headers=h, json={"secrets": {"api_key": "bad"}})
    remote["handler"] = lambda r: httpx.Response(401)
    res = (await client.post(f"{I}/providers/otx/test", headers=h)).json()
    assert res["ok"] is False and "authentication" in res["detail"]
    await client.put(
        f"{I}/providers/misp",
        headers=h,
        json={"config": {"url": "https://internal.example"}, "secrets": {"api_key": "k"}},
    )
    res = (await client.post(f"{I}/providers/misp/test", headers=h)).json()
    assert res["ok"] is False and "outbound policy" in res["detail"]
    assert (await client.post(f"{I}/providers/virustotal/test", headers=h)).json() == {
        "ok": False,
        "detail": "not configured",
    }


async def test_entities_are_tenant_isolated(client, make):
    a, ha = await _admin(make)
    b, hb = await _admin(make)
    e = (await client.post(f"{I}/lookup", headers=ha, json={"value": C2})).json()["entity"]
    await client.patch(f"{I}/entities/{e['id']}", headers=ha, json={"watch_verdict": "malicious"})
    assert (await client.get(f"{I}/entities", headers=hb)).json() == []
    for method, url, body in [
        ("get", f"{I}/entities/{e['id']}", None),
        ("patch", f"{I}/entities/{e['id']}", {"notes": "x"}),
        ("delete", f"{I}/entities/{e['id']}", None),
        ("post", f"{I}/entities/{e['id']}/enrich", None),
        ("get", f"{I}/entities/{e['id']}/sightings", None),
        ("post", f"{I}/entities/{e['id']}/relations", {"dst_id": e["id"], "kind": "uses"}),
    ]:
        kw = {"json": body} if body is not None else {}
        assert (await getattr(client, method)(url, headers=hb, **kw)).status_code == 404, (method, url)
    # B's lookup of the same indicator starts from scratch — A's verdict and notes are not shared
    own = (await client.post(f"{I}/lookup", headers=hb, json={"value": C2})).json()["entity"]
    assert own["id"] != e["id"] and own["watch_verdict"] is None and own["verdict"] != "malicious"
    # relations cannot cross tenants
    mine = (await client.post(f"{I}/entities", headers=hb, json={"type": "malware", "value": "Emotet"})).json()[
        "entity"
    ]
    assert (
        await client.post(f"{I}/entities/{mine['id']}/relations", headers=hb, json={"dst_id": e["id"], "kind": "uses"})
    ).status_code == 404
    batch = (await client.post(f"{I}/lookup-batch", headers=hb, json={"items": [{"type": "ip", "value": C2}]})).json()
    assert batch[0]["verdict"] != "malicious"


async def test_manual_entities_relations_and_validation(client, make):
    t, h = await _admin(make)
    actor = (
        await client.post(
            f"{I}/entities", headers=h, json={"type": "threat_actor", "value": "APT-Fictional", "notes": "n"}
        )
    ).json()["entity"]
    mal = (
        await client.post(
            f"{I}/entities", headers=h, json={"type": "malware", "value": "Emotet", "watch_verdict": "malicious"}
        )
    ).json()["entity"]
    assert (
        await client.post(f"{I}/entities", headers=h, json={"type": "malware", "value": "Emotet"})
    ).status_code == 409
    assert (await client.post(f"{I}/entities", headers=h, json={"type": "ip", "value": "300.1.1.1"})).status_code == 400
    assert (
        await client.post(f"{I}/entities", headers=h, json={"type": "malware", "value": "<script>"})
    ).status_code == 400
    assert (
        await client.post(
            f"{I}/entities/{actor['id']}/relations", headers=h, json={"dst_id": mal["id"], "kind": "uses"}
        )
    ).status_code == 201
    assert (
        await client.post(
            f"{I}/entities/{actor['id']}/relations", headers=h, json={"dst_id": mal["id"], "kind": "uses"}
        )
    ).status_code == 409
    assert (
        await client.post(
            f"{I}/entities/{actor['id']}/relations", headers=h, json={"dst_id": actor["id"], "kind": "uses"}
        )
    ).status_code == 400
    rel = (await client.get(f"{I}/entities/{mal['id']}", headers=h)).json()["relations"]
    assert rel[0]["direction"] == "in" and rel[0]["other"]["value"] == "apt-fictional"
    assert (await client.delete(f"/api/v1/intel/relations/{rel[0]['id']}", headers=h)).status_code == 204
    assert (await client.get(f"{I}/entities", headers=h, params={"type": "malware", "q": "emo"})).json()[0][
        "value"
    ] == "emotet"
    assert (await client.get(f"{I}/entities", headers=h, params={"q": "%"})).json() == []


async def test_sightings_find_indicator_in_telemetry_per_tenant(client, make):
    a, ha = await _admin(make)
    b, hb = await _admin(make)
    await make.index(
        a,
        [
            ev(5, event_type="network_connection", host={"hostname": "WS-01"}, network={"dst_ip": C2, "dst_port": 443}),
            ev(
                4,
                event_type="dns_query",
                host={"hostname": "WS-02"},
                dns={"question": "cdn.evil.example", "answers": [C2]},
            ),
            ev(3, host={"hostname": "WS-01"}, process={"name": "x.exe", "hash": {"sha256": "a" * 64}}),
            ev(
                2,
                host={"hostname": "WS-03"},
                process={"name": "run.exe", "command_line": "curl http://cdn.evil.example/p"},
            ),
        ],
    )
    await make.index(
        b,
        [ev(5, event_type="network_connection", host={"hostname": "B-HOST"}, network={"dst_ip": C2, "dst_port": 443})],
    )
    ip = (await client.post(f"{I}/lookup", headers=ha, json={"value": C2})).json()["entity"]
    s = (await client.get(f"{I}/entities/{ip['id']}/sightings", headers=ha)).json()
    assert s["by_field"] == {"network.dst_ip": 1, "dns.answers": 1} and {h["key"] for h in s["hosts"]} == {
        "ws-01",
        "ws-02",
    }
    assert s["first_seen"] and len(s["recent"]) == 2
    h_ent = (await client.post(f"{I}/lookup", headers=ha, json={"value": "a" * 64})).json()["entity"]
    assert (await client.get(f"{I}/entities/{h_ent['id']}/sightings", headers=ha)).json()["total"] == 1
    url = (await client.post(f"{I}/lookup", headers=ha, json={"value": "http://cdn.evil.example/p"})).json()["entity"]
    assert (await client.get(f"{I}/entities/{url['id']}/sightings", headers=ha)).json()["by_field"]
    other = (await client.post(f"{I}/lookup", headers=hb, json={"value": C2})).json()["entity"]
    assert {
        h["key"] for h in (await client.get(f"{I}/entities/{other['id']}/sightings", headers=hb)).json()["hosts"]
    } == {"b-host"}


async def test_enrich_case_iocs_and_journal(client, make):
    t, h = await _admin(make)
    await make.index(
        t, [ev(5, event_type="network_connection", host={"hostname": "WS-01"}, network={"dst_ip": C2, "dst_port": 443})]
    )
    ids = [x["id"] for x in (await client.post("/api/v1/events/search", headers=h, json={})).json()["hits"]]
    case = (await client.post("/api/v1/cases", headers=h, json={"title": "c", "event_ids": ids})).json()
    ip = (await client.post(f"{I}/lookup", headers=h, json={"value": C2})).json()["entity"]
    await client.patch(
        f"{I}/entities/{ip['id']}", headers=h, json={"watch_verdict": "malicious", "watch_confidence": 90}
    )
    r = (await client.post(f"{I}/enrich-case/{case['id']}", headers=h)).json()
    assert r["checked"] >= 1 and r["malicious"] == 1 and r["results"][0]["verdict"] == "malicious"
    kinds = [a["kind"] for a in (await client.get(f"/api/v1/cases/{case['id']}/activity", headers=h)).json()]
    assert "iocs_enriched" in kinds
    other, ho = await _admin(make)
    assert (await client.post(f"{I}/enrich-case/{case['id']}", headers=ho)).status_code == 404


STIX = {
    "type": "bundle",
    "id": "bundle--1",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": f"[ipv4-addr:value = '{C2}']",
            "labels": ["malicious-activity"],
            "confidence": 85,
        },
        {
            "type": "indicator",
            "id": "indicator--2",
            "pattern": "[domain-name:value = 'evil.example']",
            "confidence": 90,
        },
        {"type": "malware", "id": "malware--1", "name": "Emotet"},
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "indicates",
            "source_ref": "indicator--1",
            "target_ref": "malware--1",
        },
    ],
}


async def test_stix_import_sets_watchlist_without_overriding_analyst_and_validates(client, make):
    t, h = await _admin(make)
    ip = (await client.post(f"{I}/lookup", headers=h, json={"value": C2})).json()["entity"]
    await client.patch(f"{I}/entities/{ip['id']}", headers=h, json={"watch_verdict": "benign", "watch_confidence": 99})
    r = (await client.post(f"{I}/import/stix", headers=h, json=STIX)).json()
    assert r["created"] == 1 and r["updated"] == 1 and r["named_objects"] == 1 and r["relations"] == 1
    d = (await client.get(f"{I}/entities/{ip['id']}", headers=h)).json()
    assert d["entity"]["watch_verdict"] == "benign"  # analyst decision wins over the feed
    dom = (await client.get(f"{I}/entities", headers=h, params={"q": "evil.example"})).json()[0]
    assert dom["verdict"] == "malicious" and "feed:stix-import" in dom["tags"]
    assert any(r["other"]["value"] == "emotet" for r in d["relations"])
    assert (await client.post(f"{I}/import/stix", headers=h, json={"type": "nope"})).status_code == 400
    big = {"type": "bundle", "objects": [{"type": "x", "id": f"x--{i}"} for i in range(5001)]}
    assert (await client.post(f"{I}/import/stix", headers=h, json=big)).status_code == 400
    _, viewer = await make.login_as(t, Role.VIEWER)
    assert (await client.post(f"{I}/import/stix", headers=viewer, json=STIX)).status_code == 403


async def test_taxii_pull_paginates_imports_and_blocks_internal_servers(client, make, remote):
    t, h = await _admin(make)
    assert (await client.post(f"{I}/taxii/pull", headers=h)).status_code == 400  # not configured
    cfg = {
        "enabled": True,
        "config": {"url": "https://taxii.example.org/root/", "collection_id": "col-1"},
        "secrets": {"bearer": "TOK"},
    }
    assert (await client.put(f"{I}/providers/taxii", headers=h, json=cfg)).status_code == 200
    pages = [
        {"more": True, "next": "p2", "objects": STIX["objects"][:2]},
        {"more": False, "objects": STIX["objects"][2:]},
    ]

    def handler(r):
        assert r.headers["authorization"] == "Bearer TOK" and "taxii+json" in r.headers["accept"]
        return httpx.Response(200, json=pages[1 if "next=p2" in str(r.url) else 0])

    remote["handler"] = handler
    res = await client.post(f"{I}/taxii/pull", headers=h)
    assert res.status_code == 200 and res.json()["created"] == 2 and len(remote["requests"]) == 2
    prov = {p["key"]: p for p in (await client.get(f"{I}/providers", headers=h)).json()}["taxii"]
    assert prov["last_status"] == "ok"
    await client.put(
        f"{I}/providers/taxii",
        headers=h,
        json={**cfg, "config": {"url": "https://internal.example/", "collection_id": "c"}},
    )
    bad = await client.post(f"{I}/taxii/pull", headers=h)
    assert bad.status_code == 400 and "not allowed" in bad.text
