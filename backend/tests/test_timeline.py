from datetime import UTC, datetime, timedelta

from app.auth.rbac import Role
from app.events.schema import Event
from app.investigations.timeline import build
from app.seed import synthetic
from tests.helpers import ev

T = "/api/v1/timeline"


def doc(minutes: float, **kw):
    e = Event.from_input(ev(minutes, **kw), __import__("uuid").uuid4())
    return e.to_document()


def test_process_lineage_reconstructed_from_pid_matching():
    word = doc(10, process={"name": "WINWORD.EXE", "pid": 10})
    ps = doc(9, process={"name": "powershell.exe", "pid": 20, "parent": {"name": "WINWORD.EXE", "pid": 10}})
    net = doc(
        8,
        event_type="network_connection",
        process={"name": "powershell.exe", "pid": 20},
        network={"dst_ip": "203.0.113.5", "dst_port": 443},
    )
    other = doc(
        8, host={"hostname": "OTHER"}, event_type="network_connection", process={"name": "powershell.exe", "pid": 20}
    )
    tl = build([net, other, ps, word])
    by_id = {e.id: e for e in tl.entries}
    assert [e.id for e in tl.entries][:2] == [word["id"], ps["id"]] or tl.entries[0].id == word["id"]
    assert by_id[ps["id"]].parent_event_id == word["id"]
    assert by_id[net["id"]].process_event_id == ps["id"]
    assert by_id[other["id"]].process_event_id is None  # same pid on another host is not the same process
    assert by_id[net["id"]].destination == "203.0.113.5:443"


def test_pid_reuse_requires_matching_name_and_order():
    old = doc(30, process={"name": "a.exe", "pid": 5})
    child = doc(10, process={"name": "b.exe", "pid": 6, "parent": {"name": "different.exe", "pid": 5}})
    assert build([old, child]).entries[1].parent_event_id is None


def test_repeated_activity_collapses_and_periodicity_measured():
    beats = [
        doc(
            100 - i,
            event_type="network_connection",
            process={"name": "p.exe", "pid": 1},
            network={"dst_ip": "203.0.113.5", "dst_port": 443},
        )
        for i in range(10)
    ]
    noise = doc(95.5, event_type="dns_query", dns={"question": "x.example"})
    tl = build([*beats, noise])
    grouped = [e for e in tl.entries if e.event_type == "network_connection"]
    assert len(grouped) == 1 and grouped[0].count == 10 and grouped[0].title.endswith("×10")
    assert (
        grouped[0].periodicity
        and grouped[0].periodicity.median_interval_s == 60.0
        and grouped[0].periodicity.jitter_pct < 1
    )
    assert tl.total_events == 11 and len(tl.entries) == 2
    assert len(build([*beats], collapse=False).entries) == 10


def test_gap_splits_groups_and_process_creations_never_collapse():
    a = [doc(120 - i, event_type="dns_query", dns={"question": "x.example"}) for i in range(3)]
    b = [doc(20 - i, event_type="dns_query", dns={"question": "x.example"}) for i in range(3)]
    assert len(build([*a, *b]).entries) == 2
    procs = [doc(5 - i / 10, process={"name": "cmd.exe", "pid": 100 + i}) for i in range(4)]
    assert len(build(procs).entries) == 4


async def _seed_attack(make):
    t = await make.tenant()
    raw = synthetic.generate(now=datetime.now(UTC), seed=7)
    backend = make.app.state.search
    events = [Event.from_input(e, t.id) for e in raw]
    for i in range(0, len(events), 500):
        assert not (await backend.index_events(events[i : i + 500])).failed
    await make.app.state.opensearch.indices.refresh(index=backend.pattern, ignore_unavailable=True)
    return t


async def test_timeline_over_seeded_attack_chain(client, make):
    t = await _seed_attack(make)
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    r = await client.post(
        T,
        headers=h,
        json={
            "query": {
                "text": "host.hostname:ws-fin-014 user.name:mharper",
                "time_range": {
                    "start": (datetime.now(UTC) - timedelta(hours=6)).isoformat(),
                    "end": datetime.now(UTC).isoformat(),
                },
            }
        },
    )
    assert r.status_code == 200, r.text
    tl = r.json()
    entries = tl["entries"]
    stamps = [e["timestamp"] for e in entries]
    assert stamps == sorted(stamps)
    titles = [e["title"] for e in entries]
    order = [
        next(i for i, x in enumerate(titles) if needle in x)
        for needle in [
            "logon",
            "WINWORD.EXE started",
            "powershell.exe started by WINWORD.EXE",
            "schtasks.exe started",
            "rundll32.exe started",
        ]
    ]
    assert order == sorted(order)
    ps = next(e for e in entries if e["title"].startswith("powershell.exe started"))
    word = next(e for e in entries if e["title"].startswith("WINWORD.EXE started"))
    assert ps["parent_event_id"] == word["id"]
    beacon = next(e for e in entries if e["count"] > 50)
    assert beacon["destination"] == "cdn-update-check.example:443" or beacon["destination"].startswith("203.0.113.45")
    assert beacon["periodicity"]["jitter_pct"] < 15 and 50 < beacon["periodicity"]["median_interval_s"] < 70
    assert beacon["process_event_id"] == ps["id"]


async def test_timeline_around_event_and_isolation(client, make):
    t = await _seed_attack(make)
    other = await make.tenant()
    _, h = await make.login_as(t, Role.SOC_ANALYST)
    _, ho = await make.login_as(other, Role.SOC_ANALYST)
    hit = (await client.post("/api/v1/events/search", headers=h, json={"text": "process.command_line:comsvcs"})).json()[
        "hits"
    ][0]
    r = await client.post(f"{T}/around", headers=h, json={"event_id": hit["id"], "window_minutes": 15})
    assert r.status_code == 200
    assert any(hit["id"] in e["event_ids"] for e in r.json()["entries"])
    assert {e["host"] for e in r.json()["entries"]} == {"WS-FIN-014"}
    assert (await client.post(f"{T}/around", headers=ho, json={"event_id": hit["id"]})).status_code == 404
    assert (await client.post(f"{T}/around", headers=h, json={"event_id": "zz"})).status_code == 422
    assert (await client.post(T, headers=ho, json={"query": {"text": "comsvcs"}})).json()["entries"] == []


async def test_timeline_limits_and_authz(client, make):
    t = await make.tenant()
    await make.index(
        t, [ev(i / 10 + 1, event_type="process_creation", process={"name": f"p{i}.exe", "pid": i}) for i in range(30)]
    )
    _, h = await make.login_as(t, Role.VIEWER)
    tl = (await client.post(T, headers=h, json={"query": {}, "limit": 10})).json()
    assert len(tl["entries"]) == 10 and tl["truncated"] is True
    assert (await client.post(T, headers=h, json={"query": {}, "limit": 1001})).status_code == 422
    assert (await client.post(T)).status_code in (401, 422)
