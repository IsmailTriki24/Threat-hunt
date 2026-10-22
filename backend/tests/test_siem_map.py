# ruff: noqa: E501, F811
"""Where the data lives: the map of LogRhythm log sources (role, type, host, last log), and asking only the sources that can answer."""

from datetime import UTC, datetime, timedelta

from app.events import siem_map as sm
from tests.test_ai import A, Scripted, conclude, llm, nb, results, tool  # noqa: F401
from tests.test_ai_agent import H1, _run
from tests.test_ai_siem import _hunter
from tests.test_ioc_sweep import wire  # noqa: F401
from tests.test_logrhythm_ioc import lr_log, make_siem

NOW = datetime.now(UTC).replace(microsecond=0)


def iso(hours_ago):
    return None if hours_ago is None else (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")


def src(i, name, tid, tname, host, hours_ago=1, status="Enabled"):
    return {
        "id": i, "name": name, "host": {"id": i, "name": host}, "entity": {"id": 1, "name": "HQ"},
        "logSourceType": {"id": tid, "name": tname}, "status": status, "recordStatus": "Active",
        "maxLogDate": iso(hours_ago) or "1900-01-01T00:00:00Z",
    }  # fmt: skip


SOURCES = [
    src(1, "web1 access", 101, "Apache HTTP Server Access", "web1", 0.1),
    src(2, "web2 access", 101, "Apache HTTP Server Access", "web2", 2),
    src(3, "edge asa", 202, "Syslog - Cisco ASA", "fw1", 0.2),
    src(4, "dc security", 303, "MS Windows Event Logging XML - Security", "dc1", 0.1),
    src(5, "agent procs", 404, "LogRhythm Process Monitor (Windows)", "pc7", 30),  # enabled but silent for a day
    src(6, "old proxy", 505, "Squid Proxy Access", "px1", None),  # never logged
    src(7, "off sw", 606, "Syslog - Cisco Switch", "sw1", 1, status="Disabled"),
]


def test_a_log_source_type_is_placed_in_the_role_of_logs_it_holds():
    for name, role in {
        "Apache HTTP Server Access": "web_server",
        "Microsoft IIS Web Server": "web_server",
        "Squid Proxy Access": "proxy_gateway",
        "Syslog - Cisco ASA": "firewall",
        "Syslog - Cisco Firepower Threat Defense": "firewall",
        "LogRhythm Process Monitor (Windows)": "endpoint_agent",
        "LogRhythm File Monitor (Linux)": "endpoint_agent",
        "MS Windows Event Logging XML - Security": "windows_events",
        "Syslog - Cisco Router": "network_device",
        "Oracle Database Audit": "database",
        "Something Unheard Of": "other",
    }.items():
        assert sm.role_of(name) == role, name


def lr_map():
    out = []
    for s in SOURCES:
        t = s["logSourceType"]
        newest = (
            None
            if s["maxLogDate"].startswith("1900")
            else datetime.fromisoformat(s["maxLogDate"].replace("Z", "+00:00"))
        )
        out.append(
            sm.Source(
                s["id"],
                s["name"],
                s["host"]["name"],
                "HQ",
                t["id"],
                t["name"],
                sm.role_of(t["name"]),
                s["status"] == "Enabled",
                newest,
            )
        )
    return sm.LrMap(out, 0)


def test_the_summary_counts_only_sources_that_are_really_logging_and_groups_them_by_role():
    out = sm.summary(lr_map())
    assert out["totals"] == {"log_sources": 7, "active": 4, "enabled_but_silent": 2, "never_logged": 1, "disabled": 1}
    roles = out["by_role"]
    assert (
        roles["web_server"]["active_sources"] == 2
        and roles["web_server"]["types"][0]["type"] == "Apache HTTP Server Access"
    )
    assert roles["web_server"]["types"][0]["example_hosts"] == ["web1", "web2"]
    assert (
        "proxy_gateway" not in roles and "endpoint_agent" not in roles
    )  # silent or never logged: LogRhythm cannot answer from them
    assert set(sm.summary(lr_map(), about="firewall asa")["by_role"]) == {"firewall"}


def test_a_host_with_no_log_source_or_only_silent_ones_is_called_a_blind_spot():
    m = lr_map()
    assert "NO log source for this host" in sm.summary(m, host="monsrv-01")["note"]
    silent = sm.summary(m, host="pc7")
    assert silent["log_sources_of_host"][0]["active"] is False and "blind spot" in silent["note"]
    ok = sm.summary(m, host="web1")
    assert ok["log_sources_of_host"][0]["role"] == "web_server" and "note" not in ok


def test_type_names_roles_and_parts_of_names_resolve_to_ids_and_unknown_ones_are_reported():
    m = lr_map()
    assert sm.resolve_types(m, ["Apache HTTP Server Access"]) == ([101], [])
    assert sm.resolve_types(m, ["apache", "cisco asa"]) == ([101, 202], [])
    assert sm.resolve_types(m, ["web_server"]) == ([101], [])
    assert sm.resolve_types(m, ["nginx", "web server"]) == ([101], ["nginx"])


# ---- through the agent -------------------------------------------------------------------------------------------------------
def web_and_fw_logs():
    return [
        lr_log(1, originIp="203.0.113.5", impactedHost="web1", msgSourceTypeId=101),
        lr_log(2, originIp="203.0.113.5", impactedHost="fw1", msgSourceTypeId=202),
    ]


async def test_siem_map_tells_the_agent_which_kinds_of_log_exist_and_siem_search_can_ask_only_those(
    client, make, llm, app, wire
):
    handler = make_siem(web_and_fw_logs())[0]
    handler.logsources = SOURCES
    wire(handler)
    t, h = await _hunter(make, app, None)
    p = llm(
        Scripted(
            nb(H1),
            tool("siem_map", about="web"),
            tool("siem_search", query="203.0.113.5", log_source_types=["Apache HTTP Server Access"], hypothesis="H1"),
            conclude([]),
        )
    )
    await _run(client, h, mode="quick")
    mapped = next(
        r["data"] for r in results(p.calls[2]["messages"]) if (r.get("data") or {}).get("logrhythm")
    )  # older results are compacted later
    seen = results(p.calls[-1]["messages"])
    assert (
        mapped["logrhythm"][0]["by_role"]["web_server"]["active_sources"] == 2
        and "firewall" not in mapped["logrhythm"][0]["by_role"]
    )
    found = next(r["data"] for r in seen if (r.get("data") or {}).get("sources") and "events" in r["data"])
    assert (
        found["total"] == 1 and found["events"][0]["host"]["hostname"] == "web1"
    )  # the firewall's log of the same IP was not asked for
    assert any(
        "Alarms are not narrowed" in n for n in found["sources"][0]["not_asked"]
    )  # and the 100+ per-alarm requests were not made


async def test_an_unknown_log_source_type_is_refused_with_the_way_out(client, make, llm, app, wire):
    handler = make_siem(web_and_fw_logs())[0]
    handler.logsources = SOURCES
    wire(handler)
    t, h = await _hunter(make, app, None)
    llm(
        Scripted(
            nb(H1), tool("siem_search", query="203.0.113.5", log_source_types=["nginx"], hypothesis="H1"), conclude([])
        )
    )
    run = await _run(client, h, mode="quick")
    step = next(s for s in run["steps"] if s.get("name") == "siem_search")
    assert step["status"] == "error" and "siem_map" in step["error"] and "nginx" in step["error"]


async def test_the_state_brief_names_the_active_kinds_of_log_from_the_start(client, make, llm, app, wire):
    handler = make_siem(web_and_fw_logs())[0]
    handler.logsources = SOURCES
    wire(handler)
    t, h = await _hunter(make, app, None)
    p = llm(Scripted(nb(H1), conclude([])))
    await _run(client, h, mode="quick")
    brief = str(p.calls[1]["messages"])
    roles = brief.split("ACTIVE LOG SOURCES BY ROLE")[1][:160]
    assert "web_server 2" in roles and "firewall 1" in roles and "windows_events 1" in roles
    assert "endpoint_agent" not in roles and "proxy_gateway" not in roles  # silent or never logged
