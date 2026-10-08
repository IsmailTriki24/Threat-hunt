# ruff: noqa: E501
"""Threat bulletins: grouping, ATT&CK resolution, TTP/IOA derivation, signal hunting, severity, batching, API."""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, update

from app.auth.rbac import Role
from app.connectors import _http
from app.core.config import get_settings
from app.iochunt import hunting, ioa_catalog, runner, threats
from app.iochunt.models import Ioc, IocHunt, Threat, ThreatIoa, ThreatTtp
from app.mitre.models import MitreSoftware
from tests.helpers import ev
from tests.mitre_helpers import mitre_loaded  # noqa: F401

API = "/api/v1/ioc"
NOW = datetime.now(UTC)
C2 = "198.51.100.150"


async def _resolve(host, port):
    return ["93.184.216.34"]


@pytest.fixture
def wire(monkeypatch):
    def install(handler):
        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(handler))
        monkeypatch.setattr(_http, "RESOLVER", _resolve)

    return install


def row(tenant, value, typ="ip", **kw):
    base = dict(
        tenant_id=tenant.id,
        type=typ,
        value=value,
        source="test-feed",
        confidence=70,
        first_seen=NOW,
        last_seen=NOW,
        status="NEW",
    )
    base.update(kw)
    return Ioc(**base)


async def seed(app, tenant, rows):
    async with app.state.sessionmaker() as db:
        for r in rows:
            db.add(r)
        await db.flush()
        await threats.sync(db, tenant.id)
        await db.commit()


async def _admin(client, make):
    t = await make.tenant()
    user, h = await make.login_as(t, Role.TENANT_ADMIN)
    return t, user, h


@pytest.fixture
async def attack_software(app, mitre_loaded):  # noqa: F811
    async with app.state.sessionmaker() as db:
        if (await db.get(MitreSoftware, "S9999")) is None:
            db.add(
                MitreSoftware(
                    id="S9999",
                    name="QakBot",
                    kind="malware",
                    aliases=["QakBot", "QBot", "Pinkslipbot"],
                    alias_keys=["qakbot", "qbot", "pinkslipbot"],
                    description="QakBot is a banking trojan that became a loader.",
                    technique_ids=["T1059.001", "T1071", "T1105"],
                    url="https://attack.mitre.org/software/S9999",
                )
            )
            db.add(
                MitreSoftware(
                    id="G9999",
                    name="Kimsuky",
                    kind="group",
                    aliases=["Kimsuky", "Velvet Chollima"],
                    alias_keys=["kimsuky", "velvetchollima"],
                    description="North Korean group.",
                    technique_ids=["T1566"],
                    url="",
                )
            )
        await db.commit()


# ---- naming / grouping --------------------------------------------------------------------------------
def test_names_are_normalised():
    assert threats.canonical_name("win.cobalt_strike") == "Cobalt Strike"
    assert threats.canonical_name("elf.mirai") == "Mirai"
    assert threats.canonical_name("  Mozi  ") == "Mozi" and threats.canonical_name("QakBot") == "QakBot"
    assert threats.canonical_name("x" * 500) == "x" * 200


async def test_indicators_are_grouped_under_their_threat_and_aliases_merge(app, make, attack_software):
    t = await make.tenant()
    await seed(
        app,
        t,
        [
            row(
                t,
                "198.51.100.1",
                threat_name="QakBot",
                threat_kind="malware",
                malware="QakBot",
                threat_type="botnet_cc",
                confidence=90,
            ),
            row(
                t, "198.51.100.2", threat_name="QBot", malware="QBot", confidence=60
            ),  # alias of the same ATT&CK software
            row(t, "evil.example", "domain", threat_name="win.vidar", malware="win.vidar"),
            row(t, "198.51.100.3", threat_name="Kimsuky", threat_kind="actor", confidence=75),
            row(
                t, "198.51.100.4", threat_name="", malware="", threat_type="payload_delivery", source="URLhaus"
            ),  # nothing known
            row(t, "https://x.example/a", "url", threat_name="Campaign: spring phishing", threat_kind="campaign"),
        ],
    )
    async with app.state.sessionmaker() as db:
        ts = {x.name: x for x in (await db.execute(select(Threat).where(Threat.tenant_id == t.id))).scalars()}
    assert set(ts) == {
        "QakBot",
        "Vidar",
        "Kimsuky",
        "Unattributed payload delivery (URLhaus)",
        "Campaign: spring phishing",
    }
    qak = ts["QakBot"]
    assert qak.ioc_count == 2 and qak.confidence == 90 and qak.mitre_id == "S9999" and qak.kind == "malware"
    assert ts["Kimsuky"].kind == "actor" and ts["Kimsuky"].mitre_id == "G9999" and ts["Vidar"].kind == "malware"
    assert (
        ts["Unattributed payload delivery (URLhaus)"].kind == "other"
        and ts["Campaign: spring phishing"].kind == "campaign"
    )
    assert "QakBot is a banking trojan" in qak.description and "MITRE ATT&CK: S9999" in qak.description
    assert qak.severity == "CRITICAL"  # C2 role at confidence >= 90


async def test_regrouping_is_idempotent_and_an_unnamed_threat_expires_when_its_indicators_do(app, make):
    t = await make.tenant()
    await seed(app, t, [row(t, "198.51.100.10", threat_name="Lonely")])
    async with app.state.sessionmaker() as db:
        assert await threats.sync(db, t.id) == 0  # nothing ungrouped left
        await db.execute(update(Ioc).where(Ioc.tenant_id == t.id).values(status="EXPIRED"))
        await threats.refresh(db, t.id)
        th = (await db.execute(select(Threat).where(Threat.tenant_id == t.id))).scalar_one()
        assert th.status == "EXPIRED" and th.ioc_count == 0
        await db.execute(update(Ioc).where(Ioc.tenant_id == t.id).values(status="NEW"))
        await threats.refresh(db, t.id)
        assert th.status == "NEW" and th.ioc_count == 1  # re-sighted indicators bring the bulletin back
        await db.commit()


# ---- TTPs and IOAs ------------------------------------------------------------------------------------
async def test_ttps_come_from_attack_the_feed_and_the_indicator_role_in_that_order_of_trust(app, make, attack_software):
    t = await make.tenant()
    await seed(
        app,
        t,
        [
            row(t, "198.51.100.20", threat_name="QakBot", threat_type="botnet_cc", techniques=["T1566", "T9999"]),
            row(t, "198.51.100.21", threat_name="QakBot", tags=["ransomware"]),
        ],
    )
    async with app.state.sessionmaker() as db:
        th = (await db.execute(select(Threat).where(Threat.tenant_id == t.id))).scalar_one()
        ttps = {
            x.technique_id: x
            for x in (await db.execute(select(ThreatTtp).where(ThreatTtp.threat_id == th.id))).scalars()
        }
    assert ttps["T1059.001"].source == "mitre" and ttps["T1059.001"].confidence == "HIGH"
    assert ttps["T1071"].source == "mitre"  # documented by ATT&CK beats the role-derived guess
    assert ttps["T1566"].source == "feed" and ttps["T1566"].confidence == "MEDIUM"
    assert ttps["T1486"].source == "derived" and ttps["T1486"].confidence == "LOW"
    assert "T9999" not in ttps  # unknown techniques are never invented


async def test_ioas_follow_the_ttps_from_the_catalogue_and_from_the_tenants_detection_rules(
    client, make, app, attack_software
):
    t, _, h = await _admin(client, make)
    rule = (
        await client.post(
            "/api/v1/detections/rules",
            headers=h,
            json={
                "format": "hunt_query",
                "content": "# title: Rare PS child\n# level: high\nprocess.name:powershell.exe process.command_line:amsi",
            },
        )
    ).json()
    async with app.state.sessionmaker() as db:
        await db.execute(
            update(__import__("app.detections.models", fromlist=["DetectionRule"]).DetectionRule)
            .where(
                __import__("app.detections.models", fromlist=["DetectionRule"]).DetectionRule.id
                == uuid.UUID(rule["id"])
            )
            .values(status="ACTIVE", techniques=["T1059.001"])
        )
        await db.commit()
    await seed(app, t, [row(t, "198.51.100.30", threat_name="QakBot", malware="QakBot")])
    async with app.state.sessionmaker() as db:
        th = (await db.execute(select(Threat).where(Threat.tenant_id == t.id))).scalar_one()
        ioas = (await db.execute(select(ThreatIoa).where(ThreatIoa.threat_id == th.id))).scalars().all()
    names = {i.name: i for i in ioas}
    assert (
        "PowerShell encoded command" in names and "File downloaded with certutil or bitsadmin" in names
    )  # T1059.001 / T1105
    assert (
        names["PowerShell encoded command"].source == "catalog"
        and names["Rule: Rare PS child"].source == "rule"
        and names["Rule: Rare PS child"].rule_id
    )
    assert "Scheduled task created from the command line" not in names  # unrelated technique


def test_the_ioa_catalogue_is_executable():
    assert len(ioa_catalog.CATALOG) >= 15
    for d in ioa_catalog.CATALOG:
        assert d.condition() and d.readable and d.severity in ("MEDIUM", "HIGH", "CRITICAL") and len(d.trend) < 1000, (
            d.name
        )
    assert (
        ioa_catalog.related("T1059.001", "T1059")
        and ioa_catalog.related("T1059", "T1059.001")
        and not ioa_catalog.related("T1059.001", "T1071")
    )
    enc = ioa_catalog.CATALOG[0].condition()
    # command lines are analysed text: tokens are matched inside the line (an any-of list would have required the *whole* line to equal a token)
    assert hunting.ioa_matches({"process": {"name": "powershell.exe", "command_line": "powershell -nop -enc AAA"}}, enc)
    assert hunting.ioa_matches(
        {"process": {"name": "PowerShell.exe", "command_line": "powershell.exe -EncodedCommand SQBF"}}, enc
    )
    assert not hunting.ioa_matches(
        {"process": {"name": "powershell.exe", "command_line": "powershell -File a.ps1"}}, enc
    )
    assert not hunting.ioa_matches({"process": {"name": "notepad.exe", "command_line": "notepad -enc"}}, enc)
    office = next(d for d in ioa_catalog.CATALOG if d.name.startswith("Office")).condition()
    assert hunting.ioa_matches({"process": {"name": "cmd.exe", "parent": {"name": "WINWORD.EXE"}}}, office)
    assert not hunting.ioa_matches({"process": {"name": "cmd.exe", "parent": {"name": "explorer.exe"}}}, office)


# ---- API: table, bulletin, validation -------------------------------------------------------------------
async def _threat_id(client, h, name):
    page = (await client.get(f"{API}/threats?q={name}", headers=h)).json()
    return next(i["id"] for i in page["items"] if i["name"] == name)


async def test_threat_table_filters_sort_and_bulletin(client, make, app, attack_software):
    t, _, h = await _admin(client, make)
    await seed(
        app,
        t,
        [
            row(
                t,
                f"198.51.100.{n}",
                threat_name="QakBot",
                malware="QakBot",
                confidence=80,
                seen_count=2 if n == 40 else 0,
            )
            for n in range(40, 45)
        ]
        + [
            row(t, "198.51.100.50", threat_name="Kimsuky", threat_kind="actor", confidence=60),
            row(t, "bad.example", "domain", threat_name="Vidar", malware="Vidar", confidence=95),
        ],
    )
    page = (await client.get(f"{API}/threats", headers=h)).json()
    assert (
        page["total"] == 3
        and page["facets"]["status"] == {"NEW": 3}
        and set(page["facets"]["kind"]) == {"malware", "actor"}
    )
    by_name = {i["name"]: i for i in page["items"]}
    assert (
        by_name["QakBot"]["ioc_count"] == 5
        and by_name["QakBot"]["ioc_types"] == {"ip": 5}
        and by_name["QakBot"]["ttp_count"] >= 3
        and by_name["QakBot"]["ioa_count"] >= 3
    )
    assert by_name["QakBot"]["seen_count"] == 2 and by_name["QakBot"]["new_ioc_count"] == 5
    assert page["items"][0]["name"] == "QakBot"  # already seen in the environment sorts first
    q = lambda qs: client.get(f"{API}/threats{qs}", headers=h)  # noqa: E731
    assert [i["name"] for i in (await q("?sort=confidence")).json()["items"]][0] == "Vidar"
    assert [i["name"] for i in (await q("?sort=iocs")).json()["items"]][0] == "QakBot"
    assert (
        (await q("?kind=actor")).json()["total"] == 1
        and (await q("?q=qak")).json()["total"] == 1
        and (await q("?min_confidence=90")).json()["total"] == 1
        and (await q("?seen=true")).json()["total"] == 1
    )
    assert (await q("?q=pinkslip")).json()["total"] == 1  # aliases are searchable
    b = (await client.get(f"{API}/threats/{by_name['QakBot']['id']}", headers=h)).json()
    assert (
        b["name"] == "QakBot"
        and "banking trojan" in b["description"]
        and len(b["iocs"]) == 5
        and b["iocs"][0]["seen_count"] == 2
    )
    t1059 = next(x for x in b["ttps"] if x["technique_id"] == "T1059.001")
    assert (
        t1059["name"] == "PowerShell"
        and t1059["source"] == "mitre"
        and "Execution" in " ".join(t1059["tactics"]).title()
    )
    assert (
        any(i["name"] == "PowerShell encoded command" and i["query_text"] and i["trend_query"] for i in b["ioas"])
        and b["hunts"] == []
    )
    more = (await client.get(f"{API}/threats/{by_name['QakBot']['id']}/iocs?limit=2&offset=3", headers=h)).json()
    assert more["total"] == 5 and len(more["items"]) == 2


async def test_validating_a_bulletin_hunts_indicators_behaviours_and_techniques_and_builds_the_case(
    client, make, app, attack_software
):
    t, user, h = await _admin(client, make)
    await make.index(
        t,
        [
            ev(
                30,
                event_type="network_connection",
                network={"dst_ip": C2, "dst_port": 443},
                host={"hostname": "WS-21"},
                user={"name": "erin"},
            ),
            ev(
                25,
                event_type="process_creation",
                process={"name": "powershell.exe", "command_line": "powershell.exe -nop -enc SQBFAFgA"},
                host={"hostname": "WS-21"},
            ),  # IOA, same host as the IOC hit
            ev(
                20,
                event_type="process_creation",
                process={"name": "powershell.exe", "command_line": "powershell.exe -enc AAA"},
                host={"hostname": "WS-22"},
            ),
            ev(
                15,
                event_type="alert",
                action="AIE: T1105",
                tags=["attack.t1105.001", "logrhythm"],
                host={"hostname": "WS-23"},
            ),  # TTP sighting tagged by a product
            ev(10, event_type="process_creation", process={"name": "notepad.exe"}, host={"hostname": "WS-24"}),
        ],
    )
    await seed(
        app,
        t,
        [
            row(t, C2, threat_name="QakBot", malware="QakBot", threat_type="botnet_cc", confidence=90),
            row(t, "198.51.100.151", threat_name="QakBot", malware="QakBot"),
        ],
    )
    tid = await _threat_id(client, h, "QakBot")
    hunt = await client.post(f"{API}/threats/{tid}/validate", headers=h, json={"lookback_days": 7})
    assert hunt.status_code == 201, hunt.text
    hunt = hunt.json()
    assert (
        hunt["threat_name"] == "QakBot"
        and hunt["status"] == "PENDING"
        and hunt["ioc_count"] == 2
        and "QakBot (malware)" in hunt["hypothesis"]
        and "attack indicator" in hunt["hypothesis"]
    )
    assert (
        await client.post(f"{API}/threats/{tid}/validate", headers=h, json={})
    ).status_code == 409  # already hunting
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())

    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["status"] == "COMPLETED" and done["match_count"] == 1 and done["signal_count"] >= 3 and done["case_id"]
    sig = done["signal_matches"]
    assert (
        {m["kind"] for m in sig} == {"ioa", "ttp"}
        and {m["host"] for m in sig if m["kind"] == "ioa"} == {"WS-21", "WS-22"}
        and any(m["ref"] == "T1105" and m["host"] == "WS-23" for m in sig)
    )
    assert "WS-24" not in {m["host"] for m in sig}
    cov = {c["kind"]: c for c in done["coverage"]}
    assert cov["ioa:local"]["hits"] == 2 and cov["ttp:local"]["hits"] >= 1

    case = (await client.get(f"/api/v1/cases/{done['case_id']}", headers=h)).json()
    assert case["title"].startswith("Threat hunt: QakBot") and case["status"] == "OPEN"
    assert case["severity"] == "CRITICAL"  # high-confidence C2 hit + attacker behaviour on the same host
    d = case["description"]
    for section in (
        "## Threat bulletin",
        "## Techniques (TTPs)",
        "## Behaviours (IOAs)",
        "## Findings",
        "## Recommendations",
    ):
        assert section in d, section
    assert (
        "banking trojan" in d
        and "PowerShell encoded command" in d
        and "T1059.001" in d
        and "Behavioural and technique findings" in d
    )
    assert case["evidence_count"] >= 4
    maps = {
        m["technique_id"]: m
        for m in (
            await client.get(f"/api/v1/mitre/mappings?object_type=case&object_id={done['case_id']}", headers=h)
        ).json()
    }
    assert (
        maps["T1105"]["confidence"] == "MEDIUM" and maps["T1105"]["evidence_event_ids"]
    )  # observed -> evidence-backed
    assert maps["T1059.001"]["confidence"] == "MEDIUM"  # the IOA hit evidences it
    # bulletin state moved on and shows its hunt and case
    b = (await client.get(f"{API}/threats/{tid}", headers=h)).json()
    assert (
        b["status"] == "VALIDATED"
        and b["case_id"] == done["case_id"]
        and b["case_number"]
        and len(b["hunts"]) == 1
        and b["new_ioc_count"] == 0
    )


async def test_behaviour_alone_raises_a_case_for_review_and_never_closes_it(client, make, app, attack_software):
    t, _, h = await _admin(client, make)
    await make.index(
        t,
        [
            ev(
                20,
                event_type="process_creation",
                process={"name": "powershell.exe", "command_line": "powershell.exe -enc AAA"},
                host={"hostname": "WS-31"},
            )
        ],
    )
    await seed(app, t, [row(t, "198.51.100.152", threat_name="QakBot", malware="QakBot")])
    tid = await _threat_id(client, h, "QakBot")
    hunt = (await client.post(f"{API}/threats/{tid}/validate", headers=h, json={})).json()
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert done["match_count"] == 0 and done["signal_count"] >= 1
    case = (await client.get(f"/api/v1/cases/{done['case_id']}", headers=h)).json()
    assert (
        case["status"] == "OPEN"
        and case["severity"] in ("LOW", "MEDIUM", "HIGH")
        and "Behaviour consistent with QakBot" in case["description"]
        and "no known indicator" in case["description"]
    )


async def test_exclusions_and_signal_switch_are_respected(client, make, app, attack_software):
    t, _, h = await _admin(client, make)
    await make.index(
        t,
        [
            ev(
                20,
                event_type="process_creation",
                process={"name": "powershell.exe", "command_line": "powershell.exe -enc AAA"},
                host={"hostname": "WS-41"},
            )
        ],
    )
    await seed(app, t, [row(t, "198.51.100.153", threat_name="QakBot"), row(t, "198.51.100.154", threat_name="QakBot")])
    tid = await _threat_id(client, h, "QakBot")
    b = (await client.get(f"{API}/threats/{tid}", headers=h)).json()
    keep, drop = b["iocs"][0]["id"], b["iocs"][1]["id"]
    hunt = (
        await client.post(
            f"{API}/threats/{tid}/validate", headers=h, json={"exclude_ioc_ids": [drop], "include_signals": False}
        )
    ).json()
    assert hunt["ioc_count"] == 1
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    assert (
        done["signal_count"] == 0
        and done["signal_matches"] == []
        and "ioa:local" not in {c["kind"] for c in done["coverage"]}
    )
    states = {i["id"]: i["status"] for i in (await client.get(f"{API}/iocs?limit=10", headers=h)).json()["items"]}
    assert states[keep] == "VALIDATED" and states[drop] == "NEW"  # the excluded indicator stays in the queue


async def test_reject_a_bulletin_and_manual_ioa_ttp_management(client, make, app, attack_software):
    t, _, h = await _admin(client, make)
    await seed(
        app,
        t,
        [
            row(t, "198.51.100.155", threat_name="Noisy"),
            row(t, "198.51.100.156", threat_name="Noisy"),
            row(t, "198.51.100.157", threat_name="Keep"),
        ],
    )
    tid = await _threat_id(client, h, "Noisy")
    assert (
        await client.post(f"{API}/threats/{tid}/reject", headers=h, json={"reason": "not relevant to a bank"})
    ).json() == {"rejected": 2}
    assert (await client.get(f"{API}/threats?status=REJECTED", headers=h)).json()["total"] == 1
    kid = await _threat_id(client, h, "Keep")
    bad = await client.post(f"{API}/threats/{kid}/ioas", headers=h, json={"name": "x", "query_text": "notafield:1"})
    assert bad.status_code == 400
    ok = await client.post(
        f"{API}/threats/{kid}/ioas",
        headers=h,
        json={
            "name": "Tool X",
            "technique_id": "T1059.003",
            "query_text": "process.name:toolx.exe",
            "severity": "HIGH",
        },
    )
    assert ok.status_code == 201 and ok.json()["source"] == "manual"
    assert (
        await client.post(
            f"{API}/threats/{kid}/ioas", headers=h, json={"name": "Tool X", "query_text": "process.name:toolx.exe"}
        )
    ).status_code == 409
    ttp = await client.post(f"{API}/threats/{kid}/ttps", headers=h, json={"technique_id": "T1059.001"})
    assert ttp.status_code == 201 and ttp.json()["name"] == "PowerShell" and ttp.json()["source"] == "manual"
    assert (
        await client.post(f"{API}/threats/{kid}/ttps", headers=h, json={"technique_id": "T0000"})
    ).status_code == 404  # well-formed but not an ATT&CK technique
    assert (
        await client.post(f"{API}/threats/{kid}/ttps", headers=h, json={"technique_id": "bogus"})
    ).status_code == 422
    b = (await client.get(f"{API}/threats/{kid}", headers=h)).json()
    assert any(
        i["name"] == "PowerShell encoded command" for i in b["ioas"]
    )  # adding a TTP links its built-in behaviours
    assert (await client.delete(f"{API}/threats/{kid}/ioas/{ok.json()['id']}", headers=h)).status_code == 204
    cat = next(i for i in b["ioas"] if i["source"] == "catalog")
    assert (await client.delete(f"{API}/threats/{kid}/ioas/{cat['id']}", headers=h)).status_code == 409


@pytest.mark.parametrize(
    "role,validate",
    [(Role.VIEWER, False), (Role.SOC_ANALYST, False), (Role.THREAT_HUNTER, False), (Role.TENANT_ADMIN, True)],
)
async def test_only_tenant_admins_validate_a_bulletin(client, make, app, role, validate):
    t, _, admin = await _admin(client, make)
    await seed(app, t, [row(t, "198.51.100.160", threat_name="Perm")])
    tid = await _threat_id(client, admin, "Perm")
    _, h = await make.login_as(t, role)
    assert (await client.get(f"{API}/threats", headers=h)).status_code == 200 and (
        await client.get(f"{API}/threats/{tid}", headers=h)
    ).status_code == 200
    assert (await client.post(f"{API}/threats/{tid}/validate", headers=h, json={})).status_code == (
        201 if validate else 403
    )
    assert (await client.post(f"{API}/threats/{tid}/reject", headers=h, json={})).status_code in (200, 403, 409)
    assert (await client.post(f"{API}/threats/regroup", headers=h)).status_code == (200 if validate else 403)


async def test_threats_are_tenant_private(client, make, app):
    a, _, ha = await _admin(client, make)
    _, _, hb = await _admin(client, make)
    await seed(app, a, [row(a, "198.51.100.161", threat_name="Secret")])
    tid = await _threat_id(client, ha, "Secret")
    assert (await client.get(f"{API}/threats", headers=hb)).json()["total"] == 0
    for m, path in (
        ("get", f"/threats/{tid}"),
        ("get", f"/threats/{tid}/iocs"),
        ("post", f"/threats/{tid}/validate"),
        ("post", f"/threats/{tid}/reject"),
    ):
        r = await (
            client.get(f"{API}{path}", headers=hb) if m == "get" else client.post(f"{API}{path}", headers=hb, json={})
        )
        assert r.status_code == 404, path


# ---- upstream behaviours, batching, backfill -------------------------------------------------------------
async def test_trend_upstream_runs_precise_behaviour_queries_and_verifies_results(
    client, make, app, wire, attack_software
):
    t, _, h = await _admin(client, make)
    seen = []

    def handler(request):
        seen.append(request.headers["tmv1-query"])
        good = {
            "uuid": "b-1",
            "eventId": "1",
            "eventSubId": 2,
            "eventTimeDT": (NOW - timedelta(hours=1)).isoformat(),
            "endpointHostName": "WS-51",
            "processName": "winword.exe",
            "objectName": "powershell.exe",
            "objectCmd": "powershell.exe -nop -enc AAA",
            "objectPid": 9,
            "logonUser": ["CORP\\fred"],
        }
        loose = {
            **good,
            "uuid": "b-2",
            "endpointHostName": "WS-52",
            "objectCmd": "powershell.exe -File ok.ps1",
        }  # the vendor query is looser than the IOA: must be rejected
        return httpx.Response(200, json={"items": [good, loose], "progressRate": 100})

    wire(handler)
    await client.post(
        "/api/v1/data-sources",
        headers=h,
        json={
            "name": "tm-ep",
            "connector_type": "trend_vision_one",
            "config": {"dataset": "endpoint_activity"},
            "secrets": {"api_key": "K"},
            "enabled": False,
        },
    )
    await seed(app, t, [row(t, "198.51.100.170", threat_name="QakBot", malware="QakBot")])
    tid = await _threat_id(client, h, "QakBot")
    hunt = (await client.post(f"{API}/threats/{tid}/validate", headers=h, json={})).json()
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())
    done = (await client.get(f"{API}/hunts/{hunt['id']}", headers=h)).json()
    trend_ioa = next(c for c in done["coverage"] if c["kind"] == "ioa:trend")
    assert trend_ioa["status"] == "ok" and trend_ioa["hits"] >= 1
    assert any("eventId:1" in q and "objectName" in q for q in seen)
    hosts = {m["host"] for m in done["signal_matches"] if m["kind"] == "ioa"}
    assert "WS-51" in hosts and "WS-52" not in hosts


async def test_a_large_threat_is_hunted_in_prioritised_batches(client, make, app, monkeypatch):
    t, _, h = await _admin(client, make)
    monkeypatch.setattr(runner, "MAX_IOCS_PER_HUNT", 5)
    await seed(
        app,
        t,
        [
            row(t, f"198.51.100.{n}", threat_name="Big", confidence=50 + n % 40, seen_count=3 if n == 99 else 0)
            for n in range(100, 112)
        ],
    )
    tid = await _threat_id(client, h, "Big")
    hunt = (await client.post(f"{API}/threats/{tid}/validate", headers=h, json={})).json()
    assert hunt["ioc_count"] == 5
    async with app.state.sessionmaker() as db:
        first = [
            str(i)
            for i in (await db.execute(select(IocHunt.ioc_ids).where(IocHunt.id == uuid.UUID(hunt["id"])))).scalar_one()
        ]
        validated = (
            (await db.execute(select(Ioc).where(Ioc.threat_id == uuid.UUID(tid), Ioc.status == "VALIDATED")))
            .scalars()
            .all()
        )
    assert len(validated) == 12  # the whole bulletin is on the watch list...
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())
    # ...and the remainder is queued immediately, never-hunted first
    assert await runner.schedule_rehunts(app.state.sessionmaker) == 1
    async with app.state.sessionmaker() as db:
        rh = (
            await db.execute(select(IocHunt).where(IocHunt.threat_id == uuid.UUID(tid), IocHunt.mode == "rehunt"))
        ).scalar_one()
        assert len(rh.ioc_ids) == 5 and not set(rh.ioc_ids) & set(first) and rh.lookback_days == 7
        await db.commit()
    await runner.process_pending(app.state.sessionmaker, app.state.search, get_settings())
    async with app.state.sessionmaker() as db:
        left = (
            (await db.execute(select(Ioc).where(Ioc.threat_id == uuid.UUID(tid), Ioc.last_hunted_at.is_(None))))
            .scalars()
            .all()
        )
    assert len(left) == 2


async def test_regroup_backfills_indicators_imported_before_bulletins_existed(client, make, app):
    t, _, h = await _admin(client, make)
    async with app.state.sessionmaker() as db:
        db.add(row(t, "198.51.100.180", threat_name="Legacy", malware="Legacy"))
        await db.commit()  # inserted without grouping, like pre-existing rows
    assert (await client.get(f"{API}/threats", headers=h)).json()["total"] == 0
    r = await client.post(f"{API}/threats/regroup", headers=h)
    assert r.status_code == 200 and r.json()["threats"] == 1
    assert (await client.get(f"{API}/threats", headers=h)).json()["items"][0]["name"] == "Legacy"
    assert (await client.get(f"{API}/ioa-catalog", headers=h)).json()[0]["technique"].startswith("T")
