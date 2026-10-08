"""Turn a finished IOC hunt into a case: a TaHiTI-style hunt report (hypothesis, scope, coverage, findings, MITRE, recommendations),
evidence, a linked platform Hunt with findings, and a verdict. No match => the case is closed with the coverage as its resolution
(unless coverage was incomplete, in which case it stays open so the gap is not hidden). A re-hunt appends new matches to the same case
and reopens it if it was closed."""

import uuid
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import Principal
from app.auth.rbac import Role
from app.cases import service as case_service
from app.cases.models import Case, CaseIoc
from app.events.search.base import SearchBackend
from app.events.summary import summarize
from app.hunts.models import Finding, Hunt
from app.iochunt.hunting import Coverage, Hit
from app.iochunt.models import Ioc, IocHunt
from app.mitre import suggest as mitre_suggest
from app.mitre.models import MitreMapping, MitreTechnique
from app.tenants.models import Tenant
from app.users.models import User

MAX_EVIDENCE = 100
MAX_IOC_ROWS = 40

THREAT_TECHNIQUES: dict[str, list[str]] = {
    "botnet_cc": ["T1071"],
    "c2": ["T1071"],
    "command_and_control": ["T1071"],
    "payload_delivery": ["T1105"],
    "malware_download": ["T1105"],
    "phishing": ["T1566"],
    "credential_phishing": ["T1566"],
}
TAG_TECHNIQUES: dict[str, list[str]] = {
    "ransomware": ["T1486"],
    "phishing": ["T1566"],
    "c2": ["T1071"],
    "botnet": ["T1071"],
}


def defang(value: str) -> str:
    v = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return v.replace(".", "[.]") if not v.startswith("hxxp") else v.replace(".", "[.]", 50)


def derived_techniques(ioc: Ioc) -> list[str]:
    out = list(ioc.techniques)
    out += THREAT_TECHNIQUES.get(ioc.threat_type.lower(), [])
    for tag in ioc.tags:
        out += TAG_TECHNIQUES.get(tag.lower(), [])
    return list(dict.fromkeys(t.upper() for t in out))


def severity_for(matched: list[Ioc], hosts: int, events: int) -> str:
    if not matched:
        return "INFO"
    score = max(i.confidence for i in matched)
    if any(
        i.threat_type.lower() in ("botnet_cc", "c2", "command_and_control")
        or "ransomware" in [t.lower() for t in i.tags]
        for i in matched
    ):
        score += 10
    if hosts > 1:
        score += 10
    if events > 5:
        score += 5
    return "CRITICAL" if score >= 95 else "HIGH" if score >= 70 else "MEDIUM" if score >= 45 else "LOW"


PRIORITY = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P4"}


async def automation_principal(session: AsyncSession, hunt: IocHunt) -> Principal:
    user = await session.get(User, hunt.requested_by) if hunt.requested_by else None
    return Principal(
        user_id=hunt.requested_by or uuid.UUID(int=0),
        email=user.email if user else "ioc-hunt-automation",
        role=Role.TENANT_ADMIN,
        tenant_id=hunt.tenant_id,
        is_super_admin=False,
    )


def coverage_table(coverage: list[Coverage]) -> str:
    rows = ["| Data source | Status | IOCs searched | Matches | Notes |", "|---|---|---|---|---|"]
    for c in coverage:
        rows.append(f"| {c.source} | {c.status} | {c.iocs_searched} | {c.hits} | {c.detail.replace('|', '/')[:160]} |")
    return "\n".join(rows)


def incomplete(coverage: list[Coverage]) -> list[str]:
    return [f"{c.source}: {c.detail or c.status}" for c in coverage if c.status in ("error", "truncated", "skipped")]


def render_report(
    *,
    tenant: str,
    hunt: IocHunt,
    iocs: list[Ioc],
    coverage: list[Coverage],
    groups: dict[str, list[Hit]],
    hosts: set[str],
    users: set[str],
    techniques: list[str],
    verdict: str,
    severity: str,
    events_total: int,
) -> str:
    start = (hunt.window_start or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M")
    end = (hunt.window_end or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M")
    feeds = sorted({i.source for i in iocs if i.source})
    out = [
        f"## Verdict\n\n**{verdict}** (severity {severity}). {len(iocs)} indicator(s) from {', '.join(feeds) or 'manual entry'} were checked "
        f"against {len([c for c in coverage if c.status != 'skipped'])} data source(s) for the period {start} to {end} UTC.\n"
    ]
    out.append(f"## Hypothesis\n\n{hunt.hypothesis}\n")
    out.append(
        "## Scope: indicators\n\n| Type | Indicator | Source | Confidence | First seen | Context |\n|---|---|---|---|---|---|"
    )
    for i in sorted(iocs, key=lambda x: -x.confidence)[:MAX_IOC_ROWS]:
        ctx = ", ".join(x for x in [i.malware, i.threat_type, *i.tags[:3]] if x)[:80]
        out.append(
            f"| {i.type} | `{defang(i.value)}` | {i.source} | {i.confidence} | {i.first_seen:%Y-%m-%d} | {ctx} |"
        )
    if len(iocs) > MAX_IOC_ROWS:
        out.append(f"\n…and {len(iocs) - MAX_IOC_ROWS} more (see the hunt record).")
    out.append("\n## Data sources and coverage\n\n" + coverage_table(coverage) + "\n")
    if groups:
        out.append(
            f"## Findings\n\n{events_total} event(s) matched {len(groups)} indicator(s) on {len(hosts)} host(s)"
            + (f" involving {len(users)} account(s)" if users else "")
            + ".\n"
        )
        for hs in groups.values():
            ioc = hs[0].ioc
            times = sorted(h.doc["timestamp"] for h in hs)
            h_set = sorted({str((h.doc.get("host") or {}).get("hostname") or "?") for h in hs})
            out.append(
                f"- **{ioc.type} `{defang(ioc.value)}`**: {len(hs)} event(s), {times[0]} to {times[-1]}; hosts: {', '.join(h_set[:6])}"
                + (f"; {ioc.malware}" if ioc.malware else "")
                + (f"; matched field `{hs[0].field}`" if hs[0].field else "")
            )
    else:
        out.append("## Findings\n\nNo event in the searched sources contained any of these indicators.\n")
    if hosts:
        out.append(
            "## Affected assets\n\n"
            + ", ".join(f"`{h}`" for h in sorted(hosts)[:30])
            + ("\n" if not users else "\n\nAccounts seen: " + ", ".join(f"`{u}`" for u in sorted(users)[:20]) + "\n")
        )
    if techniques:
        out.append(
            "## MITRE ATT&CK\n\n"
            + ", ".join(techniques)
            + " (see the case's ATT&CK mappings for reasoning and confidence).\n"
        )
    gaps = incomplete(coverage)
    out.append("## Recommendations\n")
    if groups:
        out += [
            "1. **Contain** the affected host(s) listed above until triaged (isolate via EDR) and review the surrounding activity (the case timeline).",
            "2. **Block** the matched indicators at the proxy / firewall / EDR and add them to the Suspicious Object List.",
            "3. **Reset credentials** for the accounts seen on those hosts if the match indicates execution or C2.",
            "4. **Scope**: the indicators stay on the watch list and are re-hunted automatically; new matches are appended here.",
        ]
    else:
        out += [
            "1. No action required for these indicators at this time.",
            f"2. The indicators remain on the watch list and are re-hunted every few hours for {30} days; any later match reopens this case.",
        ]
    if gaps:
        out.append(
            "\n**Coverage gaps (this verdict is not conclusive for them):**\n" + "\n".join(f"- {g}" for g in gaps)
        )
    out.append(f"\n---\n*Generated automatically by the IOC hunt `{hunt.name}` for {tenant}. Verify before acting.*")
    return "\n".join(out)


async def finalize(
    session: AsyncSession,
    backend: SearchBackend,
    hunt: IocHunt,
    iocs: list[Ioc],
    hits: list[Hit],
    new_hits: list[Hit],
    coverage: list[Coverage],
) -> Case | None:
    principal = await automation_principal(session, hunt)
    tenant = await session.get(Tenant, hunt.tenant_id)
    tenant_name = tenant.name if tenant else "the tenant"
    if hunt.mode == "rehunt":
        return await _append_rehunt(session, backend, hunt, iocs, new_hits, coverage, principal)

    groups: dict[str, list[Hit]] = defaultdict(list)
    for h in hits:
        groups[str(h.ioc.id)].append(h)
    matched_iocs = [hs[0].ioc for hs in groups.values()]
    hosts = {str((h.doc.get("host") or {}).get("hostname")) for h in hits if (h.doc.get("host") or {}).get("hostname")}
    users = {str((h.doc.get("user") or {}).get("name")) for h in hits if (h.doc.get("user") or {}).get("name")}
    severity = severity_for(matched_iocs, len(hosts), len(hits))
    gaps = incomplete(coverage)
    verdict = (
        "Indicators observed in the environment"
        if hits
        else (
            "No evidence found"
            if not [c for c in coverage if c.status == "error"]
            else "Inconclusive: a data source could not be searched"
        )
    )

    # derived ATT&CK techniques (declared by feeds / inferred from the indicator's role); evidence-backed upgrades below
    technique_ids: dict[str, list[Ioc]] = defaultdict(list)
    for i in iocs:
        for t in derived_techniques(i):
            technique_ids[t].append(i)
    known = set(
        (
            await session.execute(select(MitreTechnique.id).where(MitreTechnique.id.in_(list(technique_ids) or ["-"])))
        ).scalars()
    )

    platform_hunt = Hunt(
        tenant_id=hunt.tenant_id,
        title=hunt.name[:200],
        hypothesis=hunt.hypothesis,
        status="COMPLETED",
        time_start=hunt.window_start,
        time_end=hunt.window_end,
        data_sources=sorted({c.kind.split(":")[0] for c in coverage if c.status != "skipped"}),
        created_by=hunt.requested_by,
        conclusion=f"{verdict}. {len(hits)} event(s) matched.",
    )
    session.add(platform_hunt)
    await session.flush()

    # most relevant evidence first: highest-confidence indicators, newest events
    ordered = sorted(hits, key=lambda h: (-h.ioc.confidence, str(h.doc["timestamp"])), reverse=False)
    event_ids = list(dict.fromkeys(h.doc["id"] for h in sorted(ordered, key=lambda h: (-h.ioc.confidence,))))[
        :MAX_EVIDENCE
    ]

    title = (
        f"IOC hunt: {len(matched_iocs)} indicator(s) observed on {len(hosts)} host(s) - {hunt.name}"
        if hits
        else f"IOC hunt: no evidence found - {hunt.name}"
    )[:200]
    techniques_list = sorted(t for t in technique_ids if t in known)
    case = Case(
        tenant_id=hunt.tenant_id,
        number=await case_service.next_number(session, hunt.tenant_id),
        title=title,
        severity=severity,
        priority=PRIORITY[severity],
        description="",
        assignee_id=hunt.requested_by,
        hunt_id=platform_hunt.id,
        created_by=hunt.requested_by,
    )
    session.add(case)
    await session.flush()
    await session.refresh(case)
    await case_service.log(
        session,
        principal,
        case,
        "created",
        "Opened automatically by an IOC hunt",
        {"ioc_hunt": str(hunt.id), "iocs": len(iocs), "matches": len(hits)},
    )
    if event_ids:
        await case_service.add_evidence(session, backend, principal, case, event_ids, f"Matched IOC hunt '{hunt.name}'")
    for i in iocs:
        await session.execute(
            insert(CaseIoc)
            .values(
                id=uuid.uuid4(),
                tenant_id=hunt.tenant_id,
                case_id=case.id,
                type=i.type,
                value=i.value[:2048],
                source="manual",
                occurrences=len(groups.get(str(i.id), [])) or 1,
                context=f"IOC hunt: {i.source} ({i.confidence})"[:300],
            )
            .on_conflict_do_nothing(constraint="uq_case_ioc")
        )
    # findings on the platform hunt, one per matched indicator
    for hs in groups.values():
        ioc = hs[0].ioc
        evid = [
            {
                "id": h.doc["id"],
                "timestamp": h.doc["timestamp"],
                "summary": summarize(h.doc),
                "host": (h.doc.get("host") or {}).get("hostname"),
            }
            for h in hs[:20]
        ]
        session.add(
            Finding(
                tenant_id=hunt.tenant_id,
                hunt_id=platform_hunt.id,
                created_by=hunt.requested_by,
                title=f"IOC observed: {defang(ioc.value)}"[:200],
                description=f"{ioc.type} indicator from {ioc.source} (confidence {ioc.confidence}). {ioc.description}"[
                    :4000
                ],
                severity=severity_for([ioc], 1, len(hs)),
                evidence=evid,
            )
        )
    # ATT&CK: declared/inferred techniques; MEDIUM when an event actually evidences the indicator, LOW otherwise
    for tid in techniques_list:
        related = [i for i in technique_ids[tid]]
        ev = list(dict.fromkeys(h.doc["id"] for i in related for h in groups.get(str(i.id), [])))[:5]
        await _map(
            session,
            case,
            tid,
            "MEDIUM" if ev else "LOW",
            ev,
            (
                f"Indicator(s) tied to this technique were observed in telemetry (feed: {', '.join(sorted({i.source for i in related}))})."
                if ev
                else f"Declared by the threat feed for the indicator(s) in this hunt ({', '.join(sorted({i.source for i in related}))}); no matching telemetry, so low confidence."
            ),
            "suggestion",
        )
    if hits:
        docs = [h.doc for h in hits][:500]
        for sug in mitre_suggest.suggest(docs):
            if sug.technique_id in techniques_list:
                continue
            await _map(
                session,
                case,
                sug.technique_id,
                sug.confidence,
                sug.event_ids[:10],
                "; ".join(sug.reasoning)[:1000],
                "suggestion",
            )
            techniques_list.append(sug.technique_id)
    case.description = render_report(
        tenant=tenant_name,
        hunt=hunt,
        iocs=iocs,
        coverage=coverage,
        groups=groups,
        hosts=hosts,
        users=users,
        techniques=sorted(set(techniques_list)),
        verdict=verdict,
        severity=severity,
        events_total=len(hits),
    )
    # a clean, fully-covered hunt is closed with its coverage as the resolution; anything doubtful stays open
    if not hits and not gaps:
        await case_service.apply_transition(
            session,
            principal,
            case,
            "CLOSED",
            "No evidence of these indicators in any searched source. Coverage: "
            + "; ".join(f"{c.source} ({c.status})" for c in coverage),
        )
    elif not hits:
        await case_service.log(
            session,
            principal,
            case,
            "note",
            "Left open: coverage was incomplete, so 'no evidence' is not conclusive.",
            {"gaps": gaps},
        )
    now = datetime.now(UTC)
    for i in iocs:
        i.case_id, i.last_hunted_at = case.id, now
    hunt.case_id, hunt.hunt_id = case.id, platform_hunt.id
    return case


async def _map(
    session: AsyncSession, case: Case, technique: str, confidence: str, events: list[str], reasoning: str, source: str
) -> None:
    await session.execute(
        insert(MitreMapping)
        .values(
            id=uuid.uuid4(),
            tenant_id=case.tenant_id,
            technique_id=technique,
            object_type="case",
            object_id=case.id,
            confidence=confidence,
            reasoning=reasoning[:2000] or "n/a",
            evidence_event_ids=events,
            source=source,
        )
        .on_conflict_do_nothing(constraint="uq_mitre_mapping")
    )


async def _append_rehunt(
    session: AsyncSession,
    backend: SearchBackend,
    hunt: IocHunt,
    iocs: list[Ioc],
    new_hits: list[Hit],
    coverage: list[Coverage],
    principal: Principal,
) -> Case | None:
    now = datetime.now(UTC)
    for i in iocs:
        i.last_hunted_at = now
    case = await session.get(Case, hunt.case_id) if hunt.case_id else None
    if case is None or not new_hits:
        return case  # quiet re-check: nothing to say
    groups: dict[str, list[Hit]] = defaultdict(list)
    for h in new_hits:
        groups[str(h.ioc.id)].append(h)
    if case.status == "CLOSED":
        await case_service.apply_transition(
            session,
            principal,
            case,
            "INVESTIGATING",
            f"Reopened: {len(new_hits)} new event(s) now match watched indicator(s).",
        )
    event_ids = list(dict.fromkeys(h.doc["id"] for h in sorted(new_hits, key=lambda h: -h.ioc.confidence)))[
        :MAX_EVIDENCE
    ]
    await case_service.add_evidence(
        session, backend, principal, case, event_ids, f"New matches from re-hunt {now:%Y-%m-%d %H:%M} UTC"
    )
    lines = [f"{len(hs)} new event(s) for {hs[0].ioc.type} `{defang(hs[0].ioc.value)}`" for hs in groups.values()]
    await case_service.log(
        session,
        principal,
        case,
        "note",
        "Scheduled re-hunt found new activity:\n- " + "\n- ".join(lines),
        {"ioc_hunt": str(hunt.id)},
    )
    matched = [hs[0].ioc for hs in groups.values()]
    hosts = {
        str((h.doc.get("host") or {}).get("hostname")) for h in new_hits if (h.doc.get("host") or {}).get("hostname")
    }
    sev = severity_for(matched, len(hosts), len(new_hits))
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if order.index(sev) > order.index(case.severity):
        case.severity, case.priority = sev, PRIORITY[sev]
    return case
