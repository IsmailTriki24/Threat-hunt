"""Turn a finished hunt into a case: a TaHiTI-style hunt report (bulletin, hypothesis, scope, coverage, findings, MITRE, recommendations),
evidence, a linked platform Hunt with findings, and a verdict.

* A known indicator observed is the strongest signal; a *behaviour* (IOA) or a technique-tagged event (TTP) alone is a lead for review and
  weighs less, but a behaviour on the same host as an indicator raises the severity.
* No evidence AND complete coverage => the case is closed with the coverage as its resolution; anything doubtful stays open.
* A re-hunt appends new evidence to the same case and reopens it if it was closed."""

import uuid
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import Principal
from app.auth.rbac import Role
from app.cases import service as case_service
from app.cases.models import Case, CaseIoc
from app.events.search.base import SearchBackend
from app.events.summary import summarize
from app.hunts.models import Finding, Hunt
from app.iochunt.hunting import Coverage, Hit, SignalHit, ttp_related
from app.iochunt.models import Ioc, IocHunt, Threat, ThreatIoa, ThreatTtp
from app.mitre import suggest as mitre_suggest
from app.mitre.models import MitreMapping, MitreTechnique
from app.tenants.models import Tenant
from app.users.models import User

MAX_EVIDENCE = 100
MAX_IOC_ROWS = 40
MAX_UNOBSERVED_MAPPINGS = 10
LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
PRIORITY = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P4"}

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


def signal_severity(sig: list[SignalHit], hosts: int) -> str:
    """Behaviour is weaker evidence than a known-bad indicator: an IOA's own severity is stepped down one level."""
    ioa = [h for h in sig if h.kind == "ioa"]
    if ioa:
        top = max(LEVELS.index(h.severity) if h.severity in LEVELS else 2 for h in ioa)
        return LEVELS[max(1, top - 1)]
    if sig:
        return "MEDIUM" if hosts > 2 else "LOW"
    return "INFO"


def bump(level: str) -> str:
    return LEVELS[min(len(LEVELS) - 1, LEVELS.index(level) + 1)]


def hosts_of(items: list[Hit] | list[SignalHit]) -> set[str]:
    return {str((h.doc.get("host") or {}).get("hostname")) for h in items if (h.doc.get("host") or {}).get("hostname")}


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
    rows = ["| Data source | Status | Searched | Matches | Notes |", "|---|---|---|---|---|"]
    for c in coverage:
        rows.append(f"| {c.source} | {c.status} | {c.iocs_searched} | {c.hits} | {c.detail.replace('|', '/')[:170]} |")
    return "\n".join(rows)


def incomplete(coverage: list[Coverage]) -> list[str]:
    return [f"{c.source}: {c.detail or c.status}" for c in coverage if c.status in ("error", "truncated", "skipped")]


class Context:
    """Everything a threat-scoped report needs besides the hits."""

    def __init__(
        self, threat: Threat | None, ttps: list[ThreatTtp], ioas: list[ThreatIoa], tech: dict[str, MitreTechnique]
    ) -> None:
        self.threat, self.ttps, self.ioas, self.tech = threat, ttps, ioas, tech


async def load_context(session: AsyncSession, hunt: IocHunt) -> Context:
    threat = await session.get(Threat, hunt.threat_id) if hunt.threat_id else None
    ttps: list[ThreatTtp] = []
    ioas: list[ThreatIoa] = []
    if threat is not None:
        want = {str(t).upper() for t in (hunt.signals or {}).get("ttps", [])}
        ttps = [
            t
            for t in (await session.execute(select(ThreatTtp).where(ThreatTtp.threat_id == threat.id))).scalars()
            if not want or t.technique_id in want
        ]
        ioa_ids = [uuid.UUID(i) for i in (hunt.signals or {}).get("ioa_ids", [])]
        if ioa_ids:
            ioas = list((await session.execute(select(ThreatIoa).where(ThreatIoa.id.in_(ioa_ids)))).scalars())
    ids = {t.technique_id for t in ttps} | {i.technique_id for i in ioas if i.technique_id}
    tech = {
        t.id: t
        for t in (
            await session.execute(select(MitreTechnique).where(MitreTechnique.id.in_(list(ids) or ["-"])))
        ).scalars()
    }
    return Context(threat, ttps, ioas, tech)


def render_report(
    *,
    tenant: str,
    hunt: IocHunt,
    iocs: list[Ioc],
    coverage: list[Coverage],
    groups: dict[str, list[Hit]],
    sig: list[SignalHit],
    ctx: Context,
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
    n_src = len([c for c in coverage if c.status not in ("skipped", "n/a")])
    what = f"{len(iocs)} indicator(s) from {', '.join(feeds) or 'manual entry'}" + (
        f", {len(ctx.ioas)} behaviour(s) and {len(ctx.ttps)} technique(s)" if ctx.threat else ""
    )
    out = [
        f"## Verdict\n\n**{verdict}** (severity {severity}). {what} were checked against {n_src} data source(s) for the period {start} to {end} UTC.\n"
    ]
    t = ctx.threat
    if t is not None:
        bits = [
            f"**{t.name}**",
            t.kind,
            f"confidence {t.confidence}",
            f"first reported {t.first_seen:%Y-%m-%d}" if t.first_seen else "",
            f"last updated {t.last_updated:%Y-%m-%d}" if t.last_updated else "",
        ]
        out.append(
            "## Threat bulletin\n\n"
            + " · ".join(b for b in bits if b)
            + (f"\n\nAlso known as: {', '.join(t.aliases)}" if t.aliases else "")
            + f"\n\n{t.description}\n"
            + (("\nReferences: " + ", ".join(t.references[:5]) + "\n") if t.references else "")
        )
    out.append(f"## Hypothesis\n\n{hunt.hypothesis}\n")
    out.append(
        "## Scope: indicators\n\n| Type | Indicator | Source | Confidence | First seen | Context |\n|---|---|---|---|---|---|"
    )
    for i in sorted(iocs, key=lambda x: -x.confidence)[:MAX_IOC_ROWS]:
        ctxs = ", ".join(dict.fromkeys(x for x in [i.malware, i.threat_type, *i.tags[:4]] if x))[:80]
        out.append(
            f"| {i.type} | `{defang(i.value)}` | {i.source} | {i.confidence} | {i.first_seen:%Y-%m-%d} | {ctxs} |"
        )
    if len(iocs) > MAX_IOC_ROWS:
        out.append(f"\n…and {len(iocs) - MAX_IOC_ROWS} more (see the hunt record).")
    if ctx.ttps:
        seen: dict[str, int] = defaultdict(int)
        for h in sig:
            if h.kind == "ttp":
                seen[h.ref] += 1
        out.append(
            "\n## Techniques (TTPs)\n\n| Technique | Name | Tactics | Basis | Events seen |\n|---|---|---|---|---|"
        )
        for tp in sorted(ctx.ttps, key=lambda x: (-seen[x.technique_id], x.technique_id))[:25]:
            m = ctx.tech.get(tp.technique_id)
            out.append(
                f"| {tp.technique_id} | {m.name if m else ''} | {', '.join(m.tactics) if m else ''} | {tp.source} ({tp.confidence.lower()}) | {seen[tp.technique_id]} |"
            )
    if ctx.ioas:
        counts: dict[str, int] = defaultdict(int)
        for h in sig:
            if h.kind == "ioa":
                counts[h.ref] += 1
        out.append("\n## Behaviours (IOAs)\n\n| Behaviour | Technique | Weight | Events |\n|---|---|---|---|")
        for ioa in sorted(ctx.ioas, key=lambda x: (-counts[str(x.id)], x.name)):
            out.append(f"| {ioa.name} | {ioa.technique_id} | {ioa.severity} | {counts[str(ioa.id)]} |")
    out.append("\n## Data sources and coverage\n\n" + coverage_table(coverage) + "\n")
    findings = []
    if groups:
        findings.append(
            f"{events_total} event(s) matched {len(groups)} known indicator(s) on {len(hosts)} host(s)"
            + (f" involving {len(users)} account(s)" if users else "")
            + ".\n"
        )
        for hs in groups.values():
            ioc = hs[0].ioc
            times = sorted(h.doc["timestamp"] for h in hs)
            h_set = sorted({str((h.doc.get("host") or {}).get("hostname") or "?") for h in hs})
            findings.append(
                f"- **{ioc.type} `{defang(ioc.value)}`**: {len(hs)} event(s), {times[0]} to {times[-1]}; hosts: {', '.join(h_set[:6])}"
                + (f"; {ioc.malware}" if ioc.malware else "")
                + (f"; matched field `{hs[0].field}`" if hs[0].field else "")
            )
    by_ref: dict[str, list[SignalHit]] = defaultdict(list)
    for h in sig:
        by_ref[f"{h.kind}:{h.ref}"].append(h)
    if by_ref:
        findings.append(
            "\nBehavioural and technique findings (leads for analyst review, weaker evidence than a known indicator):"
        )
        for _key, sgs in sorted(by_ref.items(), key=lambda kv: -len(kv[1]))[:15]:
            s_hosts = sorted({str((x.doc.get("host") or {}).get("hostname") or "?") for x in sgs})
            findings.append(
                f"- {'behaviour' if sgs[0].kind == 'ioa' else 'technique'} **{sgs[0].label}**: {len(sgs)} event(s) on {', '.join(s_hosts[:5])}"
            )
    out.append(
        "## Findings\n\n"
        + (
            "\n".join(findings)
            if findings
            else "No event in the searched sources contained any of these indicators, behaviours or techniques."
        )
        + "\n"
    )
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
    elif sig:
        out += [
            "1. **Review** the flagged hosts and the behaviours above: no known indicator of this threat matched, so confirm whether the activity is legitimate administration or tooling.",
            "2. If the behaviour is not expected, treat the host as suspicious: collect a triage image and check for the threat's known infrastructure.",
            "3. The threat stays on the watch list and is re-hunted automatically; new matches are appended here.",
        ]
    else:
        out += [
            "1. No action required for this threat at this time.",
            "2. It remains on the watch list and is re-hunted every few hours for 30 days; any later match reopens this case.",
        ]
    if gaps:
        out.append(
            "\n**Coverage gaps (this verdict is not conclusive for them):**\n" + "\n".join(f"- {g}" for g in gaps)
        )
    out.append(f"\n---\n*Generated automatically by the hunt `{hunt.name}` for {tenant}. Verify before acting.*")
    return "\n".join(out)


async def finalize(
    session: AsyncSession,
    backend: SearchBackend,
    hunt: IocHunt,
    iocs: list[Ioc],
    hits: list[Hit],
    new_hits: list[Hit],
    signal_hits: list[SignalHit],
    new_signal_hits: list[SignalHit],
    coverage: list[Coverage],
) -> Case | None:
    principal = await automation_principal(session, hunt)
    tenant = await session.get(Tenant, hunt.tenant_id)
    tenant_name = tenant.name if tenant else "the tenant"
    ctx = await load_context(session, hunt)
    if hunt.mode == "rehunt":
        return await _append_rehunt(session, backend, hunt, iocs, new_hits, new_signal_hits, coverage, principal)

    threat = ctx.threat
    groups: dict[str, list[Hit]] = defaultdict(list)
    for h in hits:
        groups[str(h.ioc.id)].append(h)
    matched_iocs = [hs[0].ioc for hs in groups.values()]
    ioc_hosts, sig_hosts = hosts_of(hits), hosts_of(signal_hits)
    hosts = ioc_hosts | sig_hosts
    all_hits: list[Hit | SignalHit] = [*hits, *signal_hits]
    users = {str((x.doc.get("user") or {}).get("name")) for x in all_hits if (x.doc.get("user") or {}).get("name")}
    severity = severity_for(matched_iocs, len(ioc_hosts), len(hits))
    if signal_hits:
        severity = max((severity, signal_severity(signal_hits, len(sig_hosts))), key=LEVELS.index)
        if hits and ioc_hosts & sig_hosts:  # known-bad indicator and attacker behaviour on the same host: corroboration
            severity = bump(severity)
    gaps = incomplete(coverage)
    if hits:
        verdict = "Indicators observed in the environment"
    elif signal_hits:
        verdict = f"Behaviour consistent with {threat.name if threat else 'this threat'} observed; no known indicators matched"
    elif [c for c in coverage if c.status == "error"]:
        verdict = "Inconclusive: a data source could not be searched"
    else:
        verdict = "No evidence found"

    technique_sources: dict[str, list[Ioc]] = defaultdict(list)
    for i in iocs:
        for t in derived_techniques(i):
            technique_sources[t].append(i)
    for tp in ctx.ttps:
        technique_sources.setdefault(tp.technique_id, [])
    known = set(
        (
            await session.execute(
                select(MitreTechnique.id).where(MitreTechnique.id.in_(list(technique_sources) or ["-"]))
            )
        ).scalars()
    )

    platform_hunt = Hunt(
        tenant_id=hunt.tenant_id,
        title=hunt.name[:200],
        hypothesis=hunt.hypothesis,
        status="COMPLETED",
        time_start=hunt.window_start,
        time_end=hunt.window_end,
        data_sources=sorted({c.kind.split(":")[0] for c in coverage if c.status not in ("skipped", "n/a")}),
        created_by=hunt.requested_by,
        conclusion=f"{verdict}. {len(hits)} indicator event(s), {len(signal_hits)} behaviour/technique event(s).",
    )
    session.add(platform_hunt)
    await session.flush()

    order_ioc = [h.doc["id"] for h in sorted(hits, key=lambda h: -h.ioc.confidence)]
    order_sig = [
        h.doc["id"]
        for h in sorted(
            signal_hits, key=lambda h: (h.kind != "ioa", -LEVELS.index(h.severity) if h.severity in LEVELS else 0)
        )
    ]
    event_ids = list(dict.fromkeys([*order_ioc, *order_sig]))[:MAX_EVIDENCE]

    if threat is not None:
        parts = [
            f"{len(matched_iocs)} indicator(s)" if hits else "",
            f"{len({h.ref for h in signal_hits if h.kind == 'ioa'})} behaviour(s)"
            if any(h.kind == "ioa" for h in signal_hits)
            else "",
        ]
        what = ", ".join(p for p in parts if p)
        title = (
            f"Threat hunt: {threat.name}: {what} observed on {len(hosts)} host(s)"
            if (hits or signal_hits)
            else f"Threat hunt: no evidence found - {threat.name}"
        )[:200]
    else:
        title = (
            f"IOC hunt: {len(matched_iocs)} indicator(s) observed on {len(hosts)} host(s) - {hunt.name}"
            if hits
            else f"IOC hunt: no evidence found - {hunt.name}"
        )[:200]
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
        "Opened automatically by a threat hunt" if threat else "Opened automatically by an IOC hunt",
        {
            "ioc_hunt": str(hunt.id),
            "iocs": len(iocs),
            "matches": len(hits),
            "signals": len(signal_hits),
            "threat": threat.name if threat else None,
        },
    )
    if event_ids:
        await case_service.add_evidence(session, backend, principal, case, event_ids, f"Matched hunt '{hunt.name}'")
    for i in iocs[:500]:
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
    ioa_groups: dict[str, list[SignalHit]] = defaultdict(list)
    for sh in signal_hits:
        if sh.kind == "ioa":
            ioa_groups[sh.ref].append(sh)
    for sgs in ioa_groups.values():
        evid = [
            {
                "id": x.doc["id"],
                "timestamp": x.doc["timestamp"],
                "summary": summarize(x.doc),
                "host": (x.doc.get("host") or {}).get("hostname"),
            }
            for x in sgs[:20]
        ]
        session.add(
            Finding(
                tenant_id=hunt.tenant_id,
                hunt_id=platform_hunt.id,
                created_by=hunt.requested_by,
                title=f"Behaviour observed: {sgs[0].label}"[:200],
                description=f"Attack behaviour matched {len(sgs)} event(s) (a lead, not proof)."[:4000],
                severity=sgs[0].severity if sgs[0].severity in LEVELS else "MEDIUM",
                evidence=evid,
            )
        )

    # ATT&CK: techniques evidenced by an event are MEDIUM (with that evidence); documented-but-unobserved ones are LOW and capped
    seen_by_tech: dict[str, list[str]] = defaultdict(list)
    for tid in technique_sources:
        for sh in signal_hits:
            if (sh.kind == "ttp" and ttp_related(sh.ref, tid)) or (
                sh.kind == "ioa"
                and any(i.id == uuid.UUID(sh.ref) and ttp_related(i.technique_id, tid) for i in ctx.ioas)
            ):
                seen_by_tech[tid].append(sh.doc["id"])
        for i in technique_sources[tid]:
            seen_by_tech[tid] += [h.doc["id"] for h in groups.get(str(i.id), [])]
    techniques_list: list[str] = []
    unobserved = 0
    for tid in sorted(t for t in technique_sources if t in known):
        ev = list(dict.fromkeys(seen_by_tech.get(tid, [])))[:5]
        if not ev:
            if unobserved >= MAX_UNOBSERVED_MAPPINGS:
                continue
            unobserved += 1
        src = ", ".join(sorted({i.source for i in technique_sources[tid]})) or (threat.name if threat else "the feed")
        basis = next((t for t in ctx.ttps if t.technique_id == tid), None)
        why = (f"{basis.note}. " if basis else "") + (
            f"Observed in telemetry ({len(ev)}+ event(s))."
            if ev
            else f"Associated with the threat ({src}) but not observed in telemetry, so low confidence."
        )
        await _map(session, case, tid, "MEDIUM" if ev else "LOW", ev, why.strip(), "suggestion")
        techniques_list.append(tid)
    if hits or signal_hits:
        docs = [x.doc for x in all_hits][:500]
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
        sig=signal_hits,
        ctx=ctx,
        hosts=hosts,
        users=users,
        techniques=sorted(set(techniques_list)),
        verdict=verdict,
        severity=severity,
        events_total=len(hits),
    )
    if not hits and not signal_hits and not gaps:
        await case_service.apply_transition(
            session,
            principal,
            case,
            "CLOSED",
            "No evidence of these indicators, behaviours or techniques in any searched source. Coverage: "
            + "; ".join(f"{c.source} ({c.status})" for c in coverage),
        )
    elif not hits and not signal_hits:
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
    if threat is not None:
        threat.case_id, threat.last_hunted_at = case.id, now
        # indicators of a large threat that this pass did not reach are picked up by the scheduled re-hunts (never-hunted first)
        await session.execute(
            update(Ioc)
            .where(Ioc.threat_id == threat.id, Ioc.status == "VALIDATED", Ioc.case_id.is_(None))
            .values(case_id=case.id)
        )
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
    new_signal_hits: list[SignalHit],
    coverage: list[Coverage],
    principal: Principal,
) -> Case | None:
    now = datetime.now(UTC)
    for i in iocs:
        i.last_hunted_at = now
    if hunt.threat_id:
        await session.execute(update(Threat).where(Threat.id == hunt.threat_id).values(last_hunted_at=now))
    case = await session.get(Case, hunt.case_id) if hunt.case_id else None
    if case is None or not (new_hits or new_signal_hits):
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
            f"Reopened: {len(new_hits) + len(new_signal_hits)} new event(s) now match this watched threat.",
        )
    event_ids = list(
        dict.fromkeys(
            [
                *(h.doc["id"] for h in sorted(new_hits, key=lambda h: -h.ioc.confidence)),
                *(h.doc["id"] for h in new_signal_hits),
            ]
        )
    )[:MAX_EVIDENCE]
    await case_service.add_evidence(
        session, backend, principal, case, event_ids, f"New matches from re-hunt {now:%Y-%m-%d %H:%M} UTC"
    )
    lines = [f"{len(hs)} new event(s) for {hs[0].ioc.type} `{defang(hs[0].ioc.value)}`" for hs in groups.values()]
    by_label: dict[str, int] = defaultdict(int)
    for sh in new_signal_hits:
        by_label[f"{'behaviour' if sh.kind == 'ioa' else 'technique'} {sh.label}"] += 1
    lines += [f"{n} new event(s) for {label}" for label, n in by_label.items()]
    await case_service.log(
        session,
        principal,
        case,
        "note",
        "Scheduled re-hunt found new activity:\n- " + "\n- ".join(lines),
        {"ioc_hunt": str(hunt.id)},
    )
    ioc_hosts, sig_hosts = hosts_of(new_hits), hosts_of(new_signal_hits)
    sev = severity_for([hs[0].ioc for hs in groups.values()], len(ioc_hosts), len(new_hits))
    if new_signal_hits:
        sev = max((sev, signal_severity(new_signal_hits, len(sig_hosts))), key=LEVELS.index)
        if new_hits and ioc_hosts & sig_hosts:
            sev = bump(sev)
    if LEVELS.index(sev) > LEVELS.index(case.severity):
        case.severity, case.priority = sev, PRIORITY[sev]
    return case
