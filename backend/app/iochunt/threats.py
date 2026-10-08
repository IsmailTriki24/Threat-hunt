"""Threat bulletins: group indicators under named threats, resolve them against ATT&CK, and derive each threat's TTPs and IOAs.

Naming: a feed says which family / actor / campaign / report an indicator belongs to; names are normalised ('win.cobalt_strike' ->
'Cobalt Strike') and resolved through ATT&CK software/group aliases so 'QBot' and 'QakBot' become one threat. Indicators with no name
fall into 'Unattributed <role> (<source>)' so nothing is hidden. TTPs come from, in order of trust: MITRE's documented usage, techniques the
feed declared, and techniques implied by the indicator's role. IOAs follow from the TTPs (built-in catalogue + the tenant's detection rules)."""

import re
import uuid
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.detections.models import DetectionRule
from app.iochunt import ioa_catalog
from app.iochunt.feeds.abusech import GENERIC_TAGS, urlhaus_threat
from app.iochunt.models import Ioc, Threat, ThreatIoa, ThreatTtp
from app.mitre.loader import alias_key
from app.mitre.models import MitreSoftware, MitreTechnique

_HOSTLIKE = re.compile(r"^\d{1,3}(-\d{1,3}){3}(-\d+)?$")  # tags like '217-60-102-5': an address, not a threat


def is_generic(name: str) -> bool:
    n = name.strip().lower()
    return (
        not n
        or n in GENERIC_TAGS
        or bool(_HOSTLIKE.match(n))
        or alias_key(n) in ("", "unknown", "unknownmalware", "none")
    )


_PREFIX = re.compile(r"^(win|elf|osx|apk|php|js|ps1|py|jar|lnk|doc)\.", re.I)
TTP_RANK = {"manual": 4, "mitre": 3, "feed": 2, "derived": 1}
CONF_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
ROLE_TECHNIQUES: dict[str, list[str]] = {
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
    "stealer": ["T1555"],
}


def canonical_name(raw: str) -> str:
    name = raw.strip()
    if _PREFIX.match(name):
        name = _PREFIX.sub("", name).replace("_", " ")
        name = " ".join(w.capitalize() if w.islower() else w for w in name.split())
    return re.sub(r"\s+", " ", name)[:200]


def fallback_name(ioc: Ioc) -> tuple[str, str]:
    role = (ioc.threat_type or "indicators").replace("_", " ")
    return f"Unattributed {role} ({ioc.source or 'manual'})"[:200], "other"


@dataclass
class Resolved:
    name: str
    key: str
    kind: str
    mitre: MitreSoftware | None


async def software_index(session: AsyncSession) -> dict[str, MitreSoftware]:
    out: dict[str, MitreSoftware] = {}
    for sw in (await session.execute(select(MitreSoftware))).scalars():
        for k in sw.alias_keys:
            # a group named like a tool must not shadow it; the first (S-prefixed software) wins over groups sharing an alias
            if k not in out or (out[k].kind == "group" and sw.kind != "group"):
                out[k] = sw
    return out


def resolve(ioc: Ioc, index: dict[str, MitreSoftware]) -> Resolved:
    hint = canonical_name(ioc.threat_name or ioc.malware or "")
    kind = ioc.threat_kind or ("malware" if ioc.malware else "")
    if is_generic(hint):
        # the stored name may be a file-type / host tag: look for a real family among the indicator's other tags
        derived = urlhaus_threat([t for t in ioc.tags if t.lower() != "urlhaus"])
        hint, kind = (canonical_name(derived), "malware") if derived and not is_generic(derived) else ("", "")
    if not hint:
        name, kind = fallback_name(ioc)
        return Resolved(name, alias_key(name), kind, None)
    sw = index.get(alias_key(hint))
    if sw is not None and len(alias_key(hint)) >= 4:
        return Resolved(sw.name, alias_key(sw.name), "actor" if sw.kind == "group" else "malware", sw)
    return Resolved(hint, alias_key(hint)[:160] or "x", kind or "other", None)


async def assign(
    session: AsyncSession, tenant_id: uuid.UUID, *, limit: int = 20000, everything: bool = False
) -> set[uuid.UUID]:
    """Attach indicators to their threat. With `everything`, re-derive every indicator's threat (after naming rules or ATT&CK data change),
    moving the ones whose threat differs and retiring bulletins left empty. Returns the ids of every threat touched."""
    q = select(Ioc).where(Ioc.tenant_id == tenant_id)
    if not everything:
        q = q.where(Ioc.threat_id.is_(None))
    rows = (await session.execute(q.limit(limit))).scalars().all()
    if not rows:
        return set()
    index = await software_index(session)
    groups: dict[str, tuple[Resolved, list[Ioc]]] = {}
    for ioc in rows:
        r = resolve(ioc, index)
        groups.setdefault(r.key, (r, []))[1].append(ioc)
    touched: set[uuid.UUID] = set()
    existing_keys = {
        t.key: t.id for t in (await session.execute(select(Threat).where(Threat.tenant_id == tenant_id))).scalars()
    }
    for key, (r, members) in groups.items():
        aliases = sorted(
            {
                canonical_name(m.threat_name or m.malware)
                for m in members
                if (m.threat_name or m.malware) and not is_generic(m.threat_name or m.malware)
            }
            - {r.name}
        )[:10]
        stmt = (
            insert(Threat)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                key=key,
                name=r.name,
                kind=r.kind,
                aliases=aliases,
                mitre_id=r.mitre.id if r.mitre else "",
                status="NEW",
            )
            .on_conflict_do_update(constraint="uq_threat_key", set_={"updated_at": func.now()})
            .returning(Threat.id)
        )
        tid = (await session.execute(stmt)).scalar_one()
        movers = [m for m in members if m.threat_id != tid]
        touched |= {m.threat_id for m in movers if m.threat_id}
        if movers or key not in existing_keys:
            await session.execute(update(Ioc).where(Ioc.id.in_([m.id for m in movers])).values(threat_id=tid))
            touched.add(tid)
    if everything and touched:
        # bulletins that lost all their indicators and were never validated are removed rather than left as empty rows
        empty = (
            (
                await session.execute(
                    select(Threat.id).where(
                        Threat.tenant_id == tenant_id,
                        Threat.status.in_(("NEW", "EXPIRED", "REJECTED")),
                        ~select(Ioc.id).where(Ioc.threat_id == Threat.id).exists(),
                    )
                )
            )
            .scalars()
            .all()
        )
        if empty:
            await session.execute(delete(Threat).where(Threat.id.in_(list(empty))))
            touched -= set(empty)
    return touched


def _severity(conf: int, roles: set[str], tags: set[str]) -> str:
    base = 3 if conf >= 85 else 2 if conf >= 60 else 1
    if ("ransomware" in tags) or (roles & {"botnet_cc", "c2", "command_and_control"} and conf >= 90):
        base = 4
    return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[base]


async def refresh(session: AsyncSession, tenant_id: uuid.UUID, threat_ids: set[uuid.UUID] | None = None) -> int:
    """Recompute aggregates, description, TTPs and IOAs. Idempotent; manual TTPs/IOAs are never overwritten."""
    q = select(Threat).where(Threat.tenant_id == tenant_id)
    if threat_ids is not None:
        if not threat_ids:
            return 0
        q = q.where(Threat.id.in_(threat_ids))
    threats = (await session.execute(q)).scalars().all()
    if not threats:
        return 0
    sw_by_id = {sw.id: sw for sw in (await session.execute(select(MitreSoftware))).scalars()}
    known_tech = set((await session.execute(select(MitreTechnique.id))).scalars())
    rules = (
        (
            await session.execute(
                select(DetectionRule).where(
                    DetectionRule.tenant_id == tenant_id,
                    DetectionRule.status.in_(("ACTIVE", "TESTING")),
                    DetectionRule.compiled.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    for t in threats:
        members = (
            (await session.execute(select(Ioc).where(Ioc.threat_id == t.id, Ioc.status != "EXPIRED"))).scalars().all()
        )
        if not members:
            if t.status != "VALIDATED":
                t.status, t.status_reason = "EXPIRED", "all indicators aged out"
            t.ioc_count, t.ioc_types, t.seen_count = 0, {}, 0
            continue
        types: dict[str, int] = defaultdict(int)
        for m in members:
            types[m.type] += 1
        sources = sorted({m.source for m in members if m.source})
        roles = {m.threat_type.lower() for m in members if m.threat_type}
        tags = {x.lower() for m in members for x in m.tags}
        t.ioc_count, t.ioc_types = len(members), dict(types)
        t.first_seen, t.last_updated = min(m.first_seen for m in members), max(m.last_seen for m in members)
        t.confidence = max(m.confidence for m in members)
        t.severity = _severity(t.confidence, roles, tags)
        t.seen_count = sum(m.seen_count for m in members)
        t.sources = sources[:10]
        refs = [m.reference for m in sorted(members, key=lambda x: -x.confidence) if m.reference]
        t.references = list(dict.fromkeys(refs))[:10]
        if t.status == "EXPIRED":
            t.status, t.status_reason = "NEW", "re-sighted"
        sw = sw_by_id.get(t.mitre_id) if t.mitre_id else None
        if sw is not None:
            t.aliases = sorted((set(t.aliases) | set(sw.aliases)) - {t.name})[
                :15
            ]  # ATT&CK knows the other names this threat goes by
        descs = [d for d in dict.fromkeys(m.description for m in sorted(members, key=lambda x: -x.confidence)) if d][:2]
        kind_word = {
            "malware": "malware family",
            "actor": "threat actor",
            "campaign": "campaign",
            "report": "intelligence report",
        }.get(t.kind, "threat")
        t.description = (
            (f"{sw.description}\n\n" if sw and sw.description else "")
            + f"Recent reporting from {', '.join(sources) or 'manual entry'} attributes {len(members)} indicator(s) "
            f"({', '.join(f'{n} {k}' for k, n in sorted(types.items(), key=lambda kv: -kv[1]))}) to this {kind_word}; "
            f"the most recent activity was {t.last_updated:%Y-%m-%d}."
            + ("".join(f"\n- {d[:200]}" for d in descs) if descs else "")
            + (f"\n\nMITRE ATT&CK: {sw.id} ({sw.name})." if sw else "")
        )[:4000]
        await _ttps(session, t, members, sw, roles, tags, known_tech)
        await _ioas(session, t, rules)
    await session.flush()
    return len(threats)


async def _ttps(
    session: AsyncSession,
    t: Threat,
    members: Sequence[Ioc],
    sw: MitreSoftware | None,
    roles: set[str],
    tags: set[str],
    known: set[str],
) -> None:
    wanted: dict[str, tuple[str, str, str]] = {}  # technique -> (source, confidence, note)

    def offer(tid: str, source: str, conf: str, note: str) -> None:
        tid = tid.upper()
        if tid not in known:
            return
        cur = wanted.get(tid)
        if cur is None or TTP_RANK[source] > TTP_RANK[cur[0]]:
            wanted[tid] = (source, conf, note)

    for tid in sw.technique_ids if sw else []:
        offer(tid, "mitre", "HIGH", f"Documented by MITRE ATT&CK for {sw.name} ({sw.id})" if sw else "")
    for m in members:
        for tid in m.techniques:
            offer(tid, "feed", "MEDIUM", f"Declared by {m.source}")
        for r in [m.threat_type.lower()] if m.threat_type else []:
            for tid in ROLE_TECHNIQUES.get(r, []):
                offer(tid, "derived", "LOW", f"Implied by the indicator role '{r}'")
    for tag in tags:
        for tid in TAG_TECHNIQUES.get(tag, []):
            offer(tid, "derived", "LOW", f"Implied by tag '{tag}'")
    for tid, (source, conf, note) in wanted.items():
        stmt = insert(ThreatTtp).values(
            id=uuid.uuid4(),
            tenant_id=t.tenant_id,
            threat_id=t.id,
            technique_id=tid,
            source=source,
            confidence=conf,
            note=note[:300],
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_threat_ttp",
            set_={"source": stmt.excluded.source, "confidence": stmt.excluded.confidence, "note": stmt.excluded.note},
            where=ThreatTtp.source != "manual",
        )
        await session.execute(stmt)


async def _ioas(session: AsyncSession, t: Threat, rules: Sequence[DetectionRule]) -> None:
    ttps = list((await session.execute(select(ThreatTtp.technique_id).where(ThreatTtp.threat_id == t.id))).scalars())
    for d in ioa_catalog.for_techniques(ttps):
        await session.execute(
            insert(ThreatIoa)
            .values(
                id=uuid.uuid4(),
                tenant_id=t.tenant_id,
                threat_id=t.id,
                name=d.name,
                description=d.description,
                technique_id=d.technique,
                query_text=d.readable,
                condition=d.cond,
                trend_query=d.trend,
                severity=d.severity,
                source="catalog",
            )
            .on_conflict_do_nothing(constraint="uq_threat_ioa")
        )
    for rule in rules:
        overlap = next((tt for tt in ttps for rt in rule.techniques if ioa_catalog.related(rt, tt)), None)
        if overlap:
            await session.execute(
                insert(ThreatIoa)
                .values(
                    id=uuid.uuid4(),
                    tenant_id=t.tenant_id,
                    threat_id=t.id,
                    name=f"Rule: {rule.title}"[:160],
                    description=rule.description[:500],
                    technique_id=overlap,
                    severity=rule.severity
                    if rule.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
                    else "MEDIUM",
                    source="rule",
                    rule_id=rule.id,
                )
                .on_conflict_do_nothing(constraint="uq_threat_ioa")
            )


async def sync(session: AsyncSession, tenant_id: uuid.UUID, *, everything: bool = False) -> int:
    """Group any ungrouped indicators (or, with `everything`, re-derive all of them), then refresh the affected bulletins."""
    touched = await assign(session, tenant_id, everything=everything)
    return await refresh(session, tenant_id, touched) if touched else 0
