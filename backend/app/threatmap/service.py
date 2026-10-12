"""Threat-map domain logic: three layers over two real data stores, joined by IP address.

* intelligence — the tenant's IOC database (`iocs`, fed by MISP/ThreatFox/OTX/... feeds and analysts) and analyst-confirmed
  lookups (`intel_entities`). Reported by third parties; never evidence of an attack on us.
* observed — the tenant's own telemetry in OpenSearch (network source/destination and sign-in source addresses).
* correlated — observed addresses that are also reported intelligence (live IP match), plus events that earlier IOC hunts already
  matched (`ioc_matches`, any indicator type) and whose events carry a public address.

Nothing is invented: a layer with no backing data is empty and the status endpoint says what is missing. Geolocation is an
approximation of the *registered/estimated* location of an address, never of an actor."""

import asyncio
import ipaddress
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cases.models import Case
from app.core.config import get_settings
from app.detections.models import Alert
from app.events.search.opensearch import OpenSearchBackend
from app.events.summary import summarize
from app.intel.models import IntelEntity
from app.iochunt.models import Ioc, IocMatch, Threat
from app.threatmap import telemetry
from app.threatmap.geo import CachedGeo, GeoPoint, classify_with_own, is_public

LAYERS = ("intelligence", "observed", "correlated")
SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_FLOOR = {"info": 0, "low": 20, "medium": 40, "high": 60, "critical": 80}  # event.severity (0-100) thresholds
STALE_AFTER = timedelta(days=30)
MAX_INTEL_ROWS = 25_000
MAX_HUNT_EVENTS = 400


def event_severity(n: int) -> str:
    for name in ("critical", "high", "medium", "low"):
        if n >= _SEV_FLOOR[name]:
            return name
    return "info"


def _rank(sev: str) -> int:
    return SEVERITIES.index(sev.lower()) if sev.lower() in SEVERITIES else 0


def ioc_severity(confidence: int, threat_severity: str | None) -> str:
    """IOCs carry no severity of their own: use the linked threat's analyst/feed severity, else derive from confidence."""
    if threat_severity and threat_severity.lower() in SEVERITIES:
        return threat_severity.lower()
    return "high" if confidence >= 85 else "medium" if confidence >= 60 else "low"


@dataclass
class Filters:
    start: datetime
    end: datetime
    layer: str = "intelligence"
    countries: list[str] = field(default_factory=list)
    continents: list[str] = field(default_factory=list)
    ioc_types: list[str] = field(default_factory=list)
    min_severity: str = "info"
    min_confidence: int = 0
    categories: list[str] = field(default_factory=list)  # threat_type / malware / threat name
    sources: list[str] = field(default_factory=list)  # intelligence feed names
    log_sources: list[str] = field(default_factory=list)  # telemetry sources (firewall, IDS, EDR, SIEM ...)
    scope: str = "any"  # any | external | internal
    q: str = ""

    @property
    def start_iso(self) -> str:
        return self.start.astimezone(UTC).isoformat()

    @property
    def end_iso(self) -> str:
        return self.end.astimezone(UTC).isoformat()

    @property
    def min_event_severity(self) -> int:
        return _SEV_FLOOR[self.min_severity]

    def active(self) -> dict[str, Any]:
        """Filters that narrow the result (everything except the time range and the layer), for the UI's chips."""
        out: dict[str, Any] = {}
        for k in ("countries", "continents", "ioc_types", "categories", "sources", "log_sources"):
            if getattr(self, k):
                out[k] = getattr(self, k)
        if self.min_severity != "info":
            out["min_severity"] = self.min_severity
        if self.min_confidence:
            out["min_confidence"] = self.min_confidence
        if self.scope != "any":
            out["scope"] = self.scope
        if self.q:
            out["q"] = self.q
        return out


@dataclass
class ParsedQuery:
    ip: str | None = None
    cidr: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    asn: int | None = None
    country: str | None = None
    text: str = ""


_ASN = re.compile(r"^(?:as)?(\d{1,10})$", re.I)


def parse_search(q: str, country_names: dict[str, str]) -> ParsedQuery:
    """Classify a free-text search: an IP / CIDR, an AS number (`AS15169`), a country (code or name), else plain text matched against
    indicator values, malware families, campaigns and organisation names."""
    q = q.strip()
    out = ParsedQuery()
    if not q:
        return out
    try:
        out.ip = str(ipaddress.ip_address(q))
        return out
    except ValueError:
        pass
    if "/" in q:
        try:
            out.cidr = ipaddress.ip_network(q, strict=False)
            return out
        except ValueError:
            pass
    m = _ASN.match(q)
    if m and (q.lower().startswith("as") or len(q) >= 4):
        out.asn = int(m.group(1))
        return out
    up = q.upper()
    if len(up) == 2 and up in country_names:
        out.country = up
        return out
    for iso, name in country_names.items():
        if name.lower() == q.lower():
            out.country = iso
            return out
    out.text = q.lower()
    return out


@dataclass
class IntelInfo:
    count: int = 0
    confidence: int = 0
    sources: set[str] = field(default_factory=set)
    threat_types: set[str] = field(default_factory=set)
    malware: set[str] = field(default_factory=set)
    threats: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    statuses: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    severity: str = "low"
    ioc_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def add(self, *, ioc_id: str, confidence: int, source: str, threat_type: str, malware: str, threat: str, tags: list[str],
            status: str, first: datetime | None, last: datetime | None, severity: str, reference: str) -> None:  # fmt: skip
        self.count += 1
        self.confidence = max(self.confidence, confidence)
        if source:
            self.sources.add(source)
        if threat_type:
            self.threat_types.add(threat_type)
        if malware:
            self.malware.add(malware)
        if threat:
            self.threats.add(threat)
        self.tags.update(t for t in tags[:10] if isinstance(t, str))
        self.statuses.add(status)
        if first and (self.first_seen is None or first < self.first_seen):
            self.first_seen = first
        if last and (self.last_seen is None or last > self.last_seen):
            self.last_seen = last
        if _rank(severity) > _rank(self.severity):
            self.severity = severity
        if len(self.ioc_ids) < 10 and ioc_id:
            self.ioc_ids.append(ioc_id)
        if reference.startswith(("http://", "https://")) and len(self.references) < 3:
            self.references.append(reference[:500])

    @property
    def stale(self) -> bool:
        return self.statuses <= {"EXPIRED"} or (
            self.last_seen is not None and datetime.now(UTC) - self.last_seen > STALE_AFTER
        )

    def public(self) -> dict[str, Any]:
        return {
            "iocs": self.count,
            "confidence": self.confidence,
            "severity": self.severity,
            "sources": sorted(self.sources),
            "threat_types": sorted(self.threat_types),
            "malware": sorted(self.malware),
            "threats": sorted(self.threats),
            "tags": sorted(self.tags)[:12],
            "statuses": sorted(self.statuses),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "stale": self.stale,
            "references": self.references,
            "ioc_ids": self.ioc_ids,
        }


@dataclass
class HuntCorr:
    """One earlier IOC-hunt match whose event carries this address."""

    ioc_id: str
    ioc_type: str
    ioc_value: str
    threat: str
    source: str
    confidence: int
    status: str
    case_id: str | None
    event_id: str
    timestamp: datetime
    matched_field: str
    host: str
    event_source: str
    severity: int


@dataclass
class Record:
    ip: str
    cls: str
    geo: GeoPoint | None
    intel: IntelInfo | None = None
    activity: telemetry.IpActivity | None = None
    hunts: list[HuntCorr] = field(default_factory=list)

    @property
    def correlated(self) -> bool:
        return (self.intel is not None and self.activity is not None) or bool(self.hunts)

    def layers(self) -> list[str]:
        out = []
        if self.intel is not None:
            out.append("intelligence")
        if self.activity is not None:
            out.append("observed")
        if self.correlated:
            out.append("correlated")
        return out

    def severity(self, layer: str) -> str:
        sevs: list[str] = []
        if layer in ("intelligence", "correlated") and self.intel:
            sevs.append(self.intel.severity)
        if layer in ("observed", "correlated") and self.activity:
            sevs.append(event_severity(self.activity.max_severity))
        if layer == "correlated" and self.hunts:
            sevs.append(event_severity(max(h.severity for h in self.hunts)))
        return max(sevs, key=_rank) if sevs else "info"

    def weight(self, layer: str) -> int:
        w = 0
        if layer in ("intelligence", "correlated") and self.intel:
            w += self.intel.count * max(1, self.intel.confidence // 20)
        if layer in ("observed", "correlated") and self.activity:
            w += self.activity.events
        if layer == "correlated":
            w += len(self.hunts)
        return w

    def last_seen(self, layer: str) -> str | None:
        vals: list[str] = []
        if layer in ("intelligence", "correlated") and self.intel and self.intel.last_seen:
            vals.append(self.intel.last_seen.isoformat())
        if layer in ("observed", "correlated") and self.activity and self.activity.last_seen:
            vals.append(self.activity.last_seen)
        if layer == "correlated":
            vals.extend(h.timestamp.isoformat() for h in self.hunts)
        return max(vals) if vals else None


def geo_json(g: GeoPoint | None) -> dict[str, Any] | None:
    if g is None:
        return None
    return {
        "country": g.country, "country_name": g.country_name, "continent": g.continent, "city": g.city, "region": g.region,
        "lat": round(g.lat, 2) if g.lat is not None else None, "lon": round(g.lon, 2) if g.lon is not None else None,
        "asn": g.asn, "org": g.org,
    }  # fmt: skip


def activity_json(a: telemetry.IpActivity) -> dict[str, Any]:
    return {
        "events": a.events,
        "as_source": a.src,
        "as_destination": a.dst,
        "as_signin_source": a.auth,
        "first_seen": a.first_seen,
        "last_seen": a.last_seen,
        "max_severity": event_severity(a.max_severity),
        "sources": [k for k, _ in sorted(a.sources.items(), key=lambda kv: -kv[1])][:5],
        "ports": [k for k, _ in sorted(a.ports.items(), key=lambda kv: -kv[1])][:5],
    }


# ---- loading ------------------------------------------------------------------------------------------------
def _needle(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


async def load_intel(session: AsyncSession, tid: uuid.UUID, f: Filters, parsed: ParsedQuery) -> dict[str, IntelInfo]:
    """Reported IP indicators in the window. `last_seen` is when the *source* last reported it, so a stale feed shows up as stale."""
    where = [
        Ioc.tenant_id == tid,
        Ioc.type == "ip",
        Ioc.status != "REJECTED",
        Ioc.last_seen >= f.start,
        Ioc.first_seen < f.end,
    ]
    if f.min_confidence:
        where.append(Ioc.confidence >= f.min_confidence)
    if f.sources:
        where.append(Ioc.source.in_(f.sources))
    if f.categories:
        where.append(or_(*[or_(Ioc.threat_type == c, Ioc.malware == c, Ioc.threat_name == c) for c in f.categories]))
    if parsed.ip:
        where.append(Ioc.value == parsed.ip)
    if parsed.text:
        n = _needle(parsed.text)
        where.append(
            or_(
                Ioc.value.ilike(n),
                Ioc.malware.ilike(n),
                Ioc.threat_name.ilike(n),
                Ioc.description.ilike(n),
                Ioc.threat_type.ilike(n),
            )
        )
    rows = (
        await session.execute(
            select(Ioc, Threat.severity, Threat.name)
            .outerjoin(Threat, Threat.id == Ioc.threat_id)
            .where(*where)
            .order_by(Ioc.confidence.desc(), Ioc.last_seen.desc())
            .limit(MAX_INTEL_ROWS)
        )
    ).all()
    out: dict[str, IntelInfo] = {}
    for ioc, t_sev, t_name in rows:
        if parsed.cidr is not None and not _in_net(ioc.value, parsed.cidr):
            continue
        sev = ioc_severity(ioc.confidence, t_sev)
        if _rank(sev) < _rank(f.min_severity):
            continue
        info = out.setdefault(ioc.value, IntelInfo())
        info.add(
            ioc_id=str(ioc.id), confidence=ioc.confidence, source=ioc.source, threat_type=ioc.threat_type, malware=ioc.malware,
            threat=t_name or ioc.threat_name, tags=list(ioc.tags or []), status=ioc.status, first=ioc.first_seen, last=ioc.last_seen,
            severity=sev, reference=ioc.reference or "",
        )  # fmt: skip
    # Analyst look-ups the platform already scored as hostile (only when no feed filter excludes a "lookup" source).
    if not f.sources and not f.categories and not f.min_confidence and not parsed.text:
        ents = (
            await session.execute(
                select(IntelEntity).where(
                    IntelEntity.tenant_id == tid, IntelEntity.type == "ip", IntelEntity.verdict.in_(("malicious", "suspicious")),
                    IntelEntity.updated_at >= f.start, IntelEntity.updated_at < f.end,
                ).limit(5000)
            )
        ).scalars().all()  # fmt: skip
        for e in ents:
            if (
                e.value in out
                or (parsed.ip and e.value != parsed.ip)
                or (parsed.cidr is not None and not _in_net(e.value, parsed.cidr))
            ):
                continue
            sev = "high" if e.verdict == "malicious" else "medium"
            if _rank(sev) < _rank(f.min_severity):
                continue
            out.setdefault(e.value, IntelInfo()).add(
                ioc_id="", confidence=int(e.score or 0), source="analyst lookup", threat_type="", malware="", threat="", tags=list(e.tags or []),
                status="VALIDATED", first=e.created_at, last=e.updated_at, severity=sev, reference="",
            )  # fmt: skip
    return out


def _in_net(value: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == net.version and ip in net


def _event_ips(doc: dict[str, Any]) -> list[tuple[str, str]]:
    """Public addresses an event names, with the field they came from."""
    out: list[tuple[str, str]] = []
    net, auth, dns = doc.get("network") or {}, doc.get("auth") or {}, doc.get("dns") or {}
    for fld, v in (
        ("network.dst_ip", net.get("dst_ip")),
        ("network.src_ip", net.get("src_ip")),
        ("auth.source_ip", auth.get("source_ip")),
    ):
        if isinstance(v, str) and is_public(v):
            out.append((v, fld))
    for a in dns.get("answers") or []:
        if isinstance(a, str) and is_public(a):
            out.append((a, "dns.answers"))
    return out


async def load_hunt_correlations(
    session: AsyncSession, search: OpenSearchBackend, tid: uuid.UUID, f: Filters
) -> dict[str, list[HuntCorr]]:
    """Events that an earlier IOC hunt matched (any indicator type) and that carry a public address, keyed by that address."""
    where = [IocMatch.tenant_id == tid, IocMatch.event_timestamp >= f.start, IocMatch.event_timestamp < f.end]
    if f.ioc_types:
        where.append(Ioc.type.in_(f.ioc_types))
    if f.sources:
        where.append(Ioc.source.in_(f.sources))
    if f.min_confidence:
        where.append(Ioc.confidence >= f.min_confidence)
    if f.categories:
        where.append(or_(*[or_(Ioc.threat_type == c, Ioc.malware == c, Ioc.threat_name == c) for c in f.categories]))
    rows = (
        await session.execute(
            select(IocMatch, Ioc, Threat.name)
            .join(Ioc, Ioc.id == IocMatch.ioc_id)
            .outerjoin(Threat, Threat.id == Ioc.threat_id)
            .where(*where)
            .order_by(IocMatch.event_timestamp.desc())
            .limit(MAX_HUNT_EVENTS)
        )
    ).all()
    if not rows:
        return {}
    ids = sorted({m.event_id for m, _, _ in rows})
    docs: dict[str, dict[str, Any]] = {}
    for i in range(0, len(ids), 200):
        for d in await search.get_events(tid, ids[i : i + 200]):
            docs[str(d.get("id"))] = d
    out: dict[str, list[HuntCorr]] = defaultdict(list)
    for m, ioc, t_name in rows:
        doc = docs.get(m.event_id)
        if doc is None:  # past retention: the match row survives but there is nothing left to place
            continue
        for ip, _fld in _event_ips(doc):
            out[ip].append(
                HuntCorr(
                    ioc_id=str(ioc.id),
                    ioc_type=ioc.type,
                    ioc_value=ioc.value,
                    threat=t_name or ioc.threat_name,
                    source=ioc.source,
                    confidence=ioc.confidence,
                    status=ioc.status,
                    case_id=str(ioc.case_id) if ioc.case_id else None,
                    event_id=m.event_id,
                    timestamp=m.event_timestamp,
                    matched_field=m.matched_field,
                    host=m.host,
                    event_source=m.source,
                    severity=int(doc.get("severity") or 0),
                )  # fmt: skip
            )
    return out


@dataclass
class Dataset:
    filters: Filters
    records: dict[str, Record]
    country_names: dict[str, str]
    total_events: int  # IP-bearing events in the window (before geo filters)
    internal: dict[str, telemetry.IpActivity]
    truncated: bool
    notes: list[str]
    intel_ips: int = 0  # reported public IPs that pass the intelligence + geo filters, whichever layer is on screen
    intel_countries: dict[str, tuple[str, int]] = field(default_factory=dict)  # iso -> (name, reported IPs)


def _geo_ok(rec: Record, f: Filters, parsed: ParsedQuery) -> bool:
    g = rec.geo
    if f.countries and (g is None or g.country not in f.countries):
        return False
    if f.continents and (g is None or g.continent not in f.continents):
        return False
    if parsed.country and (g is None or g.country != parsed.country):
        return False
    return not (parsed.asn is not None and (g is None or g.asn != parsed.asn))


def _text_ok(rec: Record, parsed: ParsedQuery) -> bool:
    """Plain-text search: intel records are already narrowed in SQL; for observed-only records match organisation / city / country."""
    if not parsed.text or rec.intel is not None:
        return True
    g = rec.geo
    hay = " ".join([rec.ip, g.org, g.city, g.country_name] if g else [rec.ip]).lower()
    return parsed.text in hay


async def build_dataset(
    session: AsyncSession,
    search: OpenSearchBackend,
    geo: CachedGeo,
    tid: uuid.UUID,
    f: Filters,
    country_names: dict[str, str],
) -> Dataset:
    parsed = parse_search(f.q, country_names)
    own = get_settings().own_networks
    notes: list[str] = []
    want_intel = f.layer in ("intelligence", "correlated")
    want_obs = f.layer in ("observed", "correlated")
    include_internal = f.scope in ("any", "internal")

    intel: dict[str, IntelInfo] = {}
    activity: dict[str, telemetry.IpActivity] = {}
    total = 0
    hunts: dict[str, list[HuntCorr]] = {}
    ip_filter = [parsed.ip] if parsed.ip else None

    # Intelligence is always loaded: the observed/correlated layers need it to decide what is "also reported".
    intel_all = await load_intel(session, tid, Filters(**{**f.__dict__, "layer": "intelligence"}), parsed)
    intel = intel_all if want_intel or want_obs else {}

    if want_obs:
        activity, total = await telemetry.ip_activity(
            search, tid, f.start_iso, f.end_iso, sources=f.log_sources or None, min_severity=f.min_event_severity,
            ips=ip_filter, include_internal=include_internal and f.layer == "observed",
        )  # fmt: skip
        public_hits = [ip for ip in intel_all if ip not in activity]
        if public_hits and f.layer in ("correlated", "observed") and not ip_filter:
            extra, _ = await telemetry.ip_activity(
                search, tid, f.start_iso, f.end_iso, sources=f.log_sources or None, min_severity=f.min_event_severity,
                ips=public_hits, include_internal=False,
            )  # fmt: skip
            activity.update({ip: a for ip, a in extra.items() if ip in intel_all})
    if f.layer == "correlated":
        hunts = await load_hunt_correlations(session, search, tid, f)

    if len(activity) >= 2900:
        notes.append("Showing the busiest 3,000 addresses per field; narrow the time range or filters to see the rest.")
    truncated = False

    records: dict[str, Record] = {}
    internal: dict[str, telemetry.IpActivity] = {}
    for ip in set(intel) | set(activity) | set(hunts):
        cls = classify_with_own(ip, own)
        if cls == "invalid":
            continue
        if cls != "public":
            if ip in activity and f.layer == "observed":
                internal[ip] = activity[ip]
            continue
        if parsed.cidr is not None and not _in_net(ip, parsed.cidr):
            continue
        rec = Record(
            ip=ip, cls=cls, geo=geo.lookup(ip), intel=intel.get(ip), activity=activity.get(ip), hunts=hunts.get(ip, [])
        )
        if f.layer == "intelligence" and rec.intel is None:
            continue
        if f.layer == "observed" and rec.activity is None:
            continue
        if f.layer == "correlated" and not rec.correlated:
            continue
        if f.layer == "correlated" and f.ioc_types and not rec.hunts and "ip" not in f.ioc_types:
            continue
        if not _geo_ok(rec, f, parsed) or not _text_ok(rec, parsed):
            continue
        records[ip] = rec
    if f.scope == "internal":
        records = {}
    # The intelligence cards describe the reported set regardless of the layer being drawn.
    n_intel = 0
    by_country: dict[str, tuple[str, int]] = {}
    for ip, info in intel_all.items():
        if classify_with_own(ip, own) != "public" or (parsed.cidr is not None and not _in_net(ip, parsed.cidr)):
            continue
        probe = Record(ip=ip, cls="public", geo=geo.lookup(ip), intel=info)
        if not _geo_ok(probe, f, parsed) or f.scope == "internal":
            continue
        n_intel += 1
        if probe.geo and probe.geo.country:
            name, n = by_country.get(probe.geo.country, (probe.geo.country_name, 0))
            by_country[probe.geo.country] = (name, n + 1)
    return Dataset(f, records, country_names, total, internal, truncated, notes, n_intel, by_country)


# ---- views --------------------------------------------------------------------------------------------------
def marker_json(rec: Record, layer: str) -> dict[str, Any]:
    g = geo_json(rec.geo)
    return {
        "ip": rec.ip,
        "geo": g,
        "layers": rec.layers(),
        "severity": rec.severity(layer),
        "weight": rec.weight(layer),
        "last_seen": rec.last_seen(layer),
        "intel": rec.intel.public() if rec.intel else None,
        "observed": activity_json(rec.activity) if rec.activity else None,
        "hunt_matches": len(rec.hunts),
    }


def correlations(ds: Dataset) -> list[dict[str, Any]]:
    """One item per correlated address (live IP match) plus one per hunt-matched IOC/event pair, newest first."""
    out: list[dict[str, Any]] = []
    for rec in ds.records.values():
        g = geo_json(rec.geo)
        if rec.intel is not None and rec.activity is not None:
            i, a = rec.intel, rec.activity
            out.append(
                {
                    "id": f"ip:{rec.ip}", "kind": "ip_match", "ip": rec.ip, "ioc_type": "ip", "ioc_value": rec.ip,
                    "reason": f"{rec.ip} is reported by {', '.join(sorted(i.sources)[:3]) or 'threat intelligence'} and appears in "
                              f"{a.events} of your events ({_roles(a)}).",
                    "source": ", ".join(sorted(i.sources)), "confidence": i.confidence,
                    "severity": max([i.severity, event_severity(a.max_severity)], key=_rank), "threat": ", ".join(sorted(i.threats | i.malware)),
                    "first_seen": min(x for x in (a.first_seen, i.first_seen.isoformat() if i.first_seen else None) if x) if (a.first_seen or i.first_seen) else None,
                    "last_seen": a.last_seen, "events": a.events, "event_ids": [], "host": "", "matched_field": _roles(a),
                    "status": "VALIDATED" if "VALIDATED" in i.statuses else sorted(i.statuses)[0] if i.statuses else "NEW",
                    "case_id": None, "country": g["country"] if g else None, "ioc_ids": i.ioc_ids,
                }
            )  # fmt: skip
        for h in rec.hunts:
            out.append(
                {
                    "id": f"hunt:{h.ioc_id}:{h.event_id}", "kind": "hunt_match", "ip": rec.ip, "ioc_type": h.ioc_type, "ioc_value": h.ioc_value,
                    "reason": f"IOC hunt matched {h.ioc_type} {h.ioc_value} on {h.matched_field or 'an event'}; the event also names {rec.ip}.",
                    "source": h.source, "confidence": h.confidence, "severity": max(event_severity(h.severity), "medium", key=_rank),
                    "threat": h.threat, "first_seen": h.timestamp.isoformat(), "last_seen": h.timestamp.isoformat(), "events": 1,
                    "event_ids": [h.event_id], "host": h.host, "matched_field": h.matched_field, "status": h.status, "case_id": h.case_id,
                    "country": g["country"] if g else None, "ioc_ids": [h.ioc_id],
                }
            )  # fmt: skip
    out.sort(key=lambda c: c["last_seen"] or "", reverse=True)
    return out


def _roles(a: telemetry.IpActivity) -> str:
    parts = []
    if a.src:
        parts.append(f"source of {a.src}")
    if a.dst:
        parts.append(f"destination of {a.dst}")
    if a.auth:
        parts.append(f"sign-in source of {a.auth}")
    return ", ".join(parts) or "seen"


def country_rows(ds: Dataset) -> list[dict[str, Any]]:
    agg: dict[str, dict[str, Any]] = {}
    for rec in ds.records.values():
        if rec.geo is None or not rec.geo.country:
            continue
        c = agg.setdefault(
            rec.geo.country,
            {"iso": rec.geo.country, "name": rec.geo.country_name, "ips": 0, "events": 0, "correlated": 0, "iocs": 0},
        )
        c["ips"] += 1
        c["events"] += rec.activity.events if rec.activity else 0
        c["iocs"] += rec.intel.count if rec.intel else 0
        c["correlated"] += 1 if rec.correlated else 0
    metric = {"intelligence": "ips", "observed": "events", "correlated": "correlated"}[ds.filters.layer]
    rows = sorted(agg.values(), key=lambda r: (-r[metric], r["iso"]))
    for r in rows:
        r["value"] = r[metric]
    return rows


def interval_for(start: datetime, end: datetime) -> tuple[str, timedelta]:
    span = end - start
    if span <= timedelta(hours=2):
        return "5m", timedelta(minutes=5)
    if span <= timedelta(hours=26):
        return "1h", timedelta(hours=1)
    if span <= timedelta(days=8):
        return "6h", timedelta(hours=6)
    if span <= timedelta(days=40):
        return "1d", timedelta(days=1)
    return "7d", timedelta(days=7)


async def timeline(
    session: AsyncSession, search: OpenSearchBackend, tid: uuid.UUID, ds: Dataset
) -> list[dict[str, Any]]:
    f = ds.filters
    label, step = interval_for(f.start, f.end)
    if f.layer == "intelligence":
        buckets: dict[str, int] = defaultdict(int)
        for rec in ds.records.values():
            ts = rec.intel.last_seen if rec.intel else None
            if ts and f.start <= ts < f.end:
                k = f.start + ((ts - f.start) // step) * step
                buckets[k.isoformat()] += 1
        cur, out = f.start, []
        while cur < f.end:
            out.append({"t": cur.isoformat(), "count": buckets.get(cur.isoformat(), 0)})
            cur += step
        return out
    ips = list(ds.records) if f.layer == "correlated" else None
    if ips is not None and not ips:
        return []
    pairs = await telemetry.histogram(
        search,
        tid,
        f.start_iso,
        f.end_iso,
        label,
        sources=f.log_sources or None,
        min_severity=f.min_event_severity,
        ips=ips,
    )
    return [{"t": t, "count": c} for t, c in pairs]


async def high_severity_detections(session: AsyncSession, tid: uuid.UUID, f: Filters) -> int:
    n = await session.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            Alert.tenant_id == tid,
            Alert.event_timestamp >= f.start,
            Alert.event_timestamp < f.end,
            func.lower(Alert.severity).in_(("high", "critical")),
        )  # fmt: skip
    )
    return int(n.scalar_one())


async def case_refs(session: AsyncSession, tid: uuid.UUID, case_ids: list[str]) -> dict[str, dict[str, Any]]:
    ids = [uuid.UUID(c) for c in set(case_ids) if c]
    if not ids:
        return {}
    rows = (await session.execute(select(Case).where(Case.tenant_id == tid, Case.id.in_(ids)))).scalars().all()
    return {
        str(c.id): {"id": str(c.id), "case_id": f"CASE-{c.number:04d}", "title": c.title, "status": c.status}
        for c in rows
    }


async def gather(*aws: Any) -> list[Any]:
    return list(await asyncio.gather(*aws))


def summarize_event(doc: dict[str, Any]) -> dict[str, Any]:
    net = doc.get("network") or {}
    return {
        "id": doc.get("id"), "timestamp": doc.get("timestamp"), "source": doc.get("source"), "event_type": doc.get("event_type"),
        "severity": int(doc.get("severity") or 0), "summary": summarize(doc)[:300], "src_ip": net.get("src_ip"), "dst_ip": net.get("dst_ip"),
        "dst_port": net.get("dst_port"), "protocol": net.get("protocol"), "host": (doc.get("host") or {}).get("hostname"),
    }  # fmt: skip
