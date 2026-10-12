"""Global threat map API. Read-only; every route is tenant-scoped through the caller's principal and needs both `intel:read` and
`events:read` (the map joins reported intelligence with the tenant's own telemetry)."""

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.cases.models import Case, CaseIoc
from app.core.config import get_settings
from app.core.db import get_session
from app.core.errors import AppError, UpstreamUnavailable
from app.core.ratelimit import enforce
from app.detections.models import Alert
from app.iochunt.models import Ioc, IocMatch, Threat
from app.threatmap import service as svc
from app.threatmap import telemetry
from app.threatmap.countries import COUNTRY_NAMES
from app.threatmap.geo import CachedGeo, classify_with_own, get_geo

router = APIRouter(prefix="/threat-map", tags=["threat-map"])
READ = Depends(require(Permission.INTEL_READ))
_EVENTS = Depends(require(Permission.EVENTS_READ))
Layer = Literal["intelligence", "observed", "correlated"]
MAX_SPAN = timedelta(days=90)
IOC_TYPES = {"ip", "domain", "url", "sha256", "sha1", "md5", "email"}


class BadRange(AppError):
    status_code = 422
    code = "invalid_range"


def _geo(request: Request) -> CachedGeo:
    s = get_settings()
    return get_geo(s.geoip_provider, s.geoip_db_path, s.geoip_asn_db_path)


def _csv(value: str | None, *, upper: bool = False, allowed: set[str] | None = None, limit: int = 25) -> list[str]:
    out: list[str] = []
    for part in (value or "").split(","):
        v = part.strip()
        if not v:
            continue
        v = v.upper() if upper else v
        if allowed is not None and v.lower() not in allowed and v not in allowed:
            raise AppError(f"unsupported value {v[:40]!r}")
        out.append(v.lower() if allowed is not None else v[:120])
    return out[:limit]


class FilterParams:
    """Query-string filters, validated once. Shared by every route so the map, the cards and the panels always agree."""

    def __init__(
        self,
        layer: Layer = "intelligence",
        range: Annotated[str, Query(pattern="^(1h|24h|7d|30d|custom)$")] = "24h",  # noqa: A002
        start: datetime | None = None,
        end: datetime | None = None,
        country: Annotated[str | None, Query(max_length=200)] = None,
        continent: Annotated[str | None, Query(max_length=40)] = None,
        ioc_type: Annotated[str | None, Query(max_length=100)] = None,
        severity: Annotated[Literal["info", "low", "medium", "high", "critical"], Query()] = "info",
        min_confidence: Annotated[int, Query(ge=0, le=100)] = 0,
        category: Annotated[str | None, Query(max_length=400)] = None,
        source: Annotated[str | None, Query(max_length=600)] = None,
        log_source: Annotated[str | None, Query(max_length=600)] = None,
        scope: Literal["any", "external", "internal"] = "any",
        q: Annotated[str, Query(max_length=120)] = "",
    ) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        if range == "custom":
            if start is None or end is None:
                raise BadRange("custom range needs start and end")
            s, e = start.astimezone(UTC), end.astimezone(UTC)
        else:
            s, e = (
                now
                - {
                    "1h": timedelta(hours=1),
                    "24h": timedelta(hours=24),
                    "7d": timedelta(days=7),
                    "30d": timedelta(days=30),
                }[range],
                now,
            )
        if e <= s:
            raise BadRange("end must be after start")
        if e - s > MAX_SPAN:
            raise BadRange("range is limited to 90 days")
        for c in _csv(country, upper=True):
            if c not in COUNTRY_NAMES:
                raise AppError(f"unknown country code {c[:8]!r}")
        self.filters = svc.Filters(
            start=s,
            end=e,
            layer=layer,
            countries=_csv(country, upper=True),
            continents=_csv(continent, upper=True, limit=7),
            ioc_types=_csv(ioc_type, allowed=IOC_TYPES, limit=7),
            min_severity=severity,
            min_confidence=min_confidence,
            categories=_csv(category),
            sources=_csv(source),
            log_sources=_csv(log_source),
            scope=scope,
            q=q.strip(),
        )


async def _dataset(request: Request, principal: Principal, session: AsyncSession, fp: FilterParams) -> svc.Dataset:
    return await svc.build_dataset(
        session, request.app.state.search, _geo(request), principal.tid, fp.filters, COUNTRY_NAMES
    )


async def _limit(request: Request, principal: Principal, name: str, limit: int = 60) -> None:
    await enforce(request, f"threatmap:{name}:{principal.user_id}", limit, 60)


@router.get("/status")
async def status(
    request: Request, principal: Principal = READ, _e: Principal = _EVENTS, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    """What the map can and cannot show right now, so empty layers can say exactly which integration is missing."""
    geo = _geo(request)
    now = datetime.now(UTC)
    start = now - timedelta(days=30)
    n_ip = (
        await session.execute(
            select(Ioc.id).where(Ioc.tenant_id == principal.tid, Ioc.type == "ip", Ioc.status != "REJECTED").limit(1)
        )
    ).first()
    telemetry_error = ""
    try:
        sources, total = await telemetry.telemetry_sources(
            request.app.state.search, principal.tid, start.isoformat(), now.isoformat()
        )
    except UpstreamUnavailable:
        sources, total = [], 0
        telemetry_error = "The search backend is unavailable, so observed activity cannot be checked right now."
    feeds = (
        (
            await session.execute(
                select(Ioc.source).where(Ioc.tenant_id == principal.tid, Ioc.type == "ip").distinct().limit(50)
            )
        )
        .scalars()
        .all()
    )
    s = get_settings()
    info = geo.info()
    return {
        "geoip": info,
        "home": (
            {"lat": s.threatmap_home_lat, "lon": s.threatmap_home_lon, "label": s.threatmap_home_label}
            if s.threatmap_home_lat is not None and s.threatmap_home_lon is not None
            else None
        ),
        "layers": {
            "intelligence": {
                "available": n_ip is not None,
                "feeds": sorted(feeds),
                "needs": ""
                if n_ip
                else "Add an IOC feed (IOC Hunting → Feeds) or import indicators; only IP indicators have a location.",
            },
            "observed": {
                "available": total > 0,
                "sources": sources,
                "error": telemetry_error,
                "needs": ""
                if (total or telemetry_error)
                else "No events with source/destination IP addresses in the last 30 days. Connect a firewall, IDS/IPS, EDR network or SIEM source under Data Sources.",
            },
            "correlated": {
                "available": n_ip is not None and total > 0,
                "needs": "" if (n_ip and total) else "Needs both an IOC feed and network telemetry.",
            },
        },
        "mappable_ioc_types": ["ip"],
        "disclaimer": "Locations are approximate, derived from a GeoIP database for the address. They are not the physical location of an attacker.",
    }


@router.get("/data")
async def data(
    request: Request,
    fp: FilterParams = Depends(),
    principal: Principal = READ,
    _e: Principal = _EVENTS,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Everything the dashboard needs for one filter set, computed once: cards, country intensity, markers, rankings, timeline."""
    await _limit(request, principal, "data")
    ds = await _dataset(request, principal, session, fp)
    f = ds.filters
    s = get_settings()
    recs = sorted(ds.records.values(), key=lambda r: (-r.weight(f.layer), r.ip))
    located = [r for r in recs if r.geo is not None and r.geo.lat is not None and r.geo.lon is not None]
    shown = located[: s.threatmap_max_markers]
    countries = svc.country_rows(ds)
    observed_events: int | None = ds.total_events
    partial: list[str] = []  # parts that depend on telemetry degrade to "unknown" instead of failing the whole map
    corr_all: list[dict[str, Any]] | None
    if f.layer == "correlated":
        corr_all = svc.correlations(ds)
    else:
        try:
            full = await svc.build_dataset(
                session,
                request.app.state.search,
                _geo(request),
                principal.tid,
                svc.Filters(**{**f.__dict__, "layer": "correlated"}),
                COUNTRY_NAMES,
            )
            corr_all = svc.correlations(full)
        except UpstreamUnavailable:
            corr_all, partial = None, ["telemetry"]
    if f.layer != "observed":  # the card is "events in scope", whichever layer is on screen
        try:
            _, observed_events = await telemetry.event_scope(
                request.app.state.search,
                principal.tid,
                f.start_iso,
                f.end_iso,
                sources=f.log_sources or None,
                min_severity=f.min_event_severity,
            )
        except UpstreamUnavailable:
            observed_events, partial = None, ["telemetry"]
    try:
        tl = await svc.timeline(session, request.app.state.search, principal.tid, ds)
    except UpstreamUnavailable:
        tl, partial = [], ["telemetry"]
    high = await svc.high_severity_detections(session, principal.tid, f)
    return {
        "layer": f.layer,
        "range": {"start": f.start.isoformat(), "end": f.end.isoformat()},
        "active_filters": f.active(),
        "cards": {
            "unique_malicious_ips": ds.intel_ips,
            "countries_with_indicators": len(ds.intel_countries),
            "top_indicator_country": (
                {"iso": top[0], "name": top[1][0], "ips": top[1][1]}
                if (top := max(ds.intel_countries.items(), key=lambda kv: (kv[1][1], kv[0]), default=None))
                else None
            ),
            "observed_events": observed_events,
            "observed_remote_ips": sum(1 for r in recs if r.activity) if f.layer != "intelligence" else None,
            "internal_addresses": len(ds.internal),
            "correlated_threats": len(corr_all) if corr_all is not None else None,
            "correlated_ips": len({c["ip"] for c in corr_all}) if corr_all is not None else None,
            "high_severity_detections": high,
        },
        "countries": countries,
        "markers": [svc.marker_json(r, f.layer) for r in shown],
        "unlocated": len(recs) - len(located),
        "truncated": len(located) > len(shown),
        "total_markers": len(located),
        "top_countries": countries[:10],
        "top_ips": [svc.marker_json(r, f.layer) for r in recs[:10]],
        "internal": [
            {"ip": ip, "class": classify_with_own(ip, get_settings().own_networks), **svc.activity_json(a)}
            for ip, a in sorted(ds.internal.items(), key=lambda kv: -kv[1].events)[:25]
        ],
        "recent_correlations": (corr_all or [])[:8],
        "partial": partial,
        "timeline": {"points": tl, "unit": svc.interval_for(f.start, f.end)[0], "layer": f.layer},
        "notes": ds.notes,
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.get("/flows")
async def flows(
    request: Request,
    fp: FilterParams = Depends(),
    principal: Principal = READ,
    _e: Principal = _EVENTS,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Source→destination pairs established by the events themselves. A pair is placed only when its public end(s) geolocate; the
    other end is the configured `home` location (inbound/outbound) or another geolocated address (external↔external)."""
    await _limit(request, principal, "flows", 30)
    f = fp.filters
    geo = _geo(request)
    s = get_settings()
    own = s.own_networks
    home = (
        (s.threatmap_home_lat, s.threatmap_home_lon)
        if s.threatmap_home_lat is not None and s.threatmap_home_lon is not None
        else None
    )
    if f.layer == "intelligence":
        return {
            "flows": [],
            "home": None,
            "reason": "Arcs are drawn from observed network events; switch to Observed or Correlated.",
        }
    ips = None
    if f.layer == "correlated":
        ds = await _dataset(request, principal, session, fp)
        ips = [ip for ip, r in ds.records.items() if r.activity is not None]
        if not ips:
            return {"flows": [], "home": None, "reason": "No correlated addresses in this window."}
    parsed = svc.parse_search(f.q, COUNTRY_NAMES)
    if parsed.ip:
        ips = [parsed.ip]
    raw = await telemetry.flows(
        request.app.state.search,
        principal.tid,
        f.start_iso,
        f.end_iso,
        sources=f.log_sources or None,
        min_severity=f.min_event_severity,
        ips=ips,
    )
    out: list[dict[str, Any]] = []
    for fl in raw:
        c_src, c_dst = classify_with_own(fl.src_ip, own), classify_with_own(fl.dst_ip, own)
        if "invalid" in (c_src, c_dst):
            continue
        direction = (
            "internal" if c_src != "public" and c_dst != "public"
            else "inbound" if c_src == "public" and c_dst != "public"
            else "outbound" if c_dst == "public" and c_src != "public"
            else "external"
        )  # fmt: skip
        if direction == "internal":
            continue
        ends: list[dict[str, Any]] = []
        for ip, cls in ((fl.src_ip, c_src), (fl.dst_ip, c_dst)):
            g = geo.lookup(ip) if cls == "public" else None
            if g is not None and g.lat is not None and g.lon is not None:
                ends.append(
                    {
                        "ip": ip,
                        "class": cls,
                        "lat": round(g.lat, 2),
                        "lon": round(g.lon, 2),
                        "country": g.country,
                        "city": g.city,
                    }
                )
            elif cls != "public" and home is not None:
                ends.append(
                    {
                        "ip": ip,
                        "class": cls,
                        "lat": round(home[0], 2),
                        "lon": round(home[1], 2),
                        "country": "",
                        "city": s.threatmap_home_label,
                    }
                )
            else:
                ends.append({"ip": ip, "class": cls, "lat": None, "lon": None, "country": "", "city": ""})
        if any(e["lat"] is None for e in ends):
            continue
        if f.countries and not any(e["country"] in f.countries for e in ends):
            continue
        if f.continents:
            ok = [geo.lookup(e["ip"]) for e in ends if e["class"] == "public"]
            if not any(g and g.continent in f.continents for g in ok):
                continue
        out.append(
            {
                "src": ends[0], "dst": ends[1], "direction": direction, "events": fl.events, "first_seen": fl.first_seen, "last_seen": fl.last_seen,
                "severity": svc.event_severity(fl.max_severity), "ports": fl.ports, "sources": fl.sources, "protocols": fl.protocols,
            }
        )  # fmt: skip
    out.sort(key=lambda x: -x["events"])
    return {
        "flows": out[:400],
        "home": {"lat": home[0], "lon": home[1], "label": s.threatmap_home_label} if home else None,
        "reason": "" if out else "No source→destination pairs with a locatable public address in this window.",
        "note": ""
        if home
        else "THREATMAP_HOME_LAT/LON is not set, so inbound/outbound pairs have no far end and are not drawn.",
    }


@router.get("/correlations")
async def list_correlations(
    request: Request,
    fp: FilterParams = Depends(),
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    offset: Annotated[int, Query(ge=0, le=5000)] = 0,
    principal: Principal = READ,
    _e: Principal = _EVENTS,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    await _limit(request, principal, "corr")
    f = fp.filters
    f.layer = "correlated"
    ds = await _dataset(request, principal, session, fp)
    items = svc.correlations(ds)
    cases = await svc.case_refs(
        session, principal.tid, [i["case_id"] for i in items[offset : offset + limit] if i["case_id"]]
    )
    page = items[offset : offset + limit]
    for i in page:
        i["case"] = cases.get(i["case_id"]) if i["case_id"] else None
    return {"total": len(items), "items": page, "limit": limit, "offset": offset}


@router.get("/indicator")
async def indicator(
    request: Request,
    ip: Annotated[str, Query(max_length=64)],
    fp: FilterParams = Depends(),
    principal: Principal = READ,
    _e: Principal = _EVENTS,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Investigation panel for one address: geolocation (approximate), reported intelligence, our own activity, related indicators,
    matched events, alerts and cases. Reads are audited; the actions the panel offers go through the existing, separately authorised APIs."""
    await _limit(request, principal, "indicator")
    try:
        norm = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise AppError("not a valid IP address") from None
    f = fp.filters
    tid = principal.tid
    cls = classify_with_own(norm, get_settings().own_networks)
    geo = _geo(request).lookup(norm)
    rows = (
        await session.execute(
            select(Ioc, Threat.name, Threat.severity)
            .outerjoin(Threat, Threat.id == Ioc.threat_id)
            .where(Ioc.tenant_id == tid, Ioc.type == "ip", Ioc.value == norm)
            .order_by(Ioc.last_seen.desc())
            .limit(25)
        )
    ).all()
    iocs: list[dict[str, Any]] = [
        {
            "id": str(i.id), "source": i.source, "confidence": i.confidence, "severity": svc.ioc_severity(i.confidence, t_sev), "threat_type": i.threat_type,
            "malware": i.malware, "threat": t_name or i.threat_name, "threat_id": str(i.threat_id) if i.threat_id else None, "tags": list(i.tags or [])[:12],
            "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat(), "status": i.status, "description": i.description[:500],
            "reference": i.reference if i.reference.startswith(("http://", "https://")) else "", "case_id": str(i.case_id) if i.case_id else None,
            "stale": i.status == "EXPIRED" or datetime.now(UTC) - i.last_seen > svc.STALE_AFTER,
        }
        for i, t_name, t_sev in rows
    ]  # fmt: skip
    threat_ids = {uuid.UUID(i["threat_id"]) for i in iocs if i["threat_id"]}
    related: list[dict[str, Any]] = []
    if threat_ids:
        rel = (
            (
                await session.execute(
                    select(Ioc)
                    .where(
                        Ioc.tenant_id == tid, Ioc.threat_id.in_(threat_ids), Ioc.value != norm, Ioc.status != "REJECTED"
                    )
                    .order_by(Ioc.confidence.desc())
                    .limit(20)
                )
            )
            .scalars()
            .all()
        )
        related = [
            {"id": str(r.id), "type": r.type, "value": r.value, "confidence": r.confidence, "source": r.source}
            for r in rel
        ]
    activity, _ = await telemetry.ip_activity(
        request.app.state.search, tid, f.start_iso, f.end_iso, ips=[norm], include_internal=True
    )
    act = activity.get(norm)
    events, event_total = await telemetry.events_for_ip(request.app.state.search, tid, norm, f.start_iso, f.end_iso)
    peers_raw = (
        await telemetry.flows(request.app.state.search, tid, f.start_iso, f.end_iso, ips=[norm], limit=20)
        if cls == "public"
        else []
    )
    peers = [
        {
            "src_ip": p.src_ip,
            "dst_ip": p.dst_ip,
            "events": p.events,
            "last_seen": p.last_seen,
            "ports": p.ports,
            "sources": p.sources,
        }
        for p in sorted(peers_raw, key=lambda p: -p.events)[:10]
    ]
    ev_ids = [e["id"] for e in events if e.get("id")]
    alerts = (
        (await session.execute(select(Alert).where(Alert.tenant_id == tid, Alert.event_id.in_(ev_ids)).order_by(Alert.event_timestamp.desc()).limit(10))).scalars().all()
        if ev_ids else []
    )  # fmt: skip
    matches = (
        await session.execute(select(IocMatch, Ioc).join(Ioc, Ioc.id == IocMatch.ioc_id).where(IocMatch.tenant_id == tid, IocMatch.event_id.in_(ev_ids)).limit(25))
        if ev_ids else None
    )  # fmt: skip
    hunt_matches = [
        {"ioc_type": ioc.type, "ioc_value": ioc.value, "event_id": m.event_id, "timestamp": m.event_timestamp.isoformat(), "matched_field": m.matched_field, "host": m.host}
        for m, ioc in (matches.all() if matches else [])
    ]  # fmt: skip
    case_rows = (
        (
            await session.execute(
                select(Case)
                .join(CaseIoc, CaseIoc.case_id == Case.id)
                .where(Case.tenant_id == tid, CaseIoc.type == "ip", CaseIoc.value == norm)
                .limit(10)
            )
        )
        .scalars()
        .all()
    )
    case_ids = {str(c.id) for c in case_rows} | {i["case_id"] for i in iocs if i["case_id"]}
    cases = await svc.case_refs(session, tid, list(case_ids))
    can = principal.has
    corr_reason = ""
    if iocs and act:
        corr_reason = f"{norm} is reported by {', '.join(sorted({i['source'] for i in iocs})[:3])} and appears in {act.events} of your events."
    await audit.record(
        request,
        "threatmap.indicator.view",
        principal=principal,
        resource_type="ip",
        resource_id=norm,
        details={"layer": f.layer},
    )
    return {
        "ip": norm,
        "class": cls,
        "geo": svc.geo_json(geo),
        "geo_note": "Approximate location of the address from a GeoIP database; not the location of whoever operates it."
        if geo
        else (
            "Private/internal address: no public location exists."
            if cls != "public"
            else "No GeoIP record for this address."
        ),
        "intel": iocs,
        "related_iocs": related,
        "observed": svc.activity_json(act) if act else None,
        "events": [svc.summarize_event(e) for e in events],
        "events_total": event_total,
        "peers": peers,
        "hunt_matches": hunt_matches,
        "alerts": [
            {
                "id": str(a.id),
                "rule": a.rule_title,
                "severity": a.severity,
                "status": a.status,
                "event_id": a.event_id,
                "timestamp": a.event_timestamp.isoformat(),
            }
            for a in alerts
        ],
        "cases": list(cases.values()),
        "correlated": bool(iocs and act),
        "correlation_reason": corr_reason,
        "actions": {
            "investigate": can(Permission.EVENTS_READ),
            "intel_lookup": can(Permission.INTEL_WRITE),
            "hunt": can(Permission.IOCHUNT_VALIDATE) and any(i["status"] in ("NEW", "VALIDATED") for i in iocs),
            "add_to_watchlist": can(Permission.IOCHUNT_VALIDATE) and cls == "public",
            "add_to_case": can(Permission.CASES_WRITE) and bool(ev_ids),
        },
    }
