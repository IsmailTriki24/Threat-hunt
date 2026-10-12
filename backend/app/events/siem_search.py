"""Live whole-SIEM search: every interactive search also asks LogRhythm, not just the slice the connector collects.

The connector is deliberately narrow (one host, 30,000 logs/minute cap), so an indicator that appears elsewhere in the SIEM would be invisible to
analysts. This module takes the indicators found in a search (IP, domain, hash, e-mail, host name) and queries the *whole* SIEM for them with the
verified filters from `connectors/logrhythm.py`, then:
  * attributes each returned log to the indicator it really contains (whole-token match; a loose vendor filter cannot create a false hit),
  * applies the query's remaining filters locally (LogRhythm cannot express them),
  * imports the matching logs as events (idempotent: ids are deterministic, so collection and search never duplicate each other), so the normal
    results, the event drawer and cases can use them.
Terms LogRhythm cannot search (process names, command lines, ports...) are reported back instead of silently ignored."""

import asyncio
import ipaddress
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import registry as connectors
from app.connectors._http import SourceError
from app.connectors.base import NormalizationError
from app.connectors.logrhythm import ioc_query_filter
from app.core.config import Settings
from app.core.crypto import decrypt_json
from app.datasources.models import DataSource
from app.events.schema import Event
from app.events.search import local
from app.events.search.base import SearchBackend
from app.events.search.query import EventQuery, Filter, TimeRange
from app.events.summary import summarize
from app.iochunt.hunting import attribute_raw

SOURCE = "LogRhythm SIEM"
MAX_WINDOW = timedelta(days=14)
BUDGET_S = 150
MAX_VALUES_PER_KIND = 50
MAX_LOGS = 3000
_GATE = asyncio.Semaphore(2)  # at most two whole-SIEM searches at once per process: LogRhythm searches are heavy

# Which event fields name which kind of indicator. A filter on one of these becomes a SIEM search for the value(s).
FIELD_KIND = {
    "network.src_ip": "ip", "network.dst_ip": "ip", "auth.source_ip": "ip", "host.ip": "ip",
    "network.dst_domain": "domain", "dns.question": "domain",
    "process.hash.md5": "md5", "process.hash.sha1": "sha1", "process.hash.sha256": "sha256", "file.hash.sha256": "sha256",
    "host.hostname": "hostname",
}  # fmt: skip
_HASH = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
_EMAIL = re.compile(r"^[^@\s]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,24}$", re.I)


@dataclass
class Plan:
    terms: dict[str, list[str]] = field(default_factory=dict)  # kind -> values
    skipped: list[str] = field(default_factory=list)  # human reasons for what LogRhythm cannot be asked
    rest: list[Filter] = field(default_factory=list)  # filters applied locally to what comes back


def classify(token: str) -> str | None:
    """Kind of indicator a bare token is, or None."""
    t = token.strip().strip("\"'")
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]+", t) and len(t) in _HASH:
        return _HASH[len(t)]
    if _EMAIL.match(t):
        return "email"
    if _DOMAIN.match(t):
        return "domain"
    return None


def _add(plan: Plan, kind: str, value: str) -> None:
    vals = plan.terms.setdefault(kind, [])
    v = value.lower() if kind in ("domain", "md5", "sha1", "sha256", "email", "hostname") else value
    if v not in vals and len(vals) < MAX_VALUES_PER_KIND:
        vals.append(v)


def plan_for(query: EventQuery) -> Plan:
    """Turn a search into SIEM terms: indicator-field filters and bare indicators in the free text; everything else is reported or applied locally."""
    plan = Plan()
    unsupported: set[str] = set()
    for f in query.effective_filters():
        kind = FIELD_KIND.get(f.field)
        if kind and not f.negate and f.op in ("eq", "in") and f.value is not None:
            for v in f.value if isinstance(f.value, list) else [f.value]:
                _add(plan, kind, str(v))
            continue
        plan.rest.append(f)
        if not (kind and f.negate) and f.op not in ("exists", "not_exists"):
            unsupported.add(f.field)
    if query.where is not None:
        unsupported.add("boolean conditions")
    free = " ".join(p for p in (query.q, query._parsed[0]) if p)
    for tok in re.findall(r'"[^"]+"|\S+', free):
        tok = tok.strip("\"'()")
        if tok.upper() in ("AND", "OR", "NOT") or tok.startswith("-"):
            continue
        kind = classify(tok)
        if kind:
            _add(plan, kind, tok)
    if unsupported:
        plan.skipped.append(
            "LogRhythm can't be searched by "
            + ", ".join(sorted(unsupported))
            + "; those filters are applied to the logs it returns"
        )
    return plan


def plan_for_indicator(kind: str, value: str) -> Plan:
    plan = Plan()
    _add(plan, kind, value)
    return plan


def _window(rng: TimeRange) -> tuple[datetime, datetime, str]:
    start, end, note = rng.start, rng.end, ""
    if end - start > MAX_WINDOW:
        start = end - MAX_WINDOW
        note = f"The SIEM is searched over at most the last {MAX_WINDOW.days} days of your range."
    return start, end, note


async def siem_search(
    session: AsyncSession, backend: SearchBackend, settings: Settings, tenant_id: uuid.UUID, plan: Plan, rng: TimeRange
) -> dict[str, Any]:
    ds = (
        await session.execute(
            select(DataSource).where(
                DataSource.tenant_id == tenant_id, DataSource.connector_type == "logrhythm", DataSource.enabled.is_(True)
            )
        )
    ).scalars().first()  # fmt: skip
    base: dict[str, Any] = {
        "source": SOURCE,
        "configured": ds is not None,
        "searched": [],
        "skipped": list(plan.skipped),
        "matched": 0,
        "imported": 0,
        "duplicates": 0,
        "truncated": False,
    }
    if ds is None:
        return {**base, "status": "unconfigured", "detail": "No LogRhythm data source is configured for this tenant."}
    if (ds.config or {}).get("siem_search") is False:
        return {
            **base,
            "status": "disabled",
            "detail": "Whole-SIEM search is switched off for this source (siem_search: false).",
        }
    if not plan.terms:
        why = "Nothing in this search can be looked up in LogRhythm: it searches for IP addresses, domains, hashes, e-mail addresses and host names."
        return {**base, "status": "not_applicable", "detail": why}

    start, end, note = _window(rng)
    t0 = time.monotonic()
    try:
        secrets = {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()} if ds.secrets_enc else {}
        conn: Any = connectors.build("logrhythm", ds.config, secrets)
        batch = conn.cfg.ioc_batch
        deadline = t0 + BUDGET_S
        cut = False
        events: dict[str, Event] = {}
        searched: list[dict[str, Any]] = []
        raw_seen = 0
        async with _GATE:
            for kind, values in plan.terms.items():
                for k in range(0, len(values), batch):
                    if time.monotonic() > deadline:
                        cut = True
                        break
                    vals = values[k : k + batch]
                    conn._filter_override = ioc_query_filter(kind, vals)
                    try:
                        logs = await conn._search_window(start, end)
                    finally:
                        conn._filter_override = None
                    searched.append({"kind": kind, "values": vals, "logs": len(logs)})
                    raw_seen += len(logs)
                    cands = [
                        SimpleNamespace(
                            value=v, type="ip" if kind == "ip" else "domain" if kind in ("domain", "hostname") else kind
                        )
                        for v in vals
                    ]
                    for raw in logs[:MAX_LOGS]:
                        attributed = attribute_raw(raw, cands)  # type: ignore[arg-type]
                        if not attributed:  # a loose vendor filter must never create a false hit
                            continue
                        try:
                            evs = [Event.from_input(e, tenant_id) for e in conn.normalize(raw)]
                        except NormalizationError:
                            continue
                        for ev in evs:
                            doc = ev.to_document()
                            if all(
                                local.matches_filter(f, doc)
                                for f in plan.rest
                                if f.field not in FIELD_KIND or f.negate or f.op not in ("eq", "in")
                            ):
                                events[ev.id] = ev
                if cut:
                    break
        res = await backend.index_events(list(events.values())) if events else None
        if events:
            await backend.refresh()
        detail = f"{len(searched)} search(es) over the whole SIEM, {(end - start).total_seconds() / 3600:.0f} h"
        if note:
            detail += ". " + note
        if cut:
            detail += ". Time budget reached; some terms were not searched."
        newest = sorted(events.values(), key=lambda e: e.timestamp, reverse=True)[:8]
        samples = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "summary": summarize(e.to_document())[:200],
                "host": e.host.hostname if e.host else None,
            }
            for e in newest
        ]
        return {
            **base, "status": "partial" if cut else "ok", "samples": samples, "searched": searched, "matched": len(events), "imported": res.accepted if res else 0,
            "duplicates": res.duplicates if res else 0, "truncated": cut or any(s["logs"] >= MAX_LOGS for s in searched), "logs_scanned": raw_seen,
            "window": {"start": start.isoformat(), "end": end.isoformat()}, "ms": int((time.monotonic() - t0) * 1000), "detail": detail,
        }  # fmt: skip
    except (SourceError, ValueError) as exc:
        return {**base, "status": "error", "detail": str(exc)[:240], "ms": int((time.monotonic() - t0) * 1000)}
