# ruff: noqa: E501
"""Where the data lives: a map of the LogRhythm log sources (type, host, entity, last log date) read once from the admin API and kept for a
while, so a hunt can go straight to the sources that can answer its question instead of searching the whole SIEM and hoping.

`maxLogDate` of a log source is the date of its newest log: a source that is enabled but silent is a blind spot, and a host with no log
source of the kind a hypothesis needs (web server logs, an endpoint agent) is a place where searching LogRhythm cannot find anything."""

import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.connectors._http import SourceError
from app.connectors.logrhythm_admin import MAX_PAGES, PAGE
from app.connectors.logrhythm_alarms import _get

TTL_S = 600
ACTIVE_HOURS = 24
_NEVER = datetime(1971, 1, 1, tzinfo=UTC)  # LogRhythm writes 1900-01-01 for a source that has never logged

# (role, keywords in the log source type name), first match wins; the order puts the specific before the general
ROLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "web_server",
        (
            "apache",
            "iis",
            "nginx",
            "tomcat",
            "weblogic",
            "websphere",
            "jboss",
            "wildfly",
            "lighttpd",
            "web server",
            "glassfish",
        ),
    ),
    (
        "proxy_gateway",
        ("squid", "bluecoat", "proxy", "web gateway", "web security", "ironport", "zscaler", "forcepoint", "wsa"),
    ),
    (
        "waf_ids",
        ("waf", "web application firewall", "imperva", "modsecurity", "snort", "suricata", "intrusion", "ids", "ips"),
    ),
    (
        "firewall",
        (
            "firewall",
            "asa",
            "firepower",
            "fortigate",
            "fortinet",
            "palo alto",
            "checkpoint",
            "check point",
            "pfsense",
            "sonicwall",
            "netscreen",
        ),
    ),
    (
        "endpoint_agent",
        (
            "logrhythm user activity",
            "logrhythm process",
            "logrhythm file monitor",
            "logrhythm registry",
            "logrhythm network connection",
            "logrhythm data loss",
            "system monitor",
        ),
    ),
    ("windows_events", ("windows event", "ms windows", "sysmon")),
    ("linux_unix", ("linux", "unix", "auditd", "openssh", "solaris", "aix", "syslog - generic")),
    ("directory_auth", ("active directory", "radius", "kerberos", "ldap", "tacacs", "okta", "adfs")),
    ("database", ("oracle", "sql server", "mssql", "mysql", "postgres", "db2", "mongodb")),
    ("dns_dhcp", ("dns", "dhcp", "infoblox", "bind")),
    ("email", ("exchange", "smtp", "mail", "o365", "office 365", "proofpoint", "mimecast")),
    ("cloud", ("azure", "aws", "amazon", "gcp", "google cloud", "entra")),
    (
        "security_tools",
        (
            "antivirus",
            "mcafee",
            "symantec",
            "kaspersky",
            "crowdstrike",
            "defender",
            "trend micro",
            "sophos",
            "carbon black",
        ),
    ),
    (
        "network_device",
        ("router", "switch", "wireless", "wlc", "access point", "cisco", "juniper", "hp procurve", "netflow"),
    ),
)


def role_of(type_name: str) -> str:
    low = type_name.lower()
    for role, words in ROLES:
        if any(re.search(rf"\b{re.escape(w)}", low) for w in words):
            return role
    return "other"


@dataclass(frozen=True)
class Source:
    id: int
    name: str
    host: str
    entity: str
    type_id: int
    type_name: str
    role: str
    enabled: bool
    newest: datetime | None


@dataclass
class LrMap:
    sources: list[Source]
    loaded: float


_CACHE: dict[uuid.UUID, LrMap] = {}


def _date(v: Any) -> datetime | None:
    if not isinstance(v, str):
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
    return None if d < _NEVER else d


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


async def load(ds_id: uuid.UUID, connector: Any) -> LrMap:
    """The log sources of one LogRhythm data source (`connector` is a built LogRhythm connector), cached for TTL_S."""
    hit = _CACHE.get(ds_id)
    if hit is not None and time.monotonic() - hit.loaded < TTL_S:
        return hit
    raw: dict[Any, dict[str, Any]] = {}
    for page_no in range(MAX_PAGES):
        page = await _get(connector, "logsources", {"count": PAGE, "offset": page_no * PAGE}, api="lr-admin-api")
        if not isinstance(page, list):
            raise SourceError("unexpected admin response shape")
        fresh = {s.get("id"): s for s in page if isinstance(s, dict) and s.get("id") not in raw}
        raw.update(fresh)
        if len(page) < PAGE or not fresh:
            break
    out: list[Source] = []
    for s in raw.values():
        t, host, entity = _obj(s.get("logSourceType")), _obj(s.get("host")), _obj(s.get("entity"))
        if not isinstance(s.get("id"), int) or not isinstance(t.get("id"), int):
            continue
        tname = str(t.get("name") or t["id"])
        out.append(
            Source(
                id=s["id"],
                name=str(s.get("name") or s["id"])[:120],
                host=str(host.get("name") or "")[:120],
                entity=str(entity.get("name") or "")[:80],
                type_id=t["id"],
                type_name=tname[:100],
                role=role_of(tname),
                enabled=str(s.get("status", "Enabled")).lower() == "enabled"
                and str(s.get("recordStatus", "Active")) == "Active",
                newest=_date(s.get("maxLogDate")),
            )
        )
    _CACHE[ds_id] = LrMap(out, time.monotonic())
    return _CACHE[ds_id]


def _age(d: datetime | None, now: datetime) -> str:
    if d is None:
        return "never"
    h = (now - d).total_seconds() / 3600
    return f"{round(h * 60)}m ago" if h < 1 else f"{round(h)}h ago" if h < 48 else f"{round(h / 24)}d ago"


def summary(
    m: LrMap, *, about: str = "", host: str = "", hours: int = ACTIVE_HOURS, max_types: int = 8
) -> dict[str, Any]:
    """The map for a model: counts and the active log source TYPES by role (what can answer what), or - with `host` - what exists for that
    host, silent or not. `about` keeps only the types/sources whose name contains one of its words."""
    now = datetime.now(UTC)
    cut = now - timedelta(hours=hours)
    active = [s for s in m.sources if s.enabled and s.newest and s.newest >= cut]
    totals = {
        "log_sources": len(m.sources),
        "active": len(active),
        "enabled_but_silent": sum(1 for s in m.sources if s.enabled and not (s.newest and s.newest >= cut)),
        "never_logged": sum(1 for s in m.sources if s.newest is None),
        "disabled": sum(1 for s in m.sources if not s.enabled),
    }
    out: dict[str, Any] = {"active_means": f"enabled and logged in the last {hours}h", "totals": totals}
    if host.strip():
        h = host.strip().lower()
        mine = [s for s in m.sources if h in s.host.lower() or h in s.name.lower()]
        rows = sorted(mine, key=lambda s: s.newest or _NEVER, reverse=True)[:30]
        out["host"] = host.strip()
        out["log_sources_of_host"] = [
            {
                "name": s.name,
                "type": s.type_name,
                "role": s.role,
                "enabled": s.enabled,
                "newest_log": _age(s.newest, now),
                "active": s in active,
            }
            for s in rows
        ]
        out["matched"] = len(mine)
        if not mine:
            out["note"] = (
                "LogRhythm has NO log source for this host: searching LogRhythm for it can only find logs OTHER devices wrote about it "
                "(firewalls, proxies, domain controllers). Its own telemetry, if any, is elsewhere (Trend)."
            )
        elif not any(s in active for s in mine):
            out["note"] = (
                "every log source of this host is silent or disabled: a blind spot, so an empty search proves nothing."
            )
        return out
    words = [w for w in re.findall(r"[a-z0-9]{3,}", about.lower())]
    pool = active
    if words:
        pool = [s for s in active if any(w in f"{s.type_name} {s.name} {s.role}".lower() for w in words)]
        out["filtered_by"] = words
    by_role: dict[str, dict[str, dict[str, Any]]] = {}
    for s in pool:
        row = by_role.setdefault(s.role, {}).setdefault(
            s.type_name, {"type": s.type_name, "sources": 0, "newest": s.newest, "hosts": []}
        )
        row["sources"] += 1
        row["newest"] = max(row["newest"], s.newest) if s.newest and row["newest"] else row["newest"] or s.newest
        if s.host and s.host not in row["hosts"] and len(row["hosts"]) < 3:
            row["hosts"].append(s.host)
    roles: dict[str, Any] = {}
    for role in sorted(by_role, key=lambda r: (r == "other", -sum(t["sources"] for t in by_role[r].values()))):
        types = sorted(by_role[role].values(), key=lambda t: -t["sources"])
        roles[role] = {
            "active_sources": sum(t["sources"] for t in types),
            "types": [
                {
                    "type": t["type"],
                    "sources": t["sources"],
                    "newest_log": _age(t["newest"], now),
                    "example_hosts": t["hosts"],
                }
                for t in types[:max_types]
            ]
            + ([{"more_types": len(types) - max_types}] if len(types) > max_types else []),
        }
    out["by_role"] = roles
    out["use"] = (
        "Scope siem_search with log_source_types=[type names from here] to ask only the sources that can answer; a role with no active "
        "source here is a question LogRhythm cannot answer."
    )
    return out


def resolve_types(m: LrMap, names: list[str]) -> tuple[list[int], list[str]]:
    """Type ids for names (exact, else case-insensitive substring of the type name; a role name selects every type of the role).
    Returns (ids, names that matched nothing)."""
    types = {s.type_id: s.type_name for s in m.sources}
    ids: list[int] = []
    missing: list[str] = []
    for raw in names:
        n = raw.strip().lower()
        if not n:
            continue
        hit = [i for i, t in types.items() if t.lower() == n]
        if not hit:
            hit = [i for i, t in types.items() if n in t.lower()]
        if not hit:
            hit = sorted({s.type_id for s in m.sources if s.role == n.replace(" ", "_")})
        if hit:
            ids += [i for i in hit if i not in ids]
        else:
            missing.append(raw)
    return ids[:50], missing
