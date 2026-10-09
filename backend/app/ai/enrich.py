"""Threat-intel enrichment for the hunt agent. Indicators the agent meets (public IPs, domains, URLs, hashes; suspicious executable
names) are checked against the tenant's own configured providers (VirusTotal, OTX, ThreatFox, URLhaus, MISP, watch-list - the same
machinery as the Threat Intel page, same keys, same cache) and, when none answers, against well-known public threat-intel sites.

Everything here decides what may LEAVE the platform: only public indicators are ever looked up, never an internal address, a host or
user name, or a file name that contains one. Provider answers are untrusted data - extracted, size-capped, never acted upon."""

import ntpath
import re
import uuid
from typing import Any, Literal
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import state as st
from app.core.config import Settings
from app.intel import service as intel_service
from app.intel import types as intel_types
from app.intel.models import IntelObservation
from app.investigations import iocs

Kind = Literal["ip", "domain", "url", "hash", "file"]

# Public sources searched on the web when no configured provider answers (Tavily `include_domains`).
TI_SITES = [
    "virustotal.com",
    "otx.alienvault.com",
    "abuseipdb.com",
    "urlhaus.abuse.ch",
    "threatfox.abuse.ch",
    "bazaar.abuse.ch",
    "hybrid-analysis.com",
    "app.any.run",
    "tria.ge",
    "talosintelligence.com",
    "greynoise.io",
    "shodan.io",
    "malpedia.caad.fkie.fraunhofer.de",
    "attack.mitre.org",
]

_EXEC_EXT = (
    ".exe",
    ".dll",
    ".scr",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".hta",
    ".msi",
    ".jar",
    ".lnk",
    ".sys",
    ".docm",
    ".xlsm",
)
# Ubiquitous operating-system / browser binaries: looking them up tells nothing and spends budget.
_COMMON_BINARIES = {
    "svchost.exe", "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe", "teams.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "notepad.exe", "services.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "smss.exe", "taskhostw.exe",
    "conhost.exe", "dllhost.exe", "taskmgr.exe", "mmc.exe", "spoolsv.exe", "searchindexer.exe", "onedrive.exe", "taskeng.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "reg.exe", "net.exe", "net1.exe", "whoami.exe", "tasklist.exe",
    "schtasks.exe", "sc.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe",
    "installutil.exe", "ping.exe", "ipconfig.exe", "nslookup.exe", "curl.exe", "wget.exe", "msiexec.exe", "cmstp.exe",
    "officeclicktorun.exe", "integrator.exe", "officec2rclient.exe", "appvshnotify.exe", "msedgewebview2.exe", "backgroundtaskhost.exe",
    "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "audiodg.exe", "dwm.exe", "fontdrvhost.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe", "wmiprvse.exe", "wudfhost.exe", "msmpeng.exe", "mpcmdrun.exe", "slack.exe",
    "zoom.exe", "code.exe", "update.exe", "setup.exe", "installer.exe", "uninstall.exe",
}  # fmt: skip
# Domains that are overwhelmingly benign infrastructure; auto-enrichment skips them (the agent can still ask explicitly).
_BENIGN_SUFFIXES = (
    "microsoft.com", "windowsupdate.com", "office.com", "office365.com", "live.com", "msftconnecttest.com", "azure.com",
    "google.com", "googleapis.com", "gstatic.com", "github.com", "githubusercontent.com", "apple.com", "digicert.com",
)  # fmt: skip
_HEX = re.compile(r"^[a-f0-9]+$")
_FILE = re.compile(r"^[\w][\w .()+\-]{0,98}\.[A-Za-z0-9]{1,6}$")


def classify(value: str, kind: str | None = None) -> tuple[Kind, str] | None:
    """(kind, normalised value) or None when it is not something that can be looked up."""
    v = value.strip()
    if not v:
        return None
    if kind is None:
        base = ntpath.basename(v.replace("/", "\\")).lower()
        if base.endswith(_EXEC_EXT) and _FILE.match(
            base
        ):  # "upd.exe" parses as a domain; an executable name is what it means
            kind = "file"
        else:
            detected = intel_types.detect_type(v)
            kind = {"ip": "ip", "domain": "domain", "url": "url", "md5": "hash", "sha1": "hash", "sha256": "hash"}.get(
                detected or ""
            )  # type: ignore[assignment]
            if kind is None and _FILE.match(v):
                kind = "file"
    if kind == "file":
        name = ntpath.basename(v.replace("/", "\\")).strip().lower()
        return ("file", name) if _FILE.match(name) else None
    if kind == "hash":
        for cand in ("sha256", "sha1", "md5"):
            h = intel_types.normalize(cand, v)
            if h:
                return ("hash", h)
        return None
    if kind in ("ip", "domain", "url"):
        n = intel_types.normalize(kind, v)
        return (kind, n) if n else None  # type: ignore[return-value]
    return None


def intel_type(kind: Kind, value: str) -> str:
    if kind == "hash":
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "sha256")
    return kind


def _names(inv: st.Investigation | None) -> set[str]:
    """Host and user names seen in this investigation: internal identifiers that must not leave the platform."""
    if inv is None:
        return set()
    out: set[str] = set()
    for e in inv.evidence.values():
        out.update(str(e.get(k) or "").lower() for k in ("host", "user"))
    out.update(e.value.lower() for e in inv.entities.values() if e.type in ("host", "user"))
    return {n for n in out if len(n) >= 3}


def _mentions(text: str, names: set[str], *, embedded: bool = False) -> bool:
    """Does `text` contain one of the names? `embedded` also catches names glued into file names / URLs ("bob_passwords.exe")."""
    low = text.lower()
    if embedded:
        return any(n in low for n in names)
    return any(re.search(rf"(?<![\w.-]){re.escape(n)}(?![\w-])", low) for n in names)


def internal_reason(inv: st.Investigation | None, kind: Kind, value: str) -> str | None:
    """Why this indicator must not be sent to an external service (None = it is a public indicator)."""
    names = _names(inv)
    if kind == "ip":
        return "an internal or non-routable IP address" if iocs.is_internal_ip(value) else None
    if kind == "hash":
        return None
    if kind in ("domain", "url"):
        host = (urlparse(value).hostname or "") if kind == "url" else value
        host = host.lower().strip(".")
        if not host:
            return "no host in the URL"
        if re.fullmatch(r"[\d.]+|[0-9a-f:]+", host) and iocs.is_internal_ip(host):
            return "an internal or non-routable IP address"
        if "." not in host or host.endswith(iocs._INTERNAL_SUFFIXES):
            return "an internal domain name"
        if host.split(".")[0] in names or host in names:
            return "an internal host name"
        if kind == "url" and _mentions(value, names, embedded=True):
            return "an internal host or user name inside the URL"
        return None
    # file name
    if value in _COMMON_BINARIES:
        return "a ubiquitous operating-system binary (a lookup would say nothing)"
    if _mentions(value, names, embedded=True):
        return "a file name containing an internal host or user name"
    return None


def web_query(kind: Kind, value: str) -> str:
    if kind == "file":
        return f'"{value}" file malware analysis'
    if kind == "hash":
        return f"{value} file hash malware report"
    if kind == "url":
        return f"{value} malicious url report"
    return f"{value} {kind} reputation malware report"


async def native_lookup(
    session: AsyncSession, settings: Settings, tenant_id: uuid.UUID, kind: Kind, value: str
) -> dict[str, Any]:
    """Run the tenant's configured providers for this indicator (cached per the platform's TTLs) and summarise their answers."""
    itype = intel_type(kind, value)
    entity = await intel_service.upsert_entity(session, tenant_id, itype, value, source="ai")
    cov = (await intel_service.enrich_many(session, settings, tenant_id, [entity]))[entity.id]
    obs = (
        (await session.execute(select(IntelObservation).where(IntelObservation.entity_id == entity.id))).scalars().all()
    )
    providers = [
        {
            "provider": o.provider,
            "status": o.status,
            "verdict": o.verdict if o.status == "ok" else None,
            "confidence": o.confidence if o.status == "ok" else None,
            "summary": (o.summary or "")[:240],
        }
        for o in sorted(obs, key=lambda o: o.provider)
        if o.status in ("ok", "not_found", "error")
    ]
    return {
        "verdict": entity.verdict or "unknown",
        "score": entity.score,
        "answered": cov.answered,
        "providers": providers,
        "providers_unavailable": sorted({s["provider"] for s in cov.skipped}),
    }


def _entity_keys(kind: Kind, value: str) -> list[str]:
    types = {"ip": ["ip"], "domain": ["domain"], "hash": ["hash"], "file": ["file", "process"], "url": []}[kind]
    return [st.ekey(t, value) for t in types]


def pick(inv: st.Investigation, limit: int, cap: int) -> list[tuple[str, Kind, str]]:
    """Entities worth an automatic look-up, best leads first: (entity key, kind, value). Nothing is picked twice per run."""
    room = max(0, min(limit, cap - len(inv.enriched)))
    out: list[tuple[str, Kind, str]] = []
    for e in sorted(inv.entities.values(), key=lambda x: (-x.score, -x.count, x.value)):
        if len(out) >= room:
            break
        key = st.ekey(e.type, e.value)
        if key in inv.enriched or e.dismissed is not None:
            continue
        if e.type in ("ip", "domain", "hash"):
            kind: Kind = e.type  # type: ignore[assignment]
            if kind == "domain" and e.value.lower().endswith(_BENIGN_SUFFIXES):
                continue
            if classify(e.value, kind) is None:
                continue
        elif e.type in ("file", "process"):
            kind = "file"
            if not e.value.lower().endswith(_EXEC_EXT) or not (e.flags or e.score >= 2):
                continue  # only executables that already look suspicious: names alone are weak and cost budget
        else:
            continue
        norm = classify(e.value, kind)
        if norm is None or internal_reason(inv, norm[0], norm[1]):
            continue
        out.append((key, norm[0], norm[1]))
    return out


def summarize(result: dict[str, Any]) -> dict[str, Any]:
    """The compact form kept in the investigation state, shown in the brief and in the UI."""
    return {
        "kind": (result.get("indicator") or {}).get("kind"),
        "value": (result.get("indicator") or {}).get("value"),
        "verdict": result.get("verdict", "unknown"),
        "score": result.get("score", 0),
        "answered": result.get("answered", 0),
        "providers": [
            {
                "provider": p["provider"],
                "status": p["status"],
                "verdict": p.get("verdict"),
                "summary": (p.get("summary") or "")[:120],
            }
            for p in (result.get("providers") or [])
        ],
        "unavailable": result.get("providers_unavailable") or [],
        "web": len(result.get("web") or []),
    }


def record(
    inv: st.Investigation, kind: Kind, value: str, result: dict[str, Any], key: str | None = None
) -> dict[str, Any]:
    """Remember an enrichment and let it steer the investigation: a malicious/suspicious verdict raises the entity's lead score."""
    s = summarize(result)
    keys = [key] if key else _entity_keys(kind, value)
    for k in keys:
        inv.intel[k] = s
        if k not in inv.enriched:
            inv.enriched.append(k)
        e = inv.entities.get(k)
        flag = {"malicious": "intel_malicious", "suspicious": "intel_suspicious"}.get(s["verdict"])
        if e is not None and flag and flag not in e.flags:
            e.flags.append(flag)
    return s
