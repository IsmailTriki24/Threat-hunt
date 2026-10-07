"""Deterministic, explainable ATT&CK technique suggestions over normalised event documents.

Principles
* Every suggestion is backed by >=1 concrete event id; a rule only fires on fields that are present.
* Confidence is LOW unless a *specific* indicator is present (named in the reasoning); it is never inferred from volume
  alone except where a rule says so (spray / repeated beacon-like traffic).
* Reasoning always names the matched field and value so an analyst can verify or reject it. These are suggestions for an
  analyst to accept, not verdicts: nothing is stored until a mapping is created explicitly.
"""

import math
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel

from app.mitre import data

Confidence = Literal["LOW", "MEDIUM", "HIGH"]
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
_NAMES = {tid: (name, tactics) for tid, name, tactics, _ in data.TECHNIQUES}

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"}
SUSPICIOUS_CHILDREN = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
}
LOTL = {
    "powershell.exe",
    "pwsh.exe",
    "rundll32.exe",
    "mshta.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "msbuild.exe",
    "certutil.exe",
}
WEB_PORTS = {80, 443, 8080}
POWERSHELL = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}


@dataclass(frozen=True)
class Match:
    technique_id: str
    confidence: Confidence
    reason: str
    index: int  # position of the evidence event in the input list


class Suggestion(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    confidence: Confidence
    reasoning: list[str]
    event_ids: list[str]
    event_count: int
    hosts: list[str]
    users: list[str]


# ---- helpers ----
def _g(doc: dict[str, Any], *path: str) -> Any:
    cur: Any = doc
    for p in path:
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


def _s(doc: dict[str, Any], *path: str) -> str:
    v = _g(doc, *path)
    return v.lower() if isinstance(v, str) else ""


def _snip(text: str, n: int = 110) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _cmd(doc: dict[str, Any]) -> str:
    return _s(doc, "process", "command_line")


def _is_proc(doc: dict[str, Any]) -> bool:
    return doc.get("event_type") == "process_creation"


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values()) if text else 0.0


# ---- per-event rules ----------------------------------------------------------------------------------------------
_PS_STRONG: list[tuple[str, re.Pattern[str]]] = [
    ("encoded command", re.compile(r"(?<![\w-])-(enc|encodedcommand|ec)(?![\w-])")),
    ("hidden window", re.compile(r"-w(indowstyle)?\s+hidden|-win\s+hidden")),
    ("execution-policy bypass", re.compile(r"(-ep|-exec|-executionpolicy)\s+bypass")),
    (
        "download cradle",
        re.compile(r"downloadstring|downloadfile|invoke-webrequest|(?<![\w-])iwr(?![\w-])|net\.webclient"),
    ),
    ("invoke-expression", re.compile(r"(?<![\w-])iex(?![\w-])|invoke-expression")),
]
_PS_WEAK = re.compile(r"(?<![\w-])-(nop|noprofile)(?![\w-])")


def _powershell(doc: dict[str, Any], i: int) -> list[Match]:
    if not (_is_proc(doc) and _s(doc, "process", "name") in POWERSHELL):
        return []
    cl = _cmd(doc)
    strong = [label for label, rx in _PS_STRONG if rx.search(cl)]
    out: list[Match] = []
    if strong:
        out.append(
            Match(
                "T1059.001",
                "HIGH",
                f"process.name={_s(doc, 'process', 'name')} with {', '.join(strong)} in process.command_line",
                i,
            )
        )
        if "encoded command" in strong:
            out.append(
                Match("T1027", "MEDIUM", "PowerShell -EncodedCommand in process.command_line (obfuscated payload)", i)
            )
    elif _PS_WEAK.search(cl):
        out.append(Match("T1059.001", "MEDIUM", "PowerShell started with -NoProfile (no other suspicious flag)", i))
    else:
        out.append(
            Match(
                "T1059.001",
                "LOW",
                f"process.name={_s(doc, 'process', 'name')} executed (no suspicious flags observed)",
                i,
            )
        )
    return out


def _cmd_shell(doc: dict[str, Any], i: int) -> list[Match]:
    if _is_proc(doc) and _s(doc, "process", "name") == "cmd.exe" and re.search(r"(?<!\w)/[ck](?!\w)", _cmd(doc)):
        return [Match("T1059.003", "LOW", f"cmd.exe /c|/k in process.command_line: {_snip(_cmd(doc), 70)}", i)]
    return []


def _scripting(doc: dict[str, Any], i: int) -> list[Match]:
    name = _s(doc, "process", "name")
    if not _is_proc(doc) or name not in ("wscript.exe", "cscript.exe", "mshta.exe"):
        return []
    cl = _cmd(doc)
    out = []
    if re.search(r"\.(vbs|vbe)\b", cl):
        out.append(Match("T1059.005", "MEDIUM", f"{name} running a VBScript file: {_snip(cl, 70)}", i))
    if re.search(r"\.(js|jse)\b|javascript:", cl):
        out.append(Match("T1059.007", "MEDIUM", f"{name} running JavaScript: {_snip(cl, 70)}", i))
    return out


def _scheduled_task(doc: dict[str, Any], i: int) -> list[Match]:
    cl = _cmd(doc)
    if _is_proc(doc) and _s(doc, "process", "name") == "schtasks.exe" and "/create" in cl:
        risky = re.search(r"powershell|cmd(\.exe)?\s|wscript|mshta|\\temp\\|appdata|-enc", cl)
        return [
            Match(
                "T1053.005",
                "HIGH" if risky else "MEDIUM",
                "schtasks.exe /create"
                + (" launching a script interpreter/user-writable path" if risky else "")
                + f": {_snip(cl, 80)}",
                i,
            )
        ]
    if doc.get("event_type") == "scheduled_task":
        return [
            Match(
                "T1053.005",
                "MEDIUM",
                f"event_type=scheduled_task ({_snip(str(doc.get('message') or doc.get('action') or ''), 80)})",
                i,
            )
        ]
    return []


def _service(doc: dict[str, Any], i: int) -> list[Match]:
    blob = " ".join([_s(doc, "message"), _cmd(doc), _s(doc, "process", "executable")])
    out: list[Match] = []
    if doc.get("event_type") == "service_install":
        out.append(
            Match("T1543.003", "MEDIUM", f"event_type=service_install ({_snip(str(doc.get('message') or ''), 80)})", i)
        )
    elif _is_proc(doc) and _s(doc, "process", "name") == "sc.exe" and re.search(r"\bcreate\b", _cmd(doc)):
        out.append(Match("T1543.003", "MEDIUM", f"sc.exe create in process.command_line: {_snip(_cmd(doc), 80)}", i))
    if "psexesvc" in blob or (_is_proc(doc) and re.search(r"psexec(64)?(\.exe)?\s", _cmd(doc) + " ")):
        why = "PSEXESVC service / PsExec usage observed"
        out += [
            Match("T1569.002", "HIGH", why, i),
            Match("T1021.002", "HIGH", why + " (SMB admin-share remote execution)", i),
        ]
    return out


def _run_keys(doc: dict[str, Any], i: int) -> list[Match]:
    key, val, path = _s(doc, "registry", "key"), _s(doc, "registry", "value"), _s(doc, "file", "path")
    if re.search(r"\\currentversion\\run(once)?(\\|$)", key):
        risky = re.search(r"powershell|cmd|wscript|mshta|\\temp\\|appdata", val)
        return [
            Match(
                "T1547.001",
                "HIGH" if risky else "MEDIUM",
                f"registry.key={_snip(key, 80)}" + (" pointing at an interpreter/user-writable path" if risky else ""),
                i,
            )
        ]
    if (
        _is_proc(doc)
        and _s(doc, "process", "name") == "reg.exe"
        and re.search(r"\\currentversion\\run", _cmd(doc))
        and " add " in _cmd(doc)
    ):
        return [Match("T1547.001", "MEDIUM", f"reg.exe add to a Run key: {_snip(_cmd(doc), 80)}", i)]
    if doc.get("event_type") == "file_event" and "\\start menu\\programs\\startup\\" in path:
        return [Match("T1547.001", "MEDIUM", f"file.path in Startup folder: {_snip(path, 80)}", i)]
    return []


def _lsass(doc: dict[str, Any], i: int) -> list[Match]:
    cl, name = _cmd(doc), _s(doc, "process", "name")
    out: list[Match] = []
    if _is_proc(doc):
        if "comsvcs" in cl and "minidump" in cl:
            out.append(Match("T1003.001", "HIGH", f"comsvcs.dll MiniDump in process.command_line: {_snip(cl, 80)}", i))
        elif "procdump" in (name + " " + cl) and "lsass" in cl:
            out.append(
                Match("T1003.001", "HIGH", f"procdump targeting lsass in process.command_line: {_snip(cl, 80)}", i)
            )
        elif "sekurlsa" in cl or "mimikatz" in name:
            out.append(Match("T1003.001", "HIGH", "mimikatz / sekurlsa credential-dumping module observed", i))
        if name == "reg.exe" and " save " in f" {cl} " and re.search(r"hklm\\sam|hkey_local_machine\\sam", cl):
            out.append(Match("T1003.002", "HIGH", f"reg.exe save of the SAM hive: {_snip(cl, 80)}", i))
        if "ntds.dit" in cl or (name == "ntdsutil.exe" and "ifm" in cl):
            out.append(
                Match("T1003.003", "HIGH", f"NTDS.dit access/extraction in process.command_line: {_snip(cl, 80)}", i)
            )
    elif doc.get("event_type") == "file_event":
        path = _s(doc, "file", "path")
        if path.endswith(".dmp") and "\\temp\\" in path and name in ("rundll32.exe", "procdump.exe", "procdump64.exe"):
            out.append(
                Match("T1003.001", "HIGH", f"{name} wrote a memory dump ({_snip(path, 60)}) to a Temp directory", i)
            )
    return out


def _office_child(doc: dict[str, Any], i: int) -> list[Match]:
    parent, child = _s(doc, "process", "parent", "name"), _s(doc, "process", "name")
    if _is_proc(doc) and parent in OFFICE and child in SUSPICIOUS_CHILDREN:
        base = f"{parent} (process.parent.name) spawned {child} (process.name)"
        return [
            Match("T1204.002", "MEDIUM", base + "; consistent with a user opening a malicious document", i),
            Match(
                "T1566.001",
                "MEDIUM",
                base
                + "; the phishing delivery vector is INFERRED from this process chain, not observed in mail telemetry",
                i,
            ),
        ]
    return []


def _rundll32(doc: dict[str, Any], i: int) -> list[Match]:
    cl = _cmd(doc)
    if _is_proc(doc) and _s(doc, "process", "name") == "rundll32.exe":
        if "javascript:" in cl or "runhtmlapplication" in cl:
            return [Match("T1218.011", "MEDIUM", f"rundll32.exe executing script content: {_snip(cl, 80)}", i)]
        if re.search(r"\\(temp|appdata|programdata|downloads)\\[^ ,]*\.dll", cl):
            return [
                Match(
                    "T1218.011", "MEDIUM", f"rundll32.exe loading a DLL from a user-writable path: {_snip(cl, 80)}", i
                )
            ]
    return []


def _ingress(doc: dict[str, Any], i: int) -> list[Match]:
    if not _is_proc(doc):
        return []
    name, cl = _s(doc, "process", "name"), _cmd(doc)
    why = None
    if name == "certutil.exe" and "urlcache" in cl:
        why = "certutil -urlcache download"
    elif name == "bitsadmin.exe" and "/transfer" in cl:
        why = "bitsadmin /transfer download"
    elif name in ("curl.exe", "wget.exe") and "http" in cl:
        why = f"{name} fetching a URL"
    elif (
        name in POWERSHELL
        and re.search(r"downloadstring|downloadfile|invoke-webrequest|(?<![\w-])iwr(?![\w-])|start-bitstransfer", cl)
        and "http" in cl
    ):
        why = "PowerShell download cradle with a URL"
    if why is None:
        return []
    args = re.sub(r'^\s*("[^"]*"|\S+)\s*', "", cl)  # drop the program itself (curl.exe would match .exe)
    exe = re.search(r"\.(exe|dll|ps1|bat|vbs|js|hta|scr)\b", args)
    out = [
        Match(
            "T1105",
            "HIGH" if exe else "MEDIUM",
            f"{why}{' of an executable/script file' if exe else ''}: {_snip(cl, 80)}",
            i,
        )
    ]
    if name == "bitsadmin.exe":
        out.append(Match("T1197", "MEDIUM", "bitsadmin /transfer creates a BITS job", i))
    return out


def _defense_and_impact(doc: dict[str, Any], i: int) -> list[Match]:
    if not _is_proc(doc):
        return []
    name, cl = _s(doc, "process", "name"), _cmd(doc)
    out: list[Match] = []
    if (name == "wevtutil.exe" and re.search(r"(?<!\w)(cl|clear-log)(?!\w)", cl)) or "clear-eventlog" in cl:
        out.append(Match("T1070.001", "HIGH", f"event log clearing: {_snip(cl, 80)}", i))
    if (
        (name == "vssadmin.exe" and "delete" in cl and "shadows" in cl)
        or (name == "wmic.exe" and "shadowcopy" in cl and "delete" in cl)
        or (name == "wbadmin.exe" and "delete" in cl)
        or (name == "bcdedit.exe" and re.search(r"recoveryenabled\s+no|ignoreallfailures", cl))
    ):
        out.append(Match("T1490", "HIGH", f"recovery inhibition command: {_snip(cl, 80)}", i))
    if (
        "set-mppreference" in cl
        and re.search(r"disable(realtimemonitoring|ioavprotection|behaviormonitoring)\s+(\$true|1)", cl)
    ) or (name == "sc.exe" and "windefend" in cl and re.search(r"\bstop\b|disabled", cl)):
        out.append(Match("T1562.001", "HIGH", f"Microsoft Defender tampering: {_snip(cl, 80)}", i))
    return out


def _accounts_and_discovery(doc: dict[str, Any], i: int) -> list[Match]:
    if not _is_proc(doc):
        return []
    name, cl = _s(doc, "process", "name"), _cmd(doc)
    out: list[Match] = []
    if name in ("net.exe", "net1.exe") and re.search(r"\buser\b", cl) and "/add" in cl:
        out.append(Match("T1136", "MEDIUM", f"net user /add: {_snip(cl, 80)}", i))
    elif "new-localuser" in cl:
        out.append(Match("T1136", "MEDIUM", "New-LocalUser in process.command_line", i))
    low = "discovery command observed (common in benign administration too)"
    if name == "whoami.exe" or re.search(r"(?<![\w-])whoami(\.exe)?(?![\w-])", cl):
        out.append(Match("T1033", "LOW", f"whoami: {low}", i))
    if name == "systeminfo.exe":
        out.append(Match("T1082", "LOW", f"systeminfo: {low}", i))
    if (name in ("net.exe", "net1.exe") and re.search(r"\bview\b", cl)) or (
        name == "nltest.exe" and re.search(r"dclist|domain_trusts", cl)
    ):
        out.append(Match("T1018", "LOW", f"remote-system enumeration ({_snip(cl, 60)}): {low}", i))
    if name == "tasklist.exe":
        out.append(Match("T1057", "LOW", f"tasklist: {low}", i))
    if name == "netstat.exe":
        out.append(Match("T1049", "LOW", f"netstat: {low}", i))
    if (
        name in ("net.exe", "net1.exe")
        and re.search(r"\b(user|group|localgroup)\b", cl)
        and "/add" not in cl
        and "/domain" in cl
    ):
        out.append(Match("T1087", "LOW", f"domain account enumeration ({_snip(cl, 60)}): {low}", i))
    return out


def _remote_logon(doc: dict[str, Any], i: int) -> list[Match]:
    if (
        doc.get("event_type") == "authentication"
        and doc.get("outcome") == "success"
        and _s(doc, "auth", "logon_type")
        in (
            "remote_interactive",
            "rdp",
            "10",
        )
    ):
        return [Match("T1021.001", "MEDIUM", "successful auth.logon_type=remote_interactive (RDP) logon", i)]
    return []


def _dga(doc: dict[str, Any], i: int) -> list[Match]:
    if doc.get("event_type") != "dns_query":
        return []
    q = _s(doc, "dns", "question").rstrip(".")
    labels = q.split(".")
    if len(labels) < 2:
        return []
    label = max(labels[:-1], key=len)
    if len(label) >= 14 and _entropy(label) >= 3.6 and sum(ch.isdigit() for ch in label) >= 2:
        return [
            Match(
                "T1568.002",
                "LOW",
                f"dns.question={_snip(q, 60)} looks algorithmically generated (label entropy {_entropy(label):.1f})",
                i,
            )
        ]
    return []


_EVENT_RULES: list[Callable[[dict[str, Any], int], list[Match]]] = [
    _powershell,
    _cmd_shell,
    _scripting,
    _scheduled_task,
    _service,
    _run_keys,
    _lsass,
    _office_child,
    _rundll32,
    _ingress,
    _defense_and_impact,
    _accounts_and_discovery,
    _remote_logon,
    _dga,
]


# ---- multi-event rules ----------------------------------------------------------------------------------------------
def _spray_and_guessing(docs: list[dict[str, Any]]) -> list[Match]:
    groups: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(docs):
        if d.get("event_type") == "authentication" and (
            d.get("outcome") == "failure" or d.get("action") == "logon_failed"
        ):
            src = _s(d, "auth", "source_ip") or _s(d, "host", "hostname")
            if src:
                groups[src].append(i)
    out: list[Match] = []
    for src, idxs in groups.items():
        has_ip = any(_s(docs[i], "auth", "source_ip") for i in idxs)
        users = {_s(docs[i], "user", "name") for i in idxs} - {""}
        per_user = Counter(_s(docs[i], "user", "name") for i in idxs)
        if has_ip and len(users) >= 5:
            conf: Confidence = "HIGH" if len(users) >= 10 else "MEDIUM"
            why = f"{len(idxs)} failed logons for {len(users)} distinct users from auth.source_ip={src}"
            out += [Match("T1110.003", conf, why, i) for i in idxs]
        elif per_user and max(per_user.values()) >= 5:
            user, n = per_user.most_common(1)[0]
            conf = "HIGH" if n >= 20 else "MEDIUM"
            out += [
                Match("T1110.001", conf, f"{n} failed logons for user.name={user} from {src}", i)
                for i in idxs
                if _s(docs[i], "user", "name") == user
            ]
    return out


def _lotl_web(docs: list[dict[str, Any]]) -> list[Match]:
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, d in enumerate(docs):
        if d.get("event_type") != "network_connection":
            continue
        port, proc = _g(d, "network", "dst_port"), _s(d, "process", "name")
        direction = _s(d, "network", "direction")
        dest = _s(d, "network", "dst_domain") or _s(d, "network", "dst_ip")
        if proc in LOTL and port in WEB_PORTS and dest and direction in ("", "outbound"):
            groups[(proc, dest)].append(i)
    out: list[Match] = []
    for (proc, dest), idxs in groups.items():
        conf: Confidence = "MEDIUM" if len(idxs) >= 10 else "LOW"
        why = f"{proc} made {len(idxs)} outbound web connection(s) to {dest} (network.dst_port in 80/443/8080)"
        out += [Match("T1071.001", conf, why, i) for i in idxs]
    return out


# ---- public API ----
def suggest(docs: list[dict[str, Any]]) -> list[Suggestion]:
    matches: list[Match] = []
    for i, d in enumerate(docs):
        for rule in _EVENT_RULES:
            matches.extend(rule(d, i))
    matches.extend(_spray_and_guessing(docs))
    matches.extend(_lotl_web(docs))

    by_tech: dict[str, list[Match]] = defaultdict(list)
    for m in matches:
        by_tech[m.technique_id].append(m)

    out: list[Suggestion] = []
    for tid, ms in by_tech.items():
        name, tactics = _NAMES[tid]
        idxs = list(dict.fromkeys(m.index for m in ms))
        if not idxs:  # defensive: never emit a technique without evidence
            continue
        reasons = Counter(m.reason for m in ms)
        reasoning = [r if n == 1 else f"{r} (×{n})" for r, n in reasons.most_common(3)]
        out.append(
            Suggestion(
                technique_id=tid,
                name=name,
                tactics=tactics,
                confidence=max((m.confidence for m in ms), key=lambda c: _RANK[c]),
                reasoning=reasoning,
                event_ids=[docs[i]["id"] for i in idxs[:50]],
                event_count=len(idxs),
                hosts=sorted({h for i in idxs if (h := _g(docs[i], "host", "hostname"))})[:20],
                users=sorted({u for i in idxs if (u := _g(docs[i], "user", "name"))})[:20],
            )
        )
    out.sort(key=lambda s: (-_RANK[s.confidence], -s.event_count, s.technique_id))
    return out
