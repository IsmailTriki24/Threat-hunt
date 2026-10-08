"""Built-in indicators of attack (IOAs): attacker *behaviours*, each tied to an ATT&CK technique.

An IOA is a boolean `Condition` tree over the canonical event schema (the same engine detection rules use), so it is evaluated identically
by OpenSearch and by the local evaluator, and every upstream result can be re-verified against it. `trend` is an optional equivalent
TMV1-Query for Trend Vision One endpoint telemetry, where `processName`/`processCmd` are the *creating* (parent) process and
`objectName`/`objectCmd` the *new* process. Behaviour alone is weaker evidence than a known-bad indicator, so IOA matches raise a case for
review rather than a verdict; `severity` is the weight of the behaviour, not of the threat.

Text fields (command lines, registry keys) are matched with `contains` per token: an any-of list on a text field means *equals*, which would
never match a real command line."""

from dataclasses import dataclass
from typing import Any

from app.events.search.query import Condition

OFFICE = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
SCRIPT = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"]
_OFFICE_T = " OR ".join(f'processName:"{n}"' for n in OFFICE)
_SCRIPT_T = " OR ".join(f'objectName:"{n}"' for n in SCRIPT)


def F(field: str, op: str, value: Any = None) -> dict[str, Any]:  # noqa: N802
    return {"filter": {"field": field, "op": op, "value": value}}


def ALL(*c: dict[str, Any]) -> dict[str, Any]:  # noqa: N802
    return {"all": list(c)}


def ANY(*c: dict[str, Any]) -> dict[str, Any]:  # noqa: N802
    return {"any": list(c)}


def name_in(*names: str) -> dict[str, Any]:
    return F("process.name", "in", list(names))


def cmd_has(*tokens: str) -> dict[str, Any]:
    """Command line contains any of these tokens."""
    return ANY(*[F("process.command_line", "contains", t) for t in tokens])


def cmd_all(*tokens: str) -> dict[str, Any]:
    return ALL(*[F("process.command_line", "contains", t) for t in tokens])


@dataclass(frozen=True)
class IoaDef:
    name: str
    technique: str
    description: str
    cond: dict[str, Any]
    readable: str
    trend: str = ""
    severity: str = "MEDIUM"

    def condition(self) -> Condition:
        return Condition.model_validate(self.cond)


CATALOG: tuple[IoaDef, ...] = (
    IoaDef(
        "PowerShell encoded command",
        "T1059.001",
        "PowerShell launched with an encoded (base64) command line, a common way to hide a payload.",
        ALL(name_in("powershell.exe"), cmd_has("enc", "encodedcommand")),
        "process powershell.exe AND command line contains -enc / -encodedcommand",
        'eventId:1 AND objectName:"powershell.exe" AND (objectCmd:"*-enc*" OR objectCmd:"*-encodedcommand*")',
        "HIGH",
    ),
    IoaDef(
        "PowerShell download cradle",
        "T1059.001",
        "PowerShell fetching content from the network (DownloadString / WebClient / Invoke-WebRequest).",
        ALL(
            name_in("powershell.exe"),
            cmd_has("downloadstring", "downloadfile", "invoke-webrequest", "webclient", "iwr"),
        ),
        "process powershell.exe AND command line contains downloadstring / downloadfile / invoke-webrequest / webclient",
        'eventId:1 AND objectName:"powershell.exe" AND (objectCmd:"*downloadstring*" OR objectCmd:"*downloadfile*" OR objectCmd:"*invoke-webrequest*" OR objectCmd:"*webclient*")',
        "HIGH",
    ),
    IoaDef(
        "Office application spawns a script interpreter",
        "T1204.002",
        "Word/Excel/PowerPoint/Outlook starting PowerShell, cmd, a script host, mshta or rundll32: the classic malicious-document pattern.",
        ALL(F("process.parent.name", "in", OFFICE), name_in(*SCRIPT)),
        f"parent in {OFFICE} AND process in {SCRIPT}",
        f"eventId:1 AND ({_OFFICE_T}) AND ({_SCRIPT_T})",
        "HIGH",
    ),
    IoaDef(
        "LSASS memory dump",
        "T1003.001",
        "A process dumping LSASS memory (comsvcs MiniDump, procdump) to steal credentials.",
        ANY(cmd_has("minidump"), ALL(name_in("procdump.exe", "procdump64.exe"), cmd_has("lsass"))),
        "command line contains minidump OR procdump against lsass",
        'eventId:1 AND (objectCmd:"*minidump*" OR (objectName:"procdump.exe" AND objectCmd:"*lsass*"))',
        "CRITICAL",
    ),
    IoaDef(
        "Shadow copies deleted",
        "T1490",
        "vssadmin/wbadmin deleting backups or shadow copies: a ransomware precursor.",
        ALL(name_in("vssadmin.exe", "wbadmin.exe"), cmd_has("delete")),
        "vssadmin.exe / wbadmin.exe AND command line contains delete",
        'eventId:1 AND (objectName:"vssadmin.exe" OR objectName:"wbadmin.exe") AND objectCmd:"*delete*"',
        "CRITICAL",
    ),
    IoaDef(
        "Boot recovery disabled",
        "T1490",
        "bcdedit disabling recovery or ignoring boot failures: a ransomware precursor.",
        ALL(name_in("bcdedit.exe"), cmd_has("recoveryenabled", "ignoreallfailures")),
        "bcdedit.exe AND command line contains recoveryenabled / ignoreallfailures",
        'eventId:1 AND objectName:"bcdedit.exe" AND (objectCmd:"*recoveryenabled*" OR objectCmd:"*ignoreallfailures*")',
        "HIGH",
    ),
    IoaDef(
        "Windows event log cleared",
        "T1070.001",
        "wevtutil clearing event logs to remove traces.",
        ALL(name_in("wevtutil.exe"), cmd_has("cl", "clear-log")),
        "wevtutil.exe AND command line contains cl",
        'eventId:1 AND objectName:"wevtutil.exe" AND objectCmd:"*cl*"',
        "HIGH",
    ),
    IoaDef(
        "Scheduled task created from the command line",
        "T1053.005",
        "schtasks creating a task, a common persistence and execution mechanism.",
        ALL(name_in("schtasks.exe"), cmd_has("create")),
        "schtasks.exe AND command line contains create",
        'eventId:1 AND objectName:"schtasks.exe" AND objectCmd:"*/create*"',
        "MEDIUM",
    ),
    IoaDef(
        "File downloaded with certutil or bitsadmin",
        "T1105",
        "Living-off-the-land download of a payload with certutil -urlcache or bitsadmin /transfer.",
        ALL(name_in("certutil.exe", "bitsadmin.exe"), cmd_has("urlcache", "transfer", "http", "https")),
        "certutil.exe / bitsadmin.exe AND command line contains urlcache / transfer / http",
        'eventId:1 AND (objectName:"certutil.exe" OR objectName:"bitsadmin.exe") AND (objectCmd:"*urlcache*" OR objectCmd:"*transfer*" OR objectCmd:"*http*")',
        "HIGH",
    ),
    IoaDef(
        "mshta runs remote or inline script",
        "T1218.005",
        "mshta.exe executing content from a URL or a javascript:/vbscript: string.",
        ALL(name_in("mshta.exe"), cmd_has("http", "https", "javascript", "vbscript")),
        "mshta.exe AND command line contains http / javascript / vbscript",
        'eventId:1 AND objectName:"mshta.exe" AND (objectCmd:"*http*" OR objectCmd:"*javascript*" OR objectCmd:"*vbscript*")',
        "HIGH",
    ),
    IoaDef(
        "regsvr32 scriptlet execution",
        "T1218.010",
        "regsvr32 loading a remote scriptlet (scrobj.dll / /i:http) to run code.",
        ALL(name_in("regsvr32.exe"), cmd_has("scrobj", "http", "https")),
        "regsvr32.exe AND command line contains scrobj / http",
        'eventId:1 AND objectName:"regsvr32.exe" AND (objectCmd:"*scrobj*" OR objectCmd:"*http*")',
        "HIGH",
    ),
    IoaDef(
        "rundll32 proxy execution",
        "T1218.011",
        "rundll32 running script, remote content or comsvcs.",
        ALL(name_in("rundll32.exe"), cmd_has("javascript", "http", "https", "comsvcs", "mshtml")),
        "rundll32.exe AND command line contains javascript / http / comsvcs / mshtml",
        'eventId:1 AND objectName:"rundll32.exe" AND (objectCmd:"*javascript*" OR objectCmd:"*http*" OR objectCmd:"*comsvcs*" OR objectCmd:"*mshtml*")',
        "HIGH",
    ),
    IoaDef(
        "Run-key persistence",
        "T1547.001",
        "A value written under CurrentVersion\\Run / RunOnce.",
        ALL(
            F("event_type", "eq", "registry_event"),
            ANY(F("registry.key", "contains", "run"), F("registry.key", "contains", "runonce")),
        ),
        "registry event with a key containing run / runonce",
        "",
        "MEDIUM",
    ),
    IoaDef(
        "New service installed",
        "T1543.003",
        "A new Windows service was installed.",
        F("event_type", "eq", "service_install"),
        "service_install event",
        "",
        "MEDIUM",
    ),
    IoaDef(
        "PsExec-style remote execution",
        "T1569.002",
        "PsExec or its service executable running: remote command execution / lateral movement.",
        name_in("psexec.exe", "psexesvc.exe", "paexec.exe"),
        "process psexec.exe / psexesvc.exe / paexec.exe",
        'eventId:1 AND (objectName:"psexec.exe" OR objectName:"psexesvc.exe" OR objectName:"paexec.exe")',
        "HIGH",
    ),
    IoaDef(
        "Local account created or added to a group",
        "T1136.001",
        "net user /add or net localgroup administrators /add.",
        ALL(name_in("net.exe", "net1.exe"), cmd_all("user", "add")),
        "net.exe / net1.exe AND command line contains user AND add",
        'eventId:1 AND (objectName:"net.exe" OR objectName:"net1.exe") AND objectCmd:"*user*" AND objectCmd:"*add*"',
        "HIGH",
    ),
    IoaDef(
        "Remote-access or tunnelling tool",
        "T1219",
        "AnyDesk / ngrok / rclone-class tools often used for access, tunnelling or exfiltration.",
        name_in("anydesk.exe", "ngrok.exe", "rclone.exe", "teamviewer.exe", "screenconnect.clientservice.exe"),
        "process anydesk.exe / ngrok.exe / rclone.exe / teamviewer.exe",
        'eventId:1 AND (objectName:"anydesk.exe" OR objectName:"ngrok.exe" OR objectName:"rclone.exe" OR objectName:"teamviewer.exe")',
        "MEDIUM",
    ),
)


def related(technique: str, ttp: str) -> bool:
    """An IOA for T1059.001 is relevant to a threat documented as using T1059 (parent) or T1059.001 itself, and vice versa."""
    return technique == ttp or technique.startswith(ttp + ".") or ttp.startswith(technique + ".")


def for_techniques(ttps: list[str]) -> list[IoaDef]:
    return [d for d in CATALOG if any(related(d.technique, t) for t in ttps)]
