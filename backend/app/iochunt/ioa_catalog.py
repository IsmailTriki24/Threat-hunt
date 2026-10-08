"""Built-in indicators of attack (IOAs): attacker *behaviours*, each tied to an ATT&CK technique.

An IOA is executable in two places. `query` runs in the hunt query language over the tenant's ingested events; `trend` (optional) is the
equivalent TMV1-Query for Trend Vision One's endpoint telemetry, where `processName`/`processCmd` are the *creating* (parent) process and
`objectName`/`objectCmd` the *new* process. Behaviour alone is weaker evidence than a known-bad indicator, so IOA matches raise a case for
review rather than a verdict; the severity here is the weight of the behaviour, not of the threat."""

from dataclasses import dataclass

OFFICE = "WINWORD.EXE|EXCEL.EXE|POWERPNT.EXE|OUTLOOK.EXE"
SCRIPT = "powershell.exe|cmd.exe|wscript.exe|cscript.exe|mshta.exe|rundll32.exe"
_OFFICE_T = " OR ".join(f'processName:"{n}"' for n in OFFICE.split("|"))
_SCRIPT_T = " OR ".join(f'objectName:"{n}"' for n in SCRIPT.split("|"))


@dataclass(frozen=True)
class IoaDef:
    name: str
    technique: str
    description: str
    query: str
    trend: str = ""
    severity: str = "MEDIUM"


CATALOG: tuple[IoaDef, ...] = (
    IoaDef(
        "PowerShell encoded command",
        "T1059.001",
        "PowerShell launched with an encoded (base64) command line, a common way to hide a payload.",
        "process.name:powershell.exe process.command_line:(enc|encodedcommand)",
        'eventId:1 AND objectName:"powershell.exe" AND (objectCmd:"*-enc*" OR objectCmd:"*-encodedcommand*")',
        "HIGH",
    ),
    IoaDef(
        "PowerShell download cradle",
        "T1059.001",
        "PowerShell fetching content from the network (DownloadString / WebClient / Invoke-WebRequest).",
        "process.name:powershell.exe process.command_line:(downloadstring|downloadfile|invoke-webrequest|webclient|iwr)",
        'eventId:1 AND objectName:"powershell.exe" AND (objectCmd:"*downloadstring*" OR objectCmd:"*downloadfile*" OR objectCmd:"*invoke-webrequest*" OR objectCmd:"*webclient*")',
        "HIGH",
    ),
    IoaDef(
        "Office application spawns a script interpreter",
        "T1204.002",
        "Word/Excel/PowerPoint/Outlook starting PowerShell, cmd, a script host, mshta or rundll32: the classic malicious-document pattern.",
        f"process.parent.name:({OFFICE}) process.name:({SCRIPT})",
        f"eventId:1 AND ({_OFFICE_T}) AND ({_SCRIPT_T})",
        "HIGH",
    ),
    IoaDef(
        "LSASS memory dump",
        "T1003.001",
        "A process dumping LSASS memory (comsvcs MiniDump, procdump) to steal credentials.",
        "process.command_line:minidump",
        'eventId:1 AND (objectCmd:"*minidump*" OR (objectName:"procdump.exe" AND objectCmd:"*lsass*"))',
        "CRITICAL",
    ),
    IoaDef(
        "Shadow copies deleted",
        "T1490",
        "vssadmin/wbadmin deleting backups or shadow copies: a ransomware precursor.",
        "process.name:(vssadmin.exe|wbadmin.exe) process.command_line:delete",
        'eventId:1 AND (objectName:"vssadmin.exe" OR objectName:"wbadmin.exe") AND objectCmd:"*delete*"',
        "CRITICAL",
    ),
    IoaDef(
        "Boot recovery disabled",
        "T1490",
        "bcdedit disabling recovery or ignoring boot failures: a ransomware precursor.",
        "process.name:bcdedit.exe process.command_line:(recoveryenabled|ignoreallfailures)",
        'eventId:1 AND objectName:"bcdedit.exe" AND (objectCmd:"*recoveryenabled*" OR objectCmd:"*ignoreallfailures*")',
        "HIGH",
    ),
    IoaDef(
        "Windows event log cleared",
        "T1070.001",
        "wevtutil clearing event logs to remove traces.",
        "process.name:wevtutil.exe process.command_line:cl",
        'eventId:1 AND objectName:"wevtutil.exe" AND objectCmd:"*cl*"',
        "HIGH",
    ),
    IoaDef(
        "Scheduled task created from the command line",
        "T1053.005",
        "schtasks creating a task, a common persistence and execution mechanism.",
        "process.name:schtasks.exe process.command_line:create",
        'eventId:1 AND objectName:"schtasks.exe" AND objectCmd:"*/create*"',
        "MEDIUM",
    ),
    IoaDef(
        "File downloaded with certutil or bitsadmin",
        "T1105",
        "Living-off-the-land download of a payload with certutil -urlcache or bitsadmin /transfer.",
        "process.name:(certutil.exe|bitsadmin.exe) process.command_line:(urlcache|transfer|http|https)",
        'eventId:1 AND (objectName:"certutil.exe" OR objectName:"bitsadmin.exe") AND (objectCmd:"*urlcache*" OR objectCmd:"*transfer*" OR objectCmd:"*http*")',
        "HIGH",
    ),
    IoaDef(
        "mshta runs remote or inline script",
        "T1218.005",
        "mshta.exe executing content from a URL or a javascript:/vbscript: string.",
        "process.name:mshta.exe process.command_line:(http|https|javascript|vbscript)",
        'eventId:1 AND objectName:"mshta.exe" AND (objectCmd:"*http*" OR objectCmd:"*javascript*" OR objectCmd:"*vbscript*")',
        "HIGH",
    ),
    IoaDef(
        "regsvr32 scriptlet execution",
        "T1218.010",
        "regsvr32 loading a remote scriptlet (scrobj.dll / /i:http) to run code.",
        "process.name:regsvr32.exe process.command_line:(scrobj|http|https)",
        'eventId:1 AND objectName:"regsvr32.exe" AND (objectCmd:"*scrobj*" OR objectCmd:"*http*")',
        "HIGH",
    ),
    IoaDef(
        "rundll32 proxy execution",
        "T1218.011",
        "rundll32 running script, remote content or comsvcs.",
        "process.name:rundll32.exe process.command_line:(javascript|http|https|comsvcs|mshtml)",
        'eventId:1 AND objectName:"rundll32.exe" AND (objectCmd:"*javascript*" OR objectCmd:"*http*" OR objectCmd:"*comsvcs*" OR objectCmd:"*mshtml*")',
        "HIGH",
    ),
    IoaDef(
        "Run-key persistence",
        "T1547.001",
        "A value written under CurrentVersion\\Run / RunOnce.",
        "event_type:registry_event registry.key:(run|runonce)",
        "",
        "MEDIUM",
    ),
    IoaDef(
        "New service installed",
        "T1543.003",
        "A new Windows service was installed.",
        "event_type:service_install",
        "",
        "MEDIUM",
    ),
    IoaDef(
        "PsExec-style remote execution",
        "T1569.002",
        "PsExec or its service executable running: remote command execution / lateral movement.",
        "process.name:(psexec.exe|psexesvc.exe|paexec.exe)",
        'eventId:1 AND (objectName:"psexec.exe" OR objectName:"psexesvc.exe" OR objectName:"paexec.exe")',
        "HIGH",
    ),
    IoaDef(
        "Local account created or added to a group",
        "T1136.001",
        "net user /add or net localgroup administrators /add.",
        "process.name:(net.exe|net1.exe) process.command_line:user process.command_line:add",
        'eventId:1 AND (objectName:"net.exe" OR objectName:"net1.exe") AND objectCmd:"*user*" AND objectCmd:"*add*"',
        "HIGH",
    ),
    IoaDef(
        "Remote-access or tunnelling tool",
        "T1219",
        "AnyDesk / ngrok / rclone-class tools often used for access, tunnelling or exfiltration.",
        "process.name:(anydesk.exe|ngrok.exe|rclone.exe|teamviewer.exe|screenconnect.clientservice.exe)",
        'eventId:1 AND (objectName:"anydesk.exe" OR objectName:"ngrok.exe" OR objectName:"rclone.exe" OR objectName:"teamviewer.exe")',
        "MEDIUM",
    ),
)


def related(technique: str, ttp: str) -> bool:
    """An IOA for T1059.001 is relevant to a threat documented as using T1059 (parent) or T1059.001 itself, and vice versa."""
    return technique == ttp or technique.startswith(ttp + ".") or ttp.startswith(technique + ".")


def for_techniques(ttps: list[str]) -> list[IoaDef]:
    return [d for d in CATALOG if any(related(d.technique, t) for t in ttps)]
