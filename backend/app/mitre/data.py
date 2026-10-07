"""Curated built-in subset of MITRE ATT&CK (Enterprise). Operators can load the complete dataset from the official
STIX bundle with `python -m app.cli mitre-load --file enterprise-attack.json` (see loader.py).

Entry: (id, name, tactic shortnames, one-line description). Sub-techniques are those whose id contains a dot."""

BUILTIN_SOURCE = "builtin-curated"

TACTICS: list[tuple[str, str, str]] = [
    # (id, shortname, name) — in ATT&CK kill-chain order
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]

_EX, _PE, _PR = "execution", "persistence", "privilege-escalation"
_DE, _CA, _DI = "defense-evasion", "credential-access", "discovery"
_IA, _LM, _CO = "initial-access", "lateral-movement", "collection"
_C2, _XF, _IM = "command-and-control", "exfiltration", "impact"

TECHNIQUES: list[tuple[str, str, list[str], str]] = [
    (
        "T1059",
        "Command and Scripting Interpreter",
        [_EX],
        "Abuse of command and script interpreters to execute commands.",
    ),
    ("T1059.001", "PowerShell", [_EX], "Abuse of PowerShell to run commands and scripts."),
    ("T1059.003", "Windows Command Shell", [_EX], "Abuse of cmd.exe to execute commands and batch scripts."),
    ("T1059.005", "Visual Basic", [_EX], "Abuse of Visual Basic / VBScript for execution."),
    ("T1059.007", "JavaScript", [_EX], "Abuse of JavaScript/JScript for execution."),
    ("T1053", "Scheduled Task/Job", [_EX, _PE, _PR], "Abuse of task scheduling to run code at a time or interval."),
    (
        "T1053.005",
        "Scheduled Task",
        [_EX, _PE, _PR],
        "Creation of Windows scheduled tasks for execution or persistence.",
    ),
    (
        "T1547",
        "Boot or Logon Autostart Execution",
        [_PE, _PR],
        "Configuring the system to run a program at boot or logon.",
    ),
    ("T1547.001", "Registry Run Keys / Startup Folder", [_PE, _PR], "Persistence via Run keys or the Startup folder."),
    (
        "T1543",
        "Create or Modify System Process",
        [_PE, _PR],
        "Creating or modifying system-level processes to repeatedly execute payloads.",
    ),
    (
        "T1543.003",
        "Windows Service",
        [_PE, _PR],
        "Creating or modifying Windows services for persistence or privilege escalation.",
    ),
    (
        "T1003",
        "OS Credential Dumping",
        [_CA],
        "Obtaining account login and credential material from the operating system.",
    ),
    ("T1003.001", "LSASS Memory", [_CA], "Accessing LSASS process memory to obtain credentials."),
    ("T1003.002", "Security Account Manager", [_CA], "Extracting credential material from the SAM database."),
    ("T1003.003", "NTDS", [_CA], "Extracting credential material from the Active Directory NTDS.dit database."),
    ("T1021", "Remote Services", [_LM], "Using valid accounts to log into a remote service."),
    ("T1021.001", "Remote Desktop Protocol", [_LM], "Using RDP to log into a remote system."),
    ("T1021.002", "SMB/Windows Admin Shares", [_LM], "Using SMB and admin shares (C$, ADMIN$) to move laterally."),
    ("T1021.006", "Windows Remote Management", [_LM], "Using WinRM to execute commands on remote systems."),
    ("T1569", "System Services", [_EX], "Abuse of system services or the service manager to execute programs."),
    ("T1569.002", "Service Execution", [_EX], "Executing commands or payloads by creating or starting a service."),
    (
        "T1071",
        "Application Layer Protocol",
        [_C2],
        "Communicating over application-layer protocols to blend in with traffic.",
    ),
    ("T1071.001", "Web Protocols", [_C2], "Command and control over HTTP/HTTPS."),
    ("T1071.004", "DNS", [_C2], "Command and control over DNS."),
    (
        "T1105",
        "Ingress Tool Transfer",
        [_C2],
        "Transferring tools or files from an external system into the environment.",
    ),
    ("T1566", "Phishing", [_IA], "Messages used to gain access to victim systems."),
    ("T1566.001", "Spearphishing Attachment", [_IA], "Phishing with a malicious attachment."),
    ("T1566.002", "Spearphishing Link", [_IA], "Phishing with a malicious link."),
    ("T1204", "User Execution", [_EX], "Relying on a user to execute malicious content."),
    ("T1204.002", "Malicious File", [_EX], "User opens a malicious file such as a document or executable."),
    (
        "T1027",
        "Obfuscated Files or Information",
        [_DE],
        "Making payloads or artifacts difficult to discover or analyze.",
    ),
    (
        "T1140",
        "Deobfuscate/Decode Files or Information",
        [_DE],
        "Decoding or deobfuscating information during execution.",
    ),
    ("T1070", "Indicator Removal", [_DE], "Deleting or modifying artifacts to remove evidence of activity."),
    ("T1070.001", "Clear Windows Event Logs", [_DE], "Clearing Windows event logs to hide activity."),
    ("T1078", "Valid Accounts", [_DE, _PE, _PR, _IA], "Using legitimate credentials to gain access or persist."),
    ("T1078.002", "Domain Accounts", [_DE, _PE, _PR, _IA], "Using compromised domain accounts."),
    ("T1110", "Brute Force", [_CA], "Guessing credentials when passwords are unknown."),
    ("T1110.001", "Password Guessing", [_CA], "Repeatedly guessing passwords for an account."),
    ("T1110.003", "Password Spraying", [_CA], "Trying one or few common passwords against many accounts."),
    ("T1082", "System Information Discovery", [_DI], "Gathering detailed information about the OS and hardware."),
    ("T1033", "System Owner/User Discovery", [_DI], "Identifying the primary user or logged-in users of a system."),
    ("T1018", "Remote System Discovery", [_DI], "Listing other systems by IP, hostname or other identifier."),
    ("T1087", "Account Discovery", [_DI], "Listing accounts on a system or domain."),
    ("T1057", "Process Discovery", [_DI], "Gathering information about running processes."),
    ("T1049", "System Network Connections Discovery", [_DI], "Listing network connections to or from a system."),
    ("T1046", "Network Service Discovery", [_DI], "Scanning remote hosts for running services."),
    ("T1041", "Exfiltration Over C2 Channel", [_XF], "Stealing data over the existing command and control channel."),
    (
        "T1048",
        "Exfiltration Over Alternative Protocol",
        [_XF],
        "Stealing data over a protocol different from the C2 channel.",
    ),
    ("T1567", "Exfiltration Over Web Service", [_XF], "Using legitimate external web services to exfiltrate data."),
    ("T1486", "Data Encrypted for Impact", [_IM], "Encrypting data to interrupt availability."),
    ("T1490", "Inhibit System Recovery", [_IM], "Deleting or disabling built-in recovery features."),
    ("T1218", "System Binary Proxy Execution", [_DE], "Proxying execution through signed, trusted system binaries."),
    ("T1218.011", "Rundll32", [_DE], "Abusing rundll32.exe to proxy execution of malicious code."),
    (
        "T1055",
        "Process Injection",
        [_DE, _PR],
        "Injecting code into processes to evade defenses or elevate privileges.",
    ),
    ("T1036", "Masquerading", [_DE], "Manipulating features of artifacts to make them appear legitimate."),
    ("T1562", "Impair Defenses", [_DE], "Maliciously modifying components to hinder or disable defensive mechanisms."),
    ("T1562.001", "Disable or Modify Tools", [_DE], "Disabling or modifying security tools to avoid detection."),
    ("T1112", "Modify Registry", [_DE], "Interacting with the Windows Registry to hide configuration or persist."),
    ("T1136", "Create Account", [_PE], "Creating an account to maintain access."),
    ("T1098", "Account Manipulation", [_PE], "Manipulating accounts to maintain or elevate access."),
    ("T1190", "Exploit Public-Facing Application", [_IA], "Exploiting a weakness in an Internet-facing system."),
    (
        "T1133",
        "External Remote Services",
        [_PE, _IA],
        "Leveraging external-facing remote services for initial access or persistence.",
    ),
    ("T1572", "Protocol Tunneling", [_C2], "Tunneling network communications inside another protocol."),
    ("T1573", "Encrypted Channel", [_C2], "Encrypting command and control traffic."),
    ("T1568", "Dynamic Resolution", [_C2], "Dynamically establishing connections to C2 infrastructure."),
    ("T1568.002", "Domain Generation Algorithms", [_C2], "Using algorithms to generate rendezvous domains."),
    (
        "T1546",
        "Event Triggered Execution",
        [_PE, _PR],
        "Establishing persistence by executing content triggered by system events.",
    ),
    ("T1197", "BITS Jobs", [_DE, _PE], "Abusing Background Intelligent Transfer Service jobs."),
    ("T1219", "Remote Access Software", [_C2], "Using legitimate remote access software to maintain access."),
    ("T1074", "Data Staged", [_CO], "Staging collected data in a central location before exfiltration."),
    ("T1560", "Archive Collected Data", [_CO], "Compressing or encrypting collected data prior to exfiltration."),
]

ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"


def technique_url(technique_id: str) -> str:
    return ATTACK_BASE_URL + technique_id.replace(".", "/")
