# ruff: noqa: E501
"""Synthetic telemetry generator. All identities, hosts and addresses are fictional; IPs come from
the RFC 5737 documentation ranges and domains use the reserved `.example` TLD."""

import base64
import random  # nosec B311
from datetime import UTC, datetime, timedelta
from typing import Any

from app.events.schema import EventIn

C2_IP = "203.0.113.45"
C2_DOMAIN = "cdn-update-check.example"
SPRAY_IP = "198.51.100.23"

USERS = ["mharper", "jdoe", "akhan", "lchen", "pnovak", "rsilva", "tbrown", "svc_backup"]
HOSTS = {
    "WS-FIN-014": "10.20.1.14",
    "WS-FIN-021": "10.20.1.21",
    "WS-HR-007": "10.20.2.7",
    "WS-IT-003": "10.20.3.3",
    "SRV-FILE-02": "10.20.10.2",
    "SRV-DC-01": "10.20.10.1",
}
BENIGN_DOMAINS = [
    "updates.example-vendor.example",
    "mail.corp.example",
    "intranet.corp.example",
    "crl.example-ca.example",
    "time.example-ntp.example",
    "files.corp.example",
]
BENIGN_PROCS = [
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "explorer.exe"),
    ("outlook.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "explorer.exe"),
    ("teams.exe", r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe", "explorer.exe"),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", "services.exe"),
    ("excel.exe", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "explorer.exe"),
]


def _h(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _base(ts: datetime, host: str, user: str, **kw: Any) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "source": "sysmon",
        "outcome": "success",
        "host": {"hostname": host, "ip": [HOSTS[host]], "os": "Windows 11"},
        "user": {"name": user, "domain": "CORP"},
        "labels": {"scenario": "demo"},
        **kw,
    }


def generate(now: datetime | None = None, *, seed: int = 7, with_attack: bool = True) -> list[EventIn]:
    rng = random.Random(seed)  # nosec B311 - synthetic data only
    now = now or datetime.now(UTC)
    events: list[dict[str, Any]] = []
    hosts = list(HOSTS)

    # ---- normal authentication across the last 24h -----------------------------------------
    for _ in range(500):
        ts = now - timedelta(seconds=rng.randint(60, 86400))
        user, host = rng.choice(USERS[:-1]), rng.choice(hosts[:4])
        events.append(
            _base(
                ts,
                host,
                user,
                source="windows",
                event_type="authentication",
                action="logon",
                message=f"{user} logged on to {host}",
                auth={"logon_type": rng.choice(["interactive", "interactive", "unlock"]), "method": "kerberos"},
            )
        )
    # ---- failed-logon burst (password spraying) from an external-looking address -------------
    spray_start = now - timedelta(hours=7)
    for i in range(36):
        user = USERS[i % len(USERS) - 1]
        events.append(
            _base(
                spray_start + timedelta(seconds=i * 4),
                "SRV-DC-01",
                user,
                source="windows",
                event_type="authentication",
                action="logon_failed",
                outcome="failure",
                severity=40,
                message=f"Failed logon for {user}",
                auth={"logon_type": "network", "method": "ntlm", "source_ip": SPRAY_IP},
            )
        )
    # ---- benign process execution --------------------------------------------------------------
    for _ in range(450):
        ts = now - timedelta(seconds=rng.randint(60, 86400))
        user, host = rng.choice(USERS[:-1]), rng.choice(hosts[:4])
        name, exe, parent = rng.choice(BENIGN_PROCS)
        events.append(
            _base(
                ts,
                host,
                user,
                event_type="process_creation",
                action="process_started",
                process={
                    "name": name,
                    "executable": exe.format(u=user),
                    "pid": rng.randint(1000, 9000),
                    "command_line": exe.format(u=user),
                    "hash": {"sha256": _h(rng, 64)},
                    "parent": {"name": parent},
                },
            )
        )
    # ---- benign DNS + network ------------------------------------------------------------------
    for _ in range(400):
        ts = now - timedelta(seconds=rng.randint(60, 86400))
        user, host = rng.choice(USERS[:-1]), rng.choice(hosts[:4])
        domain = rng.choice(BENIGN_DOMAINS)
        events.append(
            _base(
                ts,
                host,
                user,
                event_type="dns_query",
                action="dns_query",
                process={"name": "chrome.exe"},
                dns={"question": domain, "answers": [f"192.0.2.{rng.randint(2, 250)}"]},
            )
        )
    for _ in range(200):
        ts = now - timedelta(seconds=rng.randint(60, 86400))
        user, host = rng.choice(USERS[:-1]), rng.choice(hosts[:4])
        events.append(
            _base(
                ts,
                host,
                user,
                event_type="network_connection",
                action="connection_attempted",
                process={"name": "chrome.exe"},
                network={
                    "protocol": "tcp",
                    "direction": "outbound",
                    "src_ip": HOSTS[host],
                    "src_port": rng.randint(49152, 65535),
                    "dst_ip": f"192.0.2.{rng.randint(2, 250)}",
                    "dst_port": 443,
                    "bytes": rng.randint(500, 90000),
                },
            )
        )
    # ---- file activity noise ---------------------------------------------------------------------
    for i in range(120):
        ts = now - timedelta(seconds=rng.randint(60, 86400))
        user, host = rng.choice(USERS[:-1]), rng.choice(hosts[:4])
        name = f"report_{i}.xlsx"
        events.append(
            _base(
                ts,
                host,
                user,
                event_type="file_event",
                action="file_created",
                process={"name": "excel.exe"},
                file={"name": name, "path": rf"C:\Users\{user}\Documents\{name}"},
            )
        )

    if with_attack:
        events.extend(_attack_chain(rng, now))

    return [EventIn.model_validate(e) for e in sorted(events, key=lambda e: e["timestamp"])]


def _attack_chain(rng: random.Random, now: datetime) -> list[dict[str, Any]]:
    """Phishing → PowerShell → C2 → persistence → credential access → lateral movement."""
    out: list[dict[str, Any]] = []
    t0 = now - timedelta(hours=5, minutes=12)
    victim, host = "mharper", "WS-FIN-014"
    payload = base64.b64encode("Write-Output 'synthetic-demo-payload'".encode("utf-16-le")).decode()
    ps_cmd = f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {payload}"
    ps_hash = _h(rng, 64)

    def at(seconds: float) -> datetime:
        return t0 + timedelta(seconds=seconds)

    out.append(
        _base(
            at(0),
            host,
            victim,
            source="windows",
            event_type="authentication",
            action="logon",
            message="mharper logged on to WS-FIN-014",
            auth={"logon_type": "interactive", "method": "kerberos"},
        )
    )
    out.append(
        _base(
            at(3),
            host,
            victim,
            event_type="process_creation",
            action="process_started",
            severity=20,
            process={
                "name": "WINWORD.EXE",
                "pid": 5120,
                "executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "command_line": r'"WINWORD.EXE" /n "C:\Users\mharper\Downloads\Invoice_Q3.docm"',
                "parent": {"name": "explorer.exe", "pid": 3300},
            },
        )
    )
    out.append(
        _base(
            at(5),
            host,
            victim,
            event_type="process_creation",
            action="process_started",
            severity=80,
            message="PowerShell spawned by Office application",
            process={
                "name": "powershell.exe",
                "pid": 4312,
                "command_line": ps_cmd,
                "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "hash": {"sha256": ps_hash},
                "parent": {"name": "WINWORD.EXE", "pid": 5120},
            },
        )
    )
    out.append(
        _base(
            at(7),
            host,
            victim,
            event_type="dns_query",
            action="dns_query",
            severity=60,
            process={"name": "powershell.exe", "pid": 4312},
            dns={"question": C2_DOMAIN, "answers": [C2_IP]},
        )
    )
    out.append(
        _base(
            at(9),
            host,
            victim,
            event_type="network_connection",
            action="connection_attempted",
            severity=70,
            process={"name": "powershell.exe", "pid": 4312},
            network={
                "protocol": "tcp",
                "direction": "outbound",
                "src_ip": HOSTS[host],
                "src_port": 50211,
                "dst_ip": C2_IP,
                "dst_port": 443,
                "dst_domain": C2_DOMAIN,
                "bytes": 18234,
            },
        )
    )
    out.append(
        _base(
            at(11),
            host,
            victim,
            event_type="file_event",
            action="file_created",
            severity=70,
            message="Script written to temp directory",
            process={"name": "powershell.exe", "pid": 4312},
            file={
                "name": "upd.ps1",
                "path": r"C:\Users\mharper\AppData\Local\Temp\upd.ps1",
                "hash": {"sha256": _h(rng, 64)},
            },
        )
    )
    out.append(
        _base(
            at(15),
            host,
            victim,
            event_type="process_creation",
            action="process_started",
            severity=75,
            process={
                "name": "schtasks.exe",
                "pid": 6004,
                "command_line": r'schtasks.exe /create /tn "OneDrive Sync Helper" /sc onlogon /tr "powershell.exe -ep bypass -File C:\Users\mharper\AppData\Local\Temp\upd.ps1"',
                "parent": {"name": "powershell.exe", "pid": 4312},
            },
        )
    )
    out.append(
        _base(
            at(16),
            host,
            victim,
            event_type="scheduled_task",
            action="task_created",
            severity=75,
            message="Scheduled task 'OneDrive Sync Helper' created",
            process={"name": "schtasks.exe", "pid": 6004},
            tags=["persistence"],
        )
    )
    # C2 beaconing: ~60s with jitter for the next ~4 hours
    beat = 60.0
    while beat < 4 * 3600:
        out.append(
            _base(
                at(beat),
                host,
                victim,
                event_type="network_connection",
                action="connection_attempted",
                severity=50,
                process={"name": "powershell.exe", "pid": 4312},
                network={
                    "protocol": "tcp",
                    "direction": "outbound",
                    "src_ip": HOSTS[host],
                    "src_port": rng.randint(49152, 65535),
                    "dst_ip": C2_IP,
                    "dst_port": 443,
                    "dst_domain": C2_DOMAIN,
                    "bytes": rng.randint(300, 420),
                },
            )
        )
        beat += rng.uniform(55, 68)
    # credential access (LSASS memory dump via comsvcs)
    out.append(
        _base(
            at(20 * 60),
            host,
            victim,
            event_type="process_creation",
            action="process_started",
            severity=90,
            message="Possible LSASS memory dump",
            process={
                "name": "rundll32.exe",
                "pid": 7788,
                "command_line": r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 692 C:\Windows\Temp\l.dmp full",
                "parent": {"name": "powershell.exe", "pid": 4312},
            },
        )
    )
    out.append(
        _base(
            at(20 * 60 + 2),
            host,
            victim,
            event_type="file_event",
            action="file_created",
            severity=85,
            process={"name": "rundll32.exe", "pid": 7788},
            file={"name": "l.dmp", "path": r"C:\Windows\Temp\l.dmp"},
        )
    )
    # lateral movement with a service account
    out.append(
        _base(
            at(40 * 60),
            "SRV-FILE-02",
            "svc_backup",
            source="windows",
            event_type="authentication",
            action="logon",
            severity=65,
            message="Network logon from WS-FIN-014 using svc_backup",
            auth={"logon_type": "network", "method": "ntlm", "source_ip": HOSTS[host]},
        )
    )
    out.append(
        _base(
            at(40 * 60 + 3),
            "SRV-FILE-02",
            "svc_backup",
            event_type="service_install",
            action="service_installed",
            severity=85,
            message="Service PSEXESVC installed",
            process={"name": "services.exe"},
            tags=["lateral_movement"],
        )
    )
    out.append(
        _base(
            at(40 * 60 + 5),
            "SRV-FILE-02",
            "svc_backup",
            event_type="process_creation",
            action="process_started",
            severity=70,
            process={
                "name": "cmd.exe",
                "pid": 2216,
                "command_line": "cmd.exe /c whoami /all",
                "parent": {"name": "services.exe", "pid": 600},
            },
        )
    )
    return out
