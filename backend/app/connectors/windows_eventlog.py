"""Windows Security/System events in flattened JSON (Winlogbeat-style) → canonical events."""

from typing import Any

from app.connectors._util import finish, integer, obj, text
from app.connectors.base import Connector, NormalizationError
from app.connectors.sysmon import _basename
from app.events.schema import EventIn

_LOGON_TYPES = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    10: "remote_interactive",
    11: "cached_interactive",
}
_IGNORED_IPS = {"-", "::1", "127.0.0.1", ""}
SUPPORTED = (4624, 4625, 4688, 4698, 7045)


def _first(*values: Any) -> Any:
    return next((v for v in values if v not in (None, "")), None)


class WindowsEventLogConnector(Connector):
    connector_type = "windows_eventlog"
    display_name = "Windows Event Log"

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        winlog = obj(raw.get("winlog"))
        event_id = integer(_first(raw.get("event_id"), raw.get("EventID"), winlog.get("event_id")))
        if event_id is None:
            raise NormalizationError("EventID: missing or not an integer")
        if event_id not in SUPPORTED:
            raise NormalizationError(f"EventID {event_id} is not supported")
        data = {**obj(raw.get("EventData")), **obj(winlog.get("event_data")), **obj(raw.get("event_data"))}
        # winlogbeat may also flatten EventData keys to the top level
        data = {**{k: v for k, v in raw.items() if not isinstance(v, dict | list)}, **data}
        computer = text(
            _first(
                raw.get("computer_name"),
                raw.get("Computer"),
                winlog.get("computer_name"),
                obj(raw.get("host")).get("name"),
            )
        )
        record = text(_first(raw.get("record_id"), raw.get("RecordID"), winlog.get("record_id")))
        doc: dict[str, Any] = {
            "timestamp": _first(raw.get("@timestamp"), raw.get("TimeCreated"), raw.get("timestamp")),
            "source": "windows",
            "host": {"hostname": computer},
            "raw": raw,
            "original_id": f"{computer}:{event_id}:{record}" if computer and record else None,
        }
        if doc["timestamp"] is None:
            raise NormalizationError("timestamp: missing")
        handler = {4624: self._logon, 4625: self._logon, 4688: self._process, 4698: self._task, 7045: self._service}
        doc.update(handler[event_id](event_id, data))
        return finish(doc)

    @staticmethod
    def _logon(event_id: int, d: dict[str, Any]) -> dict[str, Any]:
        ok = event_id == 4624
        ip = text(d.get("IpAddress"))
        user, domain = text(d.get("TargetUserName")), text(d.get("TargetDomainName"))
        ltype = integer(d.get("LogonType"))
        return {
            "event_type": "authentication",
            "action": "logon" if ok else "logon_failed",
            "outcome": "success" if ok else "failure",
            "severity": 0 if ok else 40,
            "user": {"name": user, "domain": domain},
            "auth": {
                "logon_type": _LOGON_TYPES.get(ltype, str(ltype)) if ltype is not None else None,
                "method": (text(d.get("AuthenticationPackageName")) or "").lower() or None,
                "source_ip": None if ip in _IGNORED_IPS else ip,
            },
            "message": f"{'Logon' if ok else 'Failed logon'} for {user or 'unknown'}",
        }

    @staticmethod
    def _process(_: int, d: dict[str, Any]) -> dict[str, Any]:
        exe, parent = text(d.get("NewProcessName")), text(d.get("ParentProcessName"))
        return {
            "event_type": "process_creation",
            "action": "process_started",
            "outcome": "success",
            "user": {"name": text(d.get("SubjectUserName")), "domain": text(d.get("SubjectDomainName"))},
            "process": {
                "name": _basename(exe),
                "executable": exe,
                "pid": integer(d.get("NewProcessId")),
                "command_line": text(d.get("CommandLine")),
                "parent": {"name": _basename(parent), "pid": integer(d.get("ProcessId"))},
            },
        }

    @staticmethod
    def _task(_: int, d: dict[str, Any]) -> dict[str, Any]:
        task = text(d.get("TaskName")) or "unknown"
        return {
            "event_type": "scheduled_task",
            "action": "task_created",
            "outcome": "success",
            "severity": 60,
            "user": {"name": text(d.get("SubjectUserName")), "domain": text(d.get("SubjectDomainName"))},
            "message": f"Scheduled task {task} created",
            "tags": ["persistence"],
        }

    @staticmethod
    def _service(_: int, d: dict[str, Any]) -> dict[str, Any]:
        name, image = text(d.get("ServiceName")) or "unknown", text(d.get("ImagePath"))
        return {
            "event_type": "service_install",
            "action": "service_installed",
            "outcome": "success",
            "severity": 60,
            "message": f"Service {name} installed" + (f": {image}" if image else ""),
            "process": {
                "executable": image[:1024] if image else None,
                "name": _basename(image.split(" ")[0]) if image else None,
            },
            "tags": ["persistence"],
        }
