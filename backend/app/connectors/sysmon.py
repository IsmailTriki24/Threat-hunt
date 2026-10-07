"""Sysmon (as shipped by Winlogbeat/Wazuh/NXLog in flattened JSON form) → canonical events."""

import re
from typing import Any

from pydantic import ValidationError

from app.connectors.base import Connector, NormalizationError
from app.connectors.canonical import _summarize
from app.events.schema import EventIn

_HASH_RE = re.compile(r"(MD5|SHA1|SHA256)=([A-Fa-f0-9]+)")


def _hashes(value: str | None) -> dict[str, str] | None:
    if not value:
        return None
    found = {k.lower(): v.lower() for k, v in _HASH_RE.findall(value)}
    return found or None


def _split_user(value: str | None) -> dict[str, str] | None:
    if not value:
        return None
    domain, _, name = value.rpartition("\\")
    return {"name": name, **({"domain": domain} if domain else {})}


def _basename(path: str | None) -> str | None:
    return re.split(r"[\\/]", path)[-1] if path else None


class SysmonConnector(Connector):
    connector_type = "sysmon"
    display_name = "Sysmon"

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        try:
            event_id = int(raw.get("EventID") or raw["event_id"])
        except (TypeError, ValueError, KeyError):
            raise NormalizationError("EventID: missing or not an integer") from None
        handler = {1: self._process, 3: self._network, 11: self._file, 22: self._dns}.get(event_id)
        if handler is None:
            raise NormalizationError(f"EventID {event_id} is not supported")
        host = raw.get("Computer")
        doc: dict[str, Any] = {
            "timestamp": raw.get("UtcTime") or raw.get("@timestamp"),
            "source": "sysmon",
            "outcome": "success",
            "host": {"hostname": host} if host else None,
            "user": _split_user(raw.get("User")),
            "original_id": raw.get("RecordID") and f"{host}:{raw['RecordID']}",
            "raw": raw,
        }
        doc.update(handler(raw))
        doc = {k: v for k, v in doc.items() if v is not None}
        try:
            return [EventIn.model_validate(doc)]
        except ValidationError as exc:
            raise NormalizationError(_summarize(exc)) from None

    @staticmethod
    def _process(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_type": "process_creation",
            "action": "process_started",
            "process": {
                "name": _basename(r.get("Image")),
                "executable": r.get("Image"),
                "pid": r.get("ProcessId"),
                "command_line": r.get("CommandLine"),
                "hash": _hashes(r.get("Hashes")),
                "parent": {
                    "name": _basename(r.get("ParentImage")),
                    "pid": r.get("ParentProcessId"),
                    "command_line": r.get("ParentCommandLine"),
                },
            },
        }

    @staticmethod
    def _network(r: dict[str, Any]) -> dict[str, Any]:
        outbound = str(r.get("Initiated", "true")).lower() == "true"
        return {
            "event_type": "network_connection",
            "action": "connection_attempted",
            "process": {"name": _basename(r.get("Image")), "executable": r.get("Image"), "pid": r.get("ProcessId")},
            "network": {
                "protocol": (r.get("Protocol") or "").lower() or None,
                "direction": "outbound" if outbound else "inbound",
                "src_ip": r.get("SourceIp"),
                "src_port": r.get("SourcePort"),
                "dst_ip": r.get("DestinationIp"),
                "dst_port": r.get("DestinationPort"),
                "dst_domain": r.get("DestinationHostname"),
            },
        }

    @staticmethod
    def _file(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_type": "file_event",
            "action": "file_created",
            "process": {"name": _basename(r.get("Image")), "executable": r.get("Image"), "pid": r.get("ProcessId")},
            "file": {"name": _basename(r.get("TargetFilename")), "path": r.get("TargetFilename")},
        }

    @staticmethod
    def _dns(r: dict[str, Any]) -> dict[str, Any]:
        answers = [a.split("::ffff:")[-1] for a in str(r.get("QueryResults") or "").split(";") if a]
        return {
            "event_type": "dns_query",
            "action": "dns_query",
            "process": {"name": _basename(r.get("Image")), "executable": r.get("Image"), "pid": r.get("ProcessId")},
            "dns": {"question": r.get("QueryName"), "answers": answers},
        }
