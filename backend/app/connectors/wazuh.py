"""Wazuh alert JSON → canonical events (Sysmon-via-Wazuh alerts are delegated to the Sysmon normalizer)."""

from typing import Any

from app.connectors._util import finish, integer, obj, text
from app.connectors.base import Connector, NormalizationError
from app.connectors.sysmon import SysmonConnector
from app.events.schema import EventIn


def _cap(key: str) -> str:
    return key[:1].upper() + key[1:]


class WazuhConnector(Connector):
    connector_type = "wazuh"
    display_name = "Wazuh"

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        rule, agent, data = obj(raw.get("rule")), obj(raw.get("agent")), obj(raw.get("data"))
        if not rule:
            raise NormalizationError("rule: missing")
        level = integer(rule.get("level"))
        if level is None:
            raise NormalizationError("rule.level: missing or not an integer")
        raw_groups = rule.get("groups")
        groups = [g for g in (raw_groups[:19] if isinstance(raw_groups, list) else []) if isinstance(g, str)]
        rule_id = text(rule.get("id"))
        tags = [*groups, *([f"wazuh-rule-{rule_id}"] if rule_id else [])]
        agent_id, alert_id = text(agent.get("id")), text(raw.get("id"))
        original_id = f"{agent_id}:{alert_id}" if agent_id and alert_id else None

        win = obj(data.get("win"))
        sysmon_events = self._sysmon(win)
        if sysmon_events is not None:
            [event] = sysmon_events
            patch = event.model_dump(mode="json", exclude_none=True)
            patch["source"] = "wazuh"
            patch["tags"] = [*patch.get("tags", []), *tags][:20]
            patch["labels"] = {
                k: v for k, v in {"wazuh_rule": rule_id, "wazuh_level": str(level), "origin": "sysmon"}.items() if v
            }
            patch["original_id"] = original_id or patch.get("original_id")
            patch["severity"] = max(patch.get("severity", 0), min(100, level * 7))
            patch["message"] = (text(rule.get("description")) or "")[:1024] or None
            patch["raw"] = raw
            if not patch.get("host") and agent.get("name"):
                patch["host"] = {"hostname": text(agent.get("name"))}
            return finish(patch)

        agent_ip = text(agent.get("ip"))
        net = {"src_ip": text(data.get("srcip")), "dst_ip": text(data.get("dstip"))}
        user = text(data.get("dstuser")) or text(data.get("srcuser"))
        return finish(
            {
                "timestamp": self._ts(raw.get("timestamp")),
                "source": "wazuh",
                "event_type": "alert",
                "action": "wazuh_alert",
                "severity": min(100, level * 7),
                "outcome": "unknown",
                "message": (text(rule.get("description")) or text(raw.get("full_log")) or "Wazuh alert")[:1024],
                "host": {"hostname": text(agent.get("name")), "ip": [agent_ip] if agent_ip else []},
                "user": {"name": user},
                "network": net,
                "tags": tags,
                "original_id": original_id,
                "raw": raw,
            }
        )

    @staticmethod
    def _ts(value: Any) -> str:
        from app.connectors._util import iso_timestamp

        return iso_timestamp(value)

    def _sysmon(self, win: dict[str, Any]) -> list[EventIn] | None:
        system, edata = obj(win.get("system")), obj(win.get("eventdata"))
        if text(system.get("providerName")) != "Microsoft-Windows-Sysmon" or not edata:
            return None
        flat: dict[str, Any] = {_cap(k): v for k, v in edata.items() if not isinstance(v, dict | list)}
        flat["EventID"] = integer(system.get("eventID"))
        flat["Computer"] = text(system.get("computer"))
        flat["UtcTime"] = text(edata.get("utcTime")) and str(edata["utcTime"]).replace(" ", "T").rstrip("Z") + "Z"
        return SysmonConnector().normalize(flat)
