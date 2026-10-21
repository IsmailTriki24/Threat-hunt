# ruff: noqa: E501
"""LogRhythm Alarm API (same :8501 gateway and token as the Search API): the alarms the SIEM raised and the logs behind them.

Verified on a production 7.9 (2026-10-19):
* `GET /lr-alarm-api/alarms/` takes QUERY parameters (the same names sent as headers are ignored): `count` (<= 500), `offset`,
  `alarmStatus`, `entityName`, `alarmRuleName` (SQL pattern, `%` any run) and `dateInserted` (a lower bound, ISO, true UTC). There is no
  upper bound parameter, results are newest first, `alarmsCount` is the total that matches.
* `GET /lr-alarm-api/alarms/{id}/events` returns the logs behind an alarm, INCLUDING `logMessage`, the raw log text that the Search API
  never sends back.
* Alarm times are true UTC (unlike the Search API's `logDate`, which carries the console's +1h)."""

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from app.connectors._http import SourceError, request_json
from app.connectors._util import clip, finish, integer, labels, text, valid_ip
from app.connectors.base import NormalizationError
from app.events.schema import EventIn

PAGE = 100
MAX_PAGES = 60  # bounds the calls one listing can make (newer alarms than the range end are paged past)
STATUS = {
    0: "New", 1: "Opened", 2: "Working", 3: "Escalated", 4: "Closed", 5: "Closed - false alarm", 6: "Closed - resolved",
    7: "Closed - unresolved", 8: "Closed - reported", 9: "Closed - monitor",
}  # fmt: skip
_RAW_LOGS = 5  # raw log texts kept per alarm
_RAW_LOG_CHARS = 1500


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")


def _parse(value: Any) -> datetime | None:
    s = text(value)
    if not s:
        return None
    try:
        return datetime.fromisoformat(s[:26]).replace(tzinfo=UTC)
    except ValueError:
        return None


async def _get(connector: Any, path: str, params: dict[str, Any] | None = None, api: str = "lr-alarm-api") -> Any:
    token = connector.secrets.get("token")
    cfg = connector.cfg
    if not token or cfg.base_url is None:
        raise SourceError(
            "this needs the legacy LogRhythm API (base_url and the secret token), which is not configured"
        )
    url = f"{str(cfg.base_url).rstrip('/')}/{api}/{path}"
    if params:
        url += "?" + urlencode(params)
    out = await request_json(
        "GET",
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        verify_tls=cfg.verify_tls,
        ca_pem=cfg.ca_pem,
        tls_server_name=cfg.tls_server_name,
        timeout_s=cfg.timeout_s,
    )
    return out


async def list_alarms(
    connector: Any, start: datetime, end: datetime, rule_like: str | None = None, cap: int = 300
) -> tuple[list[dict[str, Any]], bool]:
    """(alarm summaries inserted in [start, end], newest first; True when `cap` stopped the listing)."""
    out: list[dict[str, Any]] = []
    offset = 0
    for _ in range(MAX_PAGES):
        params: dict[str, Any] = {"count": PAGE, "offset": offset, "dateInserted": _iso(start)}
        if rule_like:
            params["alarmRuleName"] = f"%{rule_like}%"
        page = await _get(connector, "alarms/", params)
        if not isinstance(page, dict):
            raise SourceError("unexpected alarm response shape")
        items = [a for a in (page.get("alarmsSearchDetails") or []) if isinstance(a, dict)]
        for a in items:
            when = _parse(a.get("dateInserted"))
            if when is None or when > end:
                continue  # newer than the range (the listing has no upper bound)
            out.append(a)
            if len(out) >= cap:
                return out, True
        if len(items) < PAGE:
            return out, False
        offset += PAGE
    return out, True


async def alarm_events(connector: Any, alarm_id: int) -> list[dict[str, Any]]:
    page = await _get(connector, f"alarms/{int(alarm_id)}/events")
    if not isinstance(page, dict):
        raise SourceError("unexpected alarm response shape")
    return [e for e in (page.get("alarmEventsDetails") or []) if isinstance(e, dict)]


def _first(events: list[dict[str, Any]], *keys: str) -> str | None:
    for e in events:
        for k in keys:
            v = text(e.get(k))
            if v:
                return v
    return None


def _distinct(events: list[dict[str, Any]], *keys: str, limit: int = 10) -> list[str]:
    seen: dict[str, None] = {}
    for e in events:
        for k in keys:
            v = text(e.get(k))
            if v:
                seen.setdefault(v)
    return list(seen)[:limit]


def normalize_alarm(summary: dict[str, Any], events: list[dict[str, Any]]) -> list[EventIn]:
    alarm_id = integer(summary.get("alarmId"))
    when = _parse(summary.get("dateInserted"))
    if alarm_id is None or when is None:
        raise NormalizationError("alarmId/dateInserted: missing")
    rule = text(summary.get("alarmRuleName")) or "LogRhythm alarm"
    status_no = integer(summary.get("alarmStatus"))
    status = STATUS.get(status_no if status_no is not None else -1, "Unknown")
    host = _first(events, "impactedHostName", "impactedName", "originHostName", "originName", "originHost")
    src_ip = next((ip for e in events if (ip := valid_ip(e.get("originIP") or e.get("originIp")))), None)
    dst_ip = next((ip for e in events if (ip := valid_ip(e.get("impactedIP") or e.get("impactedIp")))), None)
    user = _first(events, "login", "account")
    priority = max((integer(e.get("priority")) or 0 for e in events), default=0)
    first_msg = _first(events, "logMessage")
    cases = [
        str(c.get("number") or c.get("id") or c) if isinstance(c, dict) else str(c)
        for c in (summary.get("associatedCases") or [])
    ]
    doc: dict[str, Any] = {
        "timestamp": when.isoformat(),
        "source": "logrhythm",
        "event_type": "alert",
        "action": clip(rule, 64),
        "outcome": "unknown",
        "severity": max(0, min(100, priority)),
        "original_id": f"alarm-{alarm_id}",
        "message": clip(f"Alarm: {rule} [{status}]" + (f" - {first_msg}" if first_msg else ""), 1024),
        "host": {"hostname": clip(host), "ip": [dst_ip] if dst_ip else None} if host or dst_ip else None,
        "user": {"name": clip(user)} if user else None,
        "network": {"src_ip": src_ip, "dst_ip": dst_ip} if (src_ip or dst_ip) else None,
        "tags": ["logrhythm", "alarm", status.lower().replace(" ", "-")],
        "labels": labels(
            alarm_id=alarm_id,
            alarm_status=status,
            alarm_rule=rule,
            entity=summary.get("entityName"),
            event_count=len(events),
            cases=",".join(cases),
            classification=_first(events, "classificationName"),
            log_source=_first(events, "logSourceName"),
            origin_ips=",".join(_distinct(events, "originIP", "originIp")),
            impacted_ips=",".join(_distinct(events, "impactedIP", "impactedIp")),
            hosts=",".join(_distinct(events, "impactedHostName", "originHostName", "impactedName", "originName")),
            users=",".join(_distinct(events, "login", "account")),
        ),
        "raw": {
            **{k: v for k, v in summary.items() if not isinstance(v, dict | list)},
            **{
                k: v
                for k, v in (events[0] if events else {}).items()
                if not isinstance(v, dict | list) and k != "logMessage"
            },
            **{
                f"logMessage_{i + 1}": clip(e.get("logMessage"), _RAW_LOG_CHARS)
                for i, e in enumerate(events[:_RAW_LOGS])
                if text(e.get("logMessage"))
            },
        },
    }
    return finish(doc)
