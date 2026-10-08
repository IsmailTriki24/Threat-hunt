"""LogRhythm SIEM (Search API on the :8501 gateway) pull connector.

Flow per window: POST search-task -> TaskId -> POST search-result (page until a completed, empty page). A window that hits the
30,000-log cap is split in half and retried. Windows are read oldest-first and only whole windows are emitted, so the
scheduler's watermark is always safe to advance.

Time: LogRhythm searches by true (UTC) time but reports `logDate` shifted by the console's UTC offset (observed: +1h for
this deployment). `date_shift_hours` corrects the event timestamp only (true time = logDate + shift); search windows are sent
unshifted so the collection watermark and the event times agree."""

import json
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from app.connectors._http import SourceError, request_json
from app.connectors._util import clip, finish, integer, ip_list, labels, text, valid_ip
from app.connectors.base import ConnectionResult, Connector, ConnectorHealth, NormalizationError
from app.events.schema import EventIn

FILTER_HOSTNAME = 23  # LogRhythm filterType: Hostname (origin or impacted)
VALUE_STRING = 4
MAX_MSGS = 30_000
PAGE_SIZE = 500
MIN_WINDOW = timedelta(minutes=1)
MAX_SEARCHES_PER_WINDOW = 16  # bounds the load one window can put on the SIEM when splitting keeps failing
_TECHNIQUE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")


class LogRhythmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: HttpUrl = Field(description="Search API gateway, e.g. https://10.0.0.5:8501")
    verify_tls: bool = Field(
        default=True, description="Disable ONLY for a self-signed appliance you cannot add a CA for"
    )
    ca_pem: str | None = Field(default=None, max_length=20_000, description="PEM CA bundle to trust for this source")
    tls_server_name: str | None = Field(
        default=None,
        max_length=255,
        pattern=r"^[A-Za-z0-9.-]+$",
        description="Hostname the certificate must match, when base_url is an IP",
    )
    date_shift_hours: int = Field(default=-1, ge=-14, le=14)
    hostname: str | None = Field(
        default=None, max_length=255, description="Only logs where this host is origin or impacted"
    )
    query_filter: dict[str, Any] | None = Field(
        default=None,
        description="Raw LogRhythm queryFilter object, e.g. copied from a Web Console search (browser dev tools). Overrides hostname",
    )
    allow_unfiltered: bool = Field(
        default=False,
        description="Collect with no filter. Real SIEMs often exceed 30,000 logs/minute; leave off unless yours is small",
    )
    initial_lookback_hours: int = Field(default=1, ge=1, le=168)
    window_minutes: int = Field(default=10, ge=1, le=240)
    overlap_minutes: int = Field(default=10, ge=0, le=60)
    query_timeout_min: int = Field(default=5, ge=1, le=30)
    time_budget_s: int = Field(default=100, ge=10, le=200)
    timeout_s: float = Field(default=60.0, gt=0, le=120)

    @model_validator(mode="after")
    def _filter_size(self) -> "LogRhythmConfig":
        if self.query_filter is not None and (not self.query_filter or len(json.dumps(self.query_filter)) > 20_000):
            raise ValueError("query_filter must be a non-empty JSON object under 20 KB")
        return self


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class LogRhythmConnector(Connector):
    connector_type = "logrhythm"
    display_name = "LogRhythm SIEM"
    supports_collect = True
    config_model = LogRhythmConfig
    collect_limit = 20_000

    @property
    def cfg(self) -> LogRhythmConfig:
        return self.config  # type: ignore[return-value]

    # ---- transport -------------------------------------------------------------------------------
    async def _post(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        token = self.secrets.get("token")
        if not token:
            raise SourceError("no API token configured for this data source")
        base = str(self.cfg.base_url).rstrip("/")
        out = await request_json(
            "POST",
            f"{base}/lr-search-api/actions/{endpoint}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            json_body=body,
            verify_tls=self.cfg.verify_tls,
            ca_pem=self.cfg.ca_pem,
            tls_server_name=self.cfg.tls_server_name,
            timeout_s=self.cfg.timeout_s,
        )
        if not isinstance(out, dict):
            raise SourceError("unexpected response shape")
        return out

    def _task_body(self, start: datetime, end: datetime) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        if self.cfg.hostname:
            items.append(
                {
                    "filterItemType": 0,
                    "filterType": FILTER_HOSTNAME,
                    "filterMode": 1,
                    "values": [
                        {
                            "filterType": FILTER_HOSTNAME,
                            "valueType": VALUE_STRING,
                            "value": {"matchType": 0, "value": self.cfg.hostname},
                        }
                    ],
                }
            )
        query_filter: dict[str, Any] = self.cfg.query_filter or {
            "msgFilterType": 2,
            "isSavedFilter": False,
            "filterGroup": {
                "filterItemType": 1,
                "filterGroupOperator": 0,
                "filterMode": 1,
                "filterType": 1000,
                "filterItems": items,
            },
        }
        return {
            "maxMsgsToQuery": MAX_MSGS,
            "logCacheSize": 10000,
            "queryTimeout": self.cfg.query_timeout_min,
            "queryRawLog": False,
            "queryEventManager": False,
            "queryFilter": query_filter,
            "dateCriteria": {"useInsertedDate": False, "dateMin": _iso(start), "dateMax": _iso(end)},
        }

    async def _search_window(
        self, start: datetime, end: datetime, budget: list[int] | None = None
    ) -> list[dict[str, Any]]:
        budget = budget if budget is not None else [MAX_SEARCHES_PER_WINDOW]
        if budget[0] <= 0:
            raise SourceError(
                "too many searches needed for one window; narrow this source with hostname or query_filter"
            )
        budget[0] -= 1
        task = await self._post("search-task", self._task_body(start, end))
        task_id = task.get("TaskId") or task.get("taskId")
        if not task_id:
            raise SourceError("search-task returned no TaskId")
        logs: list[dict[str, Any]] = []
        origin, status = 0, "unknown"
        for _ in range(600):
            page = await self._post(
                "search-result",
                {
                    "data": {
                        "searchGuid": task_id,
                        "search": {"sort": [], "fields": [], "searchType": 2, "searchMode": 2, "entityId": 0},
                        "paginator": {"origin": origin, "page_size": PAGE_SIZE},
                    }
                },
            )
            status = str(page.get("TaskStatus") or page.get("taskStatus") or "unknown")
            items = page.get("Items") or page.get("items") or []
            if items:
                logs.extend(i for i in items if isinstance(i, dict))
                origin += len(items)
                continue
            if "Completed" in status or "Failed" in status or "Cancel" in status:
                break
            await _sleep(2)
        if "Max Results" in status or "Failed" in status:
            # Too many logs for one search (cap) or the search timed out under load: retry the two halves.
            if end - start <= MIN_WINDOW:
                raise SourceError(
                    f"LogRhythm returned '{status}' for a 1-minute window (over {MAX_MSGS} logs/minute?). "
                    "Narrow this source with hostname or query_filter"
                )
            mid = start + (end - start) / 2
            return [*await self._search_window(start, mid, budget), *await self._search_window(mid, end, budget)]
        if status == "unknown":
            raise SourceError("search window ended with an unknown status")
        return logs

    # ---- Connector API ---------------------------------------------------------------------------
    async def test_connection(self) -> ConnectionResult:
        try:
            now = datetime.now(UTC)
            task = await self._post("search-task", self._task_body(now - timedelta(minutes=1), now))
        except SourceError as exc:
            return ConnectionResult(ok=False, detail=str(exc)[:200])
        return ConnectionResult(ok="TaskId" in task or "taskId" in task, detail="search API reachable, token accepted")

    async def health(self) -> ConnectorHealth:
        res = await self.test_connection()
        return ConnectorHealth(status="ok" if res.ok else "down", detail=res.detail)

    async def collect(self, since: datetime | None = None, limit: int = 20_000) -> AsyncIterator[dict[str, Any]]:
        cfg = self.cfg
        if not (cfg.hostname or cfg.query_filter or cfg.allow_unfiltered):
            raise SourceError(
                "this source has no filter: set hostname or query_filter (a full SIEM is usually far too large to ingest)"
            )
        now = datetime.now(UTC).replace(microsecond=0)
        end_cap = now - timedelta(minutes=2)  # let the newest logs land before declaring a window complete
        start = (
            (since - timedelta(minutes=cfg.overlap_minutes))
            if since
            else now - timedelta(hours=cfg.initial_lookback_hours)
        )
        step = timedelta(minutes=cfg.window_minutes)
        deadline = time.monotonic() + cfg.time_budget_s
        emitted = 0
        t = start
        while t < end_cap:
            e = min(t + step, end_cap)
            logs = await self._search_window(t, e)
            logs.sort(key=lambda r: integer(r.get("logDate")) or 0)
            for r in logs:
                yield r
            emitted += len(logs)
            self.watermark = e  # whole window read
            t = e
            if emitted >= limit or time.monotonic() > deadline:
                break

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        return _normalize(raw, self.cfg.date_shift_hours)


async def _sleep(s: float) -> None:
    import asyncio

    await asyncio.sleep(s)


# ---- normalisation ---------------------------------------------------------------------------------
def _event_type(raw: dict[str, Any]) -> tuple[str, str | None]:
    """(canonical event_type, outcome) from LogRhythm's classification."""
    cls = (text(raw.get("classificationName")) or "").lower()
    src = (text(raw.get("logSourceTypeName")) or "").lower()
    if "authentication" in cls or "logon" in (text(raw.get("commonEventName")) or "").lower():
        return (
            "authentication",
            "failure" if "fail" in cls or "denied" in cls else "success" if "success" in cls else None,
        )
    if "ai engine" in src or cls in ("activity",) or raw.get("messageTypeEnum") == 1:
        return "alert", None
    if "dns" in cls:
        return "dns_query", None
    if any(k in cls for k in ("network", "firewall", "connection", "traffic")):
        return "network_connection", None
    if "registry" in cls:
        return "registry_event", None
    if "file" in cls:
        return "file_event", None
    if any(k in cls for k in ("malware", "attack", "compromise", "suspicious", "misuse", "reconnaissance", "vulnerab")):
        return "alert", None
    return "other", None


def _normalize(raw: dict[str, Any], shift_hours: int) -> list[EventIn]:
    log_date = integer(raw.get("logDate")) or integer(raw.get("normalDate"))
    msg_id = text(raw.get("messageId"))
    if log_date is None or not msg_id:
        raise NormalizationError("logDate/messageId: missing")
    try:
        ts = datetime.fromtimestamp(log_date / 1000, UTC) + timedelta(hours=shift_hours)
    except (OverflowError, OSError, ValueError):
        raise NormalizationError("logDate: out of range") from None
    event_type, outcome = _event_type(raw)
    name = text(raw.get("commonEventName")) or text(raw.get("classificationName")) or "logrhythm event"
    techniques = sorted(
        {f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "") for m in _TECHNIQUE.finditer(name)}
    )

    host = clip(raw.get("impactedHost")) or clip(raw.get("impactedName")) or clip(raw.get("logSourceHostName"))
    src_ip = valid_ip(raw.get("originIp"))
    dst_ip = valid_ip(raw.get("impactedIp"))
    user_name = clip(raw.get("login")) or clip(raw.get("account"))
    domain = clip(raw.get("domainOrigin")) or clip(raw.get("domainImpacted"))
    priority = integer(raw.get("priority"))
    session_type = text(raw.get("sessionType"))

    doc: dict[str, Any] = {
        "timestamp": ts.isoformat(),
        "source": "logrhythm",
        "event_type": event_type,
        "action": clip(name, 64),
        "outcome": outcome or "unknown",
        "severity": max(0, min(100, priority)) if priority is not None else 0,
        "original_id": msg_id,
        "message": clip(f"{name}: {text(raw.get('vendorInfo'))}" if text(raw.get("vendorInfo")) else name, 1024),
        "host": {"hostname": host, "ip": ip_list(dst_ip)} if host or dst_ip else None,
        "user": {"name": user_name, "domain": domain} if user_name else None,
        "network": {
            "src_ip": src_ip,
            "src_port": _port(raw.get("originPort")),
            "dst_ip": dst_ip,
            "dst_port": _port(raw.get("impactedPort")),
        }
        if (src_ip or dst_ip)
        else None,
        "tags": [
            t
            for t in dict.fromkeys(
                [
                    "logrhythm",
                    (text(raw.get("classificationName")) or "").lower().replace(" ", "-"),
                    *[f"attack.{t.lower()}" for t in techniques],
                ]
            )
            if t
        ][:20],
        "labels": labels(
            classification=raw.get("classificationName"),
            vendor_message_id=raw.get("vendorMessageId"),
            log_source=raw.get("logSourceName"),
            log_source_type=raw.get("logSourceTypeName"),
            entity=raw.get("entityName"),
            common_event_id=raw.get("commonEventId"),
            mpe_rule=raw.get("mpeRuleName"),
            origin_country=raw.get("originCountry"),
            origin_network=raw.get("originNetwork"),
            response_code=raw.get("responseCode"),
            reason=raw.get("reason"),
            identity=raw.get("userOriginIdentity"),
        ),
        "raw": {k: v for k, v in raw.items() if not isinstance(v, dict | list)},
    }
    if event_type == "authentication":
        doc["auth"] = {
            "logon_type": session_type,
            "method": clip(raw.get("objectName")) or clip(raw.get("vendorInfo"), 64),
            "source_ip": src_ip,
        }
    elif text(raw.get("process")):
        doc["process"] = {"name": clip(raw.get("process"))}
    return finish(doc)


def _port(value: Any) -> int | None:
    p = integer(value)
    return p if p is not None and 0 <= p <= 65535 else None
