"""Trend Micro Vision One (XDR) pull connector. One data source = one dataset:

  alerts             Workbench alerts          GET /v3.0/workbench/alerts          (window on updatedDateTime)
  oat                Observed Attack Techniques GET /v3.0/oat/detections            (window on ingestion time)
  endpoint_activity  Endpoint telemetry        GET /v3.0/search/endpointActivities (TMV1-Query header)
  detections         Product security events   GET /v3.0/search/detections         (TMV1-Query header)

Read-only. Pagination follows the server-supplied `nextLink` (never rebuilt). Windows are read oldest-first; only whole windows
are emitted so the scheduler watermark can advance safely. The API key is a secret (`api_key`); only the region (a fixed set of
Trend hosts) is configurable, never a free-form URL."""

import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.connectors._http import SourceError, request_json
from app.connectors._util import clip, finish, hashes, integer, ip_list, labels, obj, text
from app.connectors.base import ConnectionResult, Connector, ConnectorHealth, NormalizationError
from app.events.schema import EventIn

REGIONS = {
    "us": "https://api.xdr.trendmicro.com",
    "eu": "https://api.eu.xdr.trendmicro.com",
    "jp": "https://api.xdr.trendmicro.co.jp",
    "sg": "https://api.sg.xdr.trendmicro.com",
    "au": "https://api.au.xdr.trendmicro.com",
    "in": "https://api.in.xdr.trendmicro.com",
    "mea": "https://api.mea.xdr.trendmicro.com",
}
Dataset = Literal["alerts", "oat", "endpoint_activity", "detections"]
PATHS: dict[str, str] = {
    "alerts": "/v3.0/workbench/alerts",
    "oat": "/v3.0/oat/detections",
    "endpoint_activity": "/v3.0/search/endpointActivities",
    "detections": "/v3.0/search/detections",
}
SEVERITY = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}
MAX_PAGES_PER_WINDOW = 20  # a window needing more pages is split in half and retried
MIN_WINDOW = timedelta(minutes=1)


class _TooBig(Exception):
    pass


class _OutOfTime(Exception):
    pass


class TrendConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region: Literal["us", "eu", "jp", "sg", "au", "in", "mea"] = "eu"
    dataset: Dataset
    query: str = Field(
        default="*", max_length=1000, description="TMV1-Query for the search datasets (endpoint_activity, detections)"
    )
    initial_lookback_hours: int = Field(default=1, ge=1, le=168)
    window_minutes: int = Field(default=15, ge=5, le=240)
    overlap_minutes: int = Field(default=10, ge=0, le=60)
    filter: str | None = Field(
        default=None,
        max_length=1000,
        description="TMV1-Filter for alerts / oat (Trend filter syntax), e.g. to keep only high risk",
    )
    page_size: int = Field(default=100, ge=1, le=500)
    time_budget_s: int = Field(default=100, ge=10, le=200)
    timeout_s: float = Field(default=60.0, gt=0, le=120)

    @field_validator("query", "filter")
    @classmethod
    def _no_newlines(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if any(c in v for c in "\r\n\0"):
            raise ValueError("must be a single line")
        return v.strip() or None


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TrendVisionOneConnector(Connector):
    connector_type = "trend_vision_one"
    display_name = "Trend Micro Vision One (XDR)"
    supports_collect = True
    config_model = TrendConfig
    collect_limit = 20_000

    @property
    def cfg(self) -> TrendConfig:
        return self.config  # type: ignore[return-value]

    def _headers(self) -> dict[str, str]:
        key = self.secrets.get("api_key")
        if not key:
            raise SourceError("no API key configured for this data source")
        h = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        if self.cfg.dataset in ("endpoint_activity", "detections"):
            h["TMV1-Query"] = self.cfg.query or "*"
        elif self.cfg.filter:
            h["TMV1-Filter"] = self.cfg.filter
        return h

    async def _get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        out = await request_json("GET", url, headers=self._headers(), params=params, timeout_s=self.cfg.timeout_s)
        if not isinstance(out, dict):
            raise SourceError("unexpected response shape")
        return out

    async def test_connection(self) -> ConnectionResult:
        try:
            base = REGIONS[self.cfg.region]
            out = await request_json(
                "GET", f"{base}/v3.0/healthcheck/connectivity", headers=self._headers(), timeout_s=20
            )
        except SourceError as exc:
            return ConnectionResult(ok=False, detail=str(exc)[:200])
        ok = isinstance(out, dict) and out.get("status") == "available"
        return ConnectionResult(ok=ok, detail="Vision One reachable" if ok else f"unexpected status: {str(out)[:100]}")

    async def health(self) -> ConnectorHealth:
        res = await self.test_connection()
        return ConnectorHealth(status="ok" if res.ok else "down", detail=res.detail)

    def _params(self, start: datetime, end: datetime) -> dict[str, Any]:
        c = self.cfg
        s, e = _iso(start), _iso(end)
        if c.dataset == "alerts":
            return {
                "startDateTime": s,
                "endDateTime": e,
                "dateTimeTarget": "updatedDateTime",
                "orderBy": "createdDateTime asc",
                "top": min(c.page_size, 200),
            }
        if c.dataset == "oat":
            return {"ingestedStartDateTime": s, "ingestedEndDateTime": e, "top": min(c.page_size, 200)}
        return {"startDateTime": s, "endDateTime": e, "top": c.page_size}

    async def _read(self, start: datetime, end: datetime, deadline: float) -> list[dict[str, Any]]:
        """Read one window to exhaustion. Raises _TooBig if it needs more than MAX_PAGES_PER_WINDOW pages (caller splits it)
        and _OutOfTime if the run's time budget is spent."""
        url: str | None = REGIONS[self.cfg.region] + PATHS[self.cfg.dataset]
        params: dict[str, Any] | None = self._params(start, end)
        items: list[dict[str, Any]] = []
        pages = 0
        while url:
            if time.monotonic() > deadline:
                raise _OutOfTime
            if pages >= MAX_PAGES_PER_WINDOW:
                raise _TooBig
            body = await self._get(url, params)
            items.extend(i for i in body.get("items", []) if isinstance(i, dict))
            nxt = body.get("nextLink")
            url, params = (nxt if isinstance(nxt, str) else None), None  # nextLink is a complete URL
            pages += 1
        return items

    async def _window(self, start: datetime, end: datetime, deadline: float) -> list[dict[str, Any]]:
        try:
            return await self._read(start, end, deadline)
        except _TooBig:
            if end - start <= MIN_WINDOW:
                raise SourceError(
                    f"more than {MAX_PAGES_PER_WINDOW} pages of data in one minute; add a query/filter to narrow the source"
                ) from None
            mid = start + (end - start) / 2
            return [*await self._window(start, mid, deadline), *await self._window(mid, end, deadline)]

    async def collect(self, since: datetime | None = None, limit: int = 20_000) -> AsyncIterator[dict[str, Any]]:
        c = self.cfg
        now = datetime.now(UTC).replace(microsecond=0)
        end_cap = now - timedelta(minutes=1)
        start = (
            (since - timedelta(minutes=c.overlap_minutes)) if since else now - timedelta(hours=c.initial_lookback_hours)
        )
        step = timedelta(minutes=c.window_minutes)
        deadline = time.monotonic() + c.time_budget_s
        emitted = 0
        t = start
        while t < end_cap:
            e = min(t + step, end_cap)
            try:
                records = await self._window(t, e, deadline)
            except _OutOfTime:
                return  # watermark stays at the last fully-read window; the rest is picked up next run
            for rec in records:
                yield rec
            emitted += len(records)
            self.watermark = e
            t = e
            if emitted >= limit:
                break

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        return _NORMALIZERS[self.cfg.dataset](raw)


# ---- shared bits -------------------------------------------------------------------------------------
def _ts(*candidates: Any) -> str:
    for v in candidates:
        if isinstance(v, str) and v.strip() and not v.strip().isdigit():
            return v.strip().replace("Z", "+00:00")
        n = integer(v)
        if n is not None and n > 10**11:  # epoch milliseconds
            try:
                return datetime.fromtimestamp(n / 1000, UTC).isoformat()
            except (OverflowError, OSError, ValueError):
                continue
    raise NormalizationError("timestamp: missing")


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        return clip(value[0]) if value else None
    return clip(value)


def _techniques(*groups: Any) -> list[str]:
    out: list[str] = []
    for g in groups:
        for t in g if isinstance(g, list) else []:
            if isinstance(t, str) and t[:1].upper() == "T":
                out.append(t.upper())
    return list(dict.fromkeys(out))


def _tags(prefix: str, techniques: list[str], *extra: str | None) -> list[str]:
    return list(
        dict.fromkeys(
            ["trend-vision-one", prefix, *[f"attack.{t.lower()}" for t in techniques], *[e for e in extra if e]]
        )
    )[:20]


def _one_ip(value: Any) -> str | None:
    ips = ip_list(value)
    return ips[0] if ips else None


def _host(name: Any, ips: Any) -> dict[str, Any] | None:
    n, addrs = clip(name), ip_list(ips)
    return {"hostname": n, "ip": addrs} if n or addrs else None


# ---- alerts ------------------------------------------------------------------------------------------
def _entity_value(e: dict[str, Any]) -> tuple[str | None, list[str]]:
    v = e.get("entityValue")
    if isinstance(v, dict):
        return clip(v.get("name")), ip_list(v.get("ips"))
    return clip(v), []


def _alerts(raw: dict[str, Any]) -> list[EventIn]:
    alert_id = text(raw.get("id"))
    if not alert_id:
        raise NormalizationError("id: missing")
    scope = obj(raw.get("impactScope"))
    host_name: str | None = None
    host_ips: list[str] = []
    account: str | None = None
    for e in scope.get("entities", []) if isinstance(scope.get("entities"), list) else []:
        if not isinstance(e, dict):
            continue
        kind = (text(e.get("entityType")) or "").lower()
        if kind == "host" and host_name is None:
            host_name, host_ips = _entity_value(e)
        elif kind == "account" and account is None:
            account, _ = _entity_value(e)
    techniques: list[str] = []
    for rule in raw.get("matchedRules", []) if isinstance(raw.get("matchedRules"), list) else []:
        for f in obj(rule).get("matchedFilters", []) if isinstance(obj(rule).get("matchedFilters"), list) else []:
            techniques += _techniques(obj(f).get("mitreTechniqueIds"))
    techniques = list(dict.fromkeys(techniques))
    sev = (text(raw.get("severity")) or "").lower()
    score = integer(raw.get("score"))
    model = clip(raw.get("model")) or "workbench alert"
    return finish(
        {
            "timestamp": _ts(raw.get("createdDateTime"), raw.get("updatedDateTime")),
            "source": "trend_vision_one",
            "event_type": "alert",
            "action": clip(model, 64),
            "severity": SEVERITY.get(sev, 0) if score is None else max(0, min(100, score)),
            "original_id": alert_id,
            "message": clip(f"Workbench alert: {model}", 1024),
            "host": _host(host_name, host_ips),
            "user": {"name": account} if account else None,
            "tags": _tags("workbench", techniques, sev or None),
            "labels": labels(
                alert_id=alert_id,
                status=raw.get("status"),
                investigation_status=raw.get("investigationStatus"),
                provider=raw.get("alertProvider"),
                incident_id=raw.get("incidentId"),
                model_type=raw.get("modelType"),
            ),
            "raw": raw,
        }
    )


# ---- OAT ---------------------------------------------------------------------------------------------
def _oat(raw: dict[str, Any]) -> list[EventIn]:
    uuid_ = text(raw.get("uuid"))
    if not uuid_:
        raise NormalizationError("uuid: missing")
    d = obj(raw.get("detail"))
    filters = (
        [obj(f) for f in raw.get("filters", []) if isinstance(f, dict)] if isinstance(raw.get("filters"), list) else []
    )
    techniques = _techniques(*[f.get("mitreTechniqueIds") for f in filters])
    risks = [(text(f.get("riskLevel")) or "").lower() for f in filters]
    sev = max((SEVERITY.get(r, 0) for r in risks), default=0)
    names = ", ".join(n for n in (clip(f.get("name"), 80) for f in filters[:3]) if n)
    return finish(
        {
            "timestamp": _ts(raw.get("detectedDateTime"), d.get("eventTime")),
            "source": "trend_vision_one",
            "event_type": "alert",
            "action": clip(names or "oat detection", 64),
            "severity": sev,
            "original_id": uuid_,
            "message": clip(f"Observed attack technique: {names}" if names else "Observed attack technique", 1024),
            "host": _host(d.get("endpointHostName"), d.get("endpointIp")),
            "process": {
                "name": clip(d.get("processName")),
                "command_line": text(d.get("processCmd")),
                "executable": clip(d.get("processFilePath"), 1024),
                "pid": integer(d.get("processPid")),
            },
            "tags": _tags("oat", techniques, *[r or None for r in dict.fromkeys(risks)]),
            "labels": labels(
                filter_ids=",".join(str(f.get("id")) for f in filters[:5] if f.get("id")),
                source=raw.get("source"),
                object_path=d.get("objectFilePath"),
            ),
            "raw": raw,
        }
    )


# ---- endpoint activity -------------------------------------------------------------------------------
_PROTO = {"6": "tcp", "17": "udp"}


def _actor(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": clip(raw.get("processName")),
        "executable": clip(raw.get("processFilePath"), 1024),
        "command_line": text(raw.get("processCmd")),
        "pid": integer(raw.get("processPid")),
        "hash": hashes(raw.get("processFileHashMd5"), raw.get("processFileHashSha1"), raw.get("processFileHashSha256")),
    }


def _endpoint_activity(raw: dict[str, Any]) -> list[EventIn]:
    uuid_ = text(raw.get("uuid"))
    if not uuid_:
        raise NormalizationError("uuid: missing")
    event_id, sub = text(raw.get("eventId")) or "", text(raw.get("eventSubId")) or ""
    logon = _first(raw.get("logonUser"))
    user_name = clip(raw.get("processUser")) or logon
    doc: dict[str, Any] = {
        "timestamp": _ts(raw.get("eventTimeDT"), raw.get("eventTime")),
        "source": "trend_vision_one",
        "original_id": uuid_,
        "host": _host(raw.get("endpointHostName"), raw.get("endpointIp")),
        "user": {"name": user_name, "domain": clip(raw.get("userDomain"))} if user_name else None,
        "tags": ["trend-vision-one", "endpoint-activity"],
        "labels": labels(
            event_id=event_id,
            event_sub_id=sub,
            product=raw.get("pname"),
            os=raw.get("osName"),
            endpoint_guid=raw.get("endpointGuid"),
        ),
        "raw": raw,
    }
    if event_id == "1":  # process created: `object*` is the new process, `process*` its creator
        doc |= {
            "event_type": "process_creation",
            "action": "process_create",
            "process": {
                "name": clip(raw.get("objectName")),
                "executable": clip(raw.get("objectFilePath"), 1024),
                "command_line": text(raw.get("objectCmd")),
                "pid": integer(raw.get("objectPid")),
                "hash": hashes(
                    raw.get("objectFileHashMd5"), raw.get("objectFileHashSha1"), raw.get("objectFileHashSha256")
                ),
                "parent": {
                    "name": clip(raw.get("processName")),
                    "command_line": text(raw.get("processCmd")),
                    "pid": integer(raw.get("processPid")),
                },
            },
        }
        doc["user"] = (
            {"name": clip(raw.get("objectUser")) or user_name, "domain": clip(raw.get("userDomain"))}
            if (raw.get("objectUser") or user_name)
            else None
        )
    elif event_id == "2":
        path = clip(raw.get("objectFilePath"), 1024)
        doc |= {
            "event_type": "file_event",
            "action": "file_activity",
            "process": _actor(raw),
            "file": {
                "path": path,
                "name": path.replace("\\", "/").rsplit("/", 1)[-1][:256] if path else None,
                "hash": hashes(
                    raw.get("objectFileHashMd5"), raw.get("objectFileHashSha1"), raw.get("objectFileHashSha256")
                ),
            },
        }
    elif event_id == "3":
        proto = _PROTO.get(text(raw.get("proto")) or "")
        doc |= {
            "event_type": "network_connection",
            "action": "network_connect",
            "process": _actor(raw),
            "network": {
                "src_ip": _one_ip(raw.get("src")),
                "src_port": integer(raw.get("spt")),
                "dst_ip": _one_ip(raw.get("dst")),
                "dst_port": integer(raw.get("dpt")),
                "protocol": proto,
            },
        }
    elif event_id == "4":
        doc |= {
            "event_type": "dns_query",
            "action": "dns_query",
            "process": _actor(raw),
            "dns": {"question": clip(raw.get("hostName")), "answers": ip_list(raw.get("objectIps"), 32)},
        }
    else:
        doc |= {"event_type": "other", "action": f"trend_event_{event_id}_{sub}"[:64], "process": _actor(raw)}
    return finish(doc)


# ---- product detections ------------------------------------------------------------------------------
def _detections(raw: dict[str, Any]) -> list[EventIn]:
    uuid_ = text(raw.get("uuid"))
    if not uuid_:
        raise NormalizationError("uuid: missing")
    name = clip(raw.get("eventName")) or "detection"
    rule = clip(raw.get("ruleName"))
    return finish(
        {
            "timestamp": _ts(raw.get("eventTimeDT"), raw.get("eventTime")),
            "source": "trend_vision_one",
            "event_type": "alert",
            "action": clip(name, 64),
            "original_id": uuid_,
            "message": clip(f"{name}: {rule}" if rule else name, 1024),
            "host": _host(raw.get("endpointHostName"), raw.get("endpointIp")),
            "user": {"name": clip(raw.get("suid")) or clip(raw.get("objectUser"))}
            if (raw.get("suid") or raw.get("objectUser"))
            else None,
            "process": {"command_line": text(raw.get("processCmd"))},
            "file": {
                "path": clip(raw.get("filePath"), 1024),
                "name": _first(raw.get("fileName")),
                "hash": hashes(sha256=raw.get("fileHashSha256")),
            },
            "tags": _tags("product-detection", [], clip(raw.get("pname"), 40), (rule or "")[:40] or None),
            "labels": labels(
                event_name=name,
                event_sub_name=raw.get("eventSubName"),
                rule_name=rule,
                rule_type=raw.get("ruleType"),
                policy=raw.get("policyName"),
                product=raw.get("pname"),
                action_taken=_first(raw.get("act")),
            ),
            "raw": raw,
        }
    )


_NORMALIZERS = {"alerts": _alerts, "oat": _oat, "endpoint_activity": _endpoint_activity, "detections": _detections}
