"""Trend Micro Vision One (XDR) pull connector. One data source = one dataset:

  alerts             Workbench alerts          GET /v3.0/workbench/alerts          (window on updatedDateTime)
  oat                Observed Attack Techniques GET /v3.0/oat/detections            (window on ingestion time)
  endpoint_activity  Endpoint telemetry        GET /v3.0/search/endpointActivities (TMV1-Query header)
  detections         Product security events   GET /v3.0/search/detections         (TMV1-Query header)
  identity_activity  Entra ID sign-ins/audit   GET /v3.0/search/identityActivities
  email_activity / mobile_activity / network_activity / cloud_activity / container_activity   GET /v3.0/search/<name>Activities
  audit_logs         Vision One console audit  GET /v3.0/audit/logs                  (page size must be 50/100/200)
  response_tasks     Response-action history   GET /v3.0/response/tasks              (snapshot: no time window)

Read-only. Pagination follows the server-supplied `nextLink` (never rebuilt). Windows are read oldest-first; only whole windows
are emitted so the scheduler watermark can advance safely. The API key is a secret (`api_key`); only the region (a fixed set of
Trend hosts) is configurable, never a free-form URL."""

import time
from collections.abc import AsyncIterator, Callable
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
Dataset = Literal[
    "alerts",
    "oat",
    "endpoint_activity",
    "detections",
    "identity_activity",
    "email_activity",
    "mobile_activity",
    "network_activity",
    "cloud_activity",
    "container_activity",
    "audit_logs",
    "response_tasks",
]
SEARCH_DATASETS = {
    "endpoint_activity",
    "detections",
    "identity_activity",
    "email_activity",
    "mobile_activity",
    "network_activity",
    "cloud_activity",
    "container_activity",
}
PATHS: dict[str, str] = {
    "alerts": "/v3.0/workbench/alerts",
    "oat": "/v3.0/oat/detections",
    "endpoint_activity": "/v3.0/search/endpointActivities",
    "detections": "/v3.0/search/detections",
    "identity_activity": "/v3.0/search/identityActivities",
    "email_activity": "/v3.0/search/emailActivities",
    "mobile_activity": "/v3.0/search/mobileActivities",
    "network_activity": "/v3.0/search/networkActivities",
    "cloud_activity": "/v3.0/search/cloudActivities",
    "container_activity": "/v3.0/search/containerActivities",
    "audit_logs": "/v3.0/audit/logs",
    "response_tasks": "/v3.0/response/tasks",
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
    window_minutes: int | None = Field(
        default=None, ge=1, le=240, description="Default: 3 for endpoint_activity (very high volume), 15 otherwise"
    )
    overlap_minutes: int = Field(default=10, ge=0, le=60)
    filter: str | None = Field(
        default=None,
        max_length=1000,
        description="TMV1-Filter for alerts / oat (Trend filter syntax), e.g. to keep only high risk",
    )
    page_size: int | None = Field(
        default=None,
        ge=1,
        le=500,
        description="Default: the largest the dataset allows (500 for search feeds, 200 otherwise)",
    )
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

    @property
    def _window_minutes(self) -> int:
        return self.cfg.window_minutes or (3 if self.cfg.dataset == "endpoint_activity" else 15)

    @property
    def _top(self) -> int:
        cap = 500 if self.cfg.dataset in SEARCH_DATASETS else 200
        return min(self.cfg.page_size or cap, cap)

    def _headers(self) -> dict[str, str]:
        key = self.secrets.get("api_key")
        if not key:
            raise SourceError("no API key configured for this data source")
        h = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        if self.cfg.dataset in SEARCH_DATASETS:
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
                "top": self._top,
            }
        if c.dataset == "oat":
            return {"ingestedStartDateTime": s, "ingestedEndDateTime": e, "top": self._top}
        if c.dataset == "audit_logs":
            return {
                "startDateTime": s,
                "endDateTime": e,
                "top": 50 if self._top < 100 else 100 if self._top < 200 else 200,
            }
        if c.dataset == "response_tasks":
            return {}
        return {"startDateTime": s, "endDateTime": e, "top": self._top}

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

    async def search_query(
        self, query: str, start: datetime, end: datetime, *, max_events: int = 3000, deadline: float | None = None
    ) -> tuple[list[dict[str, Any]], bool]:
        """Run an ad-hoc TMV1-Query over [start, end) on this source's dataset (hunting, not collection). Follows `nextLink` until the
        search reports completion; returns (raw records, truncated)."""
        if self.cfg.dataset not in SEARCH_DATASETS:
            raise SourceError(f"dataset '{self.cfg.dataset}' cannot be searched by query")
        key = self.secrets.get("api_key")
        if not key:
            raise SourceError("no API key configured for this data source")
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/json", "TMV1-Query": query}
        url: str | None = REGIONS[self.cfg.region] + PATHS[self.cfg.dataset]
        params: dict[str, Any] | None = {"startDateTime": _iso(start), "endDateTime": _iso(end), "top": self._top}
        out: list[dict[str, Any]] = []
        for _ in range(200):
            if not url:
                return out, False
            if deadline is not None and time.monotonic() > deadline:
                return out, True
            body = await request_json("GET", url, headers=headers, params=params, timeout_s=self.cfg.timeout_s)
            if not isinstance(body, dict):
                raise SourceError("unexpected response shape")
            out.extend(i for i in body.get("items", []) if isinstance(i, dict))
            nxt = body.get("nextLink")
            url, params = (nxt if isinstance(nxt, str) else None), None
            if len(out) >= max_events:
                return out[:max_events], url is not None
        return out, True

    async def collect(self, since: datetime | None = None, limit: int = 20_000) -> AsyncIterator[dict[str, Any]]:
        c = self.cfg
        now = datetime.now(UTC).replace(microsecond=0)
        if (
            c.dataset == "response_tasks"
        ):  # no time window: read the whole (small) task list; ids make re-reads idempotent
            for rec in await self._read(now, now, time.monotonic() + c.time_budget_s):
                yield rec
            self.watermark = now
            return
        end_cap = now - timedelta(minutes=1)
        start = (
            (since - timedelta(minutes=c.overlap_minutes)) if since else now - timedelta(hours=c.initial_lookback_hours)
        )
        step = timedelta(minutes=self._window_minutes)
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
        result: list[EventIn] = _NORMALIZERS[self.cfg.dataset](raw)
        return result


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


def _base(path: Any) -> str | None:
    """File name of a path. Vision One reports `processName` / `objectName` as full paths, but the canonical `process.name` is the file name
    (so name-based IOAs and detection rules match); the full path belongs in `executable`."""
    p = clip(path, 1024)
    if not p:
        return None
    return clip(p.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1])


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
                "name": _base(d.get("processName") or d.get("processFilePath")),
                "command_line": text(d.get("processCmd")),
                "executable": clip(d.get("processFilePath") or d.get("processName"), 1024),
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
        "name": _base(raw.get("processName") or raw.get("processFilePath")),
        "executable": clip(raw.get("processFilePath") or raw.get("processName"), 1024),
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
                "name": _base(raw.get("objectName") or raw.get("objectFilePath")),
                "executable": clip(raw.get("objectFilePath") or raw.get("objectName"), 1024),
                "command_line": text(raw.get("objectCmd")),
                "pid": integer(raw.get("objectPid")),
                "hash": hashes(
                    raw.get("objectFileHashMd5"), raw.get("objectFileHashSha1"), raw.get("objectFileHashSha256")
                ),
                "parent": {
                    "name": _base(raw.get("processName") or raw.get("processFilePath")),
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


def _outcome(value: Any) -> str:
    v = (text(value) or "").lower()
    if v in ("success", "successful", "succeeded", "ok", "allowed") or v.startswith("success"):
        return "success"
    if v and any(k in v for k in ("fail", "denied", "error", "block", "interrupt", "reject")):
        return "failure"
    return "unknown"


def _identity(raw: dict[str, Any]) -> list[EventIn]:
    uuid_ = text(raw.get("uuid"))
    if not uuid_:
        raise NormalizationError("uuid: missing")
    name = clip(raw.get("eventName")) or "identity event"
    when = _ts(raw.get("eventTimeDT"), raw.get("eventTime"))
    if name == "IDENTITY_IAM_SIGN_INS" or raw.get("principalName"):  # a sign-in
        principal = clip(raw.get("principalName")) or clip(raw.get("userDisplayName"))
        domain = principal.split("@", 1)[1] if principal and "@" in principal else None
        risk = clip(raw.get("riskLevelDuringSignIn")) or clip(raw.get("riskLevelAggregated"))
        return finish(
            {
                "timestamp": when,
                "source": "trend_vision_one",
                "event_type": "authentication",
                "action": "sign_in",
                "outcome": _outcome(raw.get("status")),
                "original_id": uuid_,
                "message": clip(
                    f"Sign-in {clip(raw.get('status')) or ''} for {principal or 'unknown user'} to {clip(raw.get('application')) or 'application'}",
                    1024,
                ),
                "user": {"id": clip(raw.get("userId")), "name": principal, "domain": domain} if principal else None,
                "auth": {
                    "method": clip(raw.get("authenticationProtocol"), 64),
                    "source_ip": _one_ip(raw.get("ipAddress")),
                },
                "tags": _tags(
                    "identity",
                    [],
                    "entra-id",
                    "sign-in",
                    (f"risk-{risk.lower()}" if risk and risk.lower() not in ("none", "hidden") else None),
                ),
                "labels": labels(
                    application=raw.get("application"),
                    client_app=raw.get("clientApp"),
                    client_os=raw.get("clientOS"),
                    client_browser=raw.get("clientBrowser"),
                    country=raw.get("locationCountry"),
                    city=raw.get("locationCity"),
                    status_reason=raw.get("statusReason"),
                    risk_state=raw.get("riskState"),
                    risk_level=risk,
                    conditional_access=raw.get("conditionalAccessStatus"),
                    user_type=raw.get("userType"),
                    resource=raw.get("targetResourceDisplayName"),
                ),
                "raw": {k: v for k, v in raw.items() if k != "rawDataStr"},
            }
        )
    targets = (
        [obj(t) for t in raw.get("targetResources", []) if isinstance(t, dict)]
        if isinstance(raw.get("targetResources"), list)
        else []
    )
    first = targets[0] if targets else {}
    action = clip(raw.get("actionName")) or name
    return finish(
        {
            "timestamp": when,
            "source": "trend_vision_one",
            "event_type": "other",
            "action": clip(action, 64),
            "outcome": _outcome(raw.get("result")),
            "original_id": uuid_,
            "message": clip(
                f"{action} on {target_name}" if (target_name := clip(first.get("displayName"), 120)) else action,
                1024,
            ),
            "tags": _tags(
                "identity", [], "entra-id", "directory-audit", (text(raw.get("eventCategory")) or "").lower() or None
            ),
            "labels": labels(
                category=raw.get("eventCategory"),
                operation_type=raw.get("operationType"),
                service=raw.get("loggedByService"),
                initiated_by_app=raw.get("initiatedByAppDisplayName"),
                result_reason=raw.get("resultReason"),
                correlation_id=raw.get("correlationId"),
                target=first.get("displayName"),
                target_type=first.get("type"),
            ),
            "raw": raw,
        }
    )


def _activity(kind: str) -> Callable[[dict[str, Any]], list[EventIn]]:
    """Email / mobile / network / cloud / container activity. Best-effort mapping (these feeds are empty or unavailable on the
    tested tenant): network fields become a connection, everything else is kept in `raw` and in labels."""

    def normalize(raw: dict[str, Any]) -> list[EventIn]:
        uuid_ = text(raw.get("uuid"))
        if not uuid_:
            raise NormalizationError("uuid: missing")
        src, dst = (
            _one_ip(raw.get("src") or raw.get("srcIp") or raw.get("mailSenderIp")),
            _one_ip(raw.get("dst") or raw.get("dstIp")),
        )
        net = (
            {
                "src_ip": src,
                "src_port": integer(raw.get("spt")),
                "dst_ip": dst,
                "dst_port": integer(raw.get("dpt")),
                "protocol": _PROTO.get(text(raw.get("proto")) or ""),
            }
            if (src or dst)
            else None
        )
        subject = clip(raw.get("mailMsgSubject"), 300)
        return finish(
            {
                "timestamp": _ts(raw.get("eventTimeDT"), raw.get("eventTime")),
                "source": "trend_vision_one",
                "event_type": "network_connection" if (net and kind == "network") else "other",
                "action": clip(raw.get("eventName") or raw.get("eventSubName") or f"{kind}_activity", 64),
                "original_id": uuid_,
                "message": clip(f"{kind} activity: {subject}" if subject else f"{kind} activity", 1024),
                "host": _host(raw.get("endpointHostName") or raw.get("deviceName"), raw.get("endpointIp")),
                "user": {"name": _first(raw.get("mailFromAddresses")) or clip(raw.get("userName"))}
                if (raw.get("mailFromAddresses") or raw.get("userName"))
                else None,
                "network": net,
                "tags": _tags(f"{kind}-activity", []),
                "labels": labels(
                    event_id=raw.get("eventId"),
                    product=raw.get("pname"),
                    recipients=",".join(str(x) for x in raw.get("mailToAddresses", [])[:5])
                    if isinstance(raw.get("mailToAddresses"), list)
                    else None,
                    message_id=raw.get("mailMsgId"),
                ),
                "raw": raw,
            }
        )

    return normalize


# ---- console audit log + response tasks --------------------------------------------------------------
def _audit_logs(raw: dict[str, Any]) -> list[EventIn]:
    import hashlib

    when = _ts(raw.get("loggedDateTime"), raw.get("ingestedDateTime"))
    activity = clip(raw.get("activity")) or "audit event"
    # The API gives audit entries no id: derive a stable one from the entry's own content.
    ident = hashlib.sha256(
        "|".join(
            str(raw.get(k)) for k in ("loggedDateTime", "loggedUserId", "category", "activity", "details", "result")
        ).encode()
    ).hexdigest()[:32]
    return finish(
        {
            "timestamp": when,
            "source": "trend_vision_one",
            "event_type": "other",
            "action": clip(activity, 64),
            "outcome": _outcome(raw.get("result")),
            "original_id": ident,
            "message": clip(f"{activity}: {text(raw.get('details')) or ''}".rstrip(": "), 1024),
            "user": {
                "id": clip(raw.get("loggedUserId")),
                "name": clip(raw.get("loggedUser")) or clip(raw.get("loggedUserMailAddress")),
            }
            if (raw.get("loggedUser") or raw.get("loggedUserMailAddress"))
            else None,
            "tags": _tags("console-audit", [], (text(raw.get("category")) or "").lower() or None),
            "labels": labels(
                category=raw.get("category"),
                access_type=raw.get("accessType"),
                role=raw.get("loggedRole"),
                result=raw.get("result"),
            ),
            "raw": raw,
        }
    )


def _response_tasks(raw: dict[str, Any]) -> list[EventIn]:
    tid = text(raw.get("id"))
    if not tid:
        raise NormalizationError("id: missing")
    status = clip(raw.get("status")) or "unknown"
    action = clip(raw.get("action")) or "response task"
    return finish(
        {
            "timestamp": _ts(raw.get("lastActionDateTime"), raw.get("createdDateTime")),
            "source": "trend_vision_one",
            "event_type": "other",
            "action": clip(f"response_{action}", 64),
            # status is part of the id so each state change of a task is its own event, but re-reads stay idempotent
            "original_id": f"{tid}:{status}",
            "message": clip(
                f"Response action '{action}' {status}"
                + (f" on {clip(raw.get('endpointName'), 120)}" if raw.get("endpointName") else ""),
                1024,
            ),
            "host": _host(raw.get("endpointName"), None),
            "user": {"name": clip(raw.get("account"))} if raw.get("account") else None,
            "tags": _tags("response-action", [], status.lower()),
            "labels": labels(
                task_id=tid,
                status=status,
                action=action,
                agent_guid=raw.get("agentGuid"),
                description=raw.get("description"),
            ),
            "raw": raw,
        }
    )


_NORMALIZERS = {
    "alerts": _alerts,
    "oat": _oat,
    "endpoint_activity": _endpoint_activity,
    "detections": _detections,
    "identity_activity": _identity,
    "email_activity": _activity("email"),
    "mobile_activity": _activity("mobile"),
    "network_activity": _activity("network"),
    "cloud_activity": _activity("cloud"),
    "container_activity": _activity("container"),
    "audit_logs": _audit_logs,
    "response_tasks": _response_tasks,
}
