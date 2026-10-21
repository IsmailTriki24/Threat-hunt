"""LogRhythm SIEM connector. Searches go through the Web Console's own socket.io service (`logrhythm_console`, ADR 0025), the same way the
console's Search tool asks: one task per search, the logs come back with their raw text. The `:8501` Search API is no longer used.

Per window: create a console search task over [start, end], read its logs, remove the task. A window that hits the 30,000-log cap is split in
half and retried, so a window is only ever emitted whole and the scheduler's watermark is always safe to advance.

Time: LogRhythm searches by true (UTC) time but reports `logDate` shifted by the console's UTC offset (observed: +1h for this deployment).
`date_shift_hours` corrects the event timestamp only (true time = logDate + shift); search windows are sent unshifted so the collection
watermark and the event times agree."""

import json
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from app.connectors._http import SourceError
from app.connectors._util import clip, finish, integer, ip_list, labels, text, valid_ip
from app.connectors.base import ConnectionResult, Connector, ConnectorHealth, NormalizationError
from app.connectors.logrhythm_console import BudgetExceeded, ConsoleClient, ConsoleSettings, client_for
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

    console_url: HttpUrl | None = Field(
        default=None,
        description="LogRhythm Web Console, e.g. https://10.0.0.5:8443. Every search goes through its socket service; the credentials are the secrets `username` and `password` of a dedicated read-only console account",
    )
    console_verify_tls: bool | None = Field(
        default=None, description="Verify the console certificate (default: verify_tls)"
    )
    console_ca_pem: str | None = Field(
        default=None,
        max_length=20_000,
        description="PEM CA bundle (or the self-signed certificate itself) of the CONSOLE (default: ca_pem)",
    )
    console_tls_server_name: str | None = Field(
        default=None,
        max_length=255,
        pattern=r"^[A-Za-z0-9.-]+$",
        description="Hostname the console certificate must match, when console_url is an IP (default: tls_server_name)",
    )
    console_parallel: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Searches run at the same time on this console (it serves a handful of simultaneous searches)",
    )
    console_poll_s: float = Field(
        default=1.0, ge=0.2, le=10, description="Seconds between checks of a running console search"
    )
    console_task_timeout_s: int = Field(
        default=240, ge=20, le=900, description="Longest a console search may run before it is given up"
    )
    base_url: HttpUrl | None = Field(
        default=None,
        description="Legacy Search/Alarm/Admin API gateway (e.g. https://10.0.0.5:8501). Searches no longer use it; only the alarm feed and the entity/source-type pickers still do, with the secret `token`",
    )
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
    ioc_filter_templates: dict[str, dict[str, Any]] | None = Field(
        default=None,
        description='Per IOC type (ip|domain|url|sha256|sha1|md5|email), a queryFilter captured from the Web Console with the searched value replaced by the string "$IOC". Enables IOC hunts to search LogRhythm itself instead of only ingested data',
    )
    siem_search: bool = Field(
        default=True,
        description="Let every interactive search (Events, hunts, threat map) also query the whole SIEM live for the indicators in the query",
    )
    ioc_search: bool = Field(
        default=True,
        description="Let IOC hunts search the whole SIEM with the built-in, verified filters (no template needed)",
    )
    ioc_search_max: int = Field(
        default=200,
        ge=1,
        le=2000,
        description="Most indicators one hunt sends to LogRhythm (each batch of 25 costs about a minute over 7 days)",
    )
    ioc_batch: int = Field(
        default=100,
        ge=1,
        le=100,
        description="Indicators of one type combined into a single search (100 verified as fast as 25)",
    )
    url_pattern_max: int = Field(
        default=10,
        ge=0,
        le=100,
        description="Most exact URL-pattern searches per hunt (LogRhythm allows one URL pattern per search)",
    )
    ioc_sweep: bool = Field(
        default=True,
        description="Sweep the whole SIEM every few minutes for the validated indicators and keep only the logs that contain one (replaces bulk collection)",
    )
    sweep_lag_minutes: int = Field(
        default=3, ge=0, le=60, description="Only search logs older than this, so the newest ones have landed"
    )
    sweep_overlap_minutes: int = Field(
        default=2, ge=0, le=30, description="Each sweep window starts this much earlier, to catch logs that arrive late"
    )
    sweep_max_window_minutes: int = Field(
        default=60, ge=5, le=240, description="Longest time span one sweep window covers when catching up"
    )
    siem_behaviours: bool = Field(
        default=True,
        description="Also sweep this SIEM for the built-in behaviours (password spraying, brute force, account and audit changes, web attack patterns) and raise alerts",
    )
    siem_behaviours_disabled: list[str] = Field(
        default_factory=list, max_length=50, description="Keys of built-in behaviours not to run on this source"
    )
    sweep_budget_s: int = Field(
        default=240, ge=20, le=600, description="Most seconds one sweep tick spends on this source"
    )
    sweep_url_patterns: int = Field(
        default=5,
        ge=0,
        le=100,
        description="Exact-URL pattern searches one sweep tick may spend (each costs a search; every URL is already searched through its host)",
    )
    sweep_hot_size: int = Field(
        default=150,
        ge=0,
        le=1000,
        description="Indicators in the fast lane: the most urgent ones are swept on their own, close to real time (0 switches the fast lane off). The full lane still covers every indicator",
    )
    sweep_hot_ioas: int = Field(
        default=5, ge=0, le=50, description="Most severe behaviours of validated threats that also join the fast lane"
    )
    sweep_parallel: int = Field(
        default=2,
        ge=1,
        le=6,
        description="Indicator batches searched at the same time in this SIEM (be gentle with a production SIEM)",
    )
    collect_vendor_message_ids: list[str] | None = Field(
        default=None,
        max_length=200,
        description="Keep only collected logs whose vendor message id (e.g. the Windows event id) is in this list. Cuts what is stored; the SIEM is still read. None keeps everything",
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
        if self.ioc_filter_templates is not None:
            if len(json.dumps(self.ioc_filter_templates)) > 40_000:
                raise ValueError("ioc_filter_templates too large")
            for k, tpl in self.ioc_filter_templates.items():
                if k not in ("ip", "domain", "url", "sha256", "sha1", "md5", "email") or "$IOC" not in json.dumps(tpl):
                    raise ValueError(
                        f"ioc_filter_templates[{k!r}] must be a known IOC type and contain the $IOC placeholder"
                    )
        return self


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class LogRhythmConnector(Connector):
    connector_type = "logrhythm"
    display_name = "LogRhythm SIEM"
    supports_collect = True
    config_model = LogRhythmConfig
    collect_limit = 20_000

    _filter_override: dict[str, Any] | None = None
    found: int = 0  # results the SIEM reported across this connector's searches
    found_at_least: bool = False  # a search stopped early or hit the cap, so `found` is a floor, not a count
    _deadline: float | None = (
        None  # time.monotonic() by which the caller's budget is used up; searches past it raise BudgetExceeded
    )
    capped: bool = False  # the last interactive search stopped at its log cap

    @property
    def cfg(self) -> LogRhythmConfig:
        return self.config  # type: ignore[return-value]

    # ---- transport: the Web Console's socket service (logrhythm_console) -----------------------------
    def _console(self) -> ConsoleClient:
        cfg = self.cfg
        user, password = self.secrets.get("username"), self.secrets.get("password")
        if cfg.console_url is None or not user or not password:
            raise SourceError(
                "the LogRhythm console is not configured: set console_url and the username and password secrets of a read-only console account"
            )
        return client_for(
            ConsoleSettings(
                url=str(cfg.console_url),
                username=user,
                password=password,
                verify_tls=cfg.verify_tls if cfg.console_verify_tls is None else cfg.console_verify_tls,
                ca_pem=cfg.console_ca_pem or cfg.ca_pem,
                tls_server_name=cfg.console_tls_server_name or cfg.tls_server_name,
                query_timeout_min=cfg.query_timeout_min,
                max_results=MAX_MSGS,
                parallel=cfg.console_parallel,
                poll_s=cfg.console_poll_s,
                task_timeout_s=float(cfg.console_task_timeout_s),
                timeout_s=cfg.timeout_s,
            )
        )

    def _query_filter(self) -> dict[str, Any]:
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
        return (
            self._filter_override
            or self.cfg.query_filter
            or {
                "msgFilterType": 2,
                "filterGroup": {
                    "filterItemType": 1,
                    "filterGroupOperator": 0,
                    "filterMode": 1,
                    "filterType": 1000,
                    "filterItems": items,
                },
            }
        )

    async def _search_window(
        self, start: datetime, end: datetime, budget: list[int] | None = None, max_logs: int | None = None
    ) -> list[dict[str, Any]]:
        """All logs of a window. With `max_logs` (interactive search) only the newest that many are read and `self.capped` is set when there
        were more."""
        budget = budget if budget is not None else [MAX_SEARCHES_PER_WINDOW]
        if budget[0] <= 0:
            raise SourceError(
                "too many searches needed for one window; narrow this source with hostname or query_filter"
            )
        budget[0] -= 1
        if self._deadline is not None and time.monotonic() > self._deadline:
            raise BudgetExceeded("the time budget ran out before this search could start")
        out = await self._console().run_search(
            self._query_filter(), start, end, max_logs=max_logs, deadline=self._deadline
        )
        if max_logs is not None and out.logs and out.capped:
            self.capped = True
            self.found += out.total
            self.found_at_least = True
            return out.logs[:max_logs]
        status = out.status
        if "Max Results" in status or "Failed" in status or "Cancel" in status:
            # Too many logs for one search (cap) or the search failed under load: retry the two halves.
            if end - start <= MIN_WINDOW:
                raise SourceError(
                    f"LogRhythm returned '{status}' for a 1-minute window (over {MAX_MSGS} logs/minute?). "
                    "Narrow this source with hostname or query_filter"
                )
            mid = start + (end - start) / 2
            return [
                *await self._search_window(start, mid, budget, max_logs),
                *await self._search_window(mid, end, budget, max_logs),
            ]
        self.found += len(out.logs)
        return out.logs

    # ---- Connector API ---------------------------------------------------------------------------
    async def test_connection(self) -> ConnectionResult:
        try:
            detail = await self._console().ping()
        except SourceError as exc:
            return ConnectionResult(ok=False, detail=str(exc)[:200])
        return ConnectionResult(ok=True, detail=detail)

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
        keep = {str(i).strip() for i in cfg.collect_vendor_message_ids or [] if str(i).strip()}
        emitted = 0
        t = start
        while t < end_cap:
            e = min(t + step, end_cap)
            logs = await self._search_window(t, e)
            if keep:
                logs = [r for r in logs if text(r.get("vendorMessageId")) in keep]
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
        "message": clip(
            f"{name}: {text(raw.get('vendorInfo'))}"
            if text(raw.get("vendorInfo"))
            else f"{text(raw.get('command')) or ''} {text(raw.get('url'))}".strip()
            if text(raw.get("url"))
            else name,
            1024,
        ),
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
            url=raw.get("url"),
            http_status=raw.get("responseCode") if text(raw.get("url")) else None,
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
    if text(
        raw.get("process")
    ):  # also on authentication logs, where LogRhythm keeps e.g. the Kerberos service (krbtgt) here
        proc: dict[str, Any] = {"name": clip(re.split(r"[\\/]", text(raw.get("process")) or "")[-1])}
        if text(raw.get("command")):
            proc["command_line"] = clip(raw.get("command"), 8192)
        if text(raw.get("parentProcessName")):
            proc["parent"] = {"name": clip(raw.get("parentProcessName"))}
        doc["process"] = proc
    return finish(doc)


def _port(value: Any) -> int | None:
    p = integer(value)
    return p if p is not None and 0 <= p <= 65535 else None


def _substitute(node: Any, value: str) -> Any:
    if isinstance(node, str):
        return node.replace("$IOC", value)
    if isinstance(node, list):
        return [_substitute(n, value) for n in node]
    if isinstance(node, dict):
        return {k: _substitute(v, value) for k, v in node.items()}
    return node


async def search_ioc(
    connector: "LogRhythmConnector", ioc_type: str, value: str, start: datetime, end: datetime
) -> list[dict[str, Any]]:
    """Search LogRhythm itself for one indicator using the source's captured filter template for that type."""
    templates = connector.cfg.ioc_filter_templates or {}
    tpl = templates.get(ioc_type)
    if tpl is None:
        raise SourceError(f"no ioc_filter_templates entry for '{ioc_type}'")
    connector._filter_override = _substitute(tpl, value)
    try:
        return await connector._search_window(start, end)
    finally:
        connector._filter_override = None


# ---- IOC filters: verified against a production LogRhythm 7.x Search API (see docs/adr/0015) ------------------------------
# FieldFilterTypeEnum values come from the gateway's own swagger (/lr-search-api/swagger-json). Encodings were confirmed with positive and
# negative controls: an IP is valueType 5 with a PLAIN string (sending it as a string-typed value makes the search fail after ~35 s);
# strings are {matchType, value} with matchType 0 = exact, 1 = SQL pattern; several values in one filter are OR'd; fieldOperator 2 = Or.
FT_IP, FT_HOSTNAME, FT_URL, FT_HASH, FT_SENDER, FT_RECIPIENT = 17, 23, 42, 138, 31, 32
VT_STRING, VT_IP = 4, 5
EXACT, PATTERN = 0, 1


def _scheme_free(url: str) -> str:
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", url, flags=re.I)


def _item(filter_type: int, value_type: int, values: list[Any]) -> dict[str, Any]:
    return {
        "filterItemType": 0,
        "fieldOperator": 0,
        "filterMode": 1,
        "filterType": filter_type,
        "values": [{"filterType": filter_type, "valueType": value_type, "value": v} for v in values],
    }


def _str(v: str, match: int) -> dict[str, Any]:
    return {"matchType": match, "value": v}


def ioc_query_filter(kind: str, values: list[str]) -> dict[str, Any]:
    """A queryFilter finding any of `values` (all of one `kind`) anywhere in the SIEM: items are OR'd inside one group.

    kinds: ip | domain (hostname itself or anything under it) | md5 | sha1 | sha256 | email | url_pattern (exactly ONE value: a group with
    several URL-pattern items makes LogRhythm fail the search, verified on the live API)."""
    vs = list(dict.fromkeys(v for v in values if v))
    if not vs:
        raise ValueError("no values")
    items: list[dict[str, Any]]
    if kind == "ip":
        items = [_item(FT_IP, VT_IP, vs)]
    elif kind == "domain":
        items = [
            _item(FT_HOSTNAME, VT_STRING, [_str(v, EXACT) for v in vs]),  # the host itself
            _item(FT_HOSTNAME, VT_STRING, [_str(f"%.{v}", PATTERN) for v in vs]),  # ... or any host under it
        ]
    elif kind == "hostname":  # exactly this host (as origin or impacted), no subdomain widening
        items = [_item(FT_HOSTNAME, VT_STRING, [_str(v, EXACT) for v in vs])]
    elif kind == "url_pattern":
        if len(vs) != 1:
            raise ValueError("a URL-pattern search takes exactly one value")
        items = [_item(FT_URL, VT_STRING, [_str(f"%{_scheme_free(vs[0])}%", PATTERN)])]
    elif kind in ("md5", "sha1", "sha256"):
        items = [_item(FT_HASH, VT_STRING, [_str(c, EXACT) for v in vs for c in dict.fromkeys((v.lower(), v.upper()))])]
    elif kind == "email":
        items = [
            _item(FT_SENDER, VT_STRING, [_str(v, EXACT) for v in vs]),
            _item(FT_RECIPIENT, VT_STRING, [_str(v, EXACT) for v in vs]),
        ]
    else:
        raise ValueError(f"no LogRhythm filter for '{kind}'")
    return _wrap(items, 2)


def _wrap(items: list[dict[str, Any]], operator: int) -> dict[str, Any]:
    """queryFilter with one inner group whose items are combined with `operator` (1 = And, 2 = Or)."""
    return {
        "msgFilterType": 2,
        "isSavedFilter": False,
        "filterGroup": {
            "filterItemType": 1,
            "fieldOperator": 1,
            "filterMode": 1,
            "filterGroupOperator": 0,
            "filterItems": [{"filterItemType": 1, "fieldOperator": operator, "filterMode": 1, "filterItems": items}],
        },
    }


async def search_ioc_batch(
    connector: "LogRhythmConnector", ioc_type: str, values: list[str], start: datetime, end: datetime
) -> list[dict[str, Any]]:
    """One search for up to `ioc_batch` indicators of one type. A console-captured template (if the source has one for this type) is used for
    single values instead of the built-in filter."""
    templates = connector.cfg.ioc_filter_templates or {}
    out: list[dict[str, Any]] = []
    if ioc_type in templates:
        for v in values:
            out += await search_ioc(connector, ioc_type, v, start, end)
        return out
    connector._filter_override = ioc_query_filter(ioc_type, values)
    try:
        return await connector._search_window(start, end)
    finally:
        connector._filter_override = None


# ---- behaviours (IOAs): a canonical Condition -> LogRhythm searches --------------------------------------------------------
# Only filters that passed positive and negative controls on a production LogRhythm 7.9 (docs/adr/0020) are used: Process 41, Command 112,
# Login 29, VendorMsgID 37, HostName 23, SIP 18 / DIP 19 (IP value type), Hash 138, with exact (0) and SQL-pattern (1) matching. Items of one
# search are AND-ed, which narrows (verified). The search is a SUPERSET of the behaviour: conditions LogRhythm cannot express are dropped from
# it and enforced locally on the returned logs, so a loose search can only cost time, never create a false match.
FT_PROCESS, FT_COMMAND, FT_LOGIN, FT_SIP, FT_DIP, FT_VENDOR_MSG_ID = 41, 112, 29, 18, 19, 37
FT_MESSAGE = 35  # free text over the raw log message (positive/negative controls on prod 2026-10-19: matches 0xC000006A, not a normalized field)
FT_OBJECT, FT_REASON = 34, 149  # verified on production with positive and negative controls (docs/adr/0020)
# Hunting fields verified on production 2026-10-19 (exact value from a real log: every log returned carried it, a nonsense value returned none).
# String-valued (valueType 4): Action, Result, UserAgent, Subject, Policy, ResponseCode, Session, Severity, VendorInfo, ObjectType, Group, Status, Account,
# Domain. Int32-valued (valueType 2; a string value makes the search fail): SPort, DPort, Port, PID, SessionType, Direction, Protocol.
# ThreatName, ThreatId, Application, CVE, ParentProcessName had no value in any log of the window, so they are NOT used (untested).
FT_ACTION, FT_RESULT, FT_USER_AGENT, FT_SUBJECT, FT_POLICY, FT_RESPONSE_CODE, FT_SESSION = (
    154,
    141,
    144,
    33,
    139,
    155,
    40,
)
FT_SEVERITY, FT_VENDOR_INFO, FT_OBJECT_TYPE, FT_GROUP, FT_STATUS, FT_ACCOUNT, FT_DOMAIN = 110, 140, 142, 38, 150, 30, 39
FT_SPORT, FT_DPORT, FT_PORT, FT_PID = 26, 27, 45, 109
VT_INT = 2
FT_ENTITY, FT_MSG_SOURCE_TYPE = 6, 9  # Int32 ids; verified 2026-10-19 (see browse_filter)
_HUNT_TEXT_FIELDS = (
    FT_ACTION, FT_RESULT, FT_USER_AGENT, FT_SUBJECT, FT_POLICY, FT_RESPONSE_CODE, FT_SESSION, FT_VENDOR_INFO, FT_OBJECT_TYPE, FT_GROUP, FT_STATUS,
    FT_ACCOUNT, FT_DOMAIN,
)  # fmt: skip
MAX_BRANCHES = 16
_STRING_FIELDS: dict[str, int] = {
    "process.name": FT_PROCESS,
    "process.command_line": FT_COMMAND,
    "user.name": FT_LOGIN,
    "host.hostname": FT_HOSTNAME,
    "process.hash.md5": FT_HASH,
    "process.hash.sha1": FT_HASH,
    "process.hash.sha256": FT_HASH,
    "file.hash.md5": FT_HASH,
    "file.hash.sha1": FT_HASH,
    "file.hash.sha256": FT_HASH,
}
_IP_FIELDS: dict[str, int] = {"network.src_ip": FT_SIP, "auth.source_ip": FT_SIP, "network.dst_ip": FT_DIP}


def _like(v: str) -> str:
    return v.replace("*", "%").replace("?", "_")


def _filter_item(f: Any) -> dict[str, Any] | None:
    """The LogRhythm item for one canonical filter, or None when LogRhythm cannot express it (it is then checked locally)."""
    vals = f.value if isinstance(f.value, list) else [f.value]
    vals = [str(v) for v in vals if v is not None and str(v) != ""]
    if not vals:
        return None
    if f.field in _IP_FIELDS and f.op in ("eq", "in"):
        plain = [v for v in vals if "/" not in v]
        return _item(_IP_FIELDS[f.field], VT_IP, plain) if plain and len(plain) == len(vals) else None
    ft = _STRING_FIELDS.get(f.field)
    if ft is None:
        return None
    suffix = f.field == "process.name"  # LogRhythm may hold a full path where the canonical name is the file name
    if f.op in ("eq", "in"):
        values = [_str(f"%{v}", PATTERN) if suffix else _str(v, EXACT) for v in vals]
    elif f.op == "contains":
        values = [_str(f"%{v}%", PATTERN) for v in vals]
    elif f.op == "prefix":
        values = [_str(f"{v}%", PATTERN) for v in vals]
    elif f.op == "wildcard":
        values = [_str(_like(v), PATTERN) for v in vals]
    else:
        return None  # neq / exists / ranges: not a positive search term
    return _item(ft, VT_STRING, values)


def _dnf(cond: Any) -> list[list[Any]] | None:
    """Disjunctive normal form of the positive part of a condition: a list of ANDed filters per branch. `not` adds nothing (it is a
    superset), so it is enforced locally. None when the expansion is too large to search sensibly."""
    if cond.filter is not None:
        return [[cond.filter]]
    if cond.not_ is not None:
        return [[]]
    if cond.any is not None:
        out: list[list[Any]] = []
        for c in cond.any:
            sub = _dnf(c)
            if sub is None:
                return None
            out += sub
        return out if len(out) <= MAX_BRANCHES else None
    out = [[]]
    for c in cond.all or []:
        sub = _dnf(c)
        if sub is None:
            return None
        out = [a + b for a in out for b in sub]
        if len(out) > MAX_BRANCHES:
            return None
    return out


def ioa_searches(cond: Any) -> tuple[list[dict[str, Any]], int]:
    """(queryFilters to run, branches LogRhythm cannot search). A behaviour with no searchable branch returns ([], n)."""
    branches = _dnf(cond)
    if branches is None:
        return [], 1
    searches: dict[str, dict[str, Any]] = {}
    unsearchable = 0
    for branch in branches:
        items = [it for it in (_filter_item(f) for f in branch) if it is not None]
        if not items:
            unsearchable += 1
            continue
        flt = _wrap(items, 1)
        searches[json.dumps(flt, sort_keys=True)] = flt
    return list(searches.values()), unsearchable


# ---- built-in SIEM behaviours: filters (verified on production, docs/adr/0021) ------------------------------------------
def vendor_id_filter(ids: list[str]) -> dict[str, Any]:
    """Logs whose vendor message id (the Windows event id) is any of `ids`."""
    return _wrap([_item(FT_VENDOR_MSG_ID, VT_STRING, [_str(i, EXACT) for i in ids])], 1)


def url_like_filter(pattern: str) -> dict[str, Any]:
    """Logs whose URL matches one SQL pattern (`%` any run, `_` any single character). Exactly one pattern per search: several in one
    filter make LogRhythm fail the search (verified)."""
    return _wrap([_item(FT_URL, VT_STRING, [_str(pattern, PATTERN)])], 1)


def text_searches(word: str) -> list[dict[str, Any]]:
    """Searches for a bare word: it may be a process, a command line, a user, a URL, a host, a reason or an object. One search each (a URL filter must stand
    alone), all verified filters; the caller keeps only the logs that really contain the word. The last one searches the raw log text; its logs carry
    no raw text back, so a log it returns is vouched for by the SIEM (see TEXT_RAW_LABEL)."""
    like = _str(f"%{word}%", PATTERN)
    native = [_item(ft, VT_STRING, [like]) for ft in _HUNT_TEXT_FIELDS]
    if word.isdigit() and int(word) <= 65535:  # a port or a pid: Int32 values, exact
        native += [_item(ft, VT_INT, [int(word)]) for ft in (FT_PORT, FT_PID)]
    return [
        _wrap([_item(FT_PROCESS, VT_STRING, [like])], 1),
        _wrap([_item(FT_COMMAND, VT_STRING, [like])], 1),
        _wrap([_item(FT_LOGIN, VT_STRING, [like])], 1),
        _wrap([_item(FT_HOSTNAME, VT_STRING, [like])], 1),
        _wrap([_item(FT_REASON, VT_STRING, [like])], 1),
        _wrap([_item(FT_OBJECT, VT_STRING, [like])], 1),
        url_like_filter(f"%{word}%"),
        _wrap(native, 2),
        _wrap([_item(FT_MESSAGE, VT_STRING, [like])], 1),
    ]


def browse_filter(entity_ids: list[int] | None = None, source_type_ids: list[int] | None = None) -> dict[str, Any]:
    """Every log of the window: a Message search for `%` matches all of them (verified on prod 2026-10-19, 5,000+ logs in 10 minutes from 11
    source types). Optionally narrowed (AND) to entities and/or log source types, by Int32 id.
    Source types narrow exactly. The Entity filter lets LogRhythm's own diagnostics logs (entity of the emitting service) through whatever
    the id, so the caller must also check `entityId` / `originEntityId` / `impactedEntityId` locally."""
    items = [_item(FT_MESSAGE, VT_STRING, [_str("%", PATTERN)])]
    if entity_ids:
        items.append(_item(FT_ENTITY, VT_INT, list(dict.fromkeys(entity_ids))))
    if source_type_ids:
        items.append(_item(FT_MSG_SOURCE_TYPE, VT_INT, list(dict.fromkeys(source_type_ids))))
    return _wrap(items, 1)
