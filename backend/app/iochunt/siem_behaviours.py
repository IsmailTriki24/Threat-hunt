"""Built-in SIEM behaviours: attacker behaviour that needs no threat bulletin, searched INSIDE LogRhythm by the sweep.

Each behaviour is a verified LogRhythm search (docs/adr/0020-0021) plus a local check on what comes back, so a loose search can only cost time:
* password spraying / brute force / lockout bursts: Windows failed-logon events, counted per source over 10 minutes (thresholds sit above the
  normal peaks measured on the production SIEM: 19 failures and 8 accounts per source in 10 minutes), computer accounts (`name$`) ignored;
* account, group and audit-log changes: one search for a list of event ids, one alert each;
* web attack patterns in request URLs (path traversal, WebLogic exploit paths, JNDI, XSS, SQLi, command execution): one URL pattern per search
  (LogRhythm fails a search with several), then a regex on the decoded URL.

A detection becomes an Alert of a platform-managed detection rule (format `siem`), unique per (rule, event), so re-searching an overlapping window
never duplicates. The first event of a burst is the alert's event; it and a few samples are imported so the alert can be opened and cited. Nothing
else is stored."""

import asyncio
import html
import logging
import re
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import registry as connectors
from app.connectors._http import SourceError
from app.connectors.base import NormalizationError
from app.connectors.logrhythm import url_like_filter, vendor_id_filter
from app.core.config import Settings
from app.core.crypto import decrypt_json
from app.datasources.models import DataSource
from app.detections.models import Alert, DetectionRule
from app.events.schema import Event
from app.events.search.base import SearchBackend

log = logging.getLogger("app.iochunt.siem")

MAX_ALERTS_PER_BEHAVIOUR = (
    50  # per search: a scanner can produce thousands of matching requests; the rest is counted, not alerted
)
MAX_SAMPLES = 5
FAILED_LOGON_IDS = ["4625", "4771", "4776"]


# ---- helpers over raw LogRhythm logs -------------------------------------------------------------------
def _ts(raw: dict[str, Any]) -> int:
    v = raw.get("logDate")
    return int(v) if isinstance(v, int | float) else 0


def _account(raw: dict[str, Any]) -> str:
    return str(raw.get("login") or raw.get("account") or "").strip().lower()


def _human(raw: dict[str, Any]) -> str | None:
    a = _account(raw)
    return a if a and a not in ("-", "anonymous logon") and not a.endswith("$") else None


def _source(raw: dict[str, Any]) -> str | None:
    return str(raw.get("originIp") or raw.get("originHostName") or raw.get("originHost") or "") or None


def _vendor_id(raw: dict[str, Any]) -> str:
    return str(raw.get("vendorMessageId") or "")


def _failed_logon(raw: dict[str, Any]) -> str | None:
    return "failed sign-in" if _vendor_id(raw) in FAILED_LOGON_IDS and _human(raw) else None


def _url_variants(raw: dict[str, Any]) -> list[str]:
    """The request URL as logged, HTML-unescaped, and percent-decoded up to twice (double encoding is a classic evasion)."""
    url = str(raw.get("url") or "")
    if not url:
        return []
    once = unquote(html.unescape(url))
    return [url.lower(), once.lower(), unquote(once).lower()]


def _web_classifier(rx: str, label: str) -> Callable[[dict[str, Any]], str | None]:
    pattern = re.compile(rx)

    def classify(raw: dict[str, Any]) -> str | None:
        return label if any(pattern.search(v) for v in _url_variants(raw)) else None

    return classify


# ---- the catalogue --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Aggregate:
    key: Callable[[dict[str, Any]], str | None]
    member: Callable[[dict[str, Any]], str | None]
    min_events: int
    min_members: int = 0
    span: timedelta = timedelta(minutes=10)


@dataclass(frozen=True)
class Behaviour:
    key: str
    title: str
    description: str
    severity: str
    technique: str
    searches: tuple[dict[str, Any], ...]
    classify: Callable[[dict[str, Any]], str | None]  # None: this log is not the behaviour
    aggregate: Aggregate | None = None
    labels_severity: dict[str, str] = field(default_factory=dict)

    @property
    def lookback(self) -> timedelta:
        """Extra time searched before a window so a burst straddling its start is still seen."""
        return self.aggregate.span if self.aggregate else timedelta(0)


_ACCOUNT_CHANGES: dict[str, tuple[str, str]] = {
    "4720": ("a user account was created", "MEDIUM"),
    "4724": ("an account password was reset", "MEDIUM"),
    "4728": ("a member was added to a security-enabled global group", "HIGH"),
    "4732": ("a member was added to a security-enabled local group", "HIGH"),
    "4756": ("a member was added to a security-enabled universal group", "HIGH"),
    "1102": ("the Security audit log was cleared", "HIGH"),
    "104": ("an event log was cleared", "HIGH"),
    "4719": ("the system audit policy was changed", "HIGH"),
}


def _web(key: str, title: str, pattern: str, rx: str, severity: str, why: str) -> Behaviour:
    return Behaviour(
        key=key,
        title=f"Web attack: {title}",
        description=f"A request URL {why}. Searched in LogRhythm as the URL pattern `{pattern}` and re-checked on the decoded URL.",
        severity=severity,
        technique="T1190",
        searches=(url_like_filter(pattern),),
        classify=_web_classifier(rx, title),
    )


CATALOG: tuple[Behaviour, ...] = (
    Behaviour(
        "password_spray",
        "Password spraying",
        "Many different accounts failing to sign in from one source within 10 minutes (Windows 4625 / 4771 / 4776). Computer accounts are ignored.",
        "HIGH",
        "T1110.003",
        (vendor_id_filter(FAILED_LOGON_IDS),),
        _failed_logon,
        Aggregate(_source, _human, min_events=30, min_members=12),
    ),
    Behaviour(
        "brute_force",
        "Brute force against one account",
        "One account failing to sign in many times from one source within 10 minutes.",
        "MEDIUM",
        "T1110.001",
        (vendor_id_filter(FAILED_LOGON_IDS),),
        _failed_logon,
        Aggregate(lambda r: f"{_source(r) or '?'}|{_human(r) or '?'}", lambda r: _human(r), min_events=40),
    ),
    Behaviour(
        "lockout_burst",
        "Account lockout burst",
        "Several different accounts locked out within 10 minutes (Windows 4740).",
        "MEDIUM",
        "T1110",
        (vendor_id_filter(["4740"]),),
        lambda r: "account lockout" if _vendor_id(r) == "4740" else None,
        Aggregate(lambda r: "domain", lambda r: _account(r) or None, min_events=3, min_members=3),
    ),
    Behaviour(
        "account_changes",
        "Security-relevant account or audit change",
        "Account creation, password reset, privileged group membership, audit policy change or log clearing (Windows 4720 / 4724 / 4728 / 4732 / 4756 / 4719 / 1102 / 104).",
        "HIGH",
        "T1098",
        (vendor_id_filter(list(_ACCOUNT_CHANGES)),),
        lambda r: _ACCOUNT_CHANGES.get(_vendor_id(r), (None, ""))[0],
        labels_severity={v[0]: v[1] for v in _ACCOUNT_CHANGES.values()},
    ),
    _web("web_traversal", "path traversal", "%../%", r"\.\.[/\\]", "MEDIUM", "contains a directory traversal (../)"),
    _web(
        "web_sensitive_file",
        "sensitive file access",
        "%/etc/passwd%",
        r"/etc/(passwd|shadow)|boot\.ini|win\.ini|/proc/self/",
        "HIGH",
        "asks for an operating-system file",
    ),
    _web(
        "web_inf",
        "WEB-INF / META-INF access",
        "%/WEB-INF/%",
        r"/(web|meta)-inf/",
        "HIGH",
        "asks for application internals",
    ),
    _web(
        "web_wsat",
        "WebLogic wls-wsat exploit path",
        "%/wls-wsat/%",
        r"/wls-wsat/",
        "HIGH",
        "targets the WebLogic WS-AT component (CVE-2017-10271)",
    ),
    _web(
        "web_async",
        "WebLogic async response exploit path",
        "%/_async/%",
        r"/_async/asyncresponse",
        "HIGH",
        "targets the WebLogic async response service (CVE-2019-2725)",
    ),
    _web(
        "web_bea",
        "WebLogic internal application path",
        "%/bea_wls_%",
        r"/bea_wls_(deployment_)?internal/",
        "HIGH",
        "targets the WebLogic internal deployment application",
    ),
    _web(
        "web_console",
        "WebLogic console traversal",
        "%/console/css/%",
        r"/console/(css|images)/.*(\.\./|console\.portal)",
        "HIGH",
        "targets the WebLogic console with an encoded traversal (CVE-2020-14882)",
    ),
    _web(
        "web_jndi",
        "JNDI lookup injection",
        "%jndi:%",
        r"jndi:(ldaps?|rmi|dns|iiop|https?)",
        "HIGH",
        "contains a JNDI lookup (Log4Shell-style)",
    ),
    _web(
        "web_xss",
        "script injection",
        "%<script%",
        r"<script|javascript:|onerror\s*=",
        "MEDIUM",
        "contains script markup",
    ),
    _web(
        "web_sqli",
        "SQL injection",
        "%union%select%",
        r"union[\s+/*]+(all[\s+]+)?select|'\s*or\s*'?1'?\s*=\s*'?1",
        "MEDIUM",
        "contains a UNION SELECT / tautology",
    ),
    _web(
        "web_cmd",
        "command execution",
        "%cmd.exe%",
        r"cmd\.exe|/bin/(ba)?sh\b|powershell(\.exe)?[\s+]|\bwhoami\b",
        "HIGH",
        "contains an operating-system command",
    ),
)
BY_KEY: dict[str, Behaviour] = {b.key: b for b in CATALOG}


# ---- evaluation -----------------------------------------------------------------------------------------
@dataclass
class Detection:
    behaviour: Behaviour
    raw: dict[str, Any]  # the alert's event: the first log of the burst
    label: str
    count: int
    members: list[str]
    key: str | None
    samples: list[dict[str, Any]]
    message: str
    severity: str


def _summary(raw: dict[str, Any]) -> str:
    if raw.get("url"):
        return (
            f"{raw.get('command') or ''} {str(raw.get('url'))[:200]} (HTTP {raw.get('responseCode') or '?'}) "
            f"on {raw.get('impactedHostName') or raw.get('impactedHost') or '?'} from {raw.get('originIp') or '?'}"
        ).strip()
    return (
        f"{raw.get('commonEventName') or raw.get('classificationName') or 'event'} {_vendor_id(raw)} "
        f"account={_account(raw) or '?'} on {raw.get('impactedHostName') or raw.get('impactedHost') or raw.get('logSourceHostName') or '?'}"
    )


def detect(b: Behaviour, logs: list[dict[str, Any]]) -> tuple[list[Detection], int]:
    """(detections, how many more matched than were alerted). Pure: the same logs always give the same detections."""
    hits = [(r, lab) for r in logs if (lab := b.classify(r))]
    if not hits:
        return [], 0
    out: list[Detection] = []
    if b.aggregate is None:
        seen: set[Any] = set()
        for raw, label in sorted(hits, key=lambda h: _ts(h[0])):
            mid = raw.get("messageId")
            if mid in seen:
                continue
            seen.add(mid)
            sev = b.labels_severity.get(label, b.severity)
            out.append(Detection(b, raw, label, 1, [], None, [raw], f"{b.title}: {label}: {_summary(raw)}", sev))
        return out[:MAX_ALERTS_PER_BEHAVIOUR], max(0, len(out) - MAX_ALERTS_PER_BEHAVIOUR)
    agg = b.aggregate
    span_ms = int(agg.span.total_seconds() * 1000)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw, _label in hits:
        k = agg.key(raw)
        if k is not None:
            groups[k].append(raw)
    for k, evs in groups.items():
        evs.sort(key=_ts)
        i = 0
        while i < len(evs) and len(evs) - i >= agg.min_events:
            t0, j = _ts(evs[i]), i
            while j + 1 < len(evs) and _ts(evs[j + 1]) - t0 <= span_ms:
                j += 1
            window = evs[i : j + 1]
            members = sorted({m for e in window if (m := agg.member(e))})
            if len(window) >= agg.min_events and len(members) >= agg.min_members:
                shown = ", ".join(members[:5]) + (" ..." if len(members) > 5 else "")
                out.append(
                    Detection(
                        b,
                        window[0],
                        b.title.lower(),
                        len(window),
                        members,
                        k,
                        window[:MAX_SAMPLES],
                        f"{b.title}: {len(window)} events"
                        + (f" involving {len(members)} accounts ({shown})" if agg.min_members else f" for {shown}")
                        + f" from {k.split('|')[0]} within {int(agg.span.total_seconds() // 60)} minutes",
                        b.severity,
                    )
                )
                i = j + 1  # one detection per burst
            else:
                i += 1
    return out[:MAX_ALERTS_PER_BEHAVIOUR], max(0, len(out) - MAX_ALERTS_PER_BEHAVIOUR)


# ---- searching ------------------------------------------------------------------------------------------
@dataclass
class BehaviourRun:
    detections: list[Detection] = field(default_factory=list)
    covered: set[str] = field(default_factory=set)
    error: str = ""
    searches: int = 0
    overflow: int = 0


async def run_behaviours(
    settings: Settings,
    ds: DataSource,
    behaviours: list[Behaviour],
    start: datetime,
    end: datetime,
    budget_s: int,
    parallel: int = 2,
) -> BehaviourRun:
    """Run the searches of these behaviours over [start, end) in the SIEM and evaluate what returns. A behaviour counts as covered only
    when every one of its searches finished."""
    run = BehaviourRun()
    secrets = {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()} if ds.secrets_enc else {}
    deadline = time.monotonic() + budget_s
    sem = asyncio.Semaphore(max(1, parallel))

    async def one(flt: dict[str, Any], s: datetime) -> list[dict[str, Any]]:
        async with sem:
            if time.monotonic() > deadline:
                raise TimeoutError
            conn: Any = connectors.build(
                "logrhythm", ds.config, secrets
            )  # own connector: the filter override is per instance
            conn._filter_override = flt
            return await conn._search_window(s, end)  # type: ignore[no-any-return]

    for b in behaviours:
        if time.monotonic() > deadline:
            break
        s = start - b.lookback
        try:
            results = await asyncio.gather(*(one(f, s) for f in b.searches))
        except TimeoutError:
            break
        except (SourceError, ValueError) as exc:
            run.error = str(exc)[:240]
            break
        run.searches += len(b.searches)
        logs = list({r.get("messageId"): r for res in results for r in res}.values())
        dets, over = detect(b, logs)
        run.detections += dets
        run.overflow += over
        run.covered.add(b.key)
    return run


# ---- alerts ---------------------------------------------------------------------------------------------
async def ensure_rule(session: AsyncSession, tenant_id: uuid.UUID, b: Behaviour) -> DetectionRule:
    tag = f"siem:{b.key}"
    rule = (
        (
            await session.execute(
                select(DetectionRule).where(
                    DetectionRule.tenant_id == tenant_id,
                    DetectionRule.format == "siem",
                    DetectionRule.tags.contains([tag]),
                )
            )
        )
        .scalars()
        .first()
    )
    if rule is not None:
        return rule
    now = datetime.now(UTC)
    rule = DetectionRule(
        tenant_id=tenant_id,
        title=b.title,
        description=b.description,
        format="siem",
        content=f"built-in:{b.title}\n{b.description}",
        version=1,
        status="ACTIVE",
        severity=b.severity,
        compiled=None,
        unsupported=["Runs inside the SIEM (platform-managed), not over stored events"],
        warnings=[],
        techniques=[b.technique],
        tactics=[],
        tags=["siem-builtin", tag],
        tests_passed=True,
        activated_at=now,
    )
    session.add(rule)
    await session.flush()
    return rule


async def emit_alerts(
    session: AsyncSession, backend: SearchBackend, settings: Settings, ds: DataSource, detections: list[Detection]
) -> int:
    """Turn detections into alerts (unique per rule and event) and import the evidence logs. Returns the number of NEW alerts."""
    if not detections:
        return 0
    secrets = {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()} if ds.secrets_enc else {}
    conn: Any = connectors.build("logrhythm", ds.config, secrets)
    rules: dict[str, DetectionRule] = {}
    new_alerts = 0
    imported: dict[str, Event] = {}

    def docs(raw: dict[str, Any]) -> list[Event]:
        try:
            return [Event.from_input(e, ds.tenant_id) for e in conn.normalize(raw)]
        except NormalizationError:
            return []

    for d in detections:
        evs = docs(d.raw)
        if not evs:
            continue
        for sample in d.samples:
            imported.update({e.id: e for e in docs(sample)})
        rule = rules.get(d.behaviour.key) or await ensure_rule(session, ds.tenant_id, d.behaviour)
        rules[d.behaviour.key] = rule
        doc = evs[0].to_document()
        doc["message"] = d.message[:1024]
        doc["tags"] = [*dict.fromkeys([*doc.get("tags", []), "siem-builtin", f"siem:{d.behaviour.key}"])][:20]
        res = await session.execute(
            insert(Alert)
            .values(
                id=uuid.uuid4(),
                tenant_id=ds.tenant_id,
                rule_id=rule.id,
                rule_version=rule.version,
                rule_title=rule.title,
                severity=d.severity,
                event_id=doc["id"],
                event_timestamp=datetime.fromisoformat(str(doc["timestamp"]).replace("Z", "+00:00")),
                snapshot=doc,
                status="OPEN",
            )
            .on_conflict_do_nothing(constraint="uq_alert_rule_event")
            .returning(Alert.id)
        )
        if res.first():
            new_alerts += 1
            imported.update({e.id: e for e in evs})
    if imported:
        await backend.index_events(list(imported.values()))
        await backend.refresh()
    return new_alerts
