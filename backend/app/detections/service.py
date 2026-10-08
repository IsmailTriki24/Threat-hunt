import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, Conflict
from app.detections.formats import registry
from app.detections.formats.base import ParsedRule, RuleError
from app.detections.models import Alert, DetectionRule, DetectionRun, RuleTestCase, RuleVersion
from app.detections.schemas import TestResult
from app.events.schema import EventIn
from app.events.search.base import SearchBackend
from app.events.search.local import matches
from app.events.search.query import Condition, EventQuery, Filter, Sort, TimeRange
from app.mitre.models import MitreMapping, MitreTechnique

SCHEDULE_LOOKBACK = timedelta(days=7)  # an event is only considered if its own timestamp is this recent
INGEST_OVERLAP = timedelta(seconds=90)  # re-read a little: events become searchable shortly after ingested_at
MAX_ALERTS_PER_RUN = 1000
PAGE = 200

TRANSITIONS: dict[str, set[str]] = {
    "DRAFT": {"TESTING", "ARCHIVED"},
    "TESTING": {"ACTIVE", "DRAFT", "ARCHIVED"},
    "ACTIVE": {"DISABLED", "ARCHIVED"},
    "DISABLED": {"ACTIVE", "TESTING", "ARCHIVED"},
    "ARCHIVED": {"DRAFT"},
}


def parse(format_id: str, content: str) -> ParsedRule:
    try:
        fmt = registry.get(format_id)
    except KeyError:
        raise AppError(f"Unknown detection format '{format_id}'") from None
    try:
        return fmt.parse(content)
    except RuleError as exc:
        raise AppError(f"Rule error: {exc}") from None


def apply_parsed(rule: DetectionRule, parsed: ParsedRule) -> None:
    rule.title = parsed.title[:200]
    rule.description = parsed.description
    rule.severity = parsed.severity
    rule.compiled = (
        parsed.where.model_dump(by_alias=True, exclude_none=True) if parsed.executable and parsed.where else None
    )
    rule.unsupported = parsed.unsupported
    rule.warnings = parsed.warnings
    rule.techniques = list(dict.fromkeys(parsed.techniques))
    rule.tactics = list(dict.fromkeys(parsed.tactics))
    rule.tags = parsed.tags


def condition_of(rule: DetectionRule) -> Condition | None:
    return Condition.model_validate(rule.compiled) if rule.compiled else None


def sample_doc(event: EventIn | dict[str, Any], event_id: str = "sample") -> dict[str, Any]:
    ev = event if isinstance(event, EventIn) else EventIn.model_validate(event)
    return {"id": event_id, **ev.model_dump(mode="json", exclude_none=True)}


def explain(parsed_selections: dict[str, Condition], doc: dict[str, Any]) -> list[str]:
    return [name for name, cond in parsed_selections.items() if matches(cond, doc)]


def run_cases(
    where: Condition,
    selections: dict[str, Condition],
    cases: Sequence[tuple[uuid.UUID | None, str, dict[str, Any], bool]],
) -> list[TestResult]:
    out: list[TestResult] = []
    for case_id, name, event, expect in cases:
        doc = sample_doc(event)
        hit = matches(where, doc)
        out.append(
            TestResult(
                case_id=case_id,
                name=name,
                expect_match=expect,
                matched=hit,
                passed=hit == expect,
                explanation=explain(selections, doc),
            )
        )
    return out


async def load_cases(session: AsyncSession, rule: DetectionRule) -> list[RuleTestCase]:
    return list(
        (
            await session.execute(
                select(RuleTestCase).where(RuleTestCase.rule_id == rule.id).order_by(RuleTestCase.created_at)
            )
        ).scalars()
    )


def selections_of(rule: DetectionRule) -> dict[str, Condition]:
    """Re-derive the named selections for explanations (cheap: rules are small)."""
    try:
        return registry.get(rule.format).parse(rule.content).selections
    except (KeyError, RuleError):
        return {}


async def run_tests(session: AsyncSession, rule: DetectionRule) -> list[TestResult]:
    where = condition_of(rule)
    if where is None:
        raise AppError("The rule is not executable, so it cannot be tested")
    cases = await load_cases(session, rule)
    results = run_cases(where, selections_of(rule), [(c.id, c.name, c.event, c.expect_match) for c in cases])
    rule.tests_passed = bool(results) and all(r.passed for r in results)
    rule.tests_run_at = datetime.now(UTC)
    return results


async def invalidate_tests(session: AsyncSession, rule: DetectionRule) -> None:
    rule.tests_passed = None
    rule.tests_run_at = None
    if rule.status == "ACTIVE":
        rule.status = "TESTING"  # a changed test set must be re-validated before it keeps running


async def sync_mitre(session: AsyncSession, rule: DetectionRule, user_id: uuid.UUID | None) -> None:
    """Rule tags are a *declaration*, not telemetry evidence: record them as LOW-confidence analyst mappings."""
    if not rule.techniques:
        return
    known = set(
        (await session.execute(select(MitreTechnique.id).where(MitreTechnique.id.in_(rule.techniques)))).scalars()
    )
    for tid in rule.techniques:
        if tid not in known:
            continue
        await session.execute(
            insert(MitreMapping)
            .values(
                id=uuid.uuid4(),
                tenant_id=rule.tenant_id,
                technique_id=tid,
                object_type="detection",
                object_id=rule.id,
                confidence="LOW",
                reasoning=f"Declared by the rule's ATT&CK tag for {tid} (rule '{rule.title}'); not derived from telemetry.",
                evidence_event_ids=[],
                source="analyst",
                created_by=user_id,
            )
            .on_conflict_do_nothing(constraint="uq_mitre_mapping")
        )


async def remove_mitre(session: AsyncSession, rule: DetectionRule) -> None:
    await session.execute(
        delete(MitreMapping).where(
            MitreMapping.tenant_id == rule.tenant_id,
            MitreMapping.object_type == "detection",
            MitreMapping.object_id == rule.id,
        )
    )


def check_transition(rule: DetectionRule, target: str, case_count: int, has_positive: bool) -> None:
    if target not in TRANSITIONS.get(rule.status, set()):
        raise Conflict(f"A {rule.status} rule cannot move to {target}")
    if target in ("TESTING", "ACTIVE") and not rule.compiled:
        raise AppError("The rule is not executable: " + ("; ".join(rule.unsupported) or "it did not compile"))
    if target == "ACTIVE":
        if not case_count or not has_positive:
            raise AppError("Add at least one test case that the rule must match before activating it")
        if not rule.tests_passed:
            raise AppError("All test cases must pass for the current version before activating the rule")


async def snapshot_version(
    session: AsyncSession, rule: DetectionRule, user_id: uuid.UUID | None, note: str = ""
) -> None:
    session.add(
        RuleVersion(
            tenant_id=rule.tenant_id,
            rule_id=rule.id,
            version=rule.version,
            format=rule.format,
            content=rule.content,
            note=note,
            changed_by=user_id,
        )
    )


def _error_text(exc: Exception) -> str:
    return (str(exc).splitlines() or [exc.__class__.__name__])[0][:300]


async def evaluate(
    session: AsyncSession,
    backend: SearchBackend,
    rule: DetectionRule,
    *,
    kind: str,
    time_range: TimeRange | None = None,
    limit: int = 50,
    user_id: uuid.UUID | None = None,
) -> tuple[DetectionRun, list[dict[str, Any]], int]:
    """Run the rule over telemetry. `scheduled` raises alerts for events ingested since the last run; `backtest` only counts."""
    where = condition_of(rule)
    started = datetime.now(UTC)
    t0 = started
    if where is None:
        raise AppError("The rule is not executable")
    hits: list[dict[str, Any]] = []
    total = 0
    new_alerts = 0
    status, error = "ok", ""
    try:
        if kind == "backtest":
            tr = time_range or TimeRange.last(timedelta(hours=24))
            res = await backend.search(
                rule.tenant_id,
                EventQuery(where=where, time_range=tr, sort=[Sort(field="timestamp", order="desc")], limit=limit),
            )
            hits, total = res.hits, res.total
        else:
            floor = rule.activated_at or started  # events ingested before activation never alert (use a backtest)
            since = max(floor, (rule.last_evaluated_at or floor) - INGEST_OVERLAP)
            tr = TimeRange(start=started - SCHEDULE_LOOKBACK, end=started + timedelta(days=1))
            flt = Filter(field="ingested_at", op="gt", value=since.isoformat())
            high_water = started
            last_ingested: str | None = None
            offset = 0
            while True:
                res = await backend.search(
                    rule.tenant_id,
                    EventQuery(
                        where=where,
                        filters=[flt],
                        time_range=tr,
                        sort=[Sort(field="ingested_at", order="asc")],
                        offset=offset,
                        limit=PAGE,
                    ),
                )
                total = res.total
                for h in res.hits:
                    new_alerts += await _raise_alert(session, rule, h)
                    last_ingested = h.get("ingested_at") or last_ingested
                if len(hits) < 5:
                    hits.extend(res.hits[: 5 - len(hits)])
                offset += PAGE
                if offset >= total or not res.hits:
                    break
                if offset >= MAX_ALERTS_PER_RUN:
                    if last_ingested:
                        high_water = datetime.fromisoformat(last_ingested)
                    error = (
                        f"more than {MAX_ALERTS_PER_RUN} matches in one run; the remainder is picked up by the next run"
                    )
                    break
            rule.last_evaluated_at = high_water
    except AppError:
        raise
    except Exception as exc:  # engine/query failure: recorded on the rule, never fatal to the scheduler
        status, error = "error", _error_text(exc)
    rule.last_run_status, rule.last_run_error = (
        (status, error) if kind == "scheduled" else (rule.last_run_status, rule.last_run_error)
    )
    run = DetectionRun(
        tenant_id=rule.tenant_id,
        rule_id=rule.id,
        rule_version=rule.version,
        kind=kind,
        window_start=tr.start if status == "ok" else started,
        window_end=tr.end if status == "ok" else started,
        status=status,
        error=error,
        matches=total,
        new_alerts=new_alerts,
        took_ms=int((datetime.now(UTC) - t0).total_seconds() * 1000),
        sample_event_ids=[h["id"] for h in hits[:20]],
        created_by=user_id,
    )
    session.add(run)
    await session.flush()
    await session.refresh(run)
    return run, hits, total


async def _raise_alert(session: AsyncSession, rule: DetectionRule, event: dict[str, Any]) -> int:
    res = await session.execute(
        insert(Alert)
        .values(
            id=uuid.uuid4(),
            tenant_id=rule.tenant_id,
            rule_id=rule.id,
            rule_version=rule.version,
            rule_title=rule.title,
            severity=rule.severity,
            event_id=event["id"],
            event_timestamp=datetime.fromisoformat(event["timestamp"]),
            snapshot=event,
            status="OPEN",
        )
        .on_conflict_do_nothing(constraint="uq_alert_rule_event")
        .returning(Alert.id)
    )
    return 1 if res.first() else 0


async def counts(session: AsyncSession, model: Any, *where: Any) -> int:
    return (await session.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def run_scheduled(sessionmaker: Any, backend: SearchBackend) -> dict[str, int]:
    """Evaluate every ACTIVE rule (all tenants). One rule's failure never blocks the others."""
    async with sessionmaker() as session:
        ids = list((await session.execute(select(DetectionRule.id).where(DetectionRule.status == "ACTIVE"))).scalars())
    summary = {"rules": 0, "alerts": 0, "errors": 0}
    for rid in ids:
        async with sessionmaker() as session:
            rule = (
                await session.execute(
                    select(DetectionRule)
                    .where(DetectionRule.id == rid, DetectionRule.status == "ACTIVE")
                    .with_for_update(skip_locked=True)
                )
            ).scalar_one_or_none()
            if rule is None:  # deactivated meanwhile, or another worker holds it
                continue
            try:
                run, _, _ = await evaluate(session, backend, rule, kind="scheduled")
            except AppError as exc:
                rule.last_run_status, rule.last_run_error = "error", exc.message[:300]
                summary["errors"] += 1
            else:
                summary["rules"] += 1
                summary["alerts"] += run.new_alerts
                summary["errors"] += run.status != "ok"
            await session.commit()
    return summary
