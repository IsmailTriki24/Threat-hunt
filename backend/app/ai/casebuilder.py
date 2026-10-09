"""Opens (or refreshes) a case from a finished AI investigation.

The hunt report engine (`hunt_report`) decides what the report says; this module puts it where analysts work: a case holding the
report as its first report version, the verified evidence, the indicators found malicious, the ATT&CK techniques the findings
support, and a journal entry saying where it all came from. It is idempotent per run - a resumed run refreshes its case instead of
opening a second one - and it only ever uses what the platform already verified, never raw model claims."""

import logging
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai import hunt_report
from app.ai.models import AiRun
from app.auth.deps import Principal
from app.cases import service
from app.cases.models import Case, CaseIoc, CaseReport
from app.core.errors import AppError
from app.events.search.base import SearchBackend
from app.mitre.models import MitreMapping, MitreTechnique

log = logging.getLogger("hunt.ai")
SEVERITY_ORDER = hunt_report.SEVERITY_ORDER


def snapshot(run: AiRun) -> dict[str, Any]:
    return {
        "id": str(run.id), "goal": run.goal, "hours_back": run.hours_back, "mode": run.mode, "model": run.model,
        "status": run.status, "created_at": run.created_at, "steps": run.steps or [],
        "conclusion": run.conclusion or {}, "state": run.state or {},
    }  # fmt: skip


async def _technique_info(session: AsyncSession, ids: list[str]) -> dict[str, tuple[str, list[str]]]:
    """Official name and tactics per technique id; a sub-technique inherits its parent's tactics when it has none of its own."""
    if not ids:
        return {}
    wanted = list({*ids, *(i.split(".")[0] for i in ids)})
    rows = await session.execute(
        select(MitreTechnique.id, MitreTechnique.name, MitreTechnique.tactics).where(MitreTechnique.id.in_(wanted))
    )
    return {i: (n, list(t or [])) for i, n, t in rows.all()}


async def _technique_names(session: AsyncSession, ids: list[str]) -> dict[str, str]:
    return {i: n for i, (n, _) in (await _technique_info(session, ids)).items()}


async def build_report(session: AsyncSession, run: AiRun) -> hunt_report.HuntReport:
    """Two passes: the first learns which ATT&CK ids are involved, the second renders them with their official names."""
    first = hunt_report.build(snapshot(run))
    info = await _technique_info(session, [a["id"] for a in first.attack])
    if not info:
        return first
    return hunt_report.build(
        snapshot(run),
        technique_names={i: n for i, (n, _) in info.items()},
        technique_tactics={i: t for i, (_, t) in info.items() if t},
    )


async def _next_version(session: AsyncSession, case: Case) -> int:
    cur = await session.execute(
        select(func.coalesce(func.max(CaseReport.version), 0)).where(CaseReport.case_id == case.id)
    )
    return int(cur.scalar_one()) + 1


async def _attach(
    session: AsyncSession, backend: SearchBackend, principal: Principal, case: Case, report: hunt_report.HuntReport
) -> dict[str, int]:
    """Evidence, indicators and ATT&CK mappings. Anything that cannot be attached is skipped, never fatal to the case."""
    added = {"evidence": 0, "iocs": 0, "techniques": 0}
    if report.evidence_ids and not service.workflow.is_locked(case.status):
        docs = await backend.get_events(case.tenant_id, report.evidence_ids)  # tenant-scoped; events may have aged out
        ids = [d["id"] for d in docs if isinstance(d.get("id"), str)]
        if ids:
            added["evidence"] = len(
                await service.add_evidence(session, backend, principal, case, ids, "Cited by the AI hunt report")
            )
    for ind in report.indicators:
        stmt = (
            insert(CaseIoc)
            .values(
                id=uuid.uuid4(), tenant_id=case.tenant_id, case_id=case.id, type=ind["type"], value=ind["value"][:2048],
                source="ai", occurrences=1, context=ind["context"][:300],
            )
            .on_conflict_do_nothing(constraint="uq_case_ioc")
        )  # fmt: skip
        added["iocs"] += int((await session.execute(stmt)).rowcount or 0)
    known = await _technique_names(session, [c["technique_id"] for c in report.technique_claims])
    for claim in report.technique_claims:
        if claim["technique_id"] not in known:
            continue  # only techniques in the tenant's ATT&CK reference data can be mapped
        stmt = (
            insert(MitreMapping)
            .values(
                id=uuid.uuid4(), tenant_id=case.tenant_id, technique_id=claim["technique_id"], object_type="case", object_id=case.id,
                confidence=claim["confidence"], reasoning=claim["reasoning"], evidence_event_ids=claim["event_ids"],
                source="suggestion", created_by=principal.user_id,
            )
            .on_conflict_do_nothing(constraint="uq_mitre_mapping")
        )  # fmt: skip
        added["techniques"] += int((await session.execute(stmt)).rowcount or 0)
    return added


async def open_case(
    session: AsyncSession, backend: SearchBackend, principal: Principal, run: AiRun
) -> tuple[Case, bool]:
    """Open the run's case, or refresh it if the run already has one. Returns (case, created)."""
    if not run.conclusion:
        raise AppError("This investigation has no conclusion to report yet")
    report = await build_report(session, run)
    markdown = hunt_report.to_markdown(report)
    case: Case | None = None
    if run.case_id:
        case = (
            await session.execute(select(Case).where(Case.id == run.case_id, Case.tenant_id == principal.tid))
        ).scalar_one_or_none()
    created = case is None
    if case is None:
        case = Case(
            tenant_id=principal.tid,
            number=await service.next_number(session, principal.tid),
            title=hunt_report.one_line(report.title, 200),
            description=report.case_description,
            severity=report.severity,
            priority=report.priority,
            hunt_id=run.hunt_id,
            created_by=principal.user_id,
        )
        session.add(case)
        await session.flush()
        await session.refresh(case)
        await service.log(
            session, principal, case, "created", "Opened automatically from an AI hunt",
            {"ai_run_id": str(run.id), "verdict": report.verdict, "mode": run.mode, "model": run.model},
        )  # fmt: skip
    else:
        case.description = report.case_description
        if SEVERITY_ORDER.index(report.severity) > SEVERITY_ORDER.index(
            case.severity if case.severity in SEVERITY_ORDER else "INFO"
        ):
            case.severity, case.priority = (
                report.severity,
                report.priority,
            )  # a refreshed hunt can raise a case, never lower it
        await service.log(
            session,
            principal,
            case,
            "ai_report_updated",
            "AI hunt report refreshed",
            {"ai_run_id": str(run.id), "verdict": report.verdict},
        )
    added = await _attach(session, backend, principal, case, report)
    session.add(
        CaseReport(
            tenant_id=case.tenant_id,
            case_id=case.id,
            version=await _next_version(session, case),
            kind="hunt",
            content=markdown,
            data=report.to_dict(),
            created_by=principal.user_id,
        )
    )
    run.case_id = case.id
    await service.log(
        session,
        principal,
        case,
        "report_generated",
        "AI hunt report",
        {"verdict": report.verdict, "attached": added, "ai_run_id": str(run.id)},
    )
    await session.flush()
    return case, created
