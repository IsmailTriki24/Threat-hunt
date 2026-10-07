import csv
import io
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.deps import Principal, require
from app.auth.rbac import Permission
from app.core.db import get_session
from app.core.errors import AppError, NotFound
from app.core.ratelimit import enforce
from app.events.search.base import SearchBackend
from app.events.search.dsl import QueryParseError
from app.events.search.dsl import parse as parse_text
from app.events.search.query import SearchResult
from app.events.summary import summarize
from app.hunts import service
from app.hunts.models import Finding, Hunt, HuntNote, QueryHistory, SavedQuery
from app.hunts.schemas import (
    ExportRequest,
    FindingCreate,
    FindingOut,
    HistoryOut,
    HuntCreate,
    HuntOut,
    HuntRunRequest,
    HuntUpdate,
    NoteCreate,
    NoteOut,
    ParseRequest,
    SavedQueryCreate,
    SavedQueryOut,
)

router = APIRouter(tags=["hunts"])


def _backend(request: Request) -> SearchBackend:
    backend: SearchBackend = request.app.state.search
    return backend


async def _hunt(session: AsyncSession, principal: Principal, hunt_id: uuid.UUID) -> Hunt:
    hunt = (
        await session.execute(select(Hunt).where(Hunt.id == hunt_id, Hunt.tenant_id == principal.tid))
    ).scalar_one_or_none()
    if hunt is None:
        raise NotFound("Hunt not found")
    return hunt


async def _hunt_out(session: AsyncSession, hunt: Hunt) -> HuntOut:
    findings = (
        await session.execute(select(func.count()).select_from(Finding).where(Finding.hunt_id == hunt.id))
    ).scalar_one()
    queries = (
        await session.execute(select(func.count()).select_from(SavedQuery).where(SavedQuery.hunt_id == hunt.id))
    ).scalar_one()
    out = HuntOut.model_validate(hunt, from_attributes=True)
    out.finding_count, out.query_count = findings, queries
    return out


# ---- hunts ---------------------------------------------------------------------------------------
@router.get("/hunts", response_model=list[HuntOut])
async def list_hunts(
    principal: Principal = Depends(require(Permission.HUNTS_READ)), session: AsyncSession = Depends(get_session)
) -> list[HuntOut]:
    rows = (
        (
            await session.execute(
                select(Hunt).where(Hunt.tenant_id == principal.tid).order_by(Hunt.updated_at.desc()).limit(500)
            )
        )
        .scalars()
        .all()
    )
    return [await _hunt_out(session, h) for h in rows]


@router.post("/hunts", response_model=HuntOut, status_code=201)
async def create_hunt(
    body: HuntCreate,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> HuntOut:
    hunt = Hunt(tenant_id=principal.tid, created_by=principal.user_id, **body.model_dump())
    session.add(hunt)
    await session.flush()
    await session.refresh(hunt)
    await audit.record(request, "hunt.create", principal=principal, resource_type="hunt", resource_id=str(hunt.id))
    return await _hunt_out(session, hunt)


@router.get("/hunts/{hunt_id}", response_model=HuntOut)
async def get_hunt(
    hunt_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.HUNTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> HuntOut:
    return await _hunt_out(session, await _hunt(session, principal, hunt_id))


@router.patch("/hunts/{hunt_id}", response_model=HuntOut)
async def update_hunt(
    hunt_id: uuid.UUID,
    body: HuntUpdate,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> HuntOut:
    hunt = await _hunt(session, principal, hunt_id)
    changes = body.model_dump(exclude_unset=True)
    start = changes.get("time_start", hunt.time_start)
    end = changes.get("time_end", hunt.time_end)
    if (start is None) != (end is None) or (start and end and start >= end):
        raise AppError("time_start/time_end must both be set, with start before end")
    for k, v in changes.items():
        if v is None and k in ("title", "hypothesis", "status", "conclusion", "data_sources"):
            continue
        setattr(hunt, k, v)
    await session.flush()
    await session.refresh(hunt)
    await audit.record(
        request,
        "hunt.update",
        principal=principal,
        resource_type="hunt",
        resource_id=str(hunt.id),
        details={"fields": sorted(changes)},
    )
    return await _hunt_out(session, hunt)


@router.delete("/hunts/{hunt_id}", status_code=204)
async def delete_hunt(
    hunt_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_DELETE)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    hunt = await _hunt(session, principal, hunt_id)
    await session.delete(hunt)
    await audit.record(request, "hunt.delete", principal=principal, resource_type="hunt", resource_id=str(hunt_id))
    return Response(status_code=204)


@router.post("/hunts/{hunt_id}/run", response_model=SearchResult)
async def run_hunt_query(
    hunt_id: uuid.UUID,
    body: HuntRunRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> SearchResult:
    hunt = await _hunt(session, principal, hunt_id)
    await enforce(request, f"search:{principal.user_id}", 120, 60)
    scoped = service.apply_hunt_scope(hunt, body.query)
    result = await _backend(request).search(principal.tid, scoped)
    await service.record_history(session, principal, body.query, result, hunt.id)
    await audit.record(
        request,
        "hunt.run",
        principal=principal,
        resource_type="hunt",
        resource_id=str(hunt.id),
        details={"text": (body.query.text or "")[:200], "total": result.total},
    )
    return result


# ---- findings & notes ----------------------------------------------------------------------------
@router.get("/hunts/{hunt_id}/findings", response_model=list[FindingOut])
async def list_findings(
    hunt_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.HUNTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    await _hunt(session, principal, hunt_id)
    rows = await session.execute(
        select(Finding)
        .where(Finding.hunt_id == hunt_id, Finding.tenant_id == principal.tid)
        .order_by(Finding.created_at.desc())
    )
    return list(rows.scalars())


@router.post("/hunts/{hunt_id}/findings", response_model=FindingOut, status_code=201)
async def add_finding(
    hunt_id: uuid.UUID,
    body: FindingCreate,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> Finding:
    await _hunt(session, principal, hunt_id)
    ids = list(dict.fromkeys(body.event_ids))
    docs = await _backend(request).get_events(principal.tid, ids)  # tenant-scoped: foreign ids simply don't resolve
    found = {d["id"]: d for d in docs}
    missing = [i for i in ids if i not in found]
    if missing:
        raise AppError(f"Unknown event ids: {', '.join(missing[:5])}")
    evidence = [
        {
            "id": i,
            "timestamp": found[i]["timestamp"],
            "summary": summarize(found[i]),
            "host": (found[i].get("host") or {}).get("hostname"),
        }
        for i in ids
    ]
    finding = Finding(
        tenant_id=principal.tid,
        hunt_id=hunt_id,
        created_by=principal.user_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        evidence=evidence,
    )
    session.add(finding)
    await session.flush()
    await session.refresh(finding)
    await audit.record(
        request,
        "hunt.finding.create",
        principal=principal,
        resource_type="hunt",
        resource_id=str(hunt_id),
        details={"finding_id": str(finding.id), "events": len(ids)},
    )
    return finding


@router.delete("/hunts/{hunt_id}/findings/{finding_id}", status_code=204)
async def delete_finding(
    hunt_id: uuid.UUID,
    finding_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    finding = (
        await session.execute(
            select(Finding).where(
                Finding.id == finding_id, Finding.hunt_id == hunt_id, Finding.tenant_id == principal.tid
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise NotFound("Finding not found")
    await session.delete(finding)
    await audit.record(
        request, "hunt.finding.delete", principal=principal, resource_type="hunt", resource_id=str(hunt_id)
    )
    return Response(status_code=204)


@router.get("/hunts/{hunt_id}/notes", response_model=list[NoteOut])
async def list_notes(
    hunt_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.HUNTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[HuntNote]:
    await _hunt(session, principal, hunt_id)
    rows = await session.execute(
        select(HuntNote)
        .where(HuntNote.hunt_id == hunt_id, HuntNote.tenant_id == principal.tid)
        .order_by(HuntNote.created_at)
    )
    return list(rows.scalars())


@router.post("/hunts/{hunt_id}/notes", response_model=NoteOut, status_code=201)
async def add_note(
    hunt_id: uuid.UUID,
    body: NoteCreate,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> HuntNote:
    await _hunt(session, principal, hunt_id)
    note = HuntNote(tenant_id=principal.tid, hunt_id=hunt_id, author_id=principal.user_id, body=body.body)
    session.add(note)
    await session.flush()
    await session.refresh(note)
    await audit.record(request, "hunt.note.create", principal=principal, resource_type="hunt", resource_id=str(hunt_id))
    return note


# ---- saved queries & history ---------------------------------------------------------------------
def _sq_out(q: SavedQuery) -> SavedQueryOut:
    return SavedQueryOut.model_validate(q, from_attributes=True)


@router.get("/saved-queries", response_model=list[SavedQueryOut])
async def list_saved_queries(
    hunt_id: uuid.UUID | None = None,
    principal: Principal = Depends(require(Permission.HUNTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[SavedQueryOut]:
    stmt = select(SavedQuery).where(SavedQuery.tenant_id == principal.tid)
    if hunt_id is not None:
        stmt = stmt.where(SavedQuery.hunt_id == hunt_id)
    rows = await session.execute(stmt.order_by(SavedQuery.created_at.desc()).limit(500))
    return [_sq_out(q) for q in rows.scalars()]


@router.post("/saved-queries", response_model=SavedQueryOut, status_code=201)
async def save_query(
    body: SavedQueryCreate,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> SavedQueryOut:
    if body.hunt_id:
        await _hunt(session, principal, body.hunt_id)
    saved = SavedQuery(
        tenant_id=principal.tid,
        hunt_id=body.hunt_id,
        created_by=principal.user_id,
        name=body.name,
        description=body.description,
        text=body.query.text or "",
        query=body.query.model_dump(mode="json", exclude_none=True),
    )
    session.add(saved)
    await session.flush()
    await session.refresh(saved)
    await audit.record(
        request, "query.save", principal=principal, resource_type="saved_query", resource_id=str(saved.id)
    )
    return _sq_out(saved)


@router.delete("/saved-queries/{query_id}", status_code=204)
async def delete_saved_query(
    query_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Permission.HUNTS_WRITE)),
    session: AsyncSession = Depends(get_session),
) -> Response:
    saved = (
        await session.execute(
            select(SavedQuery).where(SavedQuery.id == query_id, SavedQuery.tenant_id == principal.tid)
        )
    ).scalar_one_or_none()
    if saved is None:
        raise NotFound("Saved query not found")
    await session.delete(saved)
    await audit.record(
        request, "query.delete", principal=principal, resource_type="saved_query", resource_id=str(query_id)
    )
    return Response(status_code=204)


@router.get("/query-history", response_model=list[HistoryOut])
async def query_history(
    hunt_id: uuid.UUID | None = None,
    limit: int = 50,
    principal: Principal = Depends(require(Permission.HUNTS_READ)),
    session: AsyncSession = Depends(get_session),
) -> list[QueryHistory]:
    """Always the caller's own history; other analysts' queries are never exposed."""
    stmt = select(QueryHistory).where(
        QueryHistory.user_id == principal.user_id, QueryHistory.tenant_id == principal.tid
    )
    if hunt_id is not None:
        stmt = stmt.where(QueryHistory.hunt_id == hunt_id)
    return list(
        (await session.execute(stmt.order_by(QueryHistory.executed_at.desc()).limit(max(1, min(limit, 200))))).scalars()
    )


@router.delete("/query-history", status_code=204)
async def clear_history(
    principal: Principal = Depends(require(Permission.HUNTS_READ)), session: AsyncSession = Depends(get_session)
) -> Response:
    from sqlalchemy import delete

    await session.execute(
        delete(QueryHistory).where(QueryHistory.user_id == principal.user_id, QueryHistory.tenant_id == principal.tid)
    )
    return Response(status_code=204)


# ---- query language & export ---------------------------------------------------------------------
@router.post("/queries/parse")
async def parse_query(body: ParseRequest, _: Principal = Depends(require(Permission.EVENTS_READ))) -> dict[str, Any]:
    try:
        q, filters = parse_text(body.text)
    except QueryParseError as exc:
        raise AppError(f"Query error: {exc}") from None
    return {"q": q, "filters": [f.model_dump(mode="json") for f in filters]}


_EXPORT_COLUMNS = [
    ("timestamp", ("timestamp",)),
    ("event_type", ("event_type",)),
    ("source", ("source",)),
    ("host", ("host", "hostname")),
    ("user", ("user", "name")),
    ("process", ("process", "name")),
    ("command_line", ("process", "command_line")),
    ("dst_ip", ("network", "dst_ip")),
    ("dst_port", ("network", "dst_port")),
    ("dns_question", ("dns", "question")),
    ("file_path", ("file", "path")),
    ("outcome", ("outcome",)),
    ("severity", ("severity",)),
    ("id", ("id",)),
]


def _dig(doc: dict[str, Any], path: tuple[str, ...]) -> Any:
    for p in path:
        doc = doc.get(p) if isinstance(doc, dict) else None  # type: ignore[assignment]
    return doc


@router.post("/events/export")
async def export_events(
    body: ExportRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.EVENTS_READ)),
) -> Response:
    await enforce(request, f"export:{principal.user_id}", 10, 60)
    rows: list[dict[str, Any]] = []
    offset = 0
    while len(rows) < body.max_rows:
        page = body.query.model_copy(
            update={"offset": offset, "limit": min(500, body.max_rows - len(rows)), "aggregations": []}
        )
        result = await _backend(request).search(principal.tid, page)
        rows.extend(result.hits)
        if len(result.hits) < page.limit or offset + page.limit >= 10_000:
            break
        offset += page.limit
    await audit.record(
        request,
        "event.export",
        principal=principal,
        details={"rows": len(rows), "format": body.format, "text": (body.query.text or "")[:200]},
    )
    if body.format == "json":
        import json

        return Response(
            json.dumps(rows),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="events.json"'},
        )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([c for c, _ in _EXPORT_COLUMNS])
    for r in rows:
        writer.writerow([service.csv_safe(_dig(r, p)) for _, p in _EXPORT_COLUMNS])
    return Response(
        buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="events.csv"'}
    )
