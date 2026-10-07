"""Deterministic Markdown case report. All free text is escaped for table context; the platform renders
reports as text, never as HTML."""

from datetime import datetime
from typing import Any

from app.cases.schemas import CaseOut
from app.investigations.timeline import Timeline


def _cell(value: Any) -> str:
    return (
        str(value if value is not None else "")
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")[:300]
    )


def build_markdown(
    case: CaseOut,
    *,
    assets: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    timeline: Timeline,
    activity: list[dict[str, Any]],
    generated_at: datetime,
    generated_by: str,
) -> str:
    L: list[str] = [f"# {case.case_id} — {_cell(case.title)}", ""]
    L += [
        "| Field | Value |",
        "|---|---|",
        f"| Status | {case.status} |",
        f"| Severity | {case.severity} |",
        f"| Priority | {case.priority} |",
        f"| Assignee | {_cell(case.assignee.email) if case.assignee else 'unassigned'} |",
        f"| Created | {case.created_at:%Y-%m-%d %H:%M} UTC |",
        f"| Updated | {case.updated_at:%Y-%m-%d %H:%M} UTC |",
        "",
    ]
    L += ["## Description", "", case.description or "_No description._", ""]
    if case.resolution:
        L += ["## Resolution", "", case.resolution, ""]
    L += ["## Affected assets", ""]
    L += (
        [
            "| Type | Name | Criticality |",
            "|---|---|---|",
            *[f"| {_cell(a['type'])} | {_cell(a['display_name'])} | {a['criticality']} |" for a in assets],
        ]
        if assets
        else ["_None linked._"]
    )
    L += ["", "## Indicators of compromise", ""]
    L += (
        [
            "| Type | Value | Occurrences | Source |",
            "|---|---|---|---|",
            *[f"| {i['type']} | `{_cell(i['value'])}` | {i['occurrences']} | {i['source']} |" for i in iocs],
        ]
        if iocs
        else ["_None recorded._"]
    )
    L += ["", "## Evidence", ""]
    L += (
        [
            "| Time (UTC) | Event | Host | ID |",
            "|---|---|---|---|",
            *[
                f"| {_cell(e['timestamp'])} | {_cell(e['summary'])} | {_cell(e['host'])} | `{e['event_id']}` |"
                for e in evidence
            ],
        ]
        if evidence
        else ["_No evidence attached._"]
    )
    L += ["", "## Timeline (derived from telemetry)", ""]
    if timeline.entries:
        for t in timeline.entries:
            span = f" → {t.end_timestamp:%H:%M:%S}" if t.end_timestamp else ""
            period = (
                f" (every ~{t.periodicity.median_interval_s:g}s, jitter {t.periodicity.jitter_pct:g}%)"
                if t.periodicity
                else ""
            )
            L.append(
                f"- `{t.timestamp:%Y-%m-%d %H:%M:%S}`{span} — {_cell(t.title)}{period}"
                + (f" [{_cell(t.host)}]" if t.host else "")
            )
    else:
        L.append("_No telemetry timeline._")
    L += ["", "## Case journal", ""]
    L += [f"- `{a['created_at']:%Y-%m-%d %H:%M}` **{a['kind']}** {_cell(a['body'])}".rstrip() for a in activity] or [
        "_Empty._"
    ]
    L += ["", "---", f"_Generated {generated_at:%Y-%m-%d %H:%M} UTC by {_cell(generated_by)}._", ""]
    return "\n".join(L)
