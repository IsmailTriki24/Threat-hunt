"""Hunt report engine: turns a finished AI investigation into a structured hunting report (and a case).

Pure and deterministic - no database, no model calls. The model contributes a title, public background and recommendations
when it chooses to (all optional, all treated as untrusted text); everything else is derived from what the platform recorded:
the queries that actually ran and their results, the verified findings, the playbooks followed, the intelligence gathered, and the
gaps. The verdict is conservative by construction: "no threat indicators observed - no further action" is only ever said when the
hunt finished, every check it set out to make was made, and nothing was left unresolved."""

import math
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from app.ai import playbooks

Verdict = Literal["findings", "suspicious", "clean", "clean_with_gaps", "inconclusive"]

VERDICT_LINES: dict[str, str] = {
    "findings": "Threat indicators observed - investigation and response are required",
    "suspicious": "Suspicious activity observed - analyst review is required before this can be dismissed",
    "clean": "No Threat Indicators Observed - No further action is required",
    "clean_with_gaps": (
        "No threat indicators observed in the telemetry that was searched - but some checks could not be completed, "
        "so review the coverage notes before closing"
    ),
    "inconclusive": "Inconclusive - the hunt did not finish or left questions open; this is not a clean result",
}

TELEMETRY_TOOLS = {"search_events", "aggregate_events", "pivot_entity", "events_around", "process_lineage", "get_event"}
TOOL_LABEL = {
    "search_events": "Event search",
    "aggregate_events": "Event aggregation",
    "pivot_entity": "Entity pivot",
    "events_around": "Surrounding activity",
    "process_lineage": "Process tree",
    "get_event": "Event lookup",
}
PURPOSE_TEXT = {
    "test": "Looks for evidence that supports the hypothesis.",
    "refute": "Looks for evidence against the hypothesis, or for a benign explanation.",
    "follow_up": "Follows up a lead from earlier results.",
    "scope": "Measures how widespread the activity is.",
}
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STRONG = {"confirmed", "strongly_supported"}
CONFIDENCE_FOR = {"confirmed": "HIGH", "strongly_supported": "HIGH", "suspicious": "LOW"}
MAX_SECTIONS = 30
# The agent's own mistakes: rejected before any data was touched, and normally corrected on the next try. They belong in the
# investigation trace, not in the report's list of things that could not be checked.
MODEL_MISTAKES = {"invalid_query", "invalid_arguments", "unknown_tool", "unavailable", "budget", "forbidden"}
MAX_ROWS = 5

# Defensive hardening that follows from the tactic hunted (used when the verdict calls for action or the hunt exposed a weakness).
TACTIC_RECOMMENDATIONS: dict[str, str] = {
    "initial-access": "Harden the entry points: enforce phishing-resistant MFA, filter and sandbox inbound attachments and links, and keep internet-facing services patched.",
    "execution": "Restrict script and living-off-the-land execution (application control, PowerShell constrained language mode and script-block logging) and alert on anomalous parent-child process chains.",
    "persistence": "Baseline and monitor persistence locations (scheduled tasks, services, startup items, WMI subscriptions) and alert on new entries created outside change windows.",
    "privilege-escalation": "Remove standing local administrator rights, enforce UAC at its highest setting and monitor for token manipulation and unexpected service creation.",
    "defense-evasion": "Protect the security tooling and its logs: alert on log clearing, tampering with endpoint protection and execution from user-writable paths.",
    "credential-access": "Reduce credential exposure: enable LSASS protection (Credential Guard / RunAsPPL), use long random passwords for service accounts and monitor Kerberos ticket and replication anomalies.",
    "discovery": "Alert on bursts of directory and network enumeration from non-administrative accounts.",
    "lateral-movement": "Limit lateral paths: restrict remote administration protocols to jump hosts, segment the network, and alert on one account authenticating to many hosts.",
    "collection": "Monitor for bulk file access and staging of archives in temporary or public paths.",
    "command-and-control": "Control outbound traffic: egress filtering, proxy inspection and alerting on periodic or rare external connections from servers.",
    "exfiltration": "Monitor and limit outbound data volume and uploads to personal cloud storage; apply data-loss-prevention controls to sensitive repositories.",
    "impact": "Keep tested offline backups, protect shadow copies and alert on mass file modification and recovery-inhibiting commands.",
}

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_TAG = re.compile(r"<[^>\n]{0,300}>")
_LINK = re.compile(r"!?\[([^\]\n]*)\]\(([^)\n]*)\)")
_URL = re.compile(r"^https?://[^\s<>\"']{4,500}$", re.I)


# ---- text safety -----------------------------------------------------------------------------------------------------------------


def clean(text: Any, limit: int = 1500) -> str:
    """Untrusted prose (model output, web titles): no control characters, HTML tags or markdown links, bounded length."""
    s = _CTRL.sub(" ", str(text or ""))
    s = _TAG.sub("", s)
    s = _LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})" if m.group(1) else m.group(2), s)
    # untrusted text must stay prose: no headings, quotes, table rows, fences or rules injected through line-initial markup
    s = re.sub(r"(?m)^[ \t]*(?:#{1,6}|>+|\|+|`{3,}|-{3,}|={3,})[ \t]*", "", s)
    s = re.sub(r"[ \t]+", " ", s).strip()
    return s[:limit]


def cell(text: Any, limit: int = 200) -> str:
    return one_line(text, limit).replace("\\", "\\\\").replace("|", "\\|")


def code(text: Any, limit: int = 600) -> str:
    s = _CTRL.sub(" ", str(text or "")).replace("\n", " ")[:limit]
    return f"`` {s} ``" if "`" in s else f"`{s}`"


def one_line(text: Any, limit: int) -> str:
    s = re.sub(r"\s+", " ", clean(text, limit * 2)).strip()
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


# ---- model ----------------------------------------------------------------------------------------------------------------------


@dataclass
class QuerySection:
    title: str
    description: str
    tool: str
    query: str
    status: str  # SUCCEEDED | PARTIAL | FAILED
    results: int | None
    error: str = ""
    rows: list[dict[str, str]] = field(default_factory=list)
    purpose: str = ""
    ref: str = ""


@dataclass
class HuntReport:
    title: str
    scope: str
    days: int
    verdict: Verdict
    verdict_line: str
    summary: str
    background: str
    severity: str
    priority: str
    confidence: str
    model: str
    run_id: str
    attack: list[dict[str, Any]]
    findings: list[dict[str, Any]]  # threat indicators (severity above INFO)
    observations: list[dict[str, Any]]  # verified but informational findings
    sections: list[QuerySection]
    omitted_sections: int
    intel: list[dict[str, Any]]
    playbooks: list[dict[str, Any]]
    gaps: list[str]  # things that could not be checked: they change the verdict
    notes: list[str]  # telemetry limits and caveats: informational
    recommendations: list[str]
    references: list[dict[str, str]]
    evidence_ids: list[str]
    technique_claims: list[dict[str, Any]]
    indicators: list[dict[str, str]]
    stats: dict[str, int] = field(default_factory=dict)  # headline numbers for the presentation
    hosts: list[dict[str, Any]] = field(default_factory=list)  # events reviewed per host (top few)
    timeline: list[dict[str, Any]] = field(default_factory=list)  # reviewed events over time, the cited ones flagged
    window_start: str = ""
    window_end: str = ""
    hours_back: int = 24
    mode: str = "standard"
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe structure for the presentation layer (the Markdown is the portable form of the same report)."""
        return asdict(self)

    @property
    def case_description(self) -> str:
        """The short text that sits at the top of the case (the full report is the case's report)."""
        parts = [f"**{self.verdict_line}**", "", f"Scope of hunt: {self.scope}", "", self.summary]
        return "\n".join(parts)[:4000]


# ---- helpers --------------------------------------------------------------------------------------------------------------------


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _scope(created: datetime, hours_back: int) -> tuple[str, int, datetime, datetime]:
    end = _aware(created).astimezone(UTC)
    start = end - timedelta(hours=hours_back)
    days = max(1, math.ceil(hours_back / 24))
    if hours_back < 48:
        text = f"the last {hours_back} hour(s): {start:%B %d, %Y %H:%M} through {end:%B %d, %Y %H:%M} (UTC)"
        return text, days, start, end
    return f"{start:%B %d, %Y} through {end:%B %d, %Y} (UTC) - Total Days: {days}", days, start, end


def _title(run: Mapping[str, Any], c: Mapping[str, Any], used: list[str], created: datetime) -> str:
    base = one_line(c.get("report_title") or "", 110)
    if len(base) < 8:
        cat = playbooks.catalog()
        pb = cat.get(used[0]) if used else None
        base = (
            re.sub(r"\s*\(.*?\)\s*$", "", pb.title)
            if pb
            else f"Threat hunt: {one_line(run.get('goal') or 'investigation', 80)}"
        )
    stamp = f"{_aware(created):%B %Y}"
    return base if re.search(r"\b20\d\d\b", base) else f"{base} - {stamp}"


def _max_severity(findings: list[Mapping[str, Any]]) -> str:
    sev = [str(f.get("severity", "MEDIUM")).upper() for f in findings]
    return max(sev, key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 2) if sev else "INFO"


def _attack(
    c: Mapping[str, Any],
    used: list[str],
    evidence: Mapping[str, Any],
    names: Mapping[str, str],
    tactics: Mapping[str, list[str]],
) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    def add(tid: str, src: str) -> None:
        tid = tid.upper()
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid) and tid not in out:
            path = tid.replace(".", "/")
            out[tid] = {
                "id": tid,
                "name": names.get(tid, ""),
                "source": src,
                "tactics": list(tactics.get(tid) or tactics.get(tid.split(".")[0]) or []),
                "url": f"https://attack.mitre.org/techniques/{path}/",
            }

    for f in c.get("findings", []):
        if f.get("supported"):
            for t in f.get("techniques", []):
                add(str(t), "finding")
    cat = playbooks.catalog()
    for pid in used:
        if pid in cat:
            for t in cat[pid].attack:
                add(t, "playbook")
    for e in evidence.values():
        for tag in e.get("tags") or []:
            m = re.fullmatch(r"(?i)attack\.(t\d{4}(?:\.\d{3})?)", str(tag))
            if m:
                add(m.group(1), "sensor tag")
    return list(out.values())[:16]


def _sections(
    steps: list[Mapping[str, Any]],
    state: Mapping[str, Any],
    c: Mapping[str, Any],
    totals: dict[str, int] | None = None,
) -> tuple[list[QuerySection], int]:
    cat = playbooks.catalog()
    hyps = {h.get("id"): h.get("statement", "") for h in c.get("hypotheses", [])}
    queries = {q.get("ref"): q for q in state.get("queries", []) if isinstance(q, dict)}
    evidence = state.get("evidence", {}) or {}
    out: list[QuerySection] = []
    for s in steps:
        if s.get("type") != "tool" or s.get("name") not in TELEMETRY_TOOLS or s.get("auto") or s.get("cached"):
            continue
        if s.get("kind") in MODEL_MISTAKES:
            continue
        inp = s.get("input") if isinstance(s.get("input"), dict) else {}
        tool = str(s["name"])
        query = str(inp.get("query") or "")
        if not query:
            query = " ".join(f"{k}={v}" for k, v in inp.items() if k not in ("purpose", "hypothesis"))
        purpose = str(s.get("purpose") or inp.get("purpose") or "")
        pb = s.get("pb") if isinstance(s.get("pb"), dict) else None
        if pb and pb.get("id") in cat and 0 < int(pb.get("step", 0)) <= len(cat[pb["id"]].steps):
            step = cat[pb["id"]].steps[int(pb["step"]) - 1]
            title = one_line(step.goal.rstrip("."), 90)
            desc = (
                f"What to look for: {one_line(step.look_for, 260)} "
                f"(Playbook step {pb['step']} of {pb['of']}: {cat[pb['id']].title.split(' (')[0]}.)"
            )
        else:
            hid = str(s.get("hypothesis") or inp.get("hypothesis") or "")
            title = f"{TOOL_LABEL[tool]}: {one_line(query, 70)}"
            base = PURPOSE_TEXT.get(purpose, "")
            desc = (f"{base} " if base else "") + (
                f"Hypothesis {hid}: {one_line(hyps[hid], 200)}" if hid in hyps else ""
            )
            desc = desc.strip() or f"{TOOL_LABEL[tool]} run by the investigation."
        failed = s.get("status") == "error" or bool(s.get("error"))
        status = "FAILED" if failed else ("PARTIAL" if s.get("status") == "partial" else "SUCCEEDED")
        total = (
            s.get("total")
            if isinstance(s.get("total"), int)
            else (s.get("returned") if isinstance(s.get("returned"), int) else None)
        )
        rows: list[dict[str, str]] = []
        if not failed and tool != "aggregate_events":
            rec = queries.get(s.get("ref")) or {}
            for eid in (rec.get("event_ids") or [])[:MAX_ROWS]:
                e = evidence.get(eid)
                if e:
                    rows.append(
                        {
                            "time": str(e.get("timestamp") or "")[:19].replace("T", " "),
                            "host": str(e.get("host") or ""),
                            "user": str(e.get("user") or ""),
                            "summary": str(e.get("summary") or ""),
                            "id": str(eid),
                        }
                    )
        out.append(
            QuerySection(
                title=title, description=desc, tool=tool, query=query, status=status, results=None if failed else total,
                error=clean(s.get("error") or "", 200) if failed else "", rows=rows, purpose=purpose, ref=str(s.get("ref") or ""),
            )
        )  # fmt: skip
    if totals is not None:
        totals.update(
            queries=len(out),
            with_results=sum(1 for q in out if q.status != "FAILED" and (q.results or 0) > 0),
            no_results=sum(1 for q in out if q.status != "FAILED" and not q.results),
            failed=sum(1 for q in out if q.status == "FAILED"),
        )
    return out[:MAX_SECTIONS], max(0, len(out) - MAX_SECTIONS)


def _gaps(
    run: Mapping[str, Any], c: Mapping[str, Any], sections: list[QuerySection], progress: list[Mapping[str, Any]]
) -> tuple[list[str], list[str]]:
    gaps: list[str] = []
    notes: list[str] = []
    for s in sections:
        if s.status == "FAILED":
            gaps.append(
                f"A search could not be completed ({s.error or 'error'}); its result is unknown: {one_line(s.title, 80)}"
            )
    for pb in progress:
        if pb.get("feasibility") in ("blocked", "partial"):
            gaps.append(
                f"Playbook '{one_line(pb['title'], 80)}' needs telemetry this environment does not provide ({pb['feasibility']}); that part of the hunt could not be done."
            )
        total, ran = int(pb.get("total") or 0), int(pb.get("run") or 0)
        if total and ran / total < 0.75:
            gaps.append(
                f"Playbook '{one_line(pb['title'], 80)}' was only partly followed: {ran} of {total} steps were run."
            )
        missing = [x for x in pb.get("steps", []) if not x.get("done") and x.get("purpose") in ("refute", "scope")]
        if missing:
            gaps.append(
                f"Playbook '{one_line(pb['title'], 80)}': {len(missing)} refute/scope step(s) were not run: {one_line(missing[0]['goal'], 100)}"
            )
    for q in c.get("unresolved_questions", []):
        gaps.append(f"Open question: {one_line(q, 200)}")
    cov = c.get("coverage") or {}
    for g in cov.get("gaps", []):
        if re.match(r"no \w+ telemetry in the window", str(g)):
            notes.append(one_line(g, 200))  # a limit of the environment, not a failure of this hunt
        elif not str(g).startswith("declared:"):
            gaps.append(one_line(g, 200))
        else:
            gaps.append(one_line(str(g)[len("declared:") :].strip(), 200))
    for n in c.get("validation_notes", []):
        notes.append(one_line(n, 240))
    if c.get("forced"):
        gaps.append("The investigation was concluded before every check it planned had been made.")
    rejected = sum(1 for s in run.get("steps", []) if s.get("type") == "tool" and s.get("kind") in MODEL_MISTAKES)
    if rejected:
        notes.append(
            f"{rejected} search attempt(s) were rejected as malformed before reaching the data and are listed only in the investigation trace."
        )
    dedup = lambda xs: list(dict.fromkeys(xs))  # noqa: E731
    return _group_gaps(dedup(gaps))[:20], dedup(notes)[:12]


_PREFIX = re.compile(
    r"(?i)^\s*(?:confirmed|strongly[ _]supported|suspicious|unverified|benign[ _]plausible)\s*[:\-–—]\s*"
)
_NOT_PRESENT = re.compile(
    r"(?i)\b(?:is|are|was|were|does|do|did)\s+not\b.*\b(?:occurring|present|detected|observed|found|happening|evident|visible|exist\w*)\b"
)


def _bare_title(title: Any) -> str:
    """The model often prefixes its own classification ("Confirmed: ..."); the report shows that as a badge, not in the title."""
    return _PREFIX.sub("", str(title or ""), count=1)


_NEGATIVE = re.compile(
    r"(?i)^\s*(?:no|not|none|nothing|absence of|lack of)\b.*\b(?:detected|observed|found|evidence|indications?|signs?|activity|anomal\w+|indicators?|"
    r"appear\w*|present|seen|identified)\b"
)


def _group_gaps(gaps: list[str]) -> list[str]:
    """Collapse the repetitive kinds - one line per unexplored lead, per partly-read search, per open hypothesis - into one line each."""
    rest: list[str] = []
    leads: list[str] = []
    partial = 0
    failed: list[str] = []
    hyps: list[str] = []
    for g in gaps:
        lead = re.search(r"unexplored lead\s+(\S+)", g)
        hyp = re.search(r"\b(H\d+) \[(?:open|inconclusive)\]\s*(.*)", g)
        if lead:
            leads.append(lead.group(1))
        elif re.search(r"only part of \d+ matches was read", g):
            partial += 1
        elif re.match(r"(?i)^(q\d+) \w+: telemetry backend failed", g):
            failed.append(g.split()[0])
        elif hyp:
            hyps.append(f"{hyp.group(1)}: {one_line(hyp.group(2), 70)}")
        else:
            rest.append(g)
    if leads:
        short = [v if len(v) <= 24 else f"{v[:14]}…{v[-6:]}" for v in leads[:3]]
        rest.append(
            f"{len(leads)} unexplored lead(s) were not followed up, e.g. {', '.join(short)}"
            + (f" and {len(leads) - 3} more" if len(leads) > 3 else "")
        )
    if failed:
        rest.append(
            f"{len(failed)} search(es) failed with a backend error and are unanswered, not negative ({', '.join(failed[:5])}{'…' if len(failed) > 5 else ''})"
        )
    if partial:
        rest.append(f"{partial} search(es) read only part of their matches, so those results are incomplete")
    if hyps:
        rest.append(
            f"{len(hyps)} hypothesis(es) were left open: "
            + "; ".join(hyps[:3])
            + (f"; and {len(hyps) - 3} more" if len(hyps) > 3 else "")
        )
    return rest


def _is_threat(f: Mapping[str, Any]) -> bool:
    """A finding is a threat indicator only if it carries real severity and reports something that IS there. INFO findings and
    findings that report an absence ("No privilege escalation detected", "Office never appears") are observations: they must not turn
    a clean or unanswerable hunt into an incident. ("No MFA enforced on admin accounts" still counts - it reports a weakness.)"""
    title = _bare_title(f.get("title"))
    absent = bool(_NEGATIVE.match(title) or _NOT_PRESENT.search(title))
    return str(f.get("severity", "MEDIUM")).upper() != "INFO" and not absent


def _verdict(
    run: Mapping[str, Any], c: Mapping[str, Any], findings: list[Mapping[str, Any]], gaps: list[str]
) -> Verdict:
    findings = [f for f in findings if _is_threat(f)]
    strong = [f for f in findings if f.get("classification") in STRONG]
    if strong:
        return "findings"
    if any(f.get("classification") == "suspicious" for f in findings):
        return "suspicious"
    open_h = [h for h in c.get("hypotheses", []) if h.get("status") in ("open", "inconclusive")]
    stop = str(c.get("stop_reason") or "")
    if run.get("status") != "COMPLETED" or c.get("forced") or stop.startswith("budget") or open_h:
        return "inconclusive"
    if gaps or c.get("confidence") == "LOW":
        return "clean_with_gaps"
    return "clean"


def _recommendations(
    c: Mapping[str, Any], verdict: str, used: list[str], progress: list[Mapping[str, Any]], gaps: list[str]
) -> list[str]:
    out: list[str] = [one_line(r, 300) for r in c.get("recommendations", []) if len(one_line(r, 300)) >= 12]
    out += [one_line(n, 300) for n in c.get("next_steps", []) if len(one_line(n, 300)) >= 12]
    if verdict in ("findings", "suspicious"):
        out.append(
            "Review the cited evidence events and contain the affected hosts and accounts (isolate endpoints, revoke sessions, reset credentials) while the scope is established."
        )
    cat = playbooks.catalog()
    tactics = list(dict.fromkeys(t for pid in used if pid in cat for t in cat[pid].tactics))
    if verdict in ("findings", "suspicious") or gaps:
        out += [TACTIC_RECOMMENDATIONS[t] for t in tactics if t in TACTIC_RECOMMENDATIONS][:3]
    blocked = sorted(
        {m for pb in progress if pb.get("feasibility") in ("blocked", "partial") for m in pb.get("missing", [])}
    )
    if blocked:
        out.append(
            f"Close the telemetry gaps that limited this hunt: ingest {', '.join(blocked)} data so the affected checks can run."
        )
    if verdict in ("clean", "clean_with_gaps"):
        out.append(
            "Repeat this hunt on a schedule and after relevant threat-intelligence updates; absence of evidence today does not guarantee absence tomorrow."
        )
    if verdict == "inconclusive":
        out.append("Resume or re-run the investigation with a larger budget before drawing a conclusion.")
    return list(dict.fromkeys(out))[:10]


def _references(steps: list[Mapping[str, Any]], attack: list[dict[str, str]], used: list[str]) -> list[dict[str, str]]:
    refs: dict[str, dict[str, str]] = {}
    for s in steps:
        for src in s.get("sources") or []:
            url = str(src.get("url") or "")
            if _URL.match(url) and url not in refs:
                refs[url] = {"title": one_line(src.get("title") or src.get("domain") or url, 140), "url": url}
    for a in attack[:8]:
        refs.setdefault(
            a["url"], {"title": f"MITRE ATT&CK {a['id']}" + (f": {a['name']}" if a["name"] else ""), "url": a["url"]}
        )
    if used:
        url = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills"
        refs.setdefault(
            url,
            {"title": "Threat-hunting procedures adapted from Anthropic-Cybersecurity-Skills (Apache-2.0)", "url": url},
        )
    return list(refs.values())[:14]


def _stats(
    totals: Mapping[str, int],
    evidence: Mapping[str, Any],
    findings: list[Any],
    observations: list[Any],
    attack: list[Any],
    gaps: list[str],
    progress: list[Mapping[str, Any]],
) -> dict[str, int]:
    return {
        "queries": int(totals.get("queries", 0)),
        "with_results": int(totals.get("with_results", 0)),
        "no_results": int(totals.get("no_results", 0)),
        "failed": int(totals.get("failed", 0)),
        "events_reviewed": len(evidence),
        "hosts": len({e.get("host") for e in evidence.values() if e.get("host")}),
        "findings": len(findings),
        "observations": len(observations),
        "techniques": len(attack),
        "gaps": len(gaps),
        "playbook_steps": sum(int(p.get("total") or 0) for p in progress),
        "playbook_steps_run": sum(int(p.get("run") or 0) for p in progress),
    }


def _hosts(evidence: Mapping[str, Any], top: int = 8) -> list[dict[str, Any]]:
    counts = Counter(str(e.get("host") or "unknown") for e in evidence.values())
    return [{"host": h, "events": n} for h, n in counts.most_common(top)]


def _timeline(evidence: Mapping[str, Any], cited: set[str], cap: int = 150) -> list[dict[str, Any]]:
    """The events the hunt reviewed, in time order. Cited ones are always kept; the rest are thinned evenly if there are many."""
    rows = [
        {
            "id": str(e.get("id") or i),
            "timestamp": e.get("timestamp"),
            "host": e.get("host"),
            "user": e.get("user"),
            "event_type": e.get("event_type"),
            "summary": one_line(e.get("summary"), 140),
            "cited": (e.get("id") or i) in cited,
        }
        for i, e in evidence.items()
        if e.get("timestamp")
    ]
    keep = [r for r in rows if r["cited"]]
    rest = [r for r in rows if not r["cited"]]
    room = max(0, cap - len(keep))
    if len(rest) > room and room:
        step = len(rest) / room
        rest = [rest[int(i * step)] for i in range(room)]
    elif not room:
        rest = []
    return sorted(keep + rest, key=lambda r: str(r["timestamp"]))


# ---- build ----------------------------------------------------------------------------------------------------------------------


def build(
    run: Mapping[str, Any],
    *,
    technique_names: Mapping[str, str] | None = None,
    technique_tactics: Mapping[str, list[str]] | None = None,
) -> HuntReport:
    """`run` carries: id, goal, hours_back, mode, model, status, created_at, steps, conclusion, state."""
    names = technique_names or {}
    tactics = technique_tactics or {}
    c: Mapping[str, Any] = run.get("conclusion") or {}
    state: Mapping[str, Any] = run.get("state") or {}
    steps: list[Mapping[str, Any]] = list(run.get("steps") or [])
    created = run.get("created_at") or datetime.now(UTC)
    used = [str(p) for p in (c.get("playbooks_used") or [])]
    progress = [p for p in (c.get("playbooks") or []) if isinstance(p, dict)]
    evidence = state.get("evidence", {}) or {}
    all_findings = [f for f in c.get("findings", []) if isinstance(f, dict)]
    findings = sorted(
        [f for f in all_findings if f.get("supported")],
        key=lambda f: (
            -SEVERITY_ORDER.index(str(f.get("severity", "MEDIUM")).upper())
            if str(f.get("severity", "MEDIUM")).upper() in SEVERITY_ORDER
            else -2
        ),
    )
    findings = [{**f, "title": one_line(_bare_title(f.get("title")), 160)} for f in findings]
    observations = [f for f in findings if not _is_threat(f)]
    findings = [f for f in findings if _is_threat(f)]
    totals: dict[str, int] = {}
    sections, omitted = _sections(steps, state, c, totals)
    gaps, notes = _gaps(run, c, sections, progress)
    discarded = len(all_findings) - len(findings) - len(observations)
    if discarded:
        notes.append(
            f"{discarded} claim(s) by the model were discarded because they cited no event that was actually retrieved."
        )
    verdict = _verdict(run, c, findings, gaps)
    scope, days, w_start, w_end = _scope(created, int(run.get("hours_back") or 24))
    attack = _attack(c, used, evidence, names, tactics or {})
    cat = playbooks.catalog()
    background = clean(c.get("threat_background") or "", 2000)
    if not background and used:
        background = " ".join(f"{cat[p].summary} {cat[p].hypothesis}" for p in used[:2] if p in cat)
    if not background:
        hs = [one_line(h.get("statement", ""), 220) for h in c.get("hypotheses", []) if h.get("statement")]
        background = (
            "Hypotheses tested: " + "; ".join(hs[:4])
            if hs
            else f"This hunt examined: {one_line(run.get('goal') or '', 300)}"
        )
    evidence_ids = list(dict.fromkeys(i for f in findings for i in f.get("event_ids", [])))[:50]
    claims = [
        {
            "technique_id": t.upper(),
            "confidence": CONFIDENCE_FOR.get(f.get("classification"), "LOW"),
            "reasoning": one_line(f"{f.get('title', '')}: {f.get('description', '')}", 400),
            "event_ids": list(f.get("event_ids", []))[:20],
        }
        for f in findings
        for t in f.get("techniques", [])
        if re.fullmatch(r"(?i)T\d{4}(?:\.\d{3})?", str(t))
    ]
    indicators = [
        {
            "type": {"hash": "sha256"}.get(str(v.get("kind")), str(v.get("kind"))),
            "value": str(v.get("value")),
            "context": f"AI enrichment: {v.get('verdict')}",
        }
        for v in (c.get("intel") or {}).values()
        if v.get("verdict") in ("malicious", "suspicious")
        and v.get("value")
        and v.get("kind") in ("ip", "domain", "url", "hash")
    ]
    sev = (
        _max_severity(findings)
        if verdict in ("findings", "suspicious")
        else ("LOW" if verdict in ("clean_with_gaps", "inconclusive") else "INFO")
    )
    if verdict == "suspicious" and SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index("MEDIUM"):
        sev = "MEDIUM"
    priority = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3"}.get(sev, "P4")
    return HuntReport(
        title=_title(run, c, used, created),
        scope=scope,
        days=days,
        verdict=verdict,
        verdict_line=VERDICT_LINES[verdict],
        summary=clean(c.get("summary") or "No conclusion was produced.", 3000),
        background=background,
        severity=sev,
        priority=priority,
        confidence=str(c.get("confidence") or "LOW"),
        model=str(run.get("model") or ""),
        run_id=str(run.get("id") or ""),
        attack=attack,
        findings=findings,
        observations=observations,
        sections=sections,
        omitted_sections=omitted,
        intel=sorted(
            (c.get("intel") or {}).values(),
            key=lambda v: (
                ["malicious", "suspicious", "unknown", "benign"].index(v.get("verdict", "unknown"))
                if v.get("verdict") in ("malicious", "suspicious", "unknown", "benign")
                else 2
            ),
        ),
        playbooks=progress,
        gaps=gaps,
        notes=notes,
        recommendations=_recommendations(c, verdict, used, progress, gaps),
        references=_references(steps, attack, used),
        evidence_ids=evidence_ids,
        technique_claims=claims,
        indicators=indicators,
        stats=_stats(totals, evidence, findings, observations, attack, gaps, progress),
        hosts=_hosts(evidence),
        timeline=_timeline(evidence, set(evidence_ids)),
        window_start=w_start.isoformat(),
        window_end=w_end.isoformat(),
        hours_back=int(run.get("hours_back") or 24),
        mode=str(run.get("mode") or "standard"),
    )


# ---- markdown -------------------------------------------------------------------------------------------------------------------


def to_markdown(r: HuntReport) -> str:
    L: list[str] = [f"# {r.title}", "", "## Hunting Summary", ""]
    L += [f"**Scope of Hunt:** {r.scope}", ""]
    L += [r.summary, "", f"> **{r.verdict_line}**", ""]
    L += ["## Details", "", r.background, ""]
    if r.attack:
        L += ["**Related ATT&CK Techniques**", ""]
        L += [
            f"- [{a['id']}]({a['url']})" + (f" - {cell(a['name'], 80)}" if a["name"] else "") + f" _({a['source']})_"
            for a in r.attack
        ]
        L.append("")
    if r.findings:
        L += ["## Findings", ""]
        for i, f in enumerate(r.findings, 1):
            L += [f"### {i}. {cell(f.get('title'), 160)}", ""]
            L += [
                f"**Severity:** {f.get('severity', 'MEDIUM')} · **Assessment:** {str(f.get('classification', 'unverified')).replace('_', ' ')}",
                "",
            ]
            L += [clean(f.get("description"), 1500), ""]
            if f.get("event_ids"):
                L += ["Evidence events: " + ", ".join(code(i, 40) for i in f["event_ids"][:10]), ""]
            if f.get("queries"):
                L += ["Found by searches: " + ", ".join(code(q, 20) for q in f["queries"][:8]), ""]
            if f.get("alternative_explanations"):
                L += [
                    "Benign explanations considered: "
                    + "; ".join(one_line(a, 160) for a in f["alternative_explanations"][:5]),
                    "",
                ]
    if r.observations:
        L += ["## Observations", "", "_Verified, but informational - not threat indicators._", ""]
        for f in r.observations:
            L += [f"- **{cell(f.get('title'), 160)}** - {one_line(f.get('description'), 400)}"]
            if f.get("event_ids"):
                L += ["  Evidence events: " + ", ".join(code(i, 40) for i in f["event_ids"][:5])]
        L.append("")
    if r.sections:
        L += ["## Hunt Queries", ""]
        for s in r.sections:
            L += [f"### {cell(s.title, 120)}", "", s.description, ""]
            res = "-" if s.results is None else str(s.results)
            L += ["| Search | Status | Results |", "|---|---|---|", f"| {cell(s.title, 80)} | {s.status} | {res} |", ""]
            L += [f"Query: {code(s.query)}", ""]
            if s.status == "FAILED":
                L += [f"_The search failed ({cell(s.error or 'error', 160)}); its result is unknown, not empty._", ""]
            elif s.results == 0:
                L += ["_No results returned for this query_", ""]
            elif s.rows:
                L += ["| Time (UTC) | Host | User | Event |", "|---|---|---|---|"]
                L += [
                    f"| {cell(x['time'], 19)} | {cell(x['host'], 60)} | {cell(x['user'], 40)} | {cell(x['summary'], 160)} |"
                    for x in s.rows
                ]
                shown = len(s.rows)
                if s.results and s.results > shown:
                    L += ["", f"_Showing {shown} of {s.results} results._"]
                L.append("")
        if r.omitted_sections:
            L += [f"_{r.omitted_sections} further search(es) are recorded in the AI run's investigation trace._", ""]
    if r.playbooks:
        L += ["## Hunt Playbooks Followed", ""]
        for p in r.playbooks:
            L += [
                f"**{cell(p['title'], 120)}** - {p.get('run', 0)}/{p.get('total', 0)} steps run (telemetry: {p.get('feasibility', 'unknown')})",
                "",
            ]
            L += [
                f"- {'[x]' if x.get('done') else '[ ]'} {cell(x.get('goal'), 140)} _({x.get('purpose')})_"
                for x in p.get("steps", [])
            ]
            L.append("")
    if r.intel:
        L += ["## Threat Intelligence on Indicators Met", "", "| Indicator | Verdict | Sources |", "|---|---|---|"]
        for v in r.intel[:25]:
            srcs = (
                "; ".join(
                    f"{p.get('provider')}: {p.get('summary') or p.get('verdict') or p.get('status')}"
                    for p in v.get("providers", [])
                )
                or "no provider answered"
            )
            L.append(
                f"| {cell(v.get('kind'), 10)} {code(str(v.get('value'))[:80], 90)} | {cell(v.get('verdict'), 12)} | {cell(srcs, 200)} |"
            )
        L += [
            "",
            '_External context, not evidence from this environment. "Unknown" means no source had an opinion, not that it is safe._',
            "",
        ]
    if r.gaps or r.notes:
        L += ["## Coverage and Gaps", ""]
        if r.gaps:
            L += ["**Could not be checked or left open:**", ""] + [f"- {g}" for g in r.gaps] + [""]
        if r.notes:
            L += ["**Limits and notes:**", ""] + [f"- {n}" for n in r.notes] + [""]
    if r.recommendations:
        L += ["## Recommendations", ""] + [f"- {x}" for x in r.recommendations] + [""]
    if r.references:
        L += ["## References", ""] + [f"- [{cell(x['title'], 140)}]({x['url']})" for x in r.references] + [""]
    L += [
        "---",
        f"_Generated by the AI hunting agent ({cell(r.model, 60) or 'model'}), run {r.run_id}. AI-generated analysis: every cited event was retrieved from this environment's telemetry, but the interpretation can be wrong - review the evidence before acting._",
        "",
    ]
    return "\n".join(L)
