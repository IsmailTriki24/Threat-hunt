"""Investigation timeline built from telemetry only: process lineage is reconstructed by matching
(host, pid) between events, repeated activity is collapsed, and periodicity is measured, not assumed."""

import statistics
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.events.summary import summarize

COLLAPSE_GAP_S = 300
MIN_GROUP = 3


class Periodicity(BaseModel):
    median_interval_s: float
    jitter_pct: float  # stddev / mean of intervals; low values indicate machine-like regularity


class TimelineEntry(BaseModel):
    id: str  # first underlying event
    timestamp: datetime
    end_timestamp: datetime | None = None
    count: int = 1
    event_type: str
    title: str
    severity: int = 0
    host: str | None = None
    user: str | None = None
    process: str | None = None
    pid: int | None = None
    destination: str | None = None
    parent_event_id: str | None = None  # process_creation: the event that created the parent process
    process_event_id: str | None = None  # other types: the process_creation event of the acting process
    event_ids: list[str]
    periodicity: Periodicity | None = None


class Timeline(BaseModel):
    entries: list[TimelineEntry]
    total_events: int
    truncated: bool


def _ts(doc: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(doc["timestamp"].replace("Z", "+00:00"))


def _get(doc: dict[str, Any], *path: str) -> Any:
    for p in path:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(p)  # type: ignore[assignment]
    return doc


def _lower(v: Any) -> str | None:
    return v.lower() if isinstance(v, str) else None


def build(docs: list[dict[str, Any]], *, truncated: bool = False, collapse: bool = True) -> Timeline:
    docs = sorted(docs, key=lambda d: (d["timestamp"], d["id"]))
    creators: dict[tuple[str | None, int], list[tuple[datetime, str, str | None]]] = {}
    for d in docs:
        pid = _get(d, "process", "pid")
        if d.get("event_type") == "process_creation" and isinstance(pid, int):
            creators.setdefault((_lower(_get(d, "host", "hostname")), pid), []).append(
                (_ts(d), d["id"], _lower(_get(d, "process", "name")))
            )

    def find_creator(host: str | None, pid: Any, at: datetime, name: str | None, exclude: str) -> str | None:
        if not isinstance(pid, int):
            return None
        for ts, eid, pname in reversed(creators.get((host, pid), [])):
            if eid != exclude and ts <= at and (name is None or pname == name):
                return eid
        return None

    entries: list[TimelineEntry] = []
    open_groups: dict[tuple[Any, ...], TimelineEntry] = {}
    stamps: dict[str, list[datetime]] = {}
    for d in docs:
        ts, host = _ts(d), _lower(_get(d, "host", "hostname"))
        etype = d.get("event_type", "other")
        dst = _get(d, "network", "dst_domain") or _get(d, "network", "dst_ip") or _get(d, "dns", "question")
        port = _get(d, "network", "dst_port")
        entry = TimelineEntry(
            id=d["id"],
            timestamp=ts,
            event_type=etype,
            title=summarize(d),
            severity=d.get("severity", 0),
            host=_get(d, "host", "hostname"),
            user=_get(d, "user", "name"),
            process=_get(d, "process", "name"),
            pid=_get(d, "process", "pid"),
            destination=f"{dst}:{port}" if dst and port else dst,
            event_ids=[d["id"]],
        )
        if etype == "process_creation":
            entry.parent_event_id = find_creator(
                host, _get(d, "process", "parent", "pid"), ts, _lower(_get(d, "process", "parent", "name")), d["id"]
            )
        else:
            entry.process_event_id = find_creator(host, entry.pid, ts, _lower(entry.process), d["id"])

        if collapse and etype != "process_creation":
            key = (
                etype,
                host,
                _lower(entry.process),
                entry.destination,
                d.get("action"),
                d.get("outcome"),
                _lower(entry.user),
            )
            group = open_groups.get(key)
            if group and (ts - (group.end_timestamp or group.timestamp)).total_seconds() <= COLLAPSE_GAP_S:
                group.count += 1
                group.end_timestamp = ts
                group.severity = max(group.severity, entry.severity)
                if len(group.event_ids) < 50:
                    group.event_ids.append(d["id"])
                stamps[group.id].append(ts)
                continue
            open_groups[key] = entry
            stamps[entry.id] = [ts]
        entries.append(entry)

    for e in entries:
        times = stamps.get(e.id, [])
        if e.count >= MIN_GROUP and len(times) >= 5:
            gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
            mean = statistics.fmean(gaps)
            if mean > 0:
                e.periodicity = Periodicity(
                    median_interval_s=round(statistics.median(gaps), 1),
                    jitter_pct=round(100 * statistics.pstdev(gaps) / mean, 1),
                )
        if e.count >= 2:
            e.title = f"{e.title}  ×{e.count}"
    return Timeline(entries=entries, total_events=len(docs), truncated=truncated)
