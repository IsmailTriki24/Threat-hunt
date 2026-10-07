"use client";
import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { EventQueryBody, Timeline, TimelineEntry, TimelineScope } from "@/lib/api-types";
import { BEACON_WORDING, entryForEvent, isBeaconLike, lineageDepths, periodicityLabel } from "@/lib/hunt-query";
import { fmtTime } from "@/lib/query";
import { SeverityBadge } from "./results-table";

const MARKER: Record<string, string> = {
  process_creation: "▶", network_connection: "⇄", dns_query: "◇", file_event: "▤", authentication: "●",
  scheduled_task: "⏱", service_install: "⚙", registry_event: "▦", alert: "!",
};

export function TimelineList({ timeline, onOpen }: { timeline: Timeline; onOpen: (eventId: string) => void }) {
  const [hl, setHl] = useState<string | null>(null);
  const refs = useRef(new Map<string, HTMLLIElement>());
  const depths = lineageDepths(timeline);

  function jump(e: TimelineEntry, eventId: string) {
    const target = entryForEvent(timeline, eventId);
    if (!target || target === e) return;
    setHl(target.id);
    refs.current.get(target.id)?.scrollIntoView?.({ block: "center", behavior: "smooth" });
  }

  if (!timeline.entries.length) return <p className="panel p-3 text-muted">No events in this scope.</p>;
  return (
    <div>
      <p className="text-xs text-muted mb-1">
        {timeline.entries.length} entries from {timeline.total_events} events
      </p>
      {timeline.truncated && (
        <p role="alert" className="panel p-2 mb-1 text-yellow-300 text-xs">
          Timeline truncated: more events matched than the limit. Narrow the scope or time range.
        </p>
      )}
      <ol className="space-y-0.5">
        {timeline.entries.map((e) => {
          const depth = Math.min(depths.get(e.id) ?? 0, 6);
          const parentId = e.parent_event_id ?? e.process_event_id;
          const label = periodicityLabel(e);
          const range = e.end_timestamp ? `${fmtTime(e.timestamp)} → ${fmtTime(e.end_timestamp).slice(11)}` : fmtTime(e.timestamp);
          return (
            <li key={e.id} id={`tl-${e.id}`} data-testid="timeline-entry" ref={(el) => { if (el) refs.current.set(e.id, el); }}
              style={{ marginLeft: depth * 16 }}
              className={`panel px-2 py-1 border-l-2 ${hl === e.id ? "border-accent bg-bg" : "border-line"}`}>
              <div className="flex items-baseline gap-2">
                <span aria-hidden className="w-4 text-center text-accent">{MARKER[e.event_type] ?? "·"}</span>
                <span className="font-mono text-xs text-muted whitespace-nowrap">{range}</span>
                <button className="text-left hover:text-accent font-medium" onClick={() => onOpen(e.event_ids[0])}>{e.title}</button>
                <span className="ml-auto flex items-center gap-2">
                  {e.count > 1 && <span className="text-xs border border-line px-1 rounded-sm" title="collapsed events">{e.count} events</span>}
                  <SeverityBadge value={e.severity} />
                </span>
              </div>
              <div className="pl-6 text-xs text-muted flex flex-wrap gap-x-3">
                <span>{e.event_type}</span>
                {e.host && <span>host {e.host}</span>}
                {e.user && <span>user {e.user}</span>}
                {e.process && <span>proc {e.process}{e.pid ? `:${e.pid}` : ""}</span>}
                {e.destination && <span>→ {e.destination}</span>}
                {parentId && (
                  <button className="hover:text-accent underline decoration-dotted" onClick={() => jump(e, parentId)}>
                    ↳ {e.parent_event_id ? "spawned by parent" : "caused by process"}
                  </button>
                )}
              </div>
              {label && (
                <div className="pl-6 text-xs">
                  <span className="font-mono">{label}</span>
                  {isBeaconLike(e) && <span className="ml-2 text-orange-300">{BEACON_WORDING}</span>}
                </div>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export type TimelineSource =
  | { kind: "query"; query: Partial<EventQueryBody>; label?: string }
  | { kind: "around"; eventId: string; scope: TimelineScope; windowMinutes: number };

/** Fetches (POST /timeline or /timeline/around) and renders a timeline with the collapse toggle. */
export function TimelinePanel({ source, onOpen }: { source: TimelineSource | null; onOpen: (eventId: string) => void }) {
  const [collapse, setCollapse] = useState(true);
  const q = useQuery({
    queryKey: ["timeline", JSON.stringify(source), collapse],
    queryFn: () => source!.kind === "query"
      ? api.timeline(source!.query, collapse)
      : api.timelineAround(source!.eventId, source!.scope, source!.windowMinutes, collapse),
    enabled: source !== null,
    retry: false,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  if (!source) return <p className="panel p-3 text-muted">Build a timeline from the current query, or open an event and choose “Timeline around this event”.</p>;
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3 text-xs">
        <span className="text-muted">{source.kind === "around" ? `Around event ${source.eventId.slice(0, 8)}… (${source.scope.replace("_", "+")}, ±${source.windowMinutes}m)` : "From query"}</span>
        <label className="ml-auto flex items-center gap-1">
          <input type="checkbox" checked={collapse} onChange={(e) => setCollapse(e.target.checked)} /> Collapse repeated activity
        </label>
      </div>
      {q.isLoading && <p className="text-muted">Building timeline…</p>}
      {q.error && <p role="alert" className="panel p-2 text-red-400">{q.error instanceof ApiError ? q.error.friendly : "Timeline failed"}</p>}
      {q.data && <TimelineList timeline={q.data} onOpen={onOpen} />}
    </div>
  );
}
