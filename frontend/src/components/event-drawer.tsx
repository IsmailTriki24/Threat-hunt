"use client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { EventDoc, Filter, TimelineScope } from "@/lib/api-types";
import { useOptionalAuth } from "@/lib/auth";
import { eventIndicators } from "@/lib/intel";
import { fmtTime } from "@/lib/query";
import { IntelOpenButton } from "./intel-action";
import { SeverityBadge } from "./results-table";

type Row = [string, unknown];
const rows = (pairs: Row[]): Row[] => pairs.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length));

function sections(e: EventDoc): Array<[string, Row[]]> {
  const p = e.process, n = e.network;
  return [
    ["Event", rows([["id", e.id], ["timestamp", fmtTime(e.timestamp)], ["source", e.source], ["type", e.event_type], ["action", e.action], ["outcome", e.outcome], ["message", e.message]])],
    ["Host", rows([["hostname", e.host?.hostname], ["id", e.host?.id], ["ip", e.host?.ip?.join(", ")], ["os", e.host?.os]])],
    ["User", rows([["name", e.user?.name], ["domain", e.user?.domain], ["id", e.user?.id]])],
    ["Process", rows([["name", p?.name], ["pid", p?.pid], ["executable", p?.executable], ["command line", p?.command_line], ["sha256", p?.hash?.sha256], ["md5", p?.hash?.md5],
      ["parent", p?.parent?.name], ["parent pid", p?.parent?.pid], ["parent command line", p?.parent?.command_line]])],
    ["Network", rows([["protocol", n?.protocol], ["direction", n?.direction], ["src", n?.src_ip ? `${n.src_ip}:${n.src_port ?? ""}` : undefined],
      ["dst", n?.dst_ip ? `${n.dst_ip}:${n.dst_port ?? ""}` : undefined], ["dst domain", n?.dst_domain], ["bytes", n?.bytes]])],
    ["DNS", rows([["question", e.dns?.question], ["type", e.dns?.query_type], ["answers", e.dns?.answers?.join(", ")]])],
    ["File", rows([["name", e.file?.name], ["path", e.file?.path], ["sha256", e.file?.hash?.sha256]])],
    ["Authentication", rows([["logon type", e.auth?.logon_type], ["method", e.auth?.method], ["source ip", e.auth?.source_ip]])],
    ["Registry", rows([["key", e.registry?.key], ["value", e.registry?.value]])],
    ["Tags / Labels", rows([["tags", e.tags?.join(", ")], ["labels", e.labels ? Object.entries(e.labels).map(([k, v]) => `${k}=${v}`).join(", ") : undefined]])],
  ];
}

export function EventDrawer({ id, onClose, onPivot, onPivotQuery, onTimeline, onAddToCase, snapshot }: {
  id: string; onClose: () => void; onPivot: (f: Filter) => void;
  /** Show the stored event (e.g. case evidence snapshot) instead of fetching live telemetry. */
  snapshot?: EventDoc;
  /** Offer “Add to case…” for this event. */
  onAddToCase?: (eventId: string) => void;
  /** Hunt workspace: append `field:value` to the query editor. */
  onPivotQuery?: (field: string, value: string | number) => void;
  /** Open an investigation timeline around this event. */
  onTimeline?: (eventId: string, scope: TimelineScope, windowMinutes: number) => void;
}) {
  const [scope, setScope] = useState<TimelineScope>("host");
  const [win, setWin] = useState(30);
  const live = useQuery({ queryKey: ["event", id], queryFn: () => api.getEvent(id), enabled: !snapshot });
  const q = snapshot ? { isLoading: false, error: null, data: { event: snapshot, pivots: [] } } : live;
  const [showRaw, setShowRaw] = useState(false);
  const canIntel = useOptionalAuth()?.can("intel:write") ?? false;

  return (
    <aside className="panel fixed right-0 top-9 bottom-0 w-[34rem] max-w-full overflow-y-auto p-3 z-10 shadow-xl" aria-label="Event detail">
      <div className="flex items-center mb-2">
        <h2 className="font-semibold">Event detail</h2>
        {onAddToCase && <button className="btn ml-auto" onClick={() => onAddToCase(id)}>Add to case…</button>}
        <button className={`btn ${onAddToCase ? "ml-1" : "ml-auto"}`} onClick={onClose} aria-label="Close detail">Close</button>
      </div>
      {q.isLoading && <p className="text-muted">Loading…</p>}
      {q.error && <p role="alert" className="text-red-400">{q.error instanceof ApiError ? q.error.friendly : "Failed to load event"}</p>}
      {q.data && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">Severity <SeverityBadge value={q.data.event.severity} /></div>
          {q.data.pivots.length > 0 && (
            <section>
              <h3 className="text-xs text-muted uppercase mb-1">Pivot</h3>
              <div className="flex flex-wrap gap-1">
                {q.data.pivots.map((p) => (
                  <span key={`${p.field}-${p.value}`} className="inline-flex">
                    <button className="btn text-xs" title={`Filter ${p.field} = ${p.value}`}
                      onClick={() => onPivot({ field: p.field, op: "eq", value: String(p.value) })}>
                      {p.label}: <span className="font-mono">{String(p.value).slice(0, 40)}</span>
                    </button>
                    {onPivotQuery && (
                      <button className="btn text-xs" aria-label={`Pivot into hunt query: ${p.field}`} title={`Append ${p.field}:${p.value} to the hunt query`}
                        onClick={() => onPivotQuery(p.field, p.value)}>+query</button>
                    )}
                  </span>
                ))}
              </div>
            </section>
          )}
          {onTimeline && (
            <section>
              <h3 className="text-xs text-muted uppercase mb-1">Timeline</h3>
              <div className="flex items-center gap-1 text-xs">
                <select aria-label="Timeline scope" className="input" value={scope} onChange={(e) => setScope(e.target.value as TimelineScope)}>
                  <option value="host">Host</option><option value="user">User</option><option value="host_user">Host + user</option>
                </select>
                <select aria-label="Timeline window" className="input" value={win} onChange={(e) => setWin(Number(e.target.value))}>
                  {[5, 15, 30, 60, 240, 1440].map((m) => <option key={m} value={m}>±{m >= 60 ? `${m / 60}h` : `${m}m`}</option>)}
                </select>
                <button className="btn" onClick={() => onTimeline(id, scope, win)}>Timeline around this event</button>
              </div>
            </section>
          )}
          {canIntel && eventIndicators(q.data.event).length > 0 && (
            <section>
              <h3 className="text-xs text-muted uppercase mb-1">Threat intelligence</h3>
              <ul className="text-xs space-y-0.5">
                {eventIndicators(q.data.event).map((i) => (
                  <li key={i.value} className="flex items-center gap-2"><span className="text-muted w-24">{i.label}</span><span className="font-mono break-all flex-1">{i.value}</span><IntelOpenButton type={i.type} value={i.value} /></li>
                ))}
              </ul>
            </section>
          )}
          {sections(q.data.event).filter(([, r]) => r.length).map(([title, r]) => (
            <section key={title}>
              <h3 className="text-xs text-muted uppercase mb-0.5">{title}</h3>
              <dl className="grid grid-cols-[8rem_1fr] gap-x-2">
                {r.map(([k, v]) => (<div key={k} className="contents"><dt className="text-muted">{k}</dt><dd className="font-mono break-all">{String(v)}</dd></div>))}
              </dl>
            </section>
          ))}
          <section>
            <button className="btn" onClick={() => setShowRaw((s) => !s)} aria-expanded={showRaw}>{showRaw ? "Hide" : "Show"} raw event</button>
            {showRaw && <pre className="mt-2 bg-bg border border-line p-2 text-xs overflow-x-auto">{JSON.stringify(q.data.event.raw ?? q.data.event, null, 2)}</pre>}
          </section>
        </div>
      )}
    </aside>
  );
}
