"use client";
import { CircleAlert, CircleCheck, Info, Loader2, RefreshCw, Search } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { fmtTime } from "@/lib/query";
import { SIEM_QUIET, siemHeadline, type SiemResult } from "@/lib/siem";

interface QueryLike { data?: SiemResult; isFetching: boolean; isError: boolean; error: unknown; refetch: () => unknown }

function Elapsed() {
  const [s, setS] = useState(0);
  useEffect(() => { const t = window.setInterval(() => setS((n) => n + 1), 1000); return () => window.clearInterval(t); }, []);
  return <span className="tabular-nums text-muted">{s}s</span>;
}

/** What the whole-SIEM (LogRhythm) search is doing for the search above, in plain words. Quiet when the SIEM is not configured. */
export function SiemSearchCard({ query, onShow, label = "LogRhythm SIEM", compact }: { query: QueryLike; onShow?: () => void; label?: string; compact?: boolean }) {
  const d = query.data;
  if (d && SIEM_QUIET.includes(d.status)) return null;
  const box = "flex flex-wrap items-start gap-x-3 gap-y-1 rounded-lg border px-3.5 py-2.5 text-sm";
  if (!d && query.isFetching) {
    return (
      <div role="status" className={`${box} border-accent/25 bg-accent-soft/60`}>
        <Loader2 aria-hidden className="mt-0.5 h-4 w-4 animate-spin text-accent" />
        <span className="font-medium text-ink">Searching the whole {label}…</span>
        <span className="text-xs text-muted">Not only the collected slice. This can take up to a minute. <Elapsed /></span>
      </div>
    );
  }
  if (query.isError || d?.status === "error") {
    return (
      <div role="alert" className={`${box} border-sev-critical/30 bg-sev-critical-bg text-sev-critical`}>
        <CircleAlert aria-hidden className="mt-0.5 h-4 w-4 shrink-0" />
        <div className="min-w-0 flex-1"><p className="font-medium">The whole-SIEM search failed</p><p className="text-xs opacity-90">{d?.detail || (query.error instanceof Error ? query.error.message : "Could not reach the SIEM")}. Results below only include what was already collected.</p></div>
        <button className="btn btn-sm" onClick={() => void query.refetch()}><RefreshCw aria-hidden className="h-3 w-3" />Retry</button>
      </div>
    );
  }
  if (!d) return null;
  if (d.status === "not_applicable") {
    return compact ? null : <p className="flex items-center gap-1.5 text-xs text-muted"><Info aria-hidden className="h-3.5 w-3.5" />{label}: {d.detail}</p>;
  }
  const found = d.matched > 0;
  return (
    <div role="status" className={`${box} ${found ? "border-accent/30 bg-accent-soft/50" : "border-line bg-panel"}`}>
      {found ? <CircleCheck aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> : <Search aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-muted" />}
      <div className="min-w-0 flex-1">
        <p className="font-medium text-ink">{siemHeadline(d)}</p>
        <p className="text-xs text-muted">{d.detail}{d.window ? "" : ""}</p>
        {d.skipped.map((s) => <p key={s} className="text-xs text-sev-medium">{s}</p>)}
        {d.truncated && <p className="text-xs text-sev-medium">Only part of the SIEM result could be searched or imported; narrow the query or time range.</p>}
        {!compact && found && d.samples && d.samples.length > 0 && (
          <ul className="mt-1.5 space-y-0.5 text-xs">
            {d.samples.slice(0, 4).map((e) => (
              <li key={e.id}><Link className="link" href={`/events?event=${e.id}`}>{fmtTime(e.timestamp)}</Link> <span className="text-muted">{e.host ?? ""}</span> <span className="break-words">{e.summary}</span></li>
            ))}
          </ul>
        )}
      </div>
      {found && d.imported > 0 && onShow && <button className="btn btn-sm" onClick={onShow}>Show in results</button>}
    </div>
  );
}
