"use client";
import type { EventDoc } from "@/lib/api-types";
import { fmtTime } from "@/lib/query";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { SeverityBadge as Badge, toLevel } from "./ui/severity";

/** Event severity (0-100) as the shared level badge plus the raw number. */
export function SeverityBadge({ value }: { value?: number }) {
  const v = value ?? 0;
  return v === 0 ? <span className="text-muted tabular-nums" aria-label="Severity 0">0</span> : <span className="inline-flex items-center gap-1.5"><Badge level={toLevel(v)} compact /><span className="text-xs tabular-nums text-ink-2">{v}</span></span>;
}

function summary(e: EventDoc): string {
  if (e.process?.command_line) return e.process.command_line;
  if (e.network?.dst_ip) return `${e.network.dst_domain ? e.network.dst_domain + " " : ""}${e.network.dst_ip}:${e.network.dst_port ?? ""}`;
  if (e.dns?.question) return e.dns.question;
  if (e.file?.path) return e.file.path;
  if (e.message) return e.message;
  return e.action ?? "";
}

function Outcome({ value }: { value?: string }) {
  if (!value || value === "unknown") return <span className="text-muted">—</span>;
  return <span className={`text-xs font-medium ${value === "success" ? "text-sev-ok" : value === "failure" ? "text-sev-critical" : "text-ink-2"}`}>{value === "success" ? "✓ " : value === "failure" ? "✕ " : ""}{value}</span>;
}

export interface RowSelection { ids: Set<string>; onToggle: (id: string) => void; onToggleAll: (ids: string[], on: boolean) => void }

export function ResultsTable({ hits, dense, selected, onOpen, sort, onSort, selection, sourceOf }: {
  hits: EventDoc[]; dense: boolean; selected: string | null; onOpen: (id: string) => void;
  sort: { field: string; order: "asc" | "desc" } | null; onSort: (field: string) => void; selection?: RowSelection;
  /** When given, a Source column names the system each row came from. */
  sourceOf?: (e: EventDoc) => string | undefined;
}) {
  const allOn = !!selection && hits.length > 0 && hits.every((h) => selection.ids.has(h.id));
  const head = (label: string, field?: string) => (
    <th className="th" scope="col" aria-sort={field && sort?.field === field ? (sort.order === "asc" ? "ascending" : "descending") : undefined}>
      {field ? (
        <button onClick={() => onSort(field)} className="inline-flex items-center gap-1 hover:text-ink">
          {label}{sort?.field === field ? (sort.order === "asc" ? <ArrowUp aria-hidden className="h-3 w-3 text-accent" /> : <ArrowDown aria-hidden className="h-3 w-3 text-accent" />) : <ArrowUpDown aria-hidden className="h-3 w-3 opacity-40" />}
        </button>
      ) : label}
    </th>
  );
  return (
    <div className="table-wrap max-h-[68vh]">
      <table className={`raw ${dense ? "text-xs" : "text-sm"}`}>
        <thead><tr>
          {selection && <th className="th" scope="col"><input type="checkbox" aria-label="Select all rows" checked={allOn} onChange={(e) => selection.onToggleAll(hits.map((h) => h.id), e.target.checked)} /></th>}
          {head("Time (UTC)", "timestamp")}{sourceOf && head("Source")}{head("Type", "event_type")}{head("Host", "host.hostname")}{head("User", "user.name")}
          {head("Process", "process.name")}{head("Details")}{head("Outcome")}{head("Sev", "severity")}
        </tr></thead>
        <tbody>
          {hits.map((e) => (
            <tr key={e.id} onClick={() => onOpen(e.id)} tabIndex={0} onKeyDown={(k) => k.key === "Enter" && onOpen(e.id)}
              className={`cursor-pointer focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent-brand ${selected === e.id ? "bg-accent-soft" : ""}`}>
              {selection && (
                <td className="td" onClick={(ev) => ev.stopPropagation()}>
                  <input type="checkbox" aria-label={`Select event ${e.id.slice(0, 8)}`} checked={selection.ids.has(e.id)} onChange={() => selection.onToggle(e.id)} />
                </td>
              )}
              <td className={`td whitespace-nowrap font-mono ${dense ? "py-1" : "py-2"}`}>{fmtTime(e.timestamp)}</td>
              {sourceOf && <td className="td whitespace-nowrap text-xs text-ink-2">{sourceOf(e) ?? ""}</td>}
              <td className="td whitespace-nowrap">{e.event_type}</td>
              <td className="td whitespace-nowrap">{e.host?.hostname ?? ""}</td>
              <td className="td whitespace-nowrap">{e.user?.name ?? ""}</td>
              <td className="td whitespace-nowrap">{e.process?.name ?? ""}</td>
              <td className="td max-w-[32rem] truncate font-mono" title={summary(e)}>{summary(e)}</td>
              <td className="td"><Outcome value={e.outcome} /></td>
              <td className="td"><SeverityBadge value={e.severity} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
