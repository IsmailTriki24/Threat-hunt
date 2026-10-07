"use client";
import type { EventDoc } from "@/lib/api-types";
import { fmtTime } from "@/lib/query";

export function SeverityBadge({ value }: { value?: number }) {
  const v = value ?? 0;
  const cls = v >= 80 ? "bg-red-900/60 text-red-300" : v >= 50 ? "bg-orange-900/60 text-orange-300" : v >= 20 ? "bg-yellow-900/50 text-yellow-300" : "text-muted";
  return <span className={`px-1 rounded-sm text-xs tabular-nums ${cls}`}>{v}</span>;
}

function summary(e: EventDoc): string {
  if (e.process?.command_line) return e.process.command_line;
  if (e.network?.dst_ip) return `${e.network.dst_domain ? e.network.dst_domain + " " : ""}${e.network.dst_ip}:${e.network.dst_port ?? ""}`;
  if (e.dns?.question) return e.dns.question;
  if (e.file?.path) return e.file.path;
  if (e.message) return e.message;
  return e.action ?? "";
}

export interface RowSelection { ids: Set<string>; onToggle: (id: string) => void; onToggleAll: (ids: string[], on: boolean) => void }

export function ResultsTable({ hits, dense, selected, onOpen, sort, onSort, selection }: {
  hits: EventDoc[]; dense: boolean; selected: string | null; onOpen: (id: string) => void;
  sort: { field: string; order: "asc" | "desc" } | null; onSort: (field: string) => void; selection?: RowSelection;
}) {
  const allOn = !!selection && hits.length > 0 && hits.every((h) => selection.ids.has(h.id));
  const head = (label: string, field?: string) => (
    <th className="th" scope="col" aria-sort={field && sort?.field === field ? (sort.order === "asc" ? "ascending" : "descending") : undefined}>
      {field ? <button onClick={() => onSort(field)} className="hover:text-accent">{label}{sort?.field === field ? (sort.order === "asc" ? " ▲" : " ▼") : ""}</button> : label}
    </th>
  );
  return (
    <div className="overflow-x-auto">
      <table className={`w-full ${dense ? "text-xs" : "text-sm"}`}>
        <thead><tr>
          {selection && <th className="th" scope="col"><input type="checkbox" aria-label="Select all rows" checked={allOn} onChange={(e) => selection.onToggleAll(hits.map((h) => h.id), e.target.checked)} /></th>}
          {head("Time (UTC)", "timestamp")}{head("Type", "event_type")}{head("Host", "host.hostname")}{head("User", "user.name")}
          {head("Process", "process.name")}{head("Details")}{head("Outcome")}{head("Sev", "severity")}
        </tr></thead>
        <tbody>
          {hits.map((e) => (
            <tr key={e.id} onClick={() => onOpen(e.id)} tabIndex={0} onKeyDown={(k) => k.key === "Enter" && onOpen(e.id)}
              className={`cursor-pointer hover:bg-bg ${selected === e.id ? "bg-bg outline outline-1 outline-accent" : ""}`}>
              {selection && (
                <td className="td" onClick={(ev) => ev.stopPropagation()}>
                  <input type="checkbox" aria-label={`Select event ${e.id.slice(0, 8)}`} checked={selection.ids.has(e.id)} onChange={() => selection.onToggle(e.id)} />
                </td>
              )}
              <td className="td whitespace-nowrap font-mono">{fmtTime(e.timestamp)}</td>
              <td className="td whitespace-nowrap">{e.event_type}</td>
              <td className="td whitespace-nowrap">{e.host?.hostname ?? ""}</td>
              <td className="td whitespace-nowrap">{e.user?.name ?? ""}</td>
              <td className="td whitespace-nowrap">{e.process?.name ?? ""}</td>
              <td className="td max-w-[32rem] truncate font-mono" title={summary(e)}>{summary(e)}</td>
              <td className="td">{e.outcome ?? ""}</td>
              <td className="td"><SeverityBadge value={e.severity} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
