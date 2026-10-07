"use client";
import { useQuery } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import { api } from "@/lib/api";
import { auditQuery, auditSummary, defaultAuditFilters, type AuditFilters } from "@/lib/cases";
import { fmtTime } from "@/lib/query";
import { ErrorLine } from "./badges";

const PAGE = 50;

export function AuditView() {
  const [draft, setDraft] = useState<AuditFilters>(defaultAuditFilters());
  const [applied, setApplied] = useState<AuditFilters>(defaultAuditFilters());
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const qs = auditQuery(applied, offset, PAGE);
  const rows = useQuery({ queryKey: ["audit", qs], queryFn: () => api.audit(qs) });
  const set = <K extends keyof AuditFilters>(k: K, v: string) => setDraft((d) => ({ ...d, [k]: v }));
  const apply = () => { setOffset(0); setApplied(draft); };

  return (
    <div className="space-y-2">
      <form className="flex gap-1 flex-wrap items-end text-xs" aria-label="Audit filters" onSubmit={(e) => { e.preventDefault(); apply(); }}>
        <input aria-label="Action prefix" className="input w-40" placeholder="action prefix (case.)" value={draft.action} onChange={(e) => set("action", e.target.value)} />
        <select aria-label="Outcome" className="input" value={draft.outcome} onChange={(e) => set("outcome", e.target.value)}>
          <option value="">any outcome</option><option>success</option><option>failure</option><option>denied</option>
        </select>
        <input aria-label="Actor id" className="input w-64 font-mono" placeholder="actor user id" value={draft.actor_id} onChange={(e) => set("actor_id", e.target.value)} />
        <input aria-label="Resource type" className="input w-32" placeholder="resource type" value={draft.resource_type} onChange={(e) => set("resource_type", e.target.value)} />
        <label>Since (UTC) <input aria-label="Since" type="datetime-local" className="input" value={draft.since} onChange={(e) => set("since", e.target.value)} /></label>
        <label>Until (UTC) <input aria-label="Until" type="datetime-local" className="input" value={draft.until} onChange={(e) => set("until", e.target.value)} /></label>
        <button className="btn btn-primary" type="submit">Apply</button>
        <button className="btn" type="button" onClick={() => { setDraft(defaultAuditFilters()); setApplied(defaultAuditFilters()); setOffset(0); }}>Reset</button>
      </form>
      <ErrorLine error={rows.error} fallback="Failed to load the audit trail" />
      {rows.isLoading && <p className="text-muted">Loading…</p>}
      {rows.data && (rows.data.length === 0 ? <p className="panel p-3 text-muted">No audit records match.</p> : (
        <table className="w-full">
          <thead><tr>{["Time (UTC)", "Action", "Outcome", "Actor", "Resource", "IP", ""].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {rows.data.map((r) => (
              <Fragment key={r.id}>
                <tr className="hover:bg-bg">
                  <td className="td font-mono whitespace-nowrap">{fmtTime(r.created_at)}</td>
                  <td className="td">{r.action}</td>
                  <td className={`td ${r.outcome === "success" ? "" : "text-orange-300"}`}>{r.outcome}</td>
                  <td className="td">{r.actor}</td>
                  <td className="td font-mono text-xs">{auditSummary(r)}</td>
                  <td className="td font-mono">{r.ip}</td>
                  <td className="td"><button className="btn py-0 text-xs" aria-expanded={open === r.id} onClick={() => setOpen(open === r.id ? null : r.id)}>Details</button></td>
                </tr>
                {open === r.id && (
                  <tr><td colSpan={7} className="td bg-bg"><pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify({ ...r.details, request_id: r.request_id, resource_id: r.resource_id }, null, 2)}</pre></td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      ))}
      <div className="flex gap-2 items-center text-xs">
        <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Prev</button>
        <span className="text-muted">{offset + 1}–{offset + (rows.data?.length ?? 0)}</span>
        <button className="btn" disabled={(rows.data?.length ?? 0) < PAGE} onClick={() => setOffset(offset + PAGE)}>Next</button>
      </div>
    </div>
  );
}
