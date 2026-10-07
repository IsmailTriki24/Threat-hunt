"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import type { HuntCreate, HuntStatus } from "@/lib/api-types";
import { fmtTime } from "@/lib/query";
import { useAuth } from "@/lib/auth";

export const STATUSES: HuntStatus[] = ["DRAFT", "ACTIVE", "COMPLETED", "ARCHIVED"];

export function parseSources(s: string): string[] {
  return s.split(/[,\s]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
}

export function NewHuntForm({ onCreated }: { onCreated: (id: string) => void }) {
  const qc = useQueryClient();
  const [title, setTitle] = useState("");
  const [hypothesis, setHypothesis] = useState("");
  const [status, setStatus] = useState<HuntStatus>("DRAFT");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [sources, setSources] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: (b: HuntCreate) => api.createHunt(b),
    onSuccess: (h) => { void qc.invalidateQueries({ queryKey: ["hunts"] }); onCreated(h.id); },
    onError: (e) => setError(e instanceof ApiError ? e.friendly : "Failed to create hunt"),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!title.trim()) return setError("Title is required");
    if (!!start !== !!end) return setError("Set both window start and end, or neither");
    if (start && end && start >= end) return setError("Window start must be before end");
    const body: HuntCreate = { title: title.trim(), hypothesis, status, data_sources: parseSources(sources) };
    if (start && end) { body.time_start = new Date(start + "Z").toISOString(); body.time_end = new Date(end + "Z").toISOString(); }
    create.mutate(body);
  }

  return (
    <form onSubmit={submit} className="panel p-3 space-y-2 max-w-3xl" aria-label="New hunt">
      <div className="grid grid-cols-[8rem_1fr] gap-2 items-start">
        <label htmlFor="h-title">Title</label>
        <input id="h-title" className="input" value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />
        <label htmlFor="h-hyp">Hypothesis</label>
        <textarea id="h-hyp" className="input" rows={3} maxLength={5000} value={hypothesis} onChange={(e) => setHypothesis(e.target.value)}
          placeholder="e.g. Investigate possible PowerShell-based execution and persistence during the last 24 hours." />
        <label htmlFor="h-status">Status</label>
        <select id="h-status" className="input w-40" value={status} onChange={(e) => setStatus(e.target.value as HuntStatus)}>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <span>Window (UTC)</span>
        <span className="flex gap-1 items-center">
          <input aria-label="Window start" type="datetime-local" className="input" value={start} onChange={(e) => setStart(e.target.value)} />
          →
          <input aria-label="Window end" type="datetime-local" className="input" value={end} onChange={(e) => setEnd(e.target.value)} />
          <span className="text-xs text-muted">optional default for runs</span>
        </span>
        <label htmlFor="h-src">Data sources</label>
        <input id="h-src" className="input" value={sources} onChange={(e) => setSources(e.target.value)} placeholder="sysmon, windows (optional; limits runs to these sources)" />
      </div>
      {error && <p role="alert" className="text-red-400">{error}</p>}
      <button className="btn btn-primary" type="submit" disabled={create.isPending}>Create hunt</button>
    </form>
  );
}

export function HuntsList() {
  const { can } = useAuth();
  const router = useRouter();
  const qc = useQueryClient();
  const [filter, setFilter] = useState<HuntStatus | "ALL">("ALL");
  const [showNew, setShowNew] = useState(false);
  const hunts = useQuery({ queryKey: ["hunts"], queryFn: api.listHunts });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteHunt(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["hunts"] }),
  });
  const rows = (hunts.data ?? []).filter((h) => filter === "ALL" || h.status === filter);
  const canWrite = can("hunts:write");

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <select aria-label="Status filter" className="input" value={filter} onChange={(e) => setFilter(e.target.value as HuntStatus | "ALL")}>
          <option value="ALL">All statuses</option>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <button className="btn btn-primary ml-auto" disabled={!canWrite} onClick={() => setShowNew((s) => !s)}
          title={canWrite ? "" : "Your role cannot create hunts"}>New hunt</button>
      </div>
      {!canWrite && <p className="text-xs text-muted">Read-only: your role does not allow creating or editing hunts.</p>}
      {showNew && canWrite && <NewHuntForm onCreated={(id) => router.push(`/hunts/${id}`)} />}
      {hunts.isLoading && <p className="text-muted">Loading…</p>}
      {hunts.error && <p role="alert" className="text-red-400">{hunts.error instanceof ApiError ? hunts.error.friendly : "Failed to load hunts"}</p>}
      {hunts.data && (rows.length === 0 ? <p className="panel p-3 text-muted">No hunts{filter !== "ALL" ? ` with status ${filter}` : " yet"}.</p> : (
        <table className="w-full">
          <thead><tr>
            {["Title", "Status", "Hypothesis", "Findings", "Queries", "Updated", ""].map((h) => <th key={h} className="th" scope="col">{h}</th>)}
          </tr></thead>
          <tbody>
            {rows.map((h) => (
              <tr key={h.id} className="hover:bg-bg">
                <td className="td"><Link className="text-accent hover:underline" href={`/hunts/${h.id}`}>{h.title}</Link></td>
                <td className="td">{h.status}</td>
                <td className="td max-w-[28rem] truncate text-muted" title={h.hypothesis}>{h.hypothesis.slice(0, 120)}</td>
                <td className="td tabular-nums">{h.finding_count}</td>
                <td className="td tabular-nums">{h.query_count}</td>
                <td className="td font-mono whitespace-nowrap">{fmtTime(h.updated_at)}</td>
                <td className="td">
                  {can("hunts:delete") && (
                    <button className="btn py-0 text-xs" onClick={() => { if (confirm(`Delete hunt “${h.title}”?`)) del.mutate(h.id); }}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
      {del.error && <p role="alert" className="text-red-400">{del.error instanceof ApiError ? del.error.friendly : "Delete failed"}</p>}
    </div>
  );
}
