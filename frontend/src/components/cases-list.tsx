"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import { CASE_PRIORITIES, CASE_SEVERITIES, CASE_STATUSES, type CasePriority, type CaseSeverity } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { caseListQuery, defaultCaseFilters, type CaseFilters } from "@/lib/cases";
import { fmtTime } from "@/lib/query";
import { ErrorLine, LevelBadge, StatusBadge } from "./badges";

export function NewCaseForm({ onCreated }: { onCreated: (id: string) => void }) {
  const { can, session } = useAuth();
  const qc = useQueryClient();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<CaseSeverity>("MEDIUM");
  const [priority, setPriority] = useState<CasePriority>("P3");
  const [assignee, setAssignee] = useState("");
  const users = useQuery({ queryKey: ["users"], queryFn: api.listUsers, enabled: can("users:read") });
  const assignable = (users.data ?? []).filter((u) => u.is_active && u.role !== "VIEWER");
  const create = useMutation({
    mutationFn: () => api.createCase({ title: title.trim(), description, severity, priority, assignee_id: assignee || undefined }),
    onSuccess: (c) => { void qc.invalidateQueries({ queryKey: ["cases"] }); onCreated(c.id); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (title.trim()) create.mutate(); };

  return (
    <form onSubmit={submit} className="panel p-3 space-y-2 max-w-3xl" aria-label="New case">
      <div className="grid grid-cols-[8rem_1fr] gap-2 items-start">
        <label htmlFor="c-title">Title</label>
        <input id="c-title" className="input" value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />
        <label htmlFor="c-desc">Description</label>
        <textarea id="c-desc" className="input" rows={3} maxLength={20000} value={description} onChange={(e) => setDescription(e.target.value)} />
        <label htmlFor="c-sev">Severity / priority</label>
        <span className="flex gap-1">
          <select id="c-sev" className="input" value={severity} onChange={(e) => setSeverity(e.target.value as CaseSeverity)}>{CASE_SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select>
          <select aria-label="Priority" className="input" value={priority} onChange={(e) => setPriority(e.target.value as CasePriority)}>{CASE_PRIORITIES.map((p) => <option key={p}>{p}</option>)}</select>
        </span>
        <label htmlFor="c-assignee">Assignee</label>
        <select id="c-assignee" className="input" value={assignee} onChange={(e) => setAssignee(e.target.value)}>
          <option value="">Unassigned</option>
          {session && <option value={session.user_id}>Me ({session.email})</option>}
          {assignable.filter((u) => u.user_id !== session?.user_id).map((u) => <option key={u.user_id} value={u.user_id}>{u.email} ({u.role})</option>)}
        </select>
      </div>
      <ErrorLine error={create.error} fallback="Failed to create case" />
      <button className="btn btn-primary" type="submit" disabled={!title.trim() || create.isPending}>Create case</button>
    </form>
  );
}

export function CasesList() {
  const { can } = useAuth();
  const router = useRouter();
  const [filters, setFilters] = useState<CaseFilters>(() => {
    const f = defaultCaseFilters();
    if (typeof window === "undefined") return f;
    const p = new URLSearchParams(window.location.search); // deep links, e.g. /cases?status=OPEN
    return { ...f, status: p.get("status") ?? "", severity: p.get("severity") ?? "", mine: p.get("mine") === "true", q: p.get("q") ?? "" };
  });
  const [showNew, setShowNew] = useState(false);
  const qs = caseListQuery(filters);
  const cases = useQuery({ queryKey: ["cases", qs], queryFn: () => api.listCases(qs) });
  const canWrite = can("cases:write");
  const set = <K extends keyof CaseFilters>(k: K, v: CaseFilters[K]) => setFilters((f) => ({ ...f, [k]: v }));

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <input aria-label="Search cases" className="input" placeholder="Search title…" value={filters.q} onChange={(e) => set("q", e.target.value)} />
        <select aria-label="Status filter" className="input" value={filters.status} onChange={(e) => set("status", e.target.value)}>
          <option value="">All statuses</option>{CASE_STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select aria-label="Severity filter" className="input" value={filters.severity} onChange={(e) => set("severity", e.target.value)}>
          <option value="">All severities</option>{CASE_SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={filters.mine} onChange={(e) => set("mine", e.target.checked)} /> Assigned to me</label>
        <button className="btn btn-primary ml-auto" disabled={!canWrite} title={canWrite ? "" : "Your role cannot create cases"} onClick={() => setShowNew((s) => !s)}>New case</button>
      </div>
      {!canWrite && <p className="text-xs text-muted">Read-only: your role cannot create or modify cases.</p>}
      {showNew && canWrite && <NewCaseForm onCreated={(id) => router.push(`/cases/${id}`)} />}
      {cases.isLoading && <p className="text-muted">Loading…</p>}
      <ErrorLine error={cases.error} fallback="Failed to load cases" />
      {cases.data && (cases.data.length === 0 ? <p className="panel p-3 text-muted">No cases match.</p> : (
        <table className="w-full">
          <thead><tr>{["Case", "Title", "Severity", "Pri", "Status", "Assignee", "Evid", "IOCs", "Assets", "Updated"].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {cases.data.map((c) => (
              <tr key={c.id} className="hover:bg-bg">
                <td className="td font-mono whitespace-nowrap">{c.case_id}</td>
                <td className="td"><Link className="text-accent hover:underline" href={`/cases/${c.id}`}>{c.title}</Link></td>
                <td className="td"><LevelBadge level={c.severity} /></td>
                <td className="td">{c.priority}</td>
                <td className="td"><StatusBadge status={c.status} /></td>
                <td className="td">{c.assignee?.email ?? <span className="text-muted">unassigned</span>}</td>
                <td className="td tabular-nums">{c.evidence_count}</td>
                <td className="td tabular-nums">{c.ioc_count}</td>
                <td className="td tabular-nums">{c.asset_count}</td>
                <td className="td font-mono whitespace-nowrap">{fmtTime(c.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}
