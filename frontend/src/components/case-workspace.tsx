"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { CASE_PRIORITIES, CASE_SEVERITIES, type CaseOut, type CasePriority, type CaseSeverity } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { isLocked } from "@/lib/cases";
import { fmtTime } from "@/lib/query";
import { ErrorLine, LevelBadge } from "./badges";
import { AssetsTab, AuditTab, EvidenceTab, IocsTab, JournalTab, OverviewTab, ReportsTab, TimelineTab } from "./case-tabs";
import { WorkflowBar } from "./workflow-bar";

type Tab = "overview" | "timeline" | "evidence" | "iocs" | "assets" | "journal" | "reports" | "audit";

function Header({ c, canEdit }: { c: CaseOut; canEdit: boolean }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(c.title);
  const [description, setDescription] = useState(c.description);
  const [severity, setSeverity] = useState<CaseSeverity>(c.severity);
  const [priority, setPriority] = useState<CasePriority>(c.priority);
  const [assignee, setAssignee] = useState(c.assignee?.id ?? "");
  const users = useQuery({ queryKey: ["users"], queryFn: api.listUsers, enabled: can("users:read") && editing });
  const save = useMutation({
    mutationFn: () => api.updateCase(c.id, {
      title: title.trim(), description, severity, priority,
      ...(assignee ? { assignee_id: assignee } : c.assignee ? { unassign: true } : {}),
    }),
    onSuccess: () => { setEditing(false); void qc.invalidateQueries({ queryKey: ["case", c.id] }); void qc.invalidateQueries({ queryKey: ["cases"] }); void qc.invalidateQueries({ queryKey: ["case-activity", c.id] }); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (title.trim()) save.mutate(); };
  const assignable = (users.data ?? []).filter((u) => u.is_active && u.role !== "VIEWER");

  if (editing) {
    return (
      <form onSubmit={submit} className="panel p-2 space-y-1" aria-label="Edit case">
        <input aria-label="Case title" className="input w-full text-base" value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />
        <textarea aria-label="Case description" className="input w-full" rows={3} maxLength={20000} value={description} onChange={(e) => setDescription(e.target.value)} />
        <div className="flex gap-1 items-center flex-wrap">
          <select aria-label="Severity" className="input" value={severity} onChange={(e) => setSeverity(e.target.value as CaseSeverity)}>{CASE_SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select>
          <select aria-label="Priority" className="input" value={priority} onChange={(e) => setPriority(e.target.value as CasePriority)}>{CASE_PRIORITIES.map((p) => <option key={p}>{p}</option>)}</select>
          <select aria-label="Assignee" className="input" value={assignee} onChange={(e) => setAssignee(e.target.value)}>
            <option value="">Unassigned</option>
            {c.assignee && <option value={c.assignee.id}>{c.assignee.email}</option>}
            {assignable.filter((u) => u.user_id !== c.assignee?.id).map((u) => <option key={u.user_id} value={u.user_id}>{u.email} ({u.role})</option>)}
          </select>
          <button className="btn btn-primary" type="submit" disabled={save.isPending}>Save</button>
          <button className="btn" type="button" onClick={() => setEditing(false)}>Cancel</button>
        </div>
        <ErrorLine error={save.error} fallback="Failed to update case" />
      </form>
    );
  }
  return (
    <div className="flex items-start gap-2">
      <div className="flex-1 min-w-0">
        <h1 className="text-base font-semibold flex items-center gap-2 flex-wrap">
          <span className="font-mono text-muted">{c.case_id}</span><span>{c.title}</span>
          <LevelBadge level={c.severity} /><span className="text-xs border border-line px-1 rounded-sm">{c.priority}</span>
        </h1>
        <p className="text-xs text-muted">
          Assignee {c.assignee?.email ?? "unassigned"} · created {fmtTime(c.created_at)} · updated {fmtTime(c.updated_at)}
          {c.closed_at ? ` · closed ${fmtTime(c.closed_at)}` : ""}
        </p>
      </div>
      <button className="btn" disabled={!canEdit} onClick={() => setEditing(true)} title={canEdit ? "" : "Case is read-only for you or closed"}>Edit</button>
    </div>
  );
}

export function CaseWorkspace({ id }: { id: string }) {
  const { can } = useAuth();
  const [tab, setTab] = useState<Tab>("overview");
  const c = useQuery({ queryKey: ["case", id], queryFn: () => api.getCase(id), retry: false });

  if (c.isLoading) return <p className="text-muted">Loading case…</p>;
  if (c.error || !c.data) {
    return <p role="alert" className="panel p-3 text-red-400">{c.error instanceof ApiError && c.error.status === 404 ? "Case not found." : c.error instanceof ApiError ? c.error.friendly : "Failed to load case"}</p>;
  }
  const kase = c.data;
  const canWrite = can("cases:write");
  const locked = isLocked(kase.status);
  const mutable = canWrite && !locked;
  const tabs: Array<[Tab, string]> = [
    ["overview", "Overview"], ["timeline", "Timeline"], ["evidence", `Evidence (${kase.evidence_count})`], ["iocs", `IOCs (${kase.ioc_count})`],
    ["assets", `Assets (${kase.asset_count})`], ["journal", "Notes / Journal"], ["reports", "Reports"],
    ...(can("audit:read") ? [["audit", "Audit"] as [Tab, string]] : []),
  ];

  return (
    <div className="space-y-2">
      <Header key={`${kase.updated_at}`} c={kase} canEdit={mutable} />
      <WorkflowBar c={kase} canWrite={canWrite} />
      {locked && (
        <p role="status" className="panel p-2 text-yellow-300 text-xs">
          This case is closed and locked: evidence, IOCs, assets and details cannot change until it is reopened. Notes and reports remain available.
        </p>
      )}
      {!canWrite && <p className="text-xs text-muted">Read-only: your role cannot modify cases.</p>}
      <div role="tablist" className="flex gap-0.5 border-b border-line">
        {tabs.map(([t, label]) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`px-3 py-1 border-b-2 ${tab === t ? "border-accent text-accent" : "border-transparent text-muted hover:text-[#c9d1d9]"}`}>{label}</button>
        ))}
      </div>
      <div role="tabpanel">
        {tab === "overview" && <OverviewTab c={kase} />}
        {tab === "timeline" && <TimelineTab caseId={id} />}
        {tab === "evidence" && <EvidenceTab caseId={id} mutable={mutable} />}
        {tab === "iocs" && <IocsTab caseId={id} mutable={mutable} />}
        {tab === "assets" && <AssetsTab caseId={id} mutable={mutable} />}
        {tab === "journal" && <JournalTab caseId={id} canWrite={canWrite} />}
        {tab === "reports" && <ReportsTab caseId={id} canWrite={canWrite} caseNumber={kase.case_id} />}
        {tab === "audit" && <AuditTab caseId={id} />}
      </div>
    </div>
  );
}
