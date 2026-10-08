"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api";
import { AI_DISCLAIMER, canSave, describeStep, type AiRun } from "@/lib/ai";
import { useAuth } from "@/lib/auth";
import { fmtTime } from "@/lib/query";
import { ErrorLine } from "./badges";

function Translate() {
  const [q, setQ] = useState("");
  const tr = useMutation({ mutationFn: () => api.aiTranslate(q.trim()) });
  return (
    <div className="panel p-3 space-y-2" aria-label="Question to query">
      <h2 className="font-semibold text-xs">Question → hunt query</h2>
      <div className="flex gap-2">
        <input aria-label="Question" className="input flex-1" placeholder="e.g. PowerShell started by Office apps in the last day" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="btn" disabled={q.trim().length < 3 || tr.isPending} onClick={() => tr.mutate()}>{tr.isPending ? "Translating…" : "Translate"}</button>
      </div>
      {tr.data?.query && <p className="text-xs">Validated query: <code className="font-mono">{tr.data.query}</code> — paste it into a hunt or the Events page.</p>}
      {tr.data && !tr.data.query && <p className="text-xs text-orange-300">{tr.data.note}</p>}
      <ErrorLine error={tr.error} fallback="Translation failed" />
    </div>
  );
}

function RunView({ run }: { run: AiRun }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: (i: number) => api.aiSave(run.id, [i]),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["ai-runs"] }); },
  });
  const c = run.conclusion;
  return (
    <section className="panel p-3 space-y-3" aria-label="AI run">
      <div className="flex items-center gap-2 text-xs">
        <b>{run.status}</b><span className="text-muted">{run.provider}/{run.model} · {run.input_tokens + run.output_tokens} tokens · {fmtTime(run.created_at)}</span>
      </div>
      <p className="text-xs">Goal: {run.goal}</p>
      {run.error && <p role="alert" className="text-red-400 text-xs">{run.error}</p>}
      <p className="text-xs text-orange-300">{AI_DISCLAIMER}</p>
      {c && (
        <div className="space-y-2">
          <p className="text-sm whitespace-pre-wrap">{c.summary}</p>
          <p className="text-xs text-muted">Confidence {c.confidence}{c.model_confidence !== c.confidence ? ` (model claimed ${c.model_confidence})` : ""} · {c.events_reviewed} event(s) reviewed</p>
          {c.validation_notes.map((n) => <p key={n} className="text-xs text-orange-300">{n}</p>)}
          {c.findings.map((f, i) => (
            <div key={i} className="border border-line rounded p-2 space-y-1">
              <div className="flex items-center gap-2"><b>{f.title}</b><span className="text-xs text-muted">{f.severity}</span>
                {!f.supported && <span className="text-xs text-red-400">no verified evidence</span>}</div>
              <p className="text-xs whitespace-pre-wrap">{f.description}</p>
              {f.event_ids.length > 0 && <p className="text-xs">Evidence: {f.event_ids.map((id) => <Link key={id} className="underline font-mono mr-2" href={`/events?id=${id}`}>{id.slice(0, 8)}</Link>)}</p>}
              {f.rejected_event_ids.length > 0 && <p className="text-xs text-orange-300">{f.rejected_event_ids.length} cited id(s) discarded: never retrieved from your data.</p>}
              {f.techniques.length > 0 && <p className="text-xs">ATT&amp;CK: {f.techniques.join(", ")}</p>}
              <button className="btn" disabled={!canSave(f, run) || !run.hunt_id || !can("hunts:write") || save.isPending}
                title={!run.hunt_id ? "Start the run from a hunt to save findings into it" : !f.supported ? "No verified evidence" : ""} onClick={() => save.mutate(i)}>Save as hunt finding</button>
            </div>
          ))}
          {c.next_steps.length > 0 && <ul className="text-xs list-disc pl-4">{c.next_steps.map((n) => <li key={n}>{n}</li>)}</ul>}
        </div>
      )}
      <ErrorLine error={save.error} fallback="Could not save" />
      <details>
        <summary className="cursor-pointer text-xs">Trace ({run.steps.length} steps)</summary>
        <ol className="text-xs font-mono space-y-1 mt-1">
          {run.steps.map((s, i) => (
            <li key={i}><span className={s.error ? "text-red-400" : ""}>{describeStep(s)}</span>{s.type === "tool" && <span className="text-muted"> → {s.error ? `error: ${s.error}` : (s.result_preview ?? "").slice(0, 160)}</span>}</li>
          ))}
        </ol>
      </details>
    </section>
  );
}

export function AiHuntingView() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["ai-status"], queryFn: () => api.aiStatus() });
  const hunts = useQuery({ queryKey: ["hunts"], queryFn: () => api.listHunts() });
  const runs = useQuery({ queryKey: ["ai-runs"], queryFn: () => api.aiRuns() });
  const [goal, setGoal] = useState("");
  const [huntId, setHuntId] = useState("");
  const [hours, setHours] = useState(24);
  const [openId, setOpenId] = useState<string | null>(null);
  const start = useMutation({
    mutationFn: () => api.aiRun({ goal: goal.trim(), hours_back: hours, ...(huntId ? { hunt_id: huntId } : {}) }),
    onSuccess: (r) => { setOpenId(r.id); void qc.invalidateQueries({ queryKey: ["ai-runs"] }); },
  });
  const enabled = status.data?.enabled === true;
  const shown = runs.data?.find((r) => r.id === openId) ?? start.data;
  return (
    <section className="space-y-3">
      <h1 className="text-base font-semibold">AI Hunting</h1>
      {status.data && !enabled && <p role="status" className="panel p-3 text-orange-300 text-xs">AI hunting is not configured. Set AI_PROVIDER and the provider key on the server; nothing else in the platform depends on it.</p>}
      {enabled && <p className="text-xs text-muted">{status.data?.provider}/{status.data?.model}. The assistant can only run read-only searches as you, inside your tenant; its conclusions are checked against the events it actually retrieved.</p>}
      <div className="panel p-3 space-y-2">
        <textarea aria-label="Hunting goal" className="input w-full h-20" placeholder="Describe what to hunt for, e.g. Is any host running encoded PowerShell outside of admin accounts?" value={goal} onChange={(e) => setGoal(e.target.value)} disabled={!enabled} />
        <div className="flex gap-2 items-center flex-wrap text-xs">
          <select aria-label="Hunt" className="input" value={huntId} onChange={(e) => setHuntId(e.target.value)} disabled={!enabled}>
            <option value="">no hunt (cannot save findings)</option>{hunts.data?.map((h) => <option key={h.id} value={h.id}>{h.title}</option>)}
          </select>
          <label>Window <input aria-label="Hours back" type="number" min={1} max={720} className="input w-20" value={hours} onChange={(e) => setHours(Math.max(1, Math.min(720, Number(e.target.value) || 24)))} /> h</label>
          <button className="btn btn-primary" disabled={!enabled || goal.trim().length < 5 || start.isPending} onClick={() => start.mutate()}>{start.isPending ? "Investigating… (can take a minute)" : "Investigate"}</button>
        </div>
        <ErrorLine error={start.error} fallback="The investigation failed" />
      </div>
      {enabled && <Translate />}
      {shown && <RunView key={shown.id} run={shown} />}
      {runs.data && runs.data.length > 0 && (
        <div className="space-y-1">
          <h2 className="font-semibold text-xs">Previous runs</h2>
          {runs.data.map((r) => <button key={r.id} className="block text-xs underline text-left" onClick={() => setOpenId(r.id)}>{fmtTime(r.created_at)} · {r.status} · {r.goal.slice(0, 80)}</button>)}
        </div>
      )}
    </section>
  );
}
