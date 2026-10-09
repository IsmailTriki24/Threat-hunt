"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useCallback, useState } from "react";
import { api } from "@/lib/api";
import { AI_DISCLAIMER, canSave, type AiMode, type AiRun } from "@/lib/ai";
import { itemsFromSteps } from "@/lib/ai-stream";
import { useAuth } from "@/lib/auth";
import { fmtTime } from "@/lib/query";
import { ErrorLine } from "./badges";
import { Board, Feed, Icon, useHuntStream } from "./ai-live";

const EXAMPLES = [
  "Is anything abnormal in the last day?",
  "Hunt for encoded PowerShell and anything it led to",
  "Look for lateral movement using a single account across hosts",
  "Which processes were started by Office applications?",
];

const MODES: { id: AiMode; label: string; hint: string }[] = [
  { id: "quick", label: "Quick", hint: "A fast triage pass" },
  { id: "standard", label: "Standard", hint: "Balanced depth" },
  { id: "deep", label: "Deep", hint: "Thorough, follows every lead" },
];

function Translate() {
  const [q, setQ] = useState("");
  const tr = useMutation({ mutationFn: () => api.aiTranslate(q.trim()) });
  return (
    <details className="panel p-3" aria-label="Question to query">
      <summary className="cursor-pointer text-xs font-semibold">Question → hunt query</summary>
      <div className="mt-2 space-y-2">
        <div className="flex gap-2">
          <input aria-label="Question" className="input flex-1" placeholder="e.g. PowerShell started by Office apps in the last day" value={q} onChange={(e) => setQ(e.target.value)} />
          <button className="btn" disabled={q.trim().length < 3 || tr.isPending} onClick={() => tr.mutate()}>{tr.isPending ? "Translating…" : "Translate"}</button>
        </div>
        {tr.data?.query && <p className="text-xs">Validated query: <code className="font-mono">{tr.data.query}</code> — paste it into a hunt or the Events page.</p>}
        {tr.data && !tr.data.query && <p className="text-xs text-orange-300">{tr.data.note}</p>}
        <ErrorLine error={tr.error} fallback="Translation failed" />
      </div>
    </details>
  );
}

const SEV: Record<string, string> = { CRITICAL: "border-l-red-500", HIGH: "border-l-orange-400", MEDIUM: "border-l-amber-300", LOW: "border-l-sky-400", INFO: "border-l-slate-500" };

function Confidence({ level }: { level: string }) {
  const n = level === "HIGH" ? 3 : level === "MEDIUM" ? 2 : 1;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted" aria-label={`Confidence ${level}`}>
      <span className="flex gap-0.5">{[1, 2, 3].map((i) => <span key={i} className={`h-2 w-5 rounded-sm transition-all duration-700 ${i <= n ? (n === 3 ? "bg-emerald-400" : n === 2 ? "bg-amber-400" : "bg-rose-400") : "bg-line"}`} />)}</span>
      {level}
    </span>
  );
}

function RunResult({ run }: { run: AiRun }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: (i: number) => api.aiSave(run.id, [i]),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["ai-runs"] }); },
  });
  const c = run.conclusion;
  return (
    <section className="panel animate-feed-in space-y-3 border-ai/40 p-4" aria-label="AI run result">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={`ai-chip ${run.status === "COMPLETED" ? "border-emerald-400/40 bg-emerald-400/10 text-emerald-300" : "border-amber-400/40 bg-amber-400/10 text-amber-300"}`}><Icon name={run.status === "COMPLETED" ? "check" : "alert"} className="h-3 w-3" />{run.status}</span>
        <span className="text-muted">{run.provider}/{run.model} · {run.input_tokens + run.output_tokens} tokens · {fmtTime(run.created_at)}</span>
      </div>
      <p className="text-xs text-muted">Goal: <span className="text-slate-300">{run.goal}</span></p>
      {run.error && <p role="alert" className="text-xs text-red-400">{run.error}</p>}
      {c && (
        <div className="space-y-3">
          <p className="whitespace-pre-wrap text-sm leading-6 text-slate-100">{c.summary}</p>
          <div className="flex flex-wrap items-center gap-3"><Confidence level={c.confidence} />{c.model_confidence !== c.confidence && <span className="text-xs text-muted">model claimed {c.model_confidence}</span>}<span className="text-xs text-muted">{c.events_reviewed} event(s) reviewed</span></div>
          {c.validation_notes.map((n) => <p key={n} className="text-xs text-orange-300">{n}</p>)}
          {c.findings.map((f, i) => (
            <div key={i} className={`space-y-1.5 rounded-md border border-line border-l-4 bg-bg/50 p-3 ${SEV[f.severity] ?? "border-l-slate-500"}`}>
              <div className="flex flex-wrap items-center gap-2"><b>{f.title}</b><span className="text-xs text-muted">{f.severity}</span>
                {!f.supported && <span className="text-xs text-red-400">no verified evidence</span>}</div>
              <p className="whitespace-pre-wrap text-xs leading-5">{f.description}</p>
              {f.event_ids.length > 0 && <p className="text-xs">Evidence: {f.event_ids.map((id) => <Link key={id} className="mr-2 font-mono underline" href={`/events?id=${id}`}>{id.slice(0, 8)}</Link>)}</p>}
              {f.rejected_event_ids.length > 0 && <p className="text-xs text-orange-300">{f.rejected_event_ids.length} cited id(s) discarded: never retrieved from your data.</p>}
              {f.techniques.length > 0 && <p className="text-xs">ATT&amp;CK: {f.techniques.join(", ")}</p>}
              <button className="btn" disabled={!canSave(f, run) || !run.hunt_id || !can("hunts:write") || save.isPending}
                title={!run.hunt_id ? "Start the run from a hunt to save findings into it" : !f.supported ? "No verified evidence" : ""} onClick={() => save.mutate(i)}>Save as hunt finding</button>
            </div>
          ))}
          {c.next_steps.length > 0 && <div><h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted">Next steps</h3><ul className="list-disc space-y-0.5 pl-4 text-xs">{c.next_steps.map((n) => <li key={n}>{n}</li>)}</ul></div>}
        </div>
      )}
      <p className="text-xs text-orange-300">{AI_DISCLAIMER}</p>
      <ErrorLine error={save.error} fallback="Could not save" />
    </section>
  );
}

function Replay({ run }: { run: AiRun }) {
  return (
    <details className="panel p-3" open>
      <summary className="mb-3 cursor-pointer text-xs font-semibold">Investigation trace ({run.steps.length} steps)</summary>
      <Feed items={itemsFromSteps(run.steps)} animate={false} />
    </details>
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
  const [mode, setMode] = useState<AiMode>("standard");
  const [openId, setOpenId] = useState<string | null>(null);
  const [focused, setFocused] = useState(false);
  const refresh = useCallback(() => { void qc.invalidateQueries({ queryKey: ["ai-runs"] }); }, [qc]);
  const live = useHuntStream(refresh);
  const { state } = live;
  const busy = state.phase === "connecting" || state.phase === "running";
  const enabled = status.data?.enabled === true;
  const history = openId ? runs.data?.find((r) => r.id === openId) : undefined;
  const go = () => { setOpenId(null); void live.start({ goal: goal.trim(), hours_back: hours, mode, ...(huntId ? { hunt_id: huntId } : {}) }); };
  const showLive = !history && state.phase !== "idle";
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="bg-gradient-to-r from-violet-300 via-sky-300 to-teal-200 bg-clip-text text-xl font-semibold text-transparent">AI Hunting</h1>
          {enabled && <p className="mt-0.5 text-xs text-muted">Read-only searches as you, inside your tenant. Every conclusion is checked against the events the agent actually retrieved.</p>}
        </div>
        {enabled && <span className="ai-chip border-emerald-400/30 bg-emerald-400/10 text-emerald-300"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />{status.data?.provider}/{status.data?.model}</span>}
      </div>
      {status.data && !enabled && <p role="status" className="panel p-3 text-xs text-orange-300">AI hunting is not configured. Set AI_PROVIDER and the provider key on the server; nothing else in the platform depends on it.</p>}

      <div className="ai-glow" data-active={busy || focused}>
        <span className="ai-glow-spin" aria-hidden="true" />
        <div className="ai-glow-body space-y-3 p-3">
          <textarea aria-label="Hunting goal" className="input h-20 w-full resize-none border-transparent bg-bg/70 text-sm" placeholder="Describe what to hunt for, e.g. Is any host running encoded PowerShell outside of admin accounts?"
            value={goal} onChange={(e) => setGoal(e.target.value)} onFocus={() => setFocused(true)} onBlur={() => setFocused(false)} disabled={!enabled || busy}
            onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && enabled && !busy && goal.trim().length >= 5) go(); }} />
          {!busy && state.phase === "idle" && (
            <div className="flex flex-wrap gap-1.5">{EXAMPLES.map((x) => <button key={x} type="button" className="ai-chip border-line bg-bg/60 text-muted transition hover:border-ai/60 hover:text-violet-200" disabled={!enabled} onClick={() => setGoal(x)}>{x}</button>)}</div>
          )}
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <div role="radiogroup" aria-label="Depth" className="inline-flex overflow-hidden rounded-md border border-line">
              {MODES.map((m) => { const lim = status.data?.modes?.[m.id]; return (
                <button key={m.id} role="radio" aria-checked={mode === m.id} type="button" disabled={busy} title={`${m.hint}${lim ? ` · up to ${lim.max_tool_calls} queries, ${Math.round(lim.wall_s / 60 * 10) / 10} min` : ""}`} onClick={() => setMode(m.id)}
                  className={`px-3 py-1 transition ${mode === m.id ? "bg-violet-500/20 text-violet-200" : "text-muted hover:text-slate-200"}`}>{m.label}</button>
              ); })}
            </div>
            <select aria-label="Hunt" className="input" value={huntId} onChange={(e) => setHuntId(e.target.value)} disabled={!enabled || busy}>
              <option value="">no hunt (cannot save findings)</option>{hunts.data?.map((h) => <option key={h.id} value={h.id}>{h.title}</option>)}
            </select>
            <label>Window <input aria-label="Hours back" type="number" min={1} max={720} className="input w-20" value={hours} disabled={busy} onChange={(e) => setHours(Math.max(1, Math.min(720, Number(e.target.value) || 24)))} /> h</label>
            <span className="ml-auto flex items-center gap-2">
              {busy && <button type="button" className="btn" onClick={live.detach} title="Stop watching - the investigation keeps running on the server and is saved when it finishes">Stop watching</button>}
              <button className="ai-btn" disabled={!enabled || goal.trim().length < 5 || busy} onClick={go}>{busy ? "Investigating…" : "Investigate"}</button>
            </span>
          </div>
        </div>
      </div>

      {showLive && (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="min-w-0 space-y-4">
            <Feed items={state.items} state={state} animate />
            {state.phase === "error" && <p role="alert" className="panel border-red-400/40 p-3 text-xs text-red-300">{state.error}</p>}
            {state.phase === "detached" && <p role="status" className="panel border-amber-400/40 p-3 text-xs text-amber-200">Stopped watching. The investigation keeps running on the server; open it from Previous runs when it finishes.</p>}
            {state.run && <RunResult run={state.run} />}
          </div>
          <Board state={state} />
        </div>
      )}
      {history && <><RunResult run={history} /><Replay run={history} /></>}

      {enabled && <Translate />}
      {runs.data && runs.data.length > 0 && (
        <div className="space-y-1.5">
          <h2 className="text-xs font-semibold">Previous runs</h2>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {runs.data.map((r) => (
              <button key={r.id} onClick={() => setOpenId(r.id)} className={`panel flex items-center gap-2 px-3 py-2 text-left text-xs transition hover:border-ai/60 ${r.id === openId ? "border-ai/60" : ""}`}>
                <span className={`h-2 w-2 shrink-0 rounded-full ${r.status === "COMPLETED" ? "bg-emerald-400" : r.status === "FAILED" ? "bg-red-400" : "bg-amber-400"}`} />
                <span className="min-w-0 flex-1 truncate">{r.goal}</span><span className="shrink-0 text-muted">{fmtTime(r.created_at)}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
