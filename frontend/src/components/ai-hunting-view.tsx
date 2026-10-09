"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import { api } from "@/lib/api";
import type { AiMode } from "@/lib/ai";
import { fmtTime } from "@/lib/query";
import { ErrorLine } from "./badges";
import { liveFromRun } from "@/lib/ai-stream";
import { useHuntStream } from "./ai-live";
import { AgentWindow, WindowPill } from "./ai-window";

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
  const [stopping, setStopping] = useState(false);
  const [winOpen, setWinOpen] = useState(false);
  const refresh = useCallback(() => { void qc.invalidateQueries({ queryKey: ["ai-runs"] }); }, [qc]);
  const live = useHuntStream(refresh);
  const { state } = live;
  const busy = state.phase === "connecting" || state.phase === "running";
  const enabled = status.data?.enabled === true;
  const history = openId ? runs.data?.find((r) => r.id === openId) : undefined;
  const histEvidence = useQuery({ queryKey: ["ai-evidence", history?.id], queryFn: () => api.aiRunEvidence(history?.id ?? ""), enabled: !!history });
  const go = () => { setOpenId(null); setStopping(false); setWinOpen(true); void live.start({ goal: goal.trim(), hours_back: hours, mode, ...(huntId ? { hunt_id: huntId } : {}) }); };
  const stop = () => { setStopping(true); void live.stop(); };
  const resume = () => {
    const run = history ?? state.run;
    if (!run) return;
    const ev = history ? (histEvidence.data ?? []) : state.evidence;
    setOpenId(null); setStopping(false); setWinOpen(true);
    void live.resume(run, ev);
  };
  const closeWindow = useCallback(() => { setWinOpen(false); setOpenId(null); }, []);
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

      <div className="ai-glow" data-active={busy}>
        <span className="ai-glow-spin" aria-hidden="true" />
        <div className="ai-glow-body space-y-3 p-3">
          <textarea aria-label="Hunting goal" className="input h-20 w-full resize-none border-transparent bg-bg/70 text-sm" placeholder="Describe what to hunt for, e.g. Is any host running encoded PowerShell outside of admin accounts?"
            value={goal} onChange={(e) => setGoal(e.target.value)} disabled={!enabled || busy}
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
              <button className="ai-btn" disabled={!enabled || goal.trim().length < 5 || busy} onClick={go}>{busy ? "Investigating…" : "Investigate"}</button>
            </span>
          </div>
        </div>
      </div>

      {winOpen && history && <AgentWindow state={liveFromRun(history, histEvidence.data ?? [])} onClose={closeWindow} onResume={resume} />}
      {winOpen && !history && state.phase !== "idle" && <AgentWindow state={state} onClose={closeWindow} onStop={stop} stopping={stopping} onResume={resume} onRetry={() => void live.retry()} />}
      {!winOpen && !history && state.phase !== "idle" && <WindowPill state={state} onOpen={() => setWinOpen(true)} onDismiss={live.reset} />}

      {enabled && <Translate />}
      {runs.data && runs.data.length > 0 && (
        <div className="space-y-1.5">
          <h2 className="text-xs font-semibold">Previous runs</h2>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {runs.data.map((r) => (
              <button key={r.id} onClick={() => { setOpenId(r.id); setWinOpen(true); }} className={`panel flex items-center gap-2 px-3 py-2 text-left text-xs transition hover:border-ai/60 ${r.id === openId ? "border-ai/60" : ""}`}>
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
