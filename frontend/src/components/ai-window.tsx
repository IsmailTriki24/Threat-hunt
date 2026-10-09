"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { EvidenceTimeline } from "./ai-evidence";
import { Feed, HypothesisList, Icon, Overview, PHASE, QueryLog, StatusOrb, fmtClock, isLive, nowDoing, useElapsed } from "./ai-live";
import { RunReport } from "./ai-report";
import type { LiveState } from "@/lib/ai-stream";

interface WindowProps {
  state: LiveState;
  onClose: () => void;
  onStop?: () => void;
  stopping?: boolean;
  onResume?: () => void;
  onRetry?: () => void;
}

const TABS = [["activity", "Activity"], ["queries", "Queries"], ["overview", "Overview"]] as const;
type Tab = (typeof TABS)[number][0];

function Card({ title, children, className = "" }: { title: string; children: React.ReactNode; className?: string }) {
  return <section className={`rounded-md border border-line bg-panel/60 p-2.5 ${className}`}><h3 className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted">{title}</h3>{children}</section>;
}

/** The whole investigation in one window: activity on the left; live queries, budget, hypotheses and evidence on the right. Panes scroll on their own, the page never does. */
export function AgentWindow({ state, onClose, onStop, stopping, onResume, onRetry }: WindowProps) {
  const [tab, setTab] = useState<Tab>("activity");
  const [hyp, setHyp] = useState<string | null>(null);
  const root = useRef<HTMLDivElement | null>(null);
  const elapsed = useElapsed(state);
  const live = isLive(state);
  const [label] = PHASE[state.phase];
  const cited = useMemo(() => new Set((state.run?.conclusion?.findings ?? []).filter((f) => f.supported).flatMap((f) => f.event_ids)), [state.run]);

  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    root.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { document.body.style.overflow = prev; window.removeEventListener("keydown", onKey); };
  }, [onClose]);

  const pane = (t: Tab) => `${tab === t ? "flex" : "hidden"} lg:flex min-h-0 flex-col`;
  return (
    <div className="fixed inset-0 z-50 animate-fade-in bg-black/70 backdrop-blur-sm">
      <div ref={root} tabIndex={-1} role="dialog" aria-modal="true" aria-label="AI investigation"
        className="absolute inset-2 flex animate-window-in flex-col overflow-hidden rounded-xl border border-ai/40 bg-bg shadow-[0_0_90px_-20px_rgba(139,92,246,.55)] outline-none sm:inset-4">
        <header className="flex shrink-0 items-center gap-3 border-b border-line bg-panel/70 px-4 py-2.5">
          <StatusOrb state={state} />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2"><h2 className="truncate text-sm font-semibold text-slate-100">{state.start?.goal ?? "Investigation"}</h2></div>
            <p className="truncate text-xs text-muted"><span className={live ? "text-violet-300" : ""}>{label}</span> · {nowDoing(state)}{state.start ? ` · ${state.start.model} · ${state.start.mode}` : ""}</p>
          </div>
          <span className="font-mono text-lg tabular-nums text-slate-100" aria-label="Elapsed time">{fmtClock(elapsed)}</span>
          {live && onStop && <button type="button" className="btn flex items-center gap-1.5 border-red-400/50 text-red-300" disabled={stopping || !state.runId} onClick={onStop} title="Stop now - what it found so far is saved and can be resumed"><Icon name="stop" className="h-3 w-3" />{stopping ? "Stopping…" : "Stop"}</button>}
          <button type="button" className="btn" onClick={onClose} title={live ? "Hide the window - the investigation keeps running" : "Close"}>{live ? "Minimize" : "Close"}</button>
        </header>

        <nav className="flex shrink-0 gap-1 border-b border-line px-3 pt-2 lg:hidden" aria-label="Sections">
          {TABS.map(([id, name]) => <button key={id} type="button" onClick={() => setTab(id)} aria-pressed={tab === id} className={`rounded-t px-3 py-1 text-xs ${tab === id ? "bg-panel text-violet-200" : "text-muted"}`}>{name}</button>)}
        </nav>

        <div className="grid min-h-0 flex-1 gap-3 p-3 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
          <div className={pane("activity")}>
            {state.phase === "error" && !state.run && (
              <div role="alert" className="mb-2 flex shrink-0 flex-wrap items-center gap-3 rounded-md border border-red-400/40 bg-red-400/5 p-3">
                <p className="min-w-0 flex-1 text-xs text-red-300">{state.error}</p>
                {onRetry && <button type="button" className="btn" onClick={onRetry}>Try again</button>}
              </div>
            )}
            {state.run ? (
              <div className="min-h-0 flex-1 overflow-y-auto pr-1"><RunReport run={state.run} evidence={state.evidence} onResume={onResume} resuming={live} compact /></div>
            ) : (
              <Feed items={state.items} state={state} animate scroll hypothesis={hyp} />
            )}
          </div>

          <div className="flex min-h-0 flex-col gap-3">
            <div className={`${tab === "overview" ? "block" : "hidden"} shrink-0 lg:block`}><Overview state={state} elapsed={elapsed} /></div>
            <div className={`${tab === "queries" ? "flex" : "hidden"} min-h-[160px] flex-1 flex-col lg:flex`}><QueryLog items={state.items} state={state} /></div>
            <div className={`${tab === "overview" ? "block" : "hidden"} min-h-0 flex-col gap-3 overflow-y-auto lg:flex lg:max-h-[34%] lg:shrink-0`}>
              <Card title="Hypotheses"><HypothesisList state={state} hypothesis={hyp} onHypothesis={(id) => { setHyp(id); setTab("activity"); }} /></Card>
            </div>
            <div className={`${tab === "overview" ? "block" : "hidden"} shrink-0 lg:block`}>
              <Card title={`Evidence timeline · ${state.evidence.length} events`}>
                {state.evidence.length ? <EvidenceTimeline events={state.evidence} cited={cited} live={live} maxLanes={4} /> : <p className="text-xs text-muted">Events the agent reviews will appear here.</p>}
              </Card>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Shown while the window is hidden: the run is still going (or has finished) and one click brings it back. */
export function WindowPill({ state, onOpen, onDismiss }: { state: LiveState; onOpen: () => void; onDismiss: () => void }) {
  const elapsed = useElapsed(state);
  const live = isLive(state);
  return (
    <div className="fixed bottom-4 right-4 z-40 flex animate-window-in items-center gap-3 rounded-full border border-ai/50 bg-panel py-1.5 pl-2 pr-3 shadow-lg" role="status">
      <StatusOrb state={state} />
      <button type="button" onClick={onOpen} className="min-w-0 text-left">
        <span className="block max-w-[260px] truncate text-xs font-medium text-slate-100">{live ? nowDoing(state) : PHASE[state.phase][0]}</span>
        <span className="block text-[11px] text-muted">{state.progress?.queries ?? 0} queries · {state.progress?.events ?? 0} events · <span className="font-mono">{fmtClock(elapsed)}</span> · open</span>
      </button>
      {!live && <button type="button" onClick={onDismiss} className="text-muted hover:text-slate-200" aria-label="Dismiss"><Icon name="x" className="h-3.5 w-3.5" /></button>}
    </div>
  );
}
