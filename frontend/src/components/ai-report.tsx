"use client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useMemo, useState, type ReactNode } from "react";
import { api } from "@/lib/api";
import { AI_DISCLAIMER, canSave, type AiHypothesis, type AiRun } from "@/lib/ai";
import { itemsFromSteps, type EvPoint } from "@/lib/ai-stream";
import { useAuth } from "@/lib/auth";
import { fmtTime } from "@/lib/query";
import { ErrorLine } from "./badges";
import { EvidenceTimeline } from "./ai-evidence";
import { Feed, Icon, VerdictChip } from "./ai-live";

const SEV: Record<string, string> = { CRITICAL: "border-l-red-500", HIGH: "border-l-orange-400", MEDIUM: "border-l-amber-300", LOW: "border-l-sky-400", INFO: "border-l-slate-500" };
const CLASS: Record<string, string> = {
  confirmed: "border-red-400/40 bg-red-400/10 text-red-300", strongly_supported: "border-orange-400/40 bg-orange-400/10 text-orange-300",
  suspicious: "border-amber-400/40 bg-amber-400/10 text-amber-300", benign_plausible: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300",
  unverified: "border-slate-400/40 bg-slate-400/10 text-slate-300",
};
const HYP: Record<string, string> = {
  supported: "border-red-400/40 bg-red-400/10 text-red-300", refuted: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300",
  open: "border-sky-400/40 bg-sky-400/10 text-sky-300", inconclusive: "border-amber-400/40 bg-amber-400/10 text-amber-300",
};

function Confidence({ level }: { level: string }) {
  const n = level === "HIGH" ? 3 : level === "MEDIUM" ? 2 : 1;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted" aria-label={`Confidence ${level}`}>
      <span className="flex gap-0.5">{[1, 2, 3].map((i) => <span key={i} className={`h-2 w-5 rounded-sm transition-all duration-700 ${i <= n ? (n === 3 ? "bg-emerald-400" : n === 2 ? "bg-amber-400" : "bg-rose-400") : "bg-line"}`} />)}</span>
      {level}
    </span>
  );
}

function Section({ title, children, tone = "text-muted" }: { title: string; children: ReactNode; tone?: string }) {
  return <div className="space-y-1.5"><h3 className={`text-[11px] font-medium uppercase tracking-wider ${tone}`}>{title}</h3>{children}</div>;
}

/** A clickable query reference: jumps to that step in the trace, so every claim can be checked against what the agent actually did. */
function QueryChip({ q, onJump }: { q: string; onJump: (q: string) => void }) {
  return <button type="button" onClick={() => onJump(q)} title="Show this query in the investigation trace" className="rounded border border-line bg-bg/60 px-1.5 font-mono text-[11px] text-sky-300 hover:border-sky-400/60">{q}</button>;
}

function HypothesisCard({ h, onJump }: { h: AiHypothesis; onJump: (q: string) => void }) {
  return (
    <div className="space-y-1.5 rounded-md border border-line bg-bg/50 p-3">
      <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[11px] text-muted">{h.id}</span><span className={`ai-chip ${HYP[h.status] ?? HYP.open}`}>{h.status}</span>
        <span className="ml-auto text-[11px] text-muted">{h.supporting_event_ids.length} supporting · {h.contradicting_event_ids.length} contradicting</span></div>
      <p className="text-sm text-slate-200">{h.statement}</p>
      {h.note && <p className="text-xs text-muted">{h.note}</p>}
      {h.alternatives_considered.length > 0 && <p className="text-xs text-muted">Alternatives considered: {h.alternatives_considered.join("; ")}</p>}
      {h.queries.length > 0 && <p className="flex flex-wrap items-center gap-1 text-xs text-muted">Tested by {h.queries.map((q) => <QueryChip key={q} q={q} onJump={onJump} />)}</p>}
    </div>
  );
}

interface ReportProps {
  run: AiRun;
  evidence: EvPoint[];
  /** Resume an interrupted run from its saved state. */
  onResume?: () => void;
  resuming?: boolean;
  /** Hide the evidence timeline (the agent window already shows it next to the report). */
  compact?: boolean;
}

/** The finished (or interrupted) investigation: conclusion first, evidence and provenance next, the full trace folded away. */
export function RunReport({ run, evidence, onResume, resuming, compact }: ReportProps) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const save = useMutation({ mutationFn: (i: number) => api.aiSave(run.id, [i]), onSuccess: () => { void qc.invalidateQueries({ queryKey: ["ai-runs"] }); } });
  const [traceOpen, setTraceOpen] = useState(false);
  const [focus, setFocus] = useState<{ ref: string; n: number } | null>(null);
  const jump = (ref: string) => { setTraceOpen(true); setFocus({ ref, n: Date.now() }); };
  const c = run.conclusion;
  const items = useMemo(() => itemsFromSteps(run.steps), [run.steps]);
  const cited = useMemo(() => new Set((c?.findings ?? []).filter((f) => f.supported).flatMap((f) => f.event_ids)), [c]);
  const gaps = [...(c?.unresolved_questions ?? []), ...(c?.coverage?.gaps ?? [])].filter((g, i, a) => a.indexOf(g) === i);
  const cov = c?.coverage;
  const done = run.status === "COMPLETED";
  return (
    <div className="space-y-4">
      <section className="panel animate-feed-in space-y-4 border-ai/40 p-4" aria-label="AI run result">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className={`ai-chip ${done ? "border-emerald-400/40 bg-emerald-400/10 text-emerald-300" : "border-amber-400/40 bg-amber-400/10 text-amber-300"}`}><Icon name={done ? "check" : "alert"} className="h-3 w-3" />{done ? "COMPLETED" : run.status}</span>
          <span className="text-muted">{run.provider}/{run.model} · {run.input_tokens + run.output_tokens} tokens · {fmtTime(run.created_at)}</span>
        </div>
        <p className="text-xs text-muted">Goal: <span className="text-slate-300">{run.goal}</span></p>
        {run.error && <p role="alert" className="text-xs text-amber-300">{run.error}</p>}

        {run.resumable && onResume && (
          <div className="flex flex-wrap items-center gap-3 rounded-md border border-amber-400/30 bg-amber-400/5 p-3">
            <p className="min-w-0 flex-1 text-xs text-amber-100/90">This investigation stopped before it finished. What it found is saved; resuming continues from there with a fresh budget.</p>
            <button type="button" className="btn flex items-center gap-1.5 border-amber-400/50 text-amber-200" disabled={resuming} onClick={onResume}><Icon name="play" className="h-3 w-3" />Resume</button>
          </div>
        )}

        {c && (
          <>
            <p className="whitespace-pre-wrap text-sm leading-6 text-slate-100">{c.summary}</p>
            <div className="flex flex-wrap items-center gap-3"><Confidence level={c.confidence} />{c.model_confidence !== c.confidence && <span className="text-xs text-muted">model claimed {c.model_confidence}</span>}<span className="text-xs text-muted">{c.events_reviewed} event(s) reviewed</span></div>
            {c.validation_notes.map((n) => <p key={n} className="text-xs text-orange-300">{n}</p>)}

            {c.findings.length > 0 && (
              <Section title={`Findings (${c.findings.length})`}>
                {c.findings.map((f, i) => (
                  <div key={i} className={`space-y-1.5 rounded-md border border-line border-l-4 bg-bg/50 p-3 ${SEV[f.severity] ?? "border-l-slate-500"}`}>
                    <div className="flex flex-wrap items-center gap-2"><b>{f.title}</b><span className="text-xs text-muted">{f.severity}</span>
                      {f.classification && <span className={`ai-chip ${CLASS[f.classification] ?? CLASS.unverified}`}>{f.classification.replace("_", " ")}</span>}
                      {!f.supported && <span className="text-xs text-red-400">no verified evidence</span>}</div>
                    <p className="whitespace-pre-wrap text-xs leading-5">{f.description}</p>
                    {(f.alternative_explanations?.length ?? 0) > 0 && <p className="text-xs text-muted">Benign explanations considered: {f.alternative_explanations?.join("; ")}</p>}
                    {f.event_ids.length > 0 && <p className="text-xs">Evidence: {f.event_ids.map((id) => <Link key={id} className="mr-2 font-mono underline" href={`/events?id=${id}`}>{id.slice(0, 8)}</Link>)}</p>}
                    {(f.queries?.length ?? 0) > 0 && <p className="flex flex-wrap items-center gap-1 text-xs text-muted">Found by {f.queries?.map((q) => <QueryChip key={q} q={q} onJump={jump} />)}</p>}
                    {f.rejected_event_ids.length > 0 && <p className="text-xs text-orange-300">{f.rejected_event_ids.length} cited id(s) discarded: never retrieved from your data.</p>}
                    {f.techniques.length > 0 && <p className="text-xs">ATT&amp;CK: {f.techniques.join(", ")}</p>}
                    <button className="btn" disabled={!canSave(f, run) || !run.hunt_id || !can("hunts:write") || save.isPending}
                      title={!run.hunt_id ? "Start the run from a hunt to save findings into it" : !f.supported ? "No verified evidence" : ""} onClick={() => save.mutate(i)}>Save as hunt finding</button>
                  </div>
                ))}
              </Section>
            )}

            {c.intel && Object.keys(c.intel).length > 0 && (
              <Section title="Threat intelligence on indicators it met">
                <ul className="space-y-1">
                  {Object.entries(c.intel)
                    .sort(([, a], [, b]) => ["malicious", "suspicious", "unknown", "benign"].indexOf(a.verdict) - ["malicious", "suspicious", "unknown", "benign"].indexOf(b.verdict))
                    .map(([k, v]) => (
                      <li key={k} className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-bg/50 px-2.5 py-1.5 text-xs">
                        <VerdictChip intel={v} /><span className="min-w-0 flex-1 break-all font-mono text-slate-200">{k}</span>
                        <span className="text-muted">{v.providers.map((p) => `${p.provider}: ${p.summary || p.verdict || p.status}`).join(" · ") || "no provider answered"}{v.web ? ` · ${v.web} web source(s)` : ""}</span>
                      </li>
                    ))}
                </ul>
                <p className="text-[11px] text-muted">Context from external sources, not evidence from your environment. &quot;Unknown&quot; means no source had an opinion, not that it is safe.</p>
              </Section>
            )}
            {(c.hypotheses?.length ?? 0) > 0 && <Section title="Hypotheses tested">{c.hypotheses?.map((h) => <HypothesisCard key={h.id} h={h} onJump={jump} />)}</Section>}

            {gaps.length > 0 && (
              <Section title="What it could not check" tone="text-amber-300">
                <ul className="list-disc space-y-0.5 rounded-md border border-amber-400/25 bg-amber-400/5 py-2 pl-7 pr-3 text-xs text-amber-100/90">{gaps.map((g) => <li key={g}>{g}</li>)}</ul>
              </Section>
            )}
            {c.next_steps.length > 0 && <Section title="Next steps"><ul className="list-disc space-y-0.5 pl-4 text-xs">{c.next_steps.map((n) => <li key={n}>{n}</li>)}</ul></Section>}
          </>
        )}
        <p className="text-xs text-orange-300">{AI_DISCLAIMER}</p>
        <ErrorLine error={save.error} fallback="Could not save" />
      </section>

      {!compact && evidence.length > 0 && (
        <section className="panel space-y-2 p-3">
          <h3 className="text-xs font-semibold">Evidence timeline <span className="font-normal text-muted">· {evidence.length} events reviewed</span></h3>
          <EvidenceTimeline events={evidence} cited={cited} />
        </section>
      )}

      <details className="panel p-3" open={traceOpen} onToggle={(e) => setTraceOpen((e.currentTarget as HTMLDetailsElement).open)}>
        <summary className="cursor-pointer select-none text-xs font-semibold">
          Investigation trace <span className="font-normal text-muted">· {cov ? `${cov.queries} queries · ${cov.events_reviewed} events · ` : ""}{run.steps.length} steps{cov && cov.errors > 0 ? ` · ${cov.errors} failed` : ""}</span>
        </summary>
        <div className="mt-3"><Feed items={items} animate={false} focus={focus} /></div>
      </details>
    </div>
  );
}
