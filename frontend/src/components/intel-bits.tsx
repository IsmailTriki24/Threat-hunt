import type { ReactNode } from "react";
import type { Confidence, Verdict } from "@/lib/api-types";
import { clampScore, scoreBand, VERDICT_CLASS, VERDICT_NOTE } from "@/lib/intel";

export function VerdictBadge({ verdict }: { verdict: Verdict | string | null }) {
  const v = (verdict ?? "unknown") as Verdict;
  return <span className={`px-1.5 rounded-sm text-xs ${VERDICT_CLASS[v] ?? VERDICT_CLASS.unknown}`} title={VERDICT_NOTE[v]}>{v}</span>;
}

const BAR = { high: "bg-red-500", mid: "bg-orange-400", low: "bg-slate-500" } as const;
export function ScoreBar({ score, wide }: { score: number; wide?: boolean }) {
  const n = clampScore(score);
  return (
    <span className="inline-flex items-center gap-1" title={`Threat score ${n}/100`}>
      <span role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={n} aria-label="Threat score"
        className={`inline-block bg-bg border border-line h-2 ${wide ? "w-40" : "w-16"}`}>
        <span className={`block h-full ${BAR[scoreBand(n)]}`} style={{ width: `${n}%` }} />
      </span>
      <span className="tabular-nums text-xs">{n}</span>
    </span>
  );
}

const CONF: Record<Confidence, string> = { HIGH: "text-red-300 border-red-800", MEDIUM: "text-orange-300 border-orange-800", LOW: "text-yellow-300 border-yellow-800" };
export function ConfidenceBadge({ level }: { level: Confidence | string }) {
  return <span className={`px-1 text-xs border rounded-sm ${CONF[level as Confidence] ?? "text-muted border-line"}`}>{level}</span>;
}

export function StatusPill({ status }: { status: string }) {
  const cls = status === "ok" ? "text-green-400" : status === "error" || status === "down" ? "text-red-400" : status === "not_found" ? "text-muted" : "text-yellow-400";
  return <span className={`text-xs ${cls}`}>● {status.replace("_", " ")}</span>;
}

export function Section({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="panel p-3 space-y-2">
      <div className="flex items-center gap-2"><h2 className="text-xs text-muted uppercase">{title}</h2><div className="ml-auto flex gap-1">{actions}</div></div>
      {children}
    </section>
  );
}
