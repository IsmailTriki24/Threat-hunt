"use client";
import { useState, type ReactNode } from "react";
import { TACTICS, VIZ, fmtCount, fmtNum, type HrAttack, type HrTimelinePoint } from "@/lib/hunt-report";

/* Charts for the hunt report. Hand-drawn SVG/CSS (no chart dependency): thin marks, rounded 4px data ends anchored to the baseline,
   a 2px surface gap between touching fills, labels only where they help, a legend for every multi-series chart, hover detail, and a
   data table behind every chart. Colours come from lib/hunt-report VIZ (validated against this app's dark surface). */

const INK = "text-slate-100";
const SUB = "text-slate-300";
const MUTED = "text-muted";

/* ───────────── frame ───────────── */

export function ChartCard({ title, subtitle, children, table, className = "" }: { title: string; subtitle?: string; children: ReactNode; table?: ReactNode; className?: string }) {
  const [showTable, setShowTable] = useState(false);
  return (
    <section className={`hr-card rounded-lg border border-line bg-panel/70 p-4 ${className}`}>
      <header className="mb-3 flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <h3 className={`text-sm font-semibold ${INK}`}>{title}</h3>
          {subtitle && <p className={`mt-0.5 text-xs ${MUTED}`}>{subtitle}</p>}
        </div>
        {table && <button type="button" aria-pressed={showTable} onClick={() => setShowTable((s) => !s)} className={`hr-noprint shrink-0 rounded border px-2 py-0.5 text-[11px] ${showTable ? "border-accent text-accent" : "border-line text-muted hover:text-slate-200"}`}>{showTable ? "Show chart" : "Show data table"}</button>}
      </header>
      {showTable && table ? <div className="max-h-72 overflow-auto text-xs">{table}</div> : children}
    </section>
  );
}

export function DataTable({ head, rows }: { head: string[]; rows: (string | number)[][] }) {
  return (
    <table className="w-full border-collapse text-xs">
      <thead><tr>{head.map((h) => <th key={h} className={`border-b border-line px-2 py-1 text-left font-medium ${MUTED}`}>{h}</th>)}</tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} className={`border-b border-line/60 px-2 py-1 align-top ${j === 0 ? SUB : MUTED}`}>{c}</td>)}</tr>)}</tbody>
    </table>
  );
}

/* ───────────── stat tile ───────────── */

export function StatTile({ label, value, hint, accent, icon }: { label: string; value: number; hint?: string; accent?: string; icon?: ReactNode }) {
  const v = value; // a report states its numbers; they are never animated from zero
  return (
    <div className="hr-card relative animate-feed-in overflow-hidden rounded-lg border border-line bg-panel/70 px-4 py-3">
      {accent && <span className="absolute inset-x-0 top-0 h-[3px]" style={{ background: accent }} aria-hidden="true" />}
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className={`text-[28px] font-semibold leading-8 ${INK}`}>{v.toLocaleString()}</div>
          <div className={`mt-0.5 text-xs ${SUB}`}>{label}</div>
        </div>
        {icon && <span className={MUTED} aria-hidden="true">{icon}</span>}
      </div>
      {hint && <div className={`mt-1 text-[11px] ${MUTED}`}>{hint}</div>}
    </div>
  );
}

/* ───────────── stacked bar (part to whole, few classes) ───────────── */

export interface Segment { key: string; label: string; value: number; color: string; mark?: string }

export function StackedBar({ segments, ariaLabel }: { segments: Segment[]; ariaLabel: string }) {
  const [hover, setHover] = useState<Segment | null>(null);
  const total = segments.reduce((a, s) => a + s.value, 0);
  const shown = segments.filter((s) => s.value > 0);
  return (
    <div>
      <div role="img" aria-label={ariaLabel} className="flex h-4 w-full origin-left animate-grow-x gap-[2px] overflow-hidden rounded-[4px]" onMouseLeave={() => setHover(null)}>
        {total === 0 && <span className="h-full w-full bg-line" />}
        {shown.map((s) => (
          <span key={s.key} tabIndex={0} aria-label={`${s.label}: ${s.value}`} onMouseEnter={() => setHover(s)} onFocus={() => setHover(s)} onBlur={() => setHover(null)}
            className="h-full outline-none transition-opacity focus-visible:ring-2 focus-visible:ring-white/70"
            style={{ width: `${(s.value / total) * 100}%`, background: s.color, opacity: hover && hover.key !== s.key ? 0.55 : 1 }} />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs" aria-live="polite">
        {segments.map((s) => (
          <span key={s.key} className={`inline-flex items-center gap-1.5 ${hover?.key === s.key ? INK : SUB}`}>
            <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} aria-hidden="true" />
            {s.mark && <span aria-hidden="true">{s.mark}</span>}
            {s.label} <b className={`font-semibold ${INK}`}>{fmtNum(s.value)}</b>
            {total > 0 && <span className={MUTED}>({Math.round((s.value / total) * 100)}%)</span>}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ───────────── horizontal bars (compare magnitude, one series) ───────────── */

export interface BarRow { label: string; value: number; title?: string }

export function HBars({ rows, color = VIZ.series[0], unit = "" }: { rows: BarRow[]; color?: string; unit?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="space-y-2" aria-label="Bar chart">
      {rows.map((r, i) => (
        <li key={`${i}-${r.label}`} className="group grid grid-cols-[minmax(0,17rem)_1fr_auto] items-center gap-3 text-xs" title={r.title ?? `${r.label}: ${r.value}${unit}${r.value === 10000 ? " (the search backend stops counting at 10,000)" : ""}`}>
          <span className={`truncate ${SUB} group-hover:text-slate-100`}>{r.label}</span>
          <span className="h-3 overflow-hidden rounded-r-[4px] bg-transparent">
            <span className="block h-full origin-left animate-grow-x rounded-r-[4px] group-hover:brightness-125" style={{ width: `${Math.max(1.5, (r.value / max) * 100)}%`, background: color }} />
          </span>
          <span className={`min-w-[2.5rem] text-right font-mono ${INK}`}>{fmtCount(r.value)}{unit}</span>
        </li>
      ))}
    </ul>
  );
}

/* ───────────── meter (a ratio against a limit) ───────────── */

export function Meter({ value, total, label, sub }: { value: number; total: number; label: string; sub?: ReactNode }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  const fill = pct >= 75 ? VIZ.series[0] : VIZ.warning; // below three quarters of the steps is worth a second look
  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between gap-2 text-xs">
        <span className={`min-w-0 truncate ${SUB}`} title={label}>{label}</span>
        <span className={`shrink-0 font-mono ${INK}`}>{value}/{total} <span className={MUTED}>({pct}%)</span></span>
      </div>
      <div role="meter" aria-valuemin={0} aria-valuemax={total} aria-valuenow={value} aria-label={`${label}: ${value} of ${total} steps`} className="h-2 overflow-hidden rounded-[4px]" style={{ background: "#184f9540" }}>
        <div className="h-full origin-left animate-grow-x rounded-r-[4px]" style={{ width: `${pct}%`, background: fill }} />
      </div>
      {sub}
    </div>
  );
}

/* ───────────── activity timeline (events over time, one lane per host) ───────────── */

const LANE = 26;
const W = 900;
const PAD_L = 118;
const PAD_R = 18;
const typeLabel = (t: string | null) => (t ?? "other").replace(/_/g, " ");

export function TimelineChart({ points }: { points: HrTimelinePoint[] }) {
  const [hover, setHover] = useState<HrTimelinePoint | null>(null);
  const pts = points.map((p) => ({ p, t: Date.parse(p.timestamp) })).filter((x) => Number.isFinite(x.t));
  if (!pts.length) return <p className={`text-xs ${MUTED}`}>No dated events were reviewed.</p>;
  const min = Math.min(...pts.map((x) => x.t));
  const max = Math.max(...pts.map((x) => x.t));
  const span = Math.max(1, max - min);
  const hostCount = new Map<string, number>();
  for (const { p } of pts) hostCount.set(p.host ?? "unknown", (hostCount.get(p.host ?? "unknown") ?? 0) + 1);
  const hostsByCount = [...hostCount.entries()].sort((a, b) => b[1] - a[1]).map(([h]) => h);
  const lanes = hostsByCount.length > 6 ? [...hostsByCount.slice(0, 5), "other hosts"] : hostsByCount;
  const laneOf = (h: string | null) => { const i = lanes.indexOf(h ?? "unknown"); return i >= 0 ? i : lanes.length - 1; };
  const typeCount = new Map<string, number>();
  for (const { p } of pts) typeCount.set(p.event_type ?? "other", (typeCount.get(p.event_type ?? "other") ?? 0) + 1);
  const topTypes = [...typeCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([t]) => t); // three hues at most when marks can overlap
  const colorOf = (t: string | null) => { const i = topTypes.indexOf(t ?? "other"); return i >= 0 ? VIZ.series[i] : VIZ.gray; };
  const H = lanes.length * LANE + 26;
  const INSET = 14; // keep ringed dots clear of the lane labels and the right edge
  const x = (t: number) => PAD_L + INSET + ((t - min) / span) * (W - PAD_L - PAD_R - 2 * INSET);
  const fmtTick = (t: number) => new Date(t).toLocaleString([], span > 2 * 86400000 ? { month: "short", day: "numeric" } : span > 6 * 3600000 ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
  const ticks = [0, 1 / 3, 2 / 3, 1].map((f) => min + f * span);
  const cited = pts.filter((x) => x.p.cited).length;
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`Timeline of ${pts.length} reviewed events across ${lanes.length} host lanes, ${cited} cited by findings`} onMouseLeave={() => setHover(null)}>
        {lanes.map((l, i) => (
          <g key={l}>
            <line x1={PAD_L} x2={W - PAD_R} y1={i * LANE + LANE} y2={i * LANE + LANE} stroke="#2a313c" strokeWidth={1} />
            <text x={PAD_L - 10} y={i * LANE + LANE / 2 + 4} textAnchor="end" className="fill-slate-400" fontSize={11} fontFamily="ui-monospace, monospace"><title>{l}</title>{l.length > 17 ? `${l.slice(0, 16)}…` : l}</text>
          </g>
        ))}
        {ticks.map((t, i) => (
          <g key={i}>
            <line x1={x(t)} x2={x(t)} y1={0} y2={lanes.length * LANE} stroke="#2a313c" strokeWidth={1} opacity={0.5} />
            <text x={x(t)} y={lanes.length * LANE + 16} textAnchor={i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle"} className="fill-slate-400" fontSize={10}>{fmtTick(t)}</text>
          </g>
        ))}
        {pts.map(({ p, t }) => {
          const cx = x(t);
          const cy = laneOf(p.host) * LANE + LANE / 2;
          const on = hover?.id === p.id;
          return (
            <g key={p.id} tabIndex={0} role="img" aria-label={`${new Date(t).toLocaleString()} ${p.host ?? ""} ${typeLabel(p.event_type)}: ${p.summary}${p.cited ? " (cited by a finding)" : ""}`}
              onMouseEnter={() => setHover(p)} onFocus={() => setHover(p)} onBlur={() => setHover(null)} className="outline-none">
              {p.cited && <circle cx={cx} cy={cy} r={9.5} fill="none" stroke="#ffffff" strokeWidth={1.5} opacity={0.9} />}
              <circle cx={cx} cy={cy} r={p.cited ? 6 : on ? 5.5 : 4} fill={colorOf(p.event_type)} stroke={VIZ.surface} strokeWidth={2} />
              <circle cx={cx} cy={cy} r={11} fill="transparent" />
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex min-h-[1.75rem] flex-wrap items-start gap-x-5 gap-y-1.5 text-xs" aria-live="polite">
        {hover ? (
          <span className={SUB}><span className="font-mono text-muted">{new Date(hover.timestamp).toLocaleString()}</span> · {hover.host ?? "unknown host"}{hover.user ? ` · ${hover.user}` : ""} · {typeLabel(hover.event_type)} - {hover.summary}{hover.cited ? " · cited by a finding" : ""}</span>
        ) : (
          <>
            {topTypes.map((t, i) => <span key={t} className={`inline-flex items-center gap-1.5 ${SUB}`}><span className="h-2.5 w-2.5 rounded-full" style={{ background: VIZ.series[i] }} aria-hidden="true" />{typeLabel(t)} <b className={`font-semibold ${INK}`}>{typeCount.get(t)}</b></span>)}
            {typeCount.size > 3 && <span className={`inline-flex items-center gap-1.5 ${SUB}`}><span className="h-2.5 w-2.5 rounded-full" style={{ background: VIZ.gray }} aria-hidden="true" />other types</span>}
            {cited > 0 && <span className={`inline-flex items-center gap-1.5 ${SUB}`}><span className="h-3 w-3 rounded-full border-[1.5px] border-white" aria-hidden="true" />cited by a finding <b className={`font-semibold ${INK}`}>{cited}</b></span>}
          </>
        )}
      </div>
    </div>
  );
}

/* ───────────── ATT&CK tactic strip (ordered categories; shade = number of techniques) ───────────── */

const SOURCE_MARK: Record<HrAttack["source"], { mark: string; label: string }> = {
  finding: { mark: "●", label: "supported by a finding" }, playbook: { mark: "○", label: "from a hunt playbook" }, "sensor tag": { mark: "◆", label: "tagged by a sensor" },
};

export function TacticStrip({ attack }: { attack: HrAttack[] }) {
  const cols = TACTICS.map((t) => ({ ...t, items: attack.filter((a) => a.tactics.includes(t.id)) }));
  const unmapped = attack.filter((a) => !a.tactics.length || !a.tactics.some((t) => TACTICS.some((x) => x.id === t)));
  const all = unmapped.length ? [...cols, { id: "unmapped", label: "Unmapped", items: unmapped }] : cols;
  const shade = (n: number) => VIZ.ramp[Math.min(VIZ.ramp.length, n) - 1];
  // tactics with no technique stay in the kill-chain order but shrink to a sliver; the ones with techniques get room for full ids
  const template = all.map((c) => (c.items.length ? "minmax(5.75rem,1fr)" : "1.6rem")).join(" ");
  return (
    <div>
      <div className="overflow-x-auto pb-1">
        <div className="grid min-w-fit gap-[3px]" style={{ gridTemplateColumns: template }} role="list" aria-label="ATT&CK techniques by tactic">
          {all.map((c) => (
            <div key={c.id} role="listitem" className="flex flex-col gap-1">
              {c.items.length ? (
                <div className={`flex h-32 items-end justify-center pb-1 text-center text-[11px] leading-3 ${SUB}`}>{c.label}</div>
              ) : (
                <div className="flex h-32 items-end justify-center pb-1 text-[10px] leading-3 text-slate-600"><span style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }} className="whitespace-nowrap">{c.label}</span></div>
              )}
              <div className={`flex h-8 items-center justify-center rounded-[4px] text-xs font-semibold ${c.items.length ? "text-white" : "text-slate-600"}`} style={{ background: c.items.length ? shade(c.items.length) : "#1c2128" }} aria-label={`${c.label}: ${c.items.length} technique(s)`}>
                {c.items.length || "·"}
              </div>
              <div className="flex flex-col gap-1">
                {c.items.map((a) => (
                  <a key={a.id} href={a.url} target="_blank" rel="noopener noreferrer" title={`${a.id}${a.name ? ` - ${a.name}` : ""} (${SOURCE_MARK[a.source].label})`} className="whitespace-nowrap rounded border border-line bg-bg/60 px-1 py-0.5 text-center font-mono text-[10px] text-slate-200 hover:border-accent">
                    <span aria-hidden="true" className="mr-0.5">{SOURCE_MARK[a.source].mark}</span>{a.id}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
      {!attack.length && <p className={`text-xs ${MUTED}`}>No ATT&amp;CK techniques are associated with this hunt.</p>}
      <div className={`mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs ${SUB}`}>
        {Object.values(SOURCE_MARK).map((m) => <span key={m.label}><span aria-hidden="true" className="mr-1">{m.mark}</span>{m.label}</span>)}
        <span className="inline-flex items-center gap-1">fewer <span className="inline-flex gap-[2px]" aria-hidden="true">{VIZ.ramp.map((c) => <span key={c} className="h-2.5 w-4 rounded-[2px]" style={{ background: c }} />)}</span> more techniques</span>
      </div>
    </div>
  );
}
