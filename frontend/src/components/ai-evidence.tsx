"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import type { EvPoint } from "@/lib/ai-stream";

const TYPE: Record<string, { label: string; color: string }> = {
  process_creation: { label: "process", color: "#38bdf8" },
  network_connection: { label: "network", color: "#fbbf24" },
  dns_query: { label: "dns", color: "#2dd4bf" },
  authentication: { label: "auth", color: "#a78bfa" },
  file_event: { label: "file", color: "#34d399" },
  registry_event: { label: "registry", color: "#f472b6" },
};
const typeOf = (t: string | null) => TYPE[t ?? ""] ?? { label: t ?? "other", color: "#94a3b8" };
const MAX_LANES = 6;

const fmt = (ms: number, withDate: boolean) =>
  new Date(ms).toLocaleString([], withDate ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit", second: "2-digit" });

/** Every event the agent reviewed on one time axis, one lane per host. Events cited by a finding are ringed. */
export function EvidenceTimeline({ events, cited, live = false, maxLanes = MAX_LANES }: { events: EvPoint[]; cited?: ReadonlySet<string>; live?: boolean; maxLanes?: number }) {
  const [hover, setHover] = useState<EvPoint | null>(null);
  const model = useMemo(() => {
    const pts = events.map((e) => ({ e, t: Date.parse(e.timestamp ?? "") })).filter((p) => Number.isFinite(p.t));
    if (!pts.length) return null;
    const min = Math.min(...pts.map((p) => p.t));
    const max = Math.max(...pts.map((p) => p.t));
    const pad = Math.max((max - min) * 0.03, 1000);
    const counts = new Map<string, number>();
    for (const { e } of pts) counts.set(e.host ?? "unknown", (counts.get(e.host ?? "unknown") ?? 0) + 1);
    const hosts = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([h]) => h);
    const lanes = hosts.length > maxLanes ? [...hosts.slice(0, maxLanes - 1), "other hosts"] : hosts;
    const lane = (h: string | null) => { const i = lanes.indexOf(h ?? "unknown"); return i >= 0 ? i : lanes.length - 1; };
    return { pts, from: min - pad, to: max + pad, lanes, lane, types: [...new Set(pts.map((p) => p.e.event_type ?? "other"))] };
  }, [events, maxLanes]);
  if (!model) return <p className="text-xs text-muted">No reviewed events yet.</p>;
  const span = model.to - model.from;
  const multiDay = span > 20 * 3600 * 1000;
  return (
    <div className="space-y-2" aria-label="Evidence timeline">
      <div className="flex">
        <div className="w-24 shrink-0">
          {model.lanes.map((l) => <div key={l} className="flex h-[26px] items-center truncate pr-2 text-right font-mono text-[11px] text-muted" title={l}><span className="w-full truncate text-right">{l}</span></div>)}
        </div>
        <div className="relative flex-1 border-l border-line" style={{ height: model.lanes.length * 26 }}>
          {model.lanes.map((l, i) => <div key={l} className="absolute inset-x-0 border-b border-line/40" style={{ top: i * 26, height: 26 }} />)}
          {model.pts.map(({ e, t }) => {
            const on = cited?.has(e.id);
            const c = typeOf(e.event_type).color;
            const size = on ? 13 : 8;
            return (
              <Link key={e.id} href={`/events?id=${e.id}`} aria-label={`${typeOf(e.event_type).label} on ${e.host ?? "unknown host"}: ${e.summary}`}
                onMouseEnter={() => setHover(e)} onFocus={() => setHover(e)} onMouseLeave={() => setHover(null)} onBlur={() => setHover(null)}
                className={`absolute rounded-full transition-transform hover:z-10 hover:scale-150 focus:z-10 focus:scale-150 focus:outline-none ${live ? "animate-dot-in" : ""} ${on ? "ring-2 ring-white/80" : ""}`}
                style={{ left: `calc(${((t - model.from) / span) * 100}% - ${size / 2}px)`, top: model.lane(e.host) * 26 + 13 - size / 2, width: size, height: size, background: c, boxShadow: on ? `0 0 10px ${c}` : undefined }} />
            );
          })}
        </div>
      </div>
      <div className="ml-24 flex justify-between font-mono text-[10px] text-muted"><span>{fmt(model.from, multiDay)}</span><span>{fmt(model.to, multiDay)}</span></div>
      <div className="flex min-h-[18px] flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
        {hover ? (
          <span className="truncate text-slate-200"><span className="font-mono text-muted">{fmt(Date.parse(hover.timestamp ?? ""), true)}</span> · {hover.host} · {hover.summary}</span>
        ) : (
          <>
            {model.types.map((t) => <span key={t} className="inline-flex items-center gap-1 text-muted"><span className="h-2 w-2 rounded-full" style={{ background: typeOf(t).color }} />{typeOf(t).label}</span>)}
            {cited && cited.size > 0 && <span className="inline-flex items-center gap-1 text-muted"><span className="h-2.5 w-2.5 rounded-full ring-2 ring-white/80" />cited in a finding</span>}
          </>
        )}
      </div>
    </div>
  );
}
