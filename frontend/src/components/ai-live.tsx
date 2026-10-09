"use client";
import { useCallback, useEffect, useReducer, useRef, useState, type ReactNode } from "react";
import { api, ApiError } from "@/lib/api";
import type { AiRunBody } from "@/lib/ai";
import { initialLive, liveReducer, parseSse, type FeedItem, type LiveAction, type LiveState, type NotebookOp, type Progress, type StreamEvent } from "@/lib/ai-stream";

/* ───────────── stream hook ───────────── */

const EVENTS = new Set(["start", "thinking", "tool_start", "step", "progress", "done", "error"]);

/** Starts an investigation and folds its Server-Sent Events into `LiveState`. The run itself lives on the server: leaving only detaches. */
export function useHuntStream(onDone?: () => void) {
  const [state, dispatch] = useReducer(liveReducer, initialLive);
  const abort = useRef<AbortController | null>(null);
  const finished = useRef(false);

  const send = useCallback((a: LiveAction) => dispatch({ ...a, at: Date.now() }), []);

  const start = useCallback(async (body: AiRunBody) => {
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    finished.current = false;
    send({ type: "begin" });
    try {
      const res = await api.aiRunStream(body, ac.signal);
      if (!res.body) throw new Error("no stream");
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const { events, rest } = parseSse(buf);
        buf = rest;
        for (const e of events) {
          if (!EVENTS.has(e.event)) continue;
          if (e.event === "done" || e.event === "error") finished.current = true;
          send({ type: e.event, data: e.data } as StreamEvent);
          if (e.event === "done") onDone?.();
        }
      }
      if (!finished.current) send({ type: "error", data: { message: "The connection closed early. The investigation keeps running on the server and will appear under Previous runs." } });
    } catch (e) {
      if (ac.signal.aborted) return;
      send({ type: "error", data: { message: e instanceof ApiError ? e.friendly : "The connection was lost. If the investigation was already running it will appear under Previous runs." } });
    }
  }, [send, onDone]);

  const detach = useCallback(() => { abort.current?.abort(); send({ type: "detach" }); }, [send]);
  const reset = useCallback(() => { abort.current?.abort(); send({ type: "reset" }); }, [send]);
  useEffect(() => () => abort.current?.abort(), []);
  return { state, start, detach, reset };
}

/* ───────────── small hooks ───────────── */

function useNow(active: boolean, every = 250): number {
  const [n, setN] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setN(Date.now()), every);
    return () => clearInterval(t);
  }, [active, every]);
  return n;
}

function useCountUp(target: number, ms = 650): number {
  const [v, setV] = useState(target);
  const cur = useRef(target);
  useEffect(() => {
    const from = cur.current;
    const t0 = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms);
      cur.current = from + (target - from) * (1 - Math.pow(1 - p, 3));
      setV(Math.round(cur.current));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

/* ───────────── presentation primitives ───────────── */

type Tone = "sky" | "violet" | "teal" | "amber" | "slate" | "cyan" | "rose" | "green" | "red";
const TONE: Record<Tone, { text: string; border: string; bg: string; dot: string }> = {
  sky: { text: "text-sky-300", border: "border-sky-400/40", bg: "bg-sky-400/10", dot: "bg-sky-400" },
  violet: { text: "text-violet-300", border: "border-violet-400/40", bg: "bg-violet-400/10", dot: "bg-violet-400" },
  teal: { text: "text-teal-300", border: "border-teal-400/40", bg: "bg-teal-400/10", dot: "bg-teal-400" },
  amber: { text: "text-amber-300", border: "border-amber-400/40", bg: "bg-amber-400/10", dot: "bg-amber-400" },
  slate: { text: "text-slate-300", border: "border-slate-400/40", bg: "bg-slate-400/10", dot: "bg-slate-400" },
  cyan: { text: "text-cyan-300", border: "border-cyan-400/40", bg: "bg-cyan-400/10", dot: "bg-cyan-400" },
  rose: { text: "text-rose-300", border: "border-rose-400/40", bg: "bg-rose-400/10", dot: "bg-rose-400" },
  green: { text: "text-emerald-300", border: "border-emerald-400/40", bg: "bg-emerald-400/10", dot: "bg-emerald-400" },
  red: { text: "text-red-300", border: "border-red-400/50", bg: "bg-red-400/10", dot: "bg-red-400" },
};

const PATHS: Record<string, string> = {
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zm9 16-4-4",
  chart: "M4 20V10m6 10V4m6 16v-7m4 7H2",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  share: "M18 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm12 7a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8.6 13.5l6.8 4m0-11-6.8 4",
  clock: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm0-15v5l3 2",
  tree: "M5 4h4v4H5zM15 10h4v4h-4zM15 18h4v4h-4zM7 8v10h8M7 12h8",
  db: "M12 8c4.4 0 8-1.3 8-3s-3.6-3-8-3-8 1.3-8 3 3.6 3 8 3zM4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  book: "M4 4h12a4 4 0 0 1 4 4v12H8a4 4 0 0 1-4-4zM8 4v16",
  sparkle: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 16l.7 2 2 .7-2 .7-.7 2-.7-2-2-.7 2-.7z",
  alert: "M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  check: "M20 6 9 17l-5-5",
  x: "M18 6 6 18M6 6l12 12",
  flag: "M4 22V4m0 0h13l-2 4 2 4H4",
};

export function Icon({ name, className = "h-4 w-4" }: { name: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={PATHS[name] ?? PATHS.sparkle} />
    </svg>
  );
}

const TOOLS: Record<string, { label: string; tone: Tone; icon: string; what: string }> = {
  search_events: { label: "Search events", tone: "sky", icon: "search", what: "Looking through telemetry" },
  aggregate_events: { label: "Aggregate", tone: "cyan", icon: "chart", what: "Counting and grouping" },
  get_event: { label: "Inspect event", tone: "cyan", icon: "eye", what: "Reading a single event" },
  pivot_entity: { label: "Pivot", tone: "violet", icon: "share", what: "Following an entity across hosts" },
  events_around: { label: "Neighbourhood", tone: "teal", icon: "clock", what: "What happened around that moment" },
  process_lineage: { label: "Process tree", tone: "teal", icon: "tree", what: "Walking parent and child processes" },
  data_coverage: { label: "Telemetry coverage", tone: "slate", icon: "db", what: "Checking what data exists" },
  mitre_technique: { label: "ATT&CK lookup", tone: "rose", icon: "shield", what: "Looking up a technique" },
};
const toolMeta = (name: string) => TOOLS[name] ?? { label: name, tone: "slate" as Tone, icon: "sparkle", what: "Running a tool" };

const fmtMs = (ms?: number) => (ms == null ? "" : ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`);
export const fmtClock = (ms: number) => { const s = Math.max(0, Math.floor(ms / 1000)); return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; };

function Chip({ tone, children, pop }: { tone: Tone; children: ReactNode; pop?: boolean }) {
  const t = TONE[tone];
  return <span className={`ai-chip ${t.border} ${t.bg} ${t.text} ${pop ? "animate-pop-in" : ""}`}>{children}</span>;
}

function Typewriter({ text, animate }: { text: string; animate: boolean }) {
  const [n, setN] = useState(animate ? 0 : text.length);
  useEffect(() => {
    if (!animate) { setN(text.length); return; }
    const cps = Math.max(220, text.length / 2.5); // whole reveal takes at most ~2.5s
    const t0 = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const k = Math.min(text.length, Math.floor(((t - t0) / 1000) * cps));
      setN(k);
      if (k < text.length) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [text, animate]);
  return (
    <>
      {text.slice(0, n)}
      {animate && n < text.length && <span className="ml-0.5 inline-block h-[14px] w-[7px] translate-y-[2px] animate-blink bg-ai" />}
    </>
  );
}

/** Colours the `field:value` structure of a hunt query so the analyst can read what the agent asked at a glance. */
export function Query({ q }: { q: string }) {
  const out: ReactNode[] = [];
  const re = /([\w.]+)(:|!=|>=|<=)("[^"]*"|\S+)|\b(AND|OR|NOT)\b/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(q))) {
    if (m.index > last) out.push(q.slice(last, m.index));
    if (m[4]) out.push(<span key={m.index} className="text-pink-300">{m[0]}</span>);
    else out.push(<span key={m.index}><span className="text-sky-300">{m[1]}</span><span className="text-muted">{m[2]}</span><span className="text-amber-200">{m[3]}</span></span>);
    last = re.lastIndex;
  }
  if (last < q.length) out.push(q.slice(last));
  return <code className="font-mono text-xs leading-5 break-words">{out}</code>;
}

function Node({ icon, tone, pulse, spin }: { icon: string; tone: Tone; pulse?: boolean; spin?: boolean }) {
  const t = TONE[tone];
  return (
    <span className={`absolute left-0 top-0.5 flex h-[30px] w-[30px] items-center justify-center rounded-full border bg-bg ${t.border} ${t.text} ${pulse ? "animate-pulse-ring" : ""}`}>
      {spin && <span className="absolute inset-[-3px] animate-spin-slow rounded-full" style={{ background: "conic-gradient(from 0deg, transparent 0 60%, rgba(167,139,250,.9))", mask: "radial-gradient(farthest-side, transparent calc(100% - 2px), #000 0)", WebkitMask: "radial-gradient(farthest-side, transparent calc(100% - 2px), #000 0)" }} />}
      <Icon name={icon} className="h-[15px] w-[15px]" />
    </span>
  );
}

/* ───────────── feed items ───────────── */

function ToolCard({ item }: { item: Extract<FeedItem, { kind: "tool" }> }) {
  const meta = toolMeta(item.name);
  const tone = TONE[meta.tone];
  const s = item.step;
  const failed = !item.running && (s?.status === "error" || !!s?.error);
  const cached = !item.running && !!s?.cached;
  const empty = !item.running && s?.status === "empty";
  const { purpose, hypothesis, ...rest } = item.input as Record<string, unknown>;
  const query = typeof rest.query === "string" ? rest.query : null;
  const args = Object.entries(rest).filter(([k]) => k !== "query");
  const pct = s?.total ? Math.max(4, Math.min(100, Math.round(((s.returned ?? 0) / s.total) * 100))) : 0;
  return (
    <div className={`overflow-hidden rounded-md border bg-panel/80 ${failed ? "border-red-400/50" : item.running ? tone.border : "border-line"}`}>
      {item.running && <div className="relative h-0.5 overflow-hidden bg-line"><div className="absolute inset-y-0 w-1/3 animate-scan bg-gradient-to-r from-transparent via-ai to-transparent" /></div>}
      <div className="space-y-2 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <b className={tone.text}>{meta.label}</b>
          <span className="font-mono text-[11px] text-muted">{item.name}</span>
          {(item.purpose ?? (purpose as string | undefined)) && <Chip tone="slate">{String(item.purpose ?? purpose)}</Chip>}
          {(item.hypothesis ?? (hypothesis as string | undefined)) && <Chip tone="amber">tests {String(item.hypothesis ?? hypothesis)}</Chip>}
          <span className="ml-auto flex items-center gap-1.5 text-xs">
            {item.running && <span className="text-muted">{meta.what}…</span>}
            {!item.running && s?.ms != null && !cached && <span className="font-mono text-muted">{fmtMs(s.ms)}</span>}
            {cached && <Chip tone="slate">cached</Chip>}
            {failed && <Chip tone="red" pop><Icon name="x" className="h-3 w-3" />failed</Chip>}
            {!failed && !item.running && !cached && <Chip tone={empty ? "slate" : "green"} pop><Icon name={empty ? "x" : "check"} className="h-3 w-3" />{empty ? "no matches" : "done"}</Chip>}
          </span>
        </div>
        {query && <div className="rounded border border-line bg-bg/70 px-2 py-1.5"><Query q={query} /></div>}
        {args.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {args.map(([k, v]) => <span key={k} className="rounded border border-line bg-bg/60 px-1.5 py-0.5 font-mono text-[11px]"><span className="text-muted">{k}=</span>{typeof v === "string" ? v : JSON.stringify(v)}</span>)}
          </div>
        )}
        {!item.running && s && (
          <div className="space-y-1.5">
            {s.total != null && !failed && (
              <div className="flex items-center gap-2 text-xs">
                <span className="font-mono text-slate-200">{s.returned ?? 0}<span className="text-muted"> of {s.total} events</span></span>
                <span className="h-1.5 w-28 overflow-hidden rounded-full bg-line"><span className={`block h-full rounded-full ${tone.dot} transition-all duration-700`} style={{ width: `${pct}%` }} /></span>
              </div>
            )}
            <div className="flex flex-wrap gap-1.5">
              {(s.new_events ?? 0) > 0 && <Chip tone="green" pop>+{s.new_events} new events</Chip>}
              {(s.new_entities ?? 0) > 0 && <Chip tone="violet" pop>+{s.new_entities} entities</Chip>}
              {(s.attempts ?? 1) > 1 && <Chip tone="amber">retried ×{(s.attempts ?? 1) - 1}</Chip>}
              {s.injection_suspected && <Chip tone="red" pop><Icon name="alert" className="h-3 w-3" />instruction-like text in data - ignored</Chip>}
            </div>
            {cached && <p className="text-xs text-muted">Identical to an earlier query - answered from memory, no budget spent.</p>}
            {failed && <p className="text-xs text-red-300">{s.error}</p>}
            {s.result_preview && !cached && (
              <details className="group text-xs">
                <summary className="cursor-pointer select-none text-muted hover:text-slate-200">Raw result</summary>
                <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-bg/70 p-2 font-mono text-[11px] text-slate-300">{s.result_preview}</pre>
              </details>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function opLine(op: NotebookOp): { icon: string; text: string; sub?: string } {
  switch (op.op) {
    case "add_hypothesis": return { icon: "flag", text: `New hypothesis: ${op.statement ?? ""}`, sub: op.test_plan ?? undefined };
    case "update_hypothesis": return { icon: "check", text: `${op.id ?? "Hypothesis"} → ${op.status ?? "updated"}`, sub: op.text ?? undefined };
    case "dismiss_lead": return { icon: "x", text: `Dismissed lead ${op.entity ?? ""}`, sub: op.text ?? undefined };
    case "declare_gap": return { icon: "alert", text: `Gap: ${op.text ?? ""}` };
    default: return { icon: "book", text: op.text ?? op.op };
  }
}

function Item({ item, animate }: { item: FeedItem; animate: boolean }) {
  const pop = animate ? "animate-feed-in" : "";
  if (item.kind === "reasoning") {
    return (
      <li className={`relative pl-11 ${pop}`}>
        <Node icon="sparkle" tone="violet" />
        <div className="rounded-md border border-violet-400/25 bg-gradient-to-br from-violet-500/10 via-panel/80 to-sky-500/5 p-3">
          <p className="mb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-violet-300">Reasoning</p>
          <p className="whitespace-pre-wrap text-sm leading-6 text-slate-200"><Typewriter text={item.text} animate={animate} /></p>
        </div>
      </li>
    );
  }
  if (item.kind === "gate") {
    return (
      <li className={`relative pl-11 ${pop}`}>
        <Node icon="alert" tone="amber" />
        <div className="rounded-md border border-amber-400/40 bg-amber-400/5 p-3">
          <p className="font-medium text-amber-300">Conclusion sent back{item.attempt ? ` (attempt ${item.attempt})` : ""}</p>
          <p className="mb-1 text-xs text-muted">The platform refuses to accept a conclusion until the investigation is thorough enough.</p>
          <ul className="list-disc space-y-0.5 pl-4 text-xs text-amber-100/90">{item.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </div>
      </li>
    );
  }
  if (item.kind === "notebook") {
    return (
      <li className={`relative pl-11 ${pop}`}>
        <Node icon="book" tone="amber" />
        <div className="rounded-md border border-amber-400/25 bg-panel/80 p-3">
          <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-amber-300">Notebook</p>
          <ul className="space-y-1.5">
            {item.ops.map((o, i) => { const l = opLine(o); return (
              <li key={i} className="flex gap-2 text-sm"><Icon name={l.icon} className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" /><span><span className="text-slate-200">{l.text}</span>{l.sub && <span className="block text-xs text-muted">{l.sub}</span>}</span></li>
            ); })}
          </ul>
          {item.step.error && <p className="mt-1 text-xs text-red-300">{item.step.error}</p>}
        </div>
      </li>
    );
  }
  const meta = toolMeta(item.name);
  const failed = !item.running && (item.step?.status === "error" || !!item.step?.error);
  return (
    <li className={`relative pl-11 ${pop}`}>
      <Node icon={failed ? "x" : meta.icon} tone={failed ? "red" : meta.tone} pulse={item.running} />
      <ToolCard item={item} />
    </li>
  );
}

function ThinkingRow({ state }: { state: LiveState }) {
  const t = state.thinking;
  const connecting = state.phase === "connecting";
  const limit = state.start?.limits.steps;
  return (
    <li className="relative animate-feed-in pl-11" aria-live="polite">
      <Node icon="sparkle" tone="violet" spin />
      <div className="flex min-h-[34px] items-center gap-2 rounded-md px-1 text-sm text-violet-200">
        <span>{connecting ? "Connecting to the investigator" : t?.final ? "Wrapping up - writing the conclusion" : "Deciding the next move"}</span>
        <span className="flex gap-1" aria-hidden="true">{[0, 1, 2].map((i) => <span key={i} className="h-1.5 w-1.5 animate-dot-bounce rounded-full bg-violet-300" style={{ animationDelay: `${i * 0.18}s` }} />)}</span>
        {t && limit && <span className="ml-auto font-mono text-xs text-muted">turn {t.step}/{limit}</span>}
      </div>
    </li>
  );
}

export function Feed({ items, state, animate }: { items: FeedItem[]; state?: LiveState; animate: boolean }) {
  const end = useRef<HTMLLIElement | null>(null);
  const stick = useRef(true);
  useEffect(() => {
    const onScroll = () => { stick.current = window.innerHeight + window.scrollY >= document.body.scrollHeight - 240; };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  const running = state ? state.phase === "running" || state.phase === "connecting" : false;
  const showThinking = running && !items.some((i) => i.kind === "tool" && i.running);
  useEffect(() => {
    if (animate && stick.current) end.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [items.length, showThinking, animate]);
  return (
    <ol className="ai-rail relative space-y-3" aria-label="Investigation timeline">
      {items.map((i) => <Item key={i.id} item={i} animate={animate} />)}
      {showThinking && state && <ThinkingRow state={state} />}
      <li ref={end} aria-hidden="true" />
    </ol>
  );
}

/* ───────────── status board ───────────── */

function Meter({ label, used, limit, unit }: { label: string; used: number; limit: number; unit?: string }) {
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  return (
    <div>
      <div className="mb-1 flex justify-between text-[11px]"><span className="text-muted">{label}</span><span className="font-mono text-slate-300">{used}{unit}<span className="text-muted"> / {limit}{unit}</span></span></div>
      <div className="h-1.5 overflow-hidden rounded-full bg-line"><div className={`h-full rounded-full transition-all duration-700 ease-out ${pct > 85 ? "bg-amber-400" : "bg-gradient-to-r from-violet-400 to-sky-400"}`} style={{ width: `${pct}%` }} /></div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  const v = useCountUp(value);
  return <div className="rounded-md border border-line bg-bg/60 px-2.5 py-2"><div className="font-mono text-lg leading-5 text-slate-100">{v.toLocaleString()}</div><div className="text-[11px] text-muted">{label}</div></div>;
}

const HYP: Record<string, { tone: Tone; label: string }> = {
  open: { tone: "sky", label: "open" }, supported: { tone: "red", label: "supported" }, refuted: { tone: "green", label: "refuted" }, inconclusive: { tone: "amber", label: "inconclusive" },
};

export function Board({ state }: { state: LiveState }) {
  const live = state.phase === "running" || state.phase === "connecting";
  const now = useNow(live);
  const elapsed = (state.endedAt ?? now) - (state.startedAt ?? now);
  const p: Progress | null = state.progress;
  const lim = state.start?.limits ?? p?.limits;
  const status = { idle: ["Idle", "slate"], connecting: ["Connecting", "violet"], running: ["Investigating", "violet"], done: ["Complete", "green"], error: ["Stopped", "red"], detached: ["Detached", "amber"] }[state.phase] as [string, Tone];
  const t = TONE[status[1]];
  return (
    <aside className="space-y-3 lg:sticky lg:top-3 lg:self-start" aria-label="Investigation status">
      <div className="panel space-y-3 p-3">
        <div className="flex items-center gap-3">
          <span className={`relative flex h-9 w-9 items-center justify-center rounded-full border ${t.border} ${t.bg} ${t.text} ${live ? "animate-pulse-ring" : ""}`}>
            <Icon name={state.phase === "done" ? "check" : state.phase === "error" || state.phase === "detached" ? "alert" : "sparkle"} className={`h-4 w-4 ${live ? "animate-floaty" : ""}`} />
          </span>
          <div className="min-w-0 flex-1"><div className={`font-medium ${t.text}`}>{status[0]}</div><div className="truncate text-[11px] text-muted">{state.start ? `${state.start.model} · ${state.start.mode}` : "waiting"}</div></div>
          <div className="font-mono text-lg tabular-nums text-slate-100">{fmtClock(elapsed)}</div>
        </div>
        {lim && p && (
          <div className="space-y-2">
            <Meter label="Turns" used={Math.max(0, lim.steps - p.remaining.steps)} limit={lim.steps} />
            <Meter label="Tool calls" used={Math.max(0, lim.tool_calls - p.remaining.tool_calls)} limit={lim.tool_calls} />
            <Meter label="Time" used={Math.min(lim.seconds, Math.floor(elapsed / 1000))} limit={lim.seconds} unit="s" />
          </div>
        )}
        <div className="grid grid-cols-2 gap-2">
          <Stat label="Queries" value={p?.queries ?? 0} /><Stat label="Events reviewed" value={p?.events ?? 0} />
          <Stat label="Entities" value={p?.entities ?? 0} /><Stat label="Tokens" value={p?.tokens ?? 0} />
        </div>
        {p && (p.gate_rejections > 0 || p.redundant > 0) && (
          <div className="flex flex-wrap gap-1.5">{p.gate_rejections > 0 && <Chip tone="amber">{p.gate_rejections} conclusion(s) sent back</Chip>}{p.redundant > 0 && <Chip tone="slate">{p.redundant} repeated query(ies)</Chip>}</div>
        )}
      </div>
      <div className="panel space-y-2 p-3">
        <h3 className="text-[11px] font-medium uppercase tracking-wider text-muted">Hypotheses</h3>
        {(!p || p.hypotheses.length === 0) && <p className="text-xs text-muted">None yet. The agent must state falsifiable hypotheses and try to disprove them.</p>}
        {p?.hypotheses.map((h) => {
          const s = HYP[h.status] ?? HYP.open;
          return (
            <div key={`${h.id}:${h.status}`} className="animate-flash rounded-md border border-line bg-bg/50 p-2">
              <div className="mb-1 flex items-center gap-2"><span className="font-mono text-[11px] text-muted">{h.id}</span><Chip tone={s.tone} pop>{s.label}</Chip><span className="ml-auto text-[11px] text-muted">+{h.supporting} / −{h.contradicting}</span></div>
              <p className="text-xs leading-5 text-slate-200">{h.statement}</p>
            </div>
          );
        })}
      </div>
    </aside>
  );
}
