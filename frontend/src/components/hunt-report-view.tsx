"use client";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { SEVERITY_ORDER, VERDICT_META, VIZ, fmtCount, type HuntReportData, type HrFinding, type HrIntel, type HrSection } from "@/lib/hunt-report";
import { Icon } from "./ai-live";
import { ChartCard, DataTable, HBars, Meter, StackedBar, StatTile, TacticStrip, TimelineChart } from "./viz/charts";

const TONE_COLOR = { critical: VIZ.critical, warning: VIZ.warning, good: VIZ.good, neutral: VIZ.gray } as const;
const SEV_COLOR: Record<string, string> = { CRITICAL: VIZ.critical, HIGH: VIZ.serious, MEDIUM: VIZ.warning, LOW: VIZ.series[0], INFO: VIZ.gray };
const VERDICT_STATUS: Record<string, { color: string; icon: string; label: string }> = {
  malicious: { color: VIZ.critical, icon: "x", label: "malicious" }, suspicious: { color: VIZ.warning, icon: "alert", label: "suspicious" },
  unknown: { color: VIZ.gray, icon: "help", label: "unknown" }, benign: { color: VIZ.good, icon: "check", label: "benign" },
};

const NAV: [string, string][] = [
  ["summary", "Summary"], ["numbers", "Key numbers"], ["charts", "Charts"], ["attack", "ATT&CK"], ["findings", "Findings"], ["queries", "Hunt queries"],
  ["playbooks", "Playbooks"], ["intel", "Intelligence"], ["gaps", "Coverage & gaps"], ["actions", "Recommendations"], ["references", "References"],
];

function Section({ id, title, icon, children, aside }: { id: string; title: string; icon: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section id={`hr-${id}`} className="scroll-mt-4 space-y-3" aria-labelledby={`hr-${id}-h`}>
      <div className="flex items-center gap-2 border-b border-line pb-2">
        <Icon name={icon} className="h-4 w-4 text-ai" />
        <h2 id={`hr-${id}-h`} className="text-base font-semibold text-slate-50">{title}</h2>
        {aside && <span className="ml-auto text-xs text-muted">{aside}</span>}
      </div>
      {children}
    </section>
  );
}

function Chip({ children, color, title }: { children: ReactNode; color?: string; title?: string }) {
  return <span title={title} className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] leading-4 text-slate-200" style={{ borderColor: color ?? "#2a313c" }}>{children}</span>;
}

/* ───────────── hero ───────────── */

function Hero({ d }: { d: HuntReportData }) {
  const v = VERDICT_META[d.verdict];
  const color = TONE_COLOR[v.tone];
  const [more, setMore] = useState(false);
  const paras = d.summary.split(/\n{2,}|\n(?=[A-Z][^\n]{0,40}:)/).map((s) => s.trim()).filter(Boolean);
  const long = d.summary.length > 480; // a wall of prose is folded to a few lines; the whole text is one click away
  const start = new Date(d.window_start);
  const end = new Date(d.window_end);
  const fmt = (x: Date) => x.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
  return (
    <header id="hr-summary" className="scroll-mt-4 space-y-4">
      <div>
        <p className="text-[11px] font-medium uppercase tracking-[0.14em] text-ai">AI threat hunt report</p>
        <h1 className="mt-1 text-2xl font-semibold leading-8 text-slate-50">{d.title}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <Chip title="Scope of the hunt (UTC)"><Icon name="clock" className="h-3 w-3" />{Number.isNaN(start.getTime()) ? d.scope : `${fmt(start)} → ${fmt(end)} · ${d.days} day${d.days === 1 ? "" : "s"}`}</Chip>
          <Chip>{d.mode} depth</Chip>
          {d.model && <Chip>{d.model}</Chip>}
          <Chip color={SEV_COLOR[d.severity]} title="Case severity"><span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[d.severity] }} aria-hidden="true" />severity {d.severity.toLowerCase()} · {d.priority}</Chip>
          <Chip title="Confidence in the conclusion">confidence {d.confidence.toLowerCase()}</Chip>
        </div>
      </div>
      <div className="flex items-start gap-4 rounded-lg border bg-panel/70 p-4" style={{ borderColor: color, boxShadow: `inset 4px 0 0 ${color}` }} role="status">
        <span className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-full" style={{ background: `${color}22`, color }}>
          <Icon name={v.icon === "half" ? "shield" : v.icon} className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <div className="text-xs font-medium uppercase tracking-wider" style={{ color }}>Verdict · {v.label}</div>
          <p className="mt-0.5 text-lg font-medium leading-7 text-slate-50">{d.verdict_line}</p>
        </div>
      </div>
      <div className="space-y-2 text-sm leading-6 text-slate-300">
        {(more ? paras : paras.slice(0, 1)).map((p, i) => <p key={i} className={!more && long ? "line-clamp-4" : ""}>{p}</p>)}
        {(paras.length > 1 || long) && <button type="button" className="hr-noprint text-xs text-accent hover:underline" onClick={() => setMore((m) => !m)}>{more ? "Show less" : paras.length > 1 ? `Read the full summary (${paras.length - 1} more)` : "Read the full summary"}</button>}
      </div>
      {d.background && (
        <details className="rounded-lg border border-line bg-panel/50 px-4 py-3 text-sm text-slate-300">
          <summary className="cursor-pointer text-xs font-medium uppercase tracking-wider text-muted">About this threat</summary>
          <p className="mt-2 leading-6">{d.background}</p>
        </details>
      )}
    </header>
  );
}

/* ───────────── findings ───────────── */

function FindingCard({ f, n }: { f: HrFinding; n: number }) {
  const sev = f.severity.toUpperCase();
  return (
    <article className="hr-card rounded-lg border border-line bg-panel/70 p-4" style={{ boxShadow: `inset 4px 0 0 ${SEV_COLOR[sev] ?? VIZ.gray}` }}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs text-muted">#{n}</span>
        <h3 className="min-w-0 flex-1 text-sm font-semibold text-slate-50">{f.title}</h3>
        <Chip color={SEV_COLOR[sev]}>{sev.toLowerCase()}</Chip>
        {f.classification && <Chip>{f.classification.replace(/_/g, " ")}</Chip>}
      </div>
      <p className="mt-2 text-sm leading-6 text-slate-300">{f.description}</p>
      {(f.alternative_explanations?.length ?? 0) > 0 && (
        <p className="mt-2 text-xs text-muted"><b className="font-medium text-slate-300">Benign explanations considered:</b> {f.alternative_explanations?.join("; ")}</p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs">
        {f.event_ids.slice(0, 6).map((id) => <a key={id} href={`/events?id=${id}`} className="rounded border border-line bg-bg/60 px-1.5 py-0.5 font-mono text-[11px] text-sky-300 hover:border-accent" title="Open the event">{id.slice(0, 8)}</a>)}
        {f.event_ids.length > 6 && <span className="text-muted">+{f.event_ids.length - 6} more events</span>}
        {(f.queries ?? []).map((q) => <span key={q} className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px] text-muted" title="Found by this search">{q}</span>)}
      </div>
    </article>
  );
}

/* ───────────── queries ───────────── */

const STATUS_ICON: Record<HrSection["status"], { icon: string; color: string; label: string }> = {
  SUCCEEDED: { icon: "check", color: VIZ.good, label: "Succeeded" }, PARTIAL: { icon: "alert", color: VIZ.warning, label: "Partial" }, FAILED: { icon: "x", color: VIZ.critical, label: "Failed" },
};

const FOLD = 12;

function QueryTable({ sections: all, omitted }: { sections: HrSection[]; omitted: number }) {
  const [full, setFull] = useState(false);
  const sections = full ? all : all.slice(0, FOLD); // the first dozen tell the story; the rest are one click away
  const max = Math.max(1, ...all.map((s) => s.results ?? 0));
  return (
    <div className="overflow-hidden rounded-lg border border-line bg-panel/70">
      <div className="grid grid-cols-[6.5rem_minmax(0,1fr)_minmax(6rem,12rem)_4rem] gap-3 border-b border-line px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-muted">
        <span>Status</span><span>Search</span><span>Results</span><span className="text-right">Count</span>
      </div>
      <ul>
        {sections.map((s, i) => {
          const st = STATUS_ICON[s.status];
          return (
            <li key={`${s.ref}-${i}`} className="border-b border-line/60 last:border-0">
              <details className="group">
                <summary className="grid cursor-pointer list-none grid-cols-[6.5rem_minmax(0,1fr)_minmax(6rem,12rem)_4rem] items-center gap-3 px-3 py-2 text-xs hover:bg-white/[.02]">
                  <span className="inline-flex items-center gap-1.5 text-slate-200"><span aria-hidden="true" style={{ color: st.color }}><Icon name={st.icon} className="h-3.5 w-3.5" /></span>{st.label}</span>
                  <span className="min-w-0 truncate text-slate-200" title={s.title}>{s.title}</span>
                  <span className="h-2 overflow-hidden rounded-r-[4px]"><span className="block h-full rounded-r-[4px]" style={{ width: `${s.results ? Math.max(3, (s.results / max) * 100) : 0}%`, background: VIZ.series[0] }} /></span>
                  <span className="text-right font-mono text-slate-100">{s.results == null ? "-" : fmtCount(s.results)}</span>
                </summary>
                <div className="space-y-2 border-t border-line/60 bg-bg/40 px-3 py-3 text-xs">
                  <p className="leading-5 text-slate-300">{s.description}</p>
                  <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded border border-line bg-bg/80 p-2 font-mono text-[11px] text-sky-200">{s.query}</pre>
                  {s.status === "FAILED" && <p className="text-red-300">The search failed ({s.error || "error"}); its result is unknown, not empty.</p>}
                  {s.status !== "FAILED" && s.results === 0 && <p className="text-muted">No results returned for this query.</p>}
                  {s.rows.length > 0 && (
                    <table className="w-full border-collapse">
                      <thead><tr>{["Time (UTC)", "Host", "User", "Event"].map((h) => <th key={h} className="border-b border-line px-2 py-1 text-left font-medium text-muted">{h}</th>)}</tr></thead>
                      <tbody>{s.rows.map((r) => <tr key={r.id}><td className="border-b border-line/50 px-2 py-1 font-mono text-slate-300">{r.time}</td><td className="border-b border-line/50 px-2 py-1">{r.host}</td><td className="border-b border-line/50 px-2 py-1">{r.user}</td><td className="border-b border-line/50 px-2 py-1 text-slate-300">{r.summary}</td></tr>)}</tbody>
                    </table>
                  )}
                </div>
              </details>
            </li>
          );
        })}
      </ul>
      {all.length > FOLD && <button type="button" className="hr-noprint w-full border-t border-line px-3 py-2 text-xs text-accent hover:bg-white/[.02]" onClick={() => setFull((f) => !f)}>{full ? "Show fewer searches" : `Show all ${all.length} searches`}</button>}
      {omitted > 0 && <p className="border-t border-line px-3 py-2 text-xs text-muted">{omitted} further search(es) are recorded in the AI run&apos;s investigation trace.</p>}
    </div>
  );
}

/* ───────────── intelligence ───────────── */

function IntelPanel({ intel }: { intel: HrIntel[] }) {
  const counts = ["malicious", "suspicious", "unknown", "benign"].map((k) => ({ key: k, label: VERDICT_STATUS[k].label, value: intel.filter((i) => i.verdict === k).length, color: VERDICT_STATUS[k].color }));
  return (
    <div className="space-y-4">
      <ChartCard title="Verdicts on the indicators it met" subtitle={`${intel.length} indicator${intel.length === 1 ? "" : "s"} checked against threat-intelligence sources`}
        table={<DataTable head={["Indicator", "Verdict", "Sources"]} rows={intel.map((i) => [`${i.kind ?? ""} ${i.value ?? ""}`, i.verdict, i.providers.map((p) => `${p.provider}: ${p.summary || p.verdict || p.status}`).join("; ") || "no provider answered"])} />}>
        <StackedBar ariaLabel="Indicators by verdict" segments={counts} />
      </ChartCard>
      <ul className="grid gap-2 lg:grid-cols-2">
        {intel.slice(0, 20).map((i, idx) => {
          const st = VERDICT_STATUS[i.verdict] ?? VERDICT_STATUS.unknown;
          const value = i.value ?? "";
          return (
            <li key={idx} className="min-w-0 space-y-1.5 rounded-lg border border-line bg-panel/70 p-3">
              <div className="flex min-w-0 items-center gap-2">
                <Chip color={st.color}><Icon name={st.icon} className="h-3 w-3" />{st.label}</Chip>
                <span className="rounded border border-line px-1.5 text-[11px] text-muted">{i.kind}</span>
                <span className="min-w-0 truncate font-mono text-xs text-slate-200" title={value}>{value.length > 28 ? `${value.slice(0, 14)}…${value.slice(-8)}` : value}</span>
              </div>
              {i.providers.length ? (
                <ul className="space-y-0.5 text-xs">{i.providers.map((p) => <li key={p.provider} className="flex gap-2"><span className="w-20 shrink-0 text-muted">{p.provider}</span><span className="text-slate-300">{p.summary || p.verdict || p.status}</span></li>)}</ul>
              ) : <p className="text-xs text-muted">No provider answered.</p>}
            </li>
          );
        })}
      </ul>
      <p className="text-[11px] text-muted">External context, not evidence from this environment. &quot;Unknown&quot; means no source had an opinion, not that it is safe.</p>
    </div>
  );
}

/* ───────────── the report ───────────── */

export function HuntReportView({ data: d, markdown, caseNumber }: { data: HuntReportData; markdown?: string; caseNumber?: string }) {
  const s = d.stats;
  const [active, setActive] = useState("summary");
  const root = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const els = NAV.map(([id]) => document.getElementById(`hr-${id}`)).filter((e): e is HTMLElement => !!e);
    if (!els.length || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver((entries) => {
      const vis = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (vis) setActive(vis.target.id.replace("hr-", ""));
    }, { rootMargin: "-10% 0px -70% 0px" });
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, [d.run_id]);
  const withData = useMemo(() => d.sections.filter((x) => (x.results ?? 0) > 0), [d.sections]);
  const measured = useMemo(() => withData.filter((x) => (x.results ?? 0) < 10000).sort((a, b) => (b.results ?? 0) - (a.results ?? 0)).slice(0, 8), [withData]); // a capped count is not a measurement
  const capped = withData.length - withData.filter((x) => (x.results ?? 0) < 10000).length;
  const byTool = useMemo(() => {
    const label: Record<string, string> = { search_events: "Event searches", aggregate_events: "Aggregations", pivot_entity: "Entity pivots", events_around: "Surrounding activity", process_lineage: "Process trees", get_event: "Event lookups" };
    const n = new Map<string, number>();
    for (const x of d.sections) n.set(x.tool, (n.get(x.tool) ?? 0) + 1);
    return [...n.entries()].sort((a, b) => b[1] - a[1]).map(([t, v]) => ({ label: label[t] ?? t, value: v }));
  }, [d.sections]);
  const nav = NAV.filter(([id]) => (id !== "playbooks" || d.playbooks.length > 0) && (id !== "intel" || d.intel.length > 0) && (id !== "attack" || d.attack.length > 0));
  const planned = s.playbook_steps;
  return (
    <div ref={root} className="hr-root grid gap-6 lg:grid-cols-[11rem_minmax(0,1fr)]">
      <nav aria-label="Report sections" className="hr-noprint lg:sticky lg:top-3 lg:self-start">
        <ul className="flex gap-1 overflow-x-auto pb-2 lg:flex-col lg:gap-0.5 lg:overflow-visible lg:pb-0">
          {nav.map(([id, label]) => (
            <li key={id}><a href={`#hr-${id}`} aria-current={active === id ? "location" : undefined} onClick={(e) => { e.preventDefault(); document.getElementById(`hr-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" }); setActive(id); }}
              className={`block whitespace-nowrap rounded px-2.5 py-1 text-xs transition ${active === id ? "bg-violet-500/15 text-violet-200" : "text-muted hover:text-slate-200"}`}>{label}</a></li>
          ))}
        </ul>
        <div className="mt-4 hidden space-y-1.5 lg:block">
          {markdown && <button type="button" className="btn flex w-full items-center justify-center gap-1.5 py-1 text-xs" onClick={() => {
            const url = URL.createObjectURL(new Blob([markdown], { type: "text/markdown" }));
            const a = document.createElement("a"); a.href = url; a.download = `${caseNumber ?? "hunt"}-report.md`; a.click(); URL.revokeObjectURL(url);
          }}><Icon name="download" className="h-3.5 w-3.5" />Markdown</button>}
          <button type="button" className="btn flex w-full items-center justify-center gap-1.5 py-1 text-xs" onClick={() => window.print()}><Icon name="print" className="h-3.5 w-3.5" />Print / PDF</button>
        </div>
      </nav>

      <div className="min-w-0 space-y-8">
        <Hero d={d} />

        <Section id="numbers" title="Key numbers" icon="target">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <StatTile label="Searches run" value={s.queries} hint={s.failed ? `${s.failed} failed` : "all completed"} accent={s.failed ? VIZ.critical : VIZ.series[0]} icon={<Icon name="search" className="h-4 w-4" />} />
            <StatTile label="Events reviewed" value={s.events_reviewed} hint={`${s.hosts} host${s.hosts === 1 ? "" : "s"}`} accent={VIZ.series[0]} icon={<Icon name="list" className="h-4 w-4" />} />
            <StatTile label="Threat findings" value={s.findings} hint={s.observations ? `+${s.observations} observation(s)` : "verified only"} accent={s.findings ? VIZ.critical : VIZ.good} icon={<Icon name="alert" className="h-4 w-4" />} />
            <StatTile label="ATT&CK techniques" value={s.techniques} hint="related to the hunt" accent={VIZ.series[0]} icon={<Icon name="layers" className="h-4 w-4" />} />
            <StatTile label="Playbook steps run" value={s.playbook_steps_run} hint={planned ? `of ${planned} planned` : "no playbook used"} accent={VIZ.series[0]} icon={<Icon name="book" className="h-4 w-4" />} />
            <StatTile label="Open gaps" value={s.gaps} hint={s.gaps ? "could not be checked" : "nothing left open"} accent={s.gaps ? VIZ.warning : VIZ.good} icon={<Icon name="help" className="h-4 w-4" />} />
          </div>
        </Section>

        <Section id="charts" title="The hunt at a glance" icon="chart">
          <div className="grid items-start gap-4 xl:grid-cols-2">
            <ChartCard title="How the searches turned out" subtitle={`${s.queries} search${s.queries === 1 ? "" : "es"} against the telemetry`}
              table={<DataTable head={["Outcome", "Searches"]} rows={[["Returned results", s.with_results], ["No results", s.no_results], ["Failed", s.failed], ...byTool.map((b) => [`By tool: ${b.label}`, b.value])]} />}>
              <StackedBar ariaLabel="Searches by outcome" segments={[
                { key: "hits", label: "Returned results", value: s.with_results, color: VIZ.series[0] },
                { key: "none", label: "No results", value: s.no_results, color: VIZ.gray },
                { key: "failed", label: "Failed", value: s.failed, color: VIZ.critical, mark: "✕" },
              ]} />
              {byTool.length > 0 && <div className="mt-5 border-t border-line pt-3"><p className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted">By kind of search</p><HBars rows={byTool} /></div>}
            </ChartCard>
            <ChartCard title="Events reviewed by host" subtitle="Where the evidence came from"
              table={<DataTable head={["Host", "Events"]} rows={d.hosts.map((h) => [h.host, h.events])} />}>
              {d.hosts.length ? <HBars rows={d.hosts.map((h) => ({ label: h.host, value: h.events }))} /> : <p className="text-xs text-muted">No events were retrieved.</p>}
            </ChartCard>
            <ChartCard title="Largest result sets" subtitle="Searches that matched the most events (counting stops at 10,000)" className="xl:col-span-2"
              table={<DataTable head={["Search", "Status", "Results"]} rows={d.sections.map((x) => [x.title, x.status, x.results == null ? "-" : fmtCount(x.results)])} />}>
              {measured.length ? <HBars rows={measured.map((b) => ({ label: b.title, value: b.results ?? 0, title: b.query }))} /> : !capped && <p className="text-xs text-muted">None of the searches returned results.</p>}
              {capped > 0 && <p className="mt-2 text-xs text-slate-300">{capped} search{capped === 1 ? "" : "es"} matched at least 10,000 events (the counting limit): {measured.length ? "not shown above, since their size is unknown." : "their true size is unknown."}</p>}
            </ChartCard>
            <ChartCard title="Activity timeline" subtitle="Reviewed events over the hunt window; ringed events are cited by findings" className="xl:col-span-2"
              table={<DataTable head={["Time", "Host", "Type", "Event", "Cited"]} rows={d.timeline.map((t) => [new Date(t.timestamp).toLocaleString(), t.host ?? "", t.event_type ?? "", t.summary, t.cited ? "yes" : ""])} />}>
              <TimelineChart points={d.timeline} />
            </ChartCard>
          </div>
        </Section>

        {d.attack.length > 0 && (
          <Section id="attack" title="MITRE ATT&CK coverage" icon="layers" aside={`${d.attack.length} technique(s)`}>
            <ChartCard title="Techniques by tactic" subtitle="Darker means more techniques in that tactic"
              table={<DataTable head={["Technique", "Name", "Tactics", "Source"]} rows={d.attack.map((a) => [a.id, a.name, a.tactics.join(", "), a.source])} />}>
              <TacticStrip attack={d.attack} />
            </ChartCard>
          </Section>
        )}

        <Section id="findings" title="Findings" icon="alert" aside={d.findings.length ? `${d.findings.length} threat finding(s)` : undefined}>
          {d.findings.length ? (
            <div className="space-y-3">{[...d.findings].sort((a, b) => SEVERITY_ORDER.indexOf(b.severity.toUpperCase()) - SEVERITY_ORDER.indexOf(a.severity.toUpperCase())).map((f, i) => <FindingCard key={i} f={f} n={i + 1} />)}</div>
          ) : (
            <div className="flex items-start gap-3 rounded-lg border border-line bg-panel/70 p-4 text-sm text-slate-300"><Icon name="check" className="mt-0.5 h-4 w-4 shrink-0" />No verified threat finding came out of this hunt.</div>
          )}
          {d.observations.length > 0 && (
            <details className="rounded-lg border border-line bg-panel/50 px-4 py-3">
              <summary className="cursor-pointer text-xs font-medium uppercase tracking-wider text-muted">Observations - verified, but informational ({d.observations.length})</summary>
              <ul className="mt-2 space-y-2 text-sm text-slate-300">{d.observations.map((o, i) => <li key={i}><b className="font-medium text-slate-100">{o.title}</b> - {o.description}</li>)}</ul>
            </details>
          )}
        </Section>

        <Section id="queries" title="Hunt queries" icon="search" aside="click a row for the query and sample events">
          <QueryTable sections={d.sections} omitted={d.omitted_sections} />
        </Section>

        {d.playbooks.length > 0 && (
          <Section id="playbooks" title="Hunt playbooks followed" icon="book" aside={`${s.playbook_steps_run} of ${planned} steps run`}>
            <div className="grid gap-3 lg:grid-cols-2">
              {d.playbooks.map((p) => (
                <div key={p.id} className="hr-card space-y-2 rounded-lg border border-line bg-panel/70 p-4">
                  <Meter label={p.title} value={p.run} total={p.total} />
                  <div className="flex flex-wrap gap-1">{p.attack.map((a) => <span key={a} className="rounded border border-line px-1 font-mono text-[10px] text-muted">{a}</span>)}</div>
                  <details className="text-xs">
                    <summary className="cursor-pointer text-muted hover:text-slate-200">Step checklist</summary>
                    <ul className="mt-2 space-y-1">{p.steps.map((st, i) => (
                      <li key={i} className={`flex gap-2 ${st.done ? "text-slate-200" : "text-muted"}`}>
                        <span className={st.done ? "text-emerald-400" : ""} aria-label={st.done ? "done" : "not run"}>{st.done ? "✓" : "○"}</span>
                        <span className="min-w-0 flex-1">{st.goal}</span><span className="shrink-0 text-[10px] text-muted">{st.purpose}</span>
                      </li>
                    ))}</ul>
                  </details>
                </div>
              ))}
            </div>
          </Section>
        )}

        {d.intel.length > 0 && <Section id="intel" title="Threat intelligence" icon="shield"><IntelPanel intel={d.intel} /></Section>}

        <Section id="gaps" title="Coverage & gaps" icon="help">
          <div className="grid gap-3 lg:grid-cols-2">
            <div className="hr-card rounded-lg border border-line bg-panel/70 p-4" style={{ boxShadow: `inset 4px 0 0 ${d.gaps.length ? VIZ.warning : VIZ.good}` }}>
              <h3 className="text-sm font-semibold text-slate-50">{d.gaps.length ? "Could not be checked or left open" : "Every planned check was completed"}</h3>
              {d.gaps.length > 0 && <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-300 [overflow-wrap:anywhere]">{d.gaps.map((g) => <li key={g}>{g}</li>)}</ul>}
            </div>
            <div className="hr-card rounded-lg border border-line bg-panel/70 p-4">
              <h3 className="text-sm font-semibold text-slate-50">Limits and notes</h3>
              {d.notes.length ? <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-300 [overflow-wrap:anywhere]">{d.notes.map((g) => <li key={g}>{g}</li>)}</ul> : <p className="mt-2 text-sm text-muted">None.</p>}
            </div>
          </div>
        </Section>

        <Section id="actions" title="Recommendations" icon="flag">
          <ol className="space-y-2">
            {d.recommendations.map((r, i) => (
              <li key={i} className="hr-card flex gap-3 rounded-lg border border-line bg-panel/70 p-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-violet-500/15 text-xs font-semibold text-violet-200">{i + 1}</span>
                <p className="text-sm leading-6 text-slate-200">{r}</p>
              </li>
            ))}
          </ol>
        </Section>

        <Section id="references" title="References" icon="globe">
          <ul className="space-y-1 text-sm">{d.references.map((r) => <li key={r.url}><a href={r.url} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline-offset-2 hover:underline">{r.title}</a></li>)}</ul>
        </Section>

        <footer className="border-t border-line pt-3 text-[11px] leading-5 text-muted">
          Generated by the AI hunting agent ({d.model || "model"}), run {d.run_id}. AI-generated analysis: every cited event was retrieved from this environment&apos;s telemetry, but the interpretation can be wrong - review the evidence before acting.
        </footer>
      </div>
    </div>
  );
}
