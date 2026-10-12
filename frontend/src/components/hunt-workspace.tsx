"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import type { EventQueryBody, Filter, Finding, FindingSeverity, Hunt, HuntStatus, SavedQuery, TimelineScope } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { MitrePanel, ObjectTechniqueChips } from "./mitre-panel";
import { appendPivot, downloadBlob } from "@/lib/hunt-query";
import { addFilter, clampPaging, fmtTime, MAX_WINDOW, resolveRange, SEARCH_AGGS, type RangeSpec } from "@/lib/query";
import { AggPanel } from "./agg-panel";
import { AddToCaseDialog } from "./add-to-case-dialog";
import { EventDrawer } from "./event-drawer";
import { FilterBuilder, FilterChips } from "./filter-builder";
import { STATUSES } from "./hunts-list";
import { Histogram } from "./histogram";
import { QueryEditor } from "./query-editor";
import { RangeControl } from "./range-control";
import { ResultsTable } from "./results-table";
import { TimelinePanel, type TimelineSource } from "./timeline-view";
import { Loading } from "./ui/skeleton";
import { Bookmark, Download, History, Play, Save, Trash2 } from "lucide-react";
import { useConfirm } from "./ui/confirm";
import { SiemSearchCard } from "./siem-search-card";
import { EmptyState } from "./ui/empty-state";
import { SeverityBadge } from "./ui/severity";
import { Tabs } from "./ui/tabs";
import { useToast } from "./ui/toast";

const SEVERITIES: FindingSeverity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const MAX_FINDING_EVENTS = 50;
const EXPORT_CAP = 5000;

const errMsg = (e: unknown, fallback: string) => (e instanceof ApiError ? e.friendly : fallback);

export function buildBody(text: string, range: RangeSpec, filters: Filter[], offset: number, limit: number,
  sort: { field: string; order: "asc" | "desc" } | null, withAggs = true): EventQueryBody {
  const { offset: o, limit: l } = clampPaging(offset, limit);
  const body: EventQueryBody = {
    time_range: resolveRange(range), filters, sort: sort ? [sort] : [], offset: o, limit: l,
    aggregations: withAggs ? SEARCH_AGGS : [],
  };
  if (text.trim()) body.text = text.trim();
  return body;
}

function rangeFromQuery(q: Partial<EventQueryBody>): RangeSpec | null {
  return q.time_range ? { kind: "abs", start: q.time_range.start, end: q.time_range.end } : null;
}

export function HuntWorkspace({ id }: { id: string }) {
  const hunt = useQuery({ queryKey: ["hunt", id], queryFn: () => api.getHunt(id) });
  if (hunt.isLoading) return <Loading />;
  if (hunt.error || !hunt.data) {
    return <p role="alert" className="panel p-4 text-sm text-sev-critical">{hunt.error instanceof ApiError && hunt.error.status === 404 ? "Hunt not found." : errMsg(hunt.error, "Failed to load hunt")}</p>;
  }
  return <Workspace hunt={hunt.data} />;
}

function Workspace({ hunt }: { hunt: Hunt }) {
  const { can } = useAuth();
  const router = useRouter();
  const qc = useQueryClient();
  const canWrite = can("hunts:write");
  const huntId = hunt.id;
  const { confirm, node: confirmNode } = useConfirm();
  const toast = useToast();
  const [showQueries, setShowQueries] = useState(false);

  // ---- header (inline edit) ----
  const [title, setTitle] = useState(hunt.title);
  const [hyp, setHyp] = useState(hunt.hypothesis);
  const [conclusion, setConclusion] = useState(hunt.conclusion);
  const update = useMutation({
    mutationFn: (b: Parameters<typeof api.updateHunt>[1]) => api.updateHunt(huntId, b),
    onSuccess: (h) => { qc.setQueryData(["hunt", huntId], h); void qc.invalidateQueries({ queryKey: ["hunts"] }); },
  });

  // ---- query state ----
  const [text, setText] = useState("");
  const [range, setRange] = useState<RangeSpec>(
    hunt.time_start && hunt.time_end ? { kind: "abs", start: hunt.time_start, end: hunt.time_end } : { kind: "rel", value: "24h" });
  const [filters, setFilters] = useState<Filter[]>([]);
  const [sort, setSort] = useState<{ field: string; order: "asc" | "desc" } | null>(null);
  const [applied, setApplied] = useState<EventQueryBody | null>(null);
  const [rerun, setRerun] = useState(0); // same query, fresh run (e.g. after logs were imported from the SIEM)
  const [tab, setTab] = useState<"results" | "timeline" | "mitre">("results");
  const [tlSource, setTlSource] = useState<TimelineSource | null>(null);
  const [openEvent, setOpenEvent] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dense] = useState(true);

  const fields = useQuery({ queryKey: ["fields"], queryFn: api.fields, staleTime: Infinity });
  const run = useQuery({
    queryKey: ["hunt-run", huntId, JSON.stringify(applied), rerun],
    queryFn: () => api.runHunt(huntId, applied!),
    enabled: applied !== null,
    retry: false, staleTime: Infinity, refetchOnWindowFocus: false, placeholderData: (p) => p,
  });
  // The same query is also run against the whole LogRhythm SIEM; "Show in results" re-runs the hunt query so the imported logs appear.
  const siem = useQuery({
    queryKey: ["siem-hunt", huntId, JSON.stringify(applied)], queryFn: () => api.siemSearch({ ...applied!, aggregations: [] }), enabled: applied !== null,
    staleTime: Infinity, retry: false, refetchOnWindowFocus: false,
  });
  useEffect(() => { if (run.isSuccess) void qc.invalidateQueries({ queryKey: ["history", huntId] }); }, [run.dataUpdatedAt, run.isSuccess, qc, huntId]);

  const doRun = (offset = 0, s = sort) => { setApplied(buildBody(text, range, filters, offset, 50, s)); setTab("results"); };
  const pivotToText = (field: string, value: string | number) => setText((t) => appendPivot(t, field, value));
  const data = run.data;
  const offset = applied?.offset ?? 0;
  const limit = applied?.limit ?? 50;
  const canNext = data ? offset + limit < Math.min(data.total, MAX_WINDOW) : false;

  const selection = useMemo(() => ({
    ids: selected,
    onToggle: (eid: string) => setSelected((s) => { const n = new Set(s); if (n.has(eid)) n.delete(eid); else n.add(eid); return n; }),
    onToggleAll: (ids: string[], on: boolean) => setSelected((s) => { const n = new Set(s); ids.forEach((i) => (on ? n.add(i) : n.delete(i))); return n; }),
  }), [selected]);

  // ---- saved queries / history ----
  const saved = useQuery({ queryKey: ["saved", huntId], queryFn: () => api.listSavedQueries(huntId) });
  const history = useQuery({ queryKey: ["history", huntId], queryFn: () => api.history(huntId) });
  const [saveName, setSaveName] = useState("");
  const [saveDesc, setSaveDesc] = useState("");
  const [showSave, setShowSave] = useState(false);
  const save = useMutation({
    mutationFn: () => api.saveQuery({ name: saveName.trim(), description: saveDesc, hunt_id: huntId, query: buildBody(text, range, filters, 0, 50, null, false) }),
    onSuccess: () => { toast.success("Query saved"); setShowSave(false); setSaveName(""); setSaveDesc(""); void qc.invalidateQueries({ queryKey: ["saved", huntId] }); void qc.invalidateQueries({ queryKey: ["hunt", huntId] }); },
  });
  const toRule = useMutation({
    mutationFn: () => api.ruleFromQuery({ title: `${hunt.title}: ${text.trim().slice(0, 60)}`, text: text.trim(), severity: "MEDIUM", hunt_id: huntId }),
    onSuccess: () => router.push("/detections"),
  });
  const delSaved = useMutation({ mutationFn: (sid: string) => api.deleteSavedQuery(sid), onSuccess: () => qc.invalidateQueries({ queryKey: ["saved", huntId] }) });
  const load = (q: Partial<EventQueryBody>) => {
    setText(q.text ?? "");
    setFilters(q.filters ?? []);
    const r = rangeFromQuery(q);
    if (r) setRange(r);
  };

  const [caseEvents, setCaseEvents] = useState<string[] | null>(null);
  const promote = useMutation({
    mutationFn: (f: Finding) => api.createCase({ title: f.title, description: f.description, severity: f.severity, finding_id: f.id }),
    onSuccess: (c) => { void qc.invalidateQueries({ queryKey: ["cases"] }); router.push(`/cases/${c.id}`); },
  });
  // ---- findings / notes ----
  const findings = useQuery({ queryKey: ["findings", huntId], queryFn: () => api.listFindings(huntId) });
  const notes = useQuery({ queryKey: ["notes", huntId], queryFn: () => api.listNotes(huntId) });
  const [showFinding, setShowFinding] = useState(false);
  const [fTitle, setFTitle] = useState("");
  const [fSev, setFSev] = useState<FindingSeverity>("MEDIUM");
  const [fDesc, setFDesc] = useState("");
  const addFinding = useMutation({
    mutationFn: () => api.addFinding(huntId, { title: fTitle.trim(), description: fDesc, severity: fSev, event_ids: [...selected] }),
    onSuccess: () => {
      toast.success("Finding saved", `${selected.size} event${selected.size === 1 ? "" : "s"} attached as evidence`);
      setShowFinding(false); setFTitle(""); setFDesc(""); setSelected(new Set());
      void qc.invalidateQueries({ queryKey: ["findings", huntId] }); void qc.invalidateQueries({ queryKey: ["hunt", huntId] });
    },
  });
  const delFinding = useMutation({
    mutationFn: (fid: string) => api.deleteFinding(huntId, fid),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["findings", huntId] }); void qc.invalidateQueries({ queryKey: ["hunt", huntId] }); },
  });
  const [noteBody, setNoteBody] = useState("");
  const addNote = useMutation({
    mutationFn: () => api.addNote(huntId, noteBody.trim()),
    onSuccess: () => { toast.success("Note added"); setNoteBody(""); void qc.invalidateQueries({ queryKey: ["notes", huntId] }); },
  });

  // ---- export ----
  const [exportErr, setExportErr] = useState<string | null>(null);
  async function doExport(format: "csv" | "json") {
    setExportErr(null);
    try {
      const q = applied ?? buildBody(text, range, filters, 0, 50, sort, false);
      const { aggregations: _a, offset: _o, limit: _l, ...rest } = q;
      void _a; void _o; void _l;
      downloadBlob(await api.exportEvents(rest, format, EXPORT_CAP), `hunt-${huntId.slice(0, 8)}.${format}`);
      toast.success(`Exported ${format.toUpperCase()}`);
    } catch (e) { setExportErr(errMsg(e, "Export failed")); }
  }

  const openTimelineFromQuery = () => {
    setTlSource({ kind: "query", query: buildBody(text, range, filters, 0, 50, null, false) });
    setTab("timeline");
  };
  const openTimelineAround = (eventId: string, scope: TimelineScope, windowMinutes: number) => {
    setTlSource({ kind: "around", eventId, scope, windowMinutes });
    setTab("timeline");
  };

  const submitSave = (e: FormEvent) => { e.preventDefault(); if (saveName.trim()) save.mutate(); };
  const submitFinding = (e: FormEvent) => { e.preventDefault(); if (fTitle.trim() && selected.size) addFinding.mutate(); };

  return (
    <div className="space-y-4">
      {/* header */}
      <div>
        <div className="panel space-y-3 p-4">
          <h1 className="sr-only">Hunt: {hunt.title}</h1>
          <div className="flex flex-wrap items-center gap-3">
            <input aria-label="Hunt title" className="input min-w-[16rem] flex-1 border-transparent bg-transparent px-1 text-xl font-semibold shadow-none hover:border-line-strong focus-visible:bg-panel" value={title} maxLength={200} readOnly={!canWrite}
              onChange={(e) => setTitle(e.target.value)} onBlur={() => canWrite && title.trim() && title !== hunt.title && update.mutate({ title: title.trim() })} />
            <label className="flex items-center gap-2 text-sm text-muted">Status
              <select aria-label="Hunt status" className="input" value={hunt.status} disabled={!canWrite} onChange={(e) => update.mutate({ status: e.target.value as HuntStatus })}>
                {STATUSES.map((s) => <option key={s}>{s}</option>)}
              </select></label>
          </div>
          <label className="block"><span className="eyebrow">Hypothesis</span>
            <textarea aria-label="Hypothesis" className="input mt-1 w-full text-sm" rows={2} value={hyp} readOnly={!canWrite} maxLength={5000}
              placeholder="What do you expect to find, and why?" onChange={(e) => setHyp(e.target.value)}
              onBlur={() => canWrite && hyp !== hunt.hypothesis && update.mutate({ hypothesis: hyp })} /></label>
          {update.error && <p role="alert" className="text-sm text-sev-critical">{errMsg(update.error, "Save failed")}</p>}
          <ObjectTechniqueChips objectType="hunt" objectId={huntId} />
        </div>
      </div>

      <div className="flex flex-col items-start gap-4 xl:flex-row">
        {/* centre: editor + results */}
        <div className="min-w-0 w-full flex-1 space-y-3">
          <div className="panel space-y-3 p-3">
          <QueryEditor value={text} onChange={setText} onRun={() => doRun()} />
          <div className="flex flex-wrap items-center gap-2">
            <RangeControl value={range} onChange={setRange} />
            {fields.data && <FilterBuilder fields={fields.data.filter((f) => f.kind !== "date")} onAdd={(f) => setFilters((fs) => addFilter(fs, f))} />}
            <button className="btn btn-primary" onClick={() => doRun()}><Play aria-hidden className="h-3.5 w-3.5" />Run <kbd className="kbd border-white/25 bg-accent-strong text-white">Ctrl+Enter</kbd></button>
            <button className="btn" disabled={!canWrite} onClick={() => setShowSave((s) => !s)}><Save aria-hidden className="h-3.5 w-3.5" />Save query</button>
            <button className="btn" aria-expanded={showQueries} onClick={() => setShowQueries((v) => !v)}><History aria-hidden className="h-3.5 w-3.5" />Saved &amp; history ({(saved.data?.length ?? 0) + (history.data?.length ?? 0)})</button>
            <button className="btn" onClick={openTimelineFromQuery}>Timeline</button>
            <button className="btn" disabled={!can("detections:write") || !text.trim() || toRule.isPending} onClick={() => toRule.mutate()}
              title="Create a DRAFT detection from the query text (filter chips are not included)">Promote to detection</button>
            <span className="ml-auto flex items-center gap-1">
              <button className="btn" onClick={() => void doExport("csv")}><Download aria-hidden className="h-3.5 w-3.5" />Export CSV</button>
              <button className="btn" onClick={() => void doExport("json")}><Download aria-hidden className="h-3.5 w-3.5" />Export JSON</button>
              <span className="text-xs text-muted">max {EXPORT_CAP.toLocaleString()} rows</span>
            </span>
          </div>
          {showQueries && (
            <div className="grid gap-4 rounded-md border border-line bg-subtle p-3 md:grid-cols-2" aria-label="Queries">
              <section>
                <h2 className="eyebrow mb-1.5 flex items-center gap-1"><Bookmark aria-hidden className="h-3 w-3" />Saved queries</h2>
                {saved.data?.length ? (
                  <ul className="space-y-0.5">
                    {saved.data.map((q: SavedQuery) => (
                      <li key={q.id} className="flex items-center gap-1">
                        <button className="flex-1 truncate rounded px-1.5 py-1 text-left text-sm hover:bg-accent-soft" title={q.query.text ?? q.description} onClick={() => load(q.query)}>{q.name}</button>
                        {canWrite && <button className="btn btn-ghost px-1.5 text-muted hover:text-sev-critical" aria-label={`Delete saved query ${q.name}`}
                          onClick={() => confirm({ title: `Delete saved query “${q.name}”?`, message: "The query is removed from this hunt. Results already produced are not affected.", confirmLabel: "Delete query", run: () => delSaved.mutate(q.id) })}><Trash2 aria-hidden className="h-3.5 w-3.5" /></button>}
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-sm text-muted">None yet. Run a query you want to keep, then choose Save query.</p>}
              </section>
              <section>
                <h2 className="eyebrow mb-1.5 flex items-center gap-1"><History aria-hidden className="h-3 w-3" />History (this hunt)</h2>
                {history.data?.length ? (
                  <ul className="space-y-0.5">
                    {history.data.slice(0, 12).map((h) => (
                      <li key={h.id}><button className="w-full rounded px-1.5 py-1 text-left hover:bg-accent-soft" onClick={() => load(h.query)} title={h.query.text ?? ""}>
                        <span className="block truncate font-mono text-xs">{h.query.text || "(all events)"}</span><span className="text-xs text-muted">{fmtTime(h.executed_at)} · {h.total} hits</span></button></li>
                    ))}
                  </ul>
                ) : <p className="text-sm text-muted">No runs yet.</p>}
              </section>
            </div>
          )}
          {toRule.error && <p role="alert" className="text-red-700 text-xs">{toRule.error instanceof Error ? toRule.error.message : "Could not create detection"}</p>}
          <FilterChips filters={filters} onRemove={(i) => setFilters((fs) => fs.filter((_, j) => j !== i))} />
          {exportErr && <p role="alert" className="text-red-700 text-xs">{exportErr}</p>}
          {showSave && (
            <form onSubmit={submitSave} className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-subtle p-2" aria-label="Save query">
              <input aria-label="Query name" className="input" placeholder="Name" value={saveName} maxLength={200} onChange={(e) => setSaveName(e.target.value)} />
              <input aria-label="Query description" className="input flex-1" placeholder="Description (optional)" value={saveDesc} onChange={(e) => setSaveDesc(e.target.value)} />
              <button className="btn btn-primary" type="submit" disabled={!saveName.trim() || save.isPending}>Save</button>
              {save.error && <span role="alert" className="text-red-700 text-xs">{errMsg(save.error, "Save failed")}</span>}
            </form>
          )}

          </div>

          <Tabs<"results" | "timeline" | "mitre"> label="Hunt views" value={tab} onChange={setTab}
            tabs={[{ key: "results", label: "Results", count: data ? (data.total_relation === "gte" ? `${data.total.toLocaleString("en-US")}+` : data.total.toLocaleString("en-US")) : null }, { key: "timeline", label: "Timeline" }, ...(can("mitre:read") ? [{ key: "mitre" as const, label: "MITRE ATT&CK" }] : [])]} />

          {tab === "results" && (
            <div className="space-y-2">
              {run.error && <p role="alert" className="rounded-lg border border-sev-critical/30 bg-sev-critical-bg px-4 py-3 text-sm text-sev-critical">{errMsg(run.error, "Run failed")}</p>}
              {!applied && <div className="panel"><EmptyState icon={Play} title="Ready when you are">Write a query and press Run. Hunt defaults (window, data sources) apply when you leave them unset.</EmptyState></div>}
              {applied && <SiemSearchCard query={siem} onShow={() => setRerun((n) => n + 1)} />}
              {data && (
                <>
                  <div className="flex flex-wrap items-center gap-3 text-sm text-muted">
                    <span className="font-semibold text-ink">{data.total_relation === "gte" ? "≥ " : ""}{data.total.toLocaleString()} events</span><span className="text-xs">{data.took_ms} ms</span>
                    {run.isFetching && <span className="text-xs text-accent" role="status">running…</span>}
                    <span className="ml-auto flex items-center gap-1">
                      {selected.size > 0 && <span>{selected.size} selected</span>}
                      <button className="btn" disabled={!canWrite || selected.size === 0} onClick={() => setShowFinding((s) => !s)}>Add finding</button>
                      <button className="btn" disabled={!can("cases:write") || selected.size === 0 || selected.size > 100} onClick={() => setCaseEvents([...selected])}>Add to case…</button>
                    </span>
                  </div>
                  {showFinding && (
                    <form onSubmit={submitFinding} className="panel space-y-2 p-3" aria-label="Add finding">
                      <div className="flex gap-1">
                        <input aria-label="Finding title" className="input flex-1" placeholder="Finding title" value={fTitle} maxLength={200} onChange={(e) => setFTitle(e.target.value)} />
                        <select aria-label="Finding severity" className="input" value={fSev} onChange={(e) => setFSev(e.target.value as FindingSeverity)}>
                          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
                        </select>
                      </div>
                      <textarea aria-label="Finding description" className="input w-full text-xs" rows={2} placeholder="Description" value={fDesc} onChange={(e) => setFDesc(e.target.value)} />
                      {selected.size > MAX_FINDING_EVENTS && <p role="alert" className="text-red-700 text-xs">At most {MAX_FINDING_EVENTS} events per finding.</p>}
                      <button className="btn btn-primary" type="submit" disabled={!fTitle.trim() || selected.size === 0 || selected.size > MAX_FINDING_EVENTS || addFinding.isPending}>
                        Save finding ({selected.size} events)
                      </button>
                      {addFinding.error && <span role="alert" className="ml-2 text-red-700 text-xs">{errMsg(addFinding.error, "Failed to save finding")}</span>}
                    </form>
                  )}
                  <Histogram buckets={data.aggregations.timeline?.buckets ?? []} rangeEnd={data.time_range.end}
                    onSelect={(start, end) => setRange({ kind: "abs", start, end })} />
                  <div className="flex gap-4">
                    <div className="min-w-0 flex-1">
                      {data.hits.length === 0 ? <div className="panel"><EmptyState title="No events match">Nothing matched this query in the selected time range. Widen the window or relax a filter.</EmptyState></div> : (
                        <ResultsTable hits={data.hits} dense={dense} selected={openEvent} onOpen={setOpenEvent} sort={sort} selection={selection}
                          onSort={(field) => {
                            const next = sort?.field === field ? { field, order: (sort.order === "desc" ? "asc" : "desc") as "asc" | "desc" } : { field, order: "desc" as const };
                            setSort(next); doRun(0, next);
                          }} />
                      )}
                      <div className="mt-3 flex items-center gap-2 text-sm">
                        <button className="btn" disabled={offset === 0} onClick={() => doRun(Math.max(0, offset - limit))}>Prev</button>
                        <span className="text-muted">{data.total ? offset + 1 : 0}–{Math.min(offset + limit, data.total)}</span>
                        <button className="btn" disabled={!canNext} onClick={() => doRun(offset + limit)}>Next</button>
                      </div>
                    </div>
                    <AggPanel aggs={data.aggregations} onFilter={(f) => pivotToText(f.field, String(f.value))} />
                  </div>
                </>
              )}
            </div>
          )}
          {tab === "mitre" && (
            <MitrePanel source={{ hunt_id: huntId }} mutable={canWrite}
              targets={[{ type: "hunt", id: huntId, label: "This hunt" }, ...(findings.data ?? []).map((f) => ({ type: "finding" as const, id: f.id, label: `Finding: ${f.title}` }))]} />
          )}
          {tab === "timeline" && <TimelinePanel source={tlSource} onOpen={setOpenEvent} />}
        </div>

        {/* right: findings, notes, conclusion */}
        <aside className="w-full shrink-0 space-y-4 xl:w-80" aria-label="Evidence">
          <section className="panel">
            <h2 className="flex items-center justify-between border-b border-line px-4 py-2.5 text-sm font-semibold">Findings<span className="rounded-full bg-subtle px-2 text-xs font-medium text-muted tabular-nums">{findings.data?.length ?? 0}</span></h2>
            <div className="p-3">
            {findings.data?.length ? (
              <ul className="space-y-2">
                {findings.data.map((f) => (
                  <li key={f.id} className="rounded-md border border-line p-2.5">
                    <div className="flex items-start gap-2">
                      <SeverityBadge level={f.severity} label={f.severity} />
                      <span className="min-w-0 flex-1 break-words text-sm font-medium">{f.title}</span>
                      {canWrite && <button className="btn btn-ghost px-1 text-muted hover:text-sev-critical" aria-label={`Delete finding ${f.title}`}
                        onClick={() => confirm({ title: `Delete finding “${f.title}”?`, message: "The finding and its evidence references are removed from this hunt.", confirmLabel: "Delete finding", run: () => delFinding.mutate(f.id) })}><Trash2 aria-hidden className="h-3.5 w-3.5" /></button>}
                    </div>
                    {f.description && <p className="mt-1 whitespace-pre-wrap text-xs text-ink-2">{f.description}</p>}
                    <ul className="mt-1.5 space-y-0.5 text-xs text-muted">
                      {f.evidence.map((ev) => (
                        <li key={ev.id}><button className="text-left hover:text-accent" onClick={() => setOpenEvent(ev.id)}>{fmtTime(ev.timestamp)} {ev.host ? `[${ev.host}] ` : ""}{ev.summary}</button></li>
                      ))}
                    </ul>
                    {can("cases:write") && <button className="btn btn-sm mt-2" aria-label={`Promote finding ${f.title} to case`} disabled={promote.isPending} onClick={() => promote.mutate(f)}>→ Open as case</button>}
                  </li>
                ))}
              </ul>
            ) : <p className="text-sm text-muted">Select result rows, then choose “Add finding” to record what you found with its evidence.</p>}
            </div>
          </section>
          <section className="panel">
            <h2 className="border-b border-line px-4 py-2.5 text-sm font-semibold">Notes</h2>
            <div className="space-y-2 p-3">
              <ul className="space-y-2">
                {notes.data?.map((n) => (
                  <li key={n.id} className="whitespace-pre-wrap rounded-md bg-subtle p-2.5 text-sm">
                    {n.body}
                    <div className="mt-1 text-xs text-muted">{fmtTime(n.created_at)}</div>
                  </li>
                ))}
              </ul>
              {canWrite && (
                <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (noteBody.trim()) addNote.mutate(); }}>
                  <textarea aria-label="New note" className="input w-full text-sm" rows={2} placeholder="Add a note…" maxLength={10000} value={noteBody} onChange={(e) => setNoteBody(e.target.value)} />
                  <button className="btn" type="submit" disabled={!noteBody.trim() || addNote.isPending}>Add note</button>
                  {addNote.error && <span role="alert" className="ml-2 text-xs text-sev-critical">{errMsg(addNote.error, "Failed")}</span>}
                </form>
              )}
            </div>
          </section>
          <section className="panel">
            <h2 className="border-b border-line px-4 py-2.5 text-sm font-semibold">Conclusion</h2>
            <div className="p-3">
              <textarea aria-label="Conclusion" className="input w-full text-sm" rows={4} value={conclusion} readOnly={!canWrite} maxLength={10000} placeholder="What did this hunt establish?"
                onChange={(e) => setConclusion(e.target.value)}
                onBlur={() => canWrite && conclusion !== hunt.conclusion && update.mutate({ conclusion })} />
              <p className="mt-1 text-xs text-muted">Saved when you leave the field.</p>
            </div>
          </section>
        </aside>
      </div>

      {openEvent && (
        <EventDrawer id={openEvent} onClose={() => setOpenEvent(null)}
          onPivot={(f) => { setFilters((fs) => addFilter(fs, f)); setOpenEvent(null); }}
          onPivotQuery={pivotToText} onTimeline={openTimelineAround}
          onAddToCase={can("cases:write") ? (eid) => setCaseEvents([eid]) : undefined} />
      )}
      {caseEvents && <AddToCaseDialog eventIds={caseEvents} onClose={() => setCaseEvents(null)} />}
      {confirmNode}
    </div>
  );
}
