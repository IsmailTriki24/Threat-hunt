"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import type { EventQueryBody, Filter, FindingSeverity, Hunt, HuntStatus, SavedQuery, TimelineScope } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { appendPivot, downloadBlob } from "@/lib/hunt-query";
import { addFilter, clampPaging, fmtTime, MAX_WINDOW, resolveRange, SEARCH_AGGS, type RangeSpec } from "@/lib/query";
import { AggPanel } from "./agg-panel";
import { EventDrawer } from "./event-drawer";
import { FilterBuilder, FilterChips } from "./filter-builder";
import { STATUSES } from "./hunts-list";
import { Histogram } from "./histogram";
import { QueryEditor } from "./query-editor";
import { RangeControl } from "./range-control";
import { ResultsTable } from "./results-table";
import { TimelinePanel, type TimelineSource } from "./timeline-view";

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
  if (hunt.isLoading) return <p className="text-muted">Loading…</p>;
  if (hunt.error || !hunt.data) {
    return <p role="alert" className="panel p-3 text-red-400">{hunt.error instanceof ApiError && hunt.error.status === 404 ? "Hunt not found." : errMsg(hunt.error, "Failed to load hunt")}</p>;
  }
  return <Workspace hunt={hunt.data} />;
}

function Workspace({ hunt }: { hunt: Hunt }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const canWrite = can("hunts:write");
  const huntId = hunt.id;

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
  const [tab, setTab] = useState<"results" | "timeline">("results");
  const [tlSource, setTlSource] = useState<TimelineSource | null>(null);
  const [openEvent, setOpenEvent] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dense] = useState(true);

  const fields = useQuery({ queryKey: ["fields"], queryFn: api.fields, staleTime: Infinity });
  const run = useQuery({
    queryKey: ["hunt-run", huntId, JSON.stringify(applied)],
    queryFn: () => api.runHunt(huntId, applied!),
    enabled: applied !== null,
    retry: false, staleTime: Infinity, refetchOnWindowFocus: false, placeholderData: (p) => p,
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
    onSuccess: () => { setShowSave(false); setSaveName(""); setSaveDesc(""); void qc.invalidateQueries({ queryKey: ["saved", huntId] }); void qc.invalidateQueries({ queryKey: ["hunt", huntId] }); },
  });
  const delSaved = useMutation({ mutationFn: (sid: string) => api.deleteSavedQuery(sid), onSuccess: () => qc.invalidateQueries({ queryKey: ["saved", huntId] }) });
  const load = (q: Partial<EventQueryBody>) => {
    setText(q.text ?? "");
    setFilters(q.filters ?? []);
    const r = rangeFromQuery(q);
    if (r) setRange(r);
  };

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
    onSuccess: () => { setNoteBody(""); void qc.invalidateQueries({ queryKey: ["notes", huntId] }); },
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
    <div className="space-y-2">
      {/* header */}
      <div className="panel p-2 space-y-1">
        <div className="flex items-center gap-2">
          <input aria-label="Hunt title" className="input flex-1 font-semibold text-base" value={title} maxLength={200} readOnly={!canWrite}
            onChange={(e) => setTitle(e.target.value)} onBlur={() => canWrite && title.trim() && title !== hunt.title && update.mutate({ title: title.trim() })} />
          <select aria-label="Hunt status" className="input" value={hunt.status} disabled={!canWrite}
            onChange={(e) => update.mutate({ status: e.target.value as HuntStatus })}>
            {STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <textarea aria-label="Hypothesis" className="input w-full text-xs" rows={2} value={hyp} readOnly={!canWrite} maxLength={5000}
          placeholder="Hypothesis" onChange={(e) => setHyp(e.target.value)}
          onBlur={() => canWrite && hyp !== hunt.hypothesis && update.mutate({ hypothesis: hyp })} />
        {update.error && <p role="alert" className="text-red-400 text-xs">{errMsg(update.error, "Save failed")}</p>}
      </div>

      <div className="flex gap-3 items-start">
        {/* left: saved queries + history */}
        <aside className="w-60 shrink-0 space-y-3" aria-label="Queries">
          <section>
            <h3 className="text-xs text-muted uppercase mb-0.5">Saved queries</h3>
            {saved.data?.length ? (
              <ul className="space-y-0.5">
                {saved.data.map((q: SavedQuery) => (
                  <li key={q.id} className="flex items-center gap-1">
                    <button className="flex-1 text-left truncate hover:text-accent" title={q.query.text ?? q.description} onClick={() => load(q.query)}>{q.name}</button>
                    {canWrite && <button className="text-muted hover:text-red-400" aria-label={`Delete saved query ${q.name}`} onClick={() => delSaved.mutate(q.id)}>×</button>}
                  </li>
                ))}
              </ul>
            ) : <p className="text-xs text-muted">None yet.</p>}
          </section>
          <section>
            <h3 className="text-xs text-muted uppercase mb-0.5">My history (this hunt)</h3>
            {history.data?.length ? (
              <ul className="space-y-0.5">
                {history.data.slice(0, 15).map((h) => (
                  <li key={h.id}>
                    <button className="w-full text-left hover:text-accent" onClick={() => load(h.query)} title={h.query.text ?? ""}>
                      <span className="block truncate font-mono text-xs">{h.query.text || "(all events)"}</span>
                      <span className="text-xs text-muted">{fmtTime(h.executed_at)} · {h.total} hits</span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : <p className="text-xs text-muted">No runs yet.</p>}
          </section>
        </aside>

        {/* centre: editor + results */}
        <div className="flex-1 min-w-0 space-y-2">
          <QueryEditor value={text} onChange={setText} onRun={() => doRun()} />
          <div className="flex flex-wrap items-center gap-1">
            <RangeControl value={range} onChange={setRange} />
            {fields.data && <FilterBuilder fields={fields.data.filter((f) => f.kind !== "date")} onAdd={(f) => setFilters((fs) => addFilter(fs, f))} />}
            <button className="btn btn-primary" onClick={() => doRun()}>Run <span className="text-muted text-xs">Ctrl+Enter</span></button>
            <button className="btn" disabled={!canWrite} onClick={() => setShowSave((s) => !s)}>Save query</button>
            <button className="btn" onClick={openTimelineFromQuery}>Timeline</button>
            <span className="ml-auto flex items-center gap-1">
              <button className="btn" onClick={() => void doExport("csv")}>Export CSV</button>
              <button className="btn" onClick={() => void doExport("json")}>Export JSON</button>
              <span className="text-xs text-muted">max {EXPORT_CAP.toLocaleString()} rows</span>
            </span>
          </div>
          <FilterChips filters={filters} onRemove={(i) => setFilters((fs) => fs.filter((_, j) => j !== i))} />
          {exportErr && <p role="alert" className="text-red-400 text-xs">{exportErr}</p>}
          {showSave && (
            <form onSubmit={submitSave} className="panel p-2 flex flex-wrap gap-1 items-center" aria-label="Save query">
              <input aria-label="Query name" className="input" placeholder="Name" value={saveName} maxLength={200} onChange={(e) => setSaveName(e.target.value)} />
              <input aria-label="Query description" className="input flex-1" placeholder="Description (optional)" value={saveDesc} onChange={(e) => setSaveDesc(e.target.value)} />
              <button className="btn btn-primary" type="submit" disabled={!saveName.trim() || save.isPending}>Save</button>
              {save.error && <span role="alert" className="text-red-400 text-xs">{errMsg(save.error, "Save failed")}</span>}
            </form>
          )}

          <div role="tablist" className="flex gap-1 border-b border-line">
            {(["results", "timeline"] as const).map((t) => (
              <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                className={`px-3 py-1 capitalize ${tab === t ? "text-accent border-b-2 border-accent" : "text-muted"}`}>{t}</button>
            ))}
          </div>

          {tab === "results" && (
            <div className="space-y-2">
              {run.error && <p role="alert" className="panel p-2 text-red-400">{errMsg(run.error, "Run failed")}</p>}
              {!applied && <p className="panel p-3 text-muted">Write a query and press Run. Hunt defaults (window, data sources) apply when you leave them unset.</p>}
              {data && (
                <>
                  <div className="flex items-center gap-3 text-xs text-muted">
                    <span>{data.total_relation === "gte" ? "≥ " : ""}{data.total.toLocaleString()} events</span><span>{data.took_ms} ms</span>
                    {run.isFetching && <span>running…</span>}
                    <span className="ml-auto flex items-center gap-1">
                      {selected.size > 0 && <span>{selected.size} selected</span>}
                      <button className="btn" disabled={!canWrite || selected.size === 0} onClick={() => setShowFinding((s) => !s)}>Add finding</button>
                    </span>
                  </div>
                  {showFinding && (
                    <form onSubmit={submitFinding} className="panel p-2 space-y-1" aria-label="Add finding">
                      <div className="flex gap-1">
                        <input aria-label="Finding title" className="input flex-1" placeholder="Finding title" value={fTitle} maxLength={200} onChange={(e) => setFTitle(e.target.value)} />
                        <select aria-label="Finding severity" className="input" value={fSev} onChange={(e) => setFSev(e.target.value as FindingSeverity)}>
                          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
                        </select>
                      </div>
                      <textarea aria-label="Finding description" className="input w-full text-xs" rows={2} placeholder="Description" value={fDesc} onChange={(e) => setFDesc(e.target.value)} />
                      {selected.size > MAX_FINDING_EVENTS && <p role="alert" className="text-red-400 text-xs">At most {MAX_FINDING_EVENTS} events per finding.</p>}
                      <button className="btn btn-primary" type="submit" disabled={!fTitle.trim() || selected.size === 0 || selected.size > MAX_FINDING_EVENTS || addFinding.isPending}>
                        Save finding ({selected.size} events)
                      </button>
                      {addFinding.error && <span role="alert" className="ml-2 text-red-400 text-xs">{errMsg(addFinding.error, "Failed to save finding")}</span>}
                    </form>
                  )}
                  <Histogram buckets={data.aggregations.timeline?.buckets ?? []} rangeEnd={data.time_range.end}
                    onSelect={(start, end) => setRange({ kind: "abs", start, end })} />
                  <div className="flex gap-3">
                    <div className="flex-1 min-w-0">
                      {data.hits.length === 0 ? <p className="panel p-3 text-muted">No events match this query in the selected time range.</p> : (
                        <ResultsTable hits={data.hits} dense={dense} selected={openEvent} onOpen={setOpenEvent} sort={sort} selection={selection}
                          onSort={(field) => {
                            const next = sort?.field === field ? { field, order: (sort.order === "desc" ? "asc" : "desc") as "asc" | "desc" } : { field, order: "desc" as const };
                            setSort(next); doRun(0, next);
                          }} />
                      )}
                      <div className="flex items-center gap-2 mt-2 text-xs">
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
          {tab === "timeline" && <TimelinePanel source={tlSource} onOpen={setOpenEvent} />}
        </div>

        {/* right: findings, notes, conclusion */}
        <aside className="w-72 shrink-0 space-y-3" aria-label="Evidence">
          <section>
            <h3 className="text-xs text-muted uppercase mb-0.5">Findings ({findings.data?.length ?? 0})</h3>
            {findings.data?.length ? (
              <ul className="space-y-1">
                {findings.data.map((f) => (
                  <li key={f.id} className="panel p-1.5">
                    <div className="flex items-center gap-1">
                      <span className="text-xs border border-line px-1 rounded-sm">{f.severity}</span>
                      <span className="font-medium flex-1 truncate">{f.title}</span>
                      {canWrite && <button className="text-muted hover:text-red-400" aria-label={`Delete finding ${f.title}`} onClick={() => delFinding.mutate(f.id)}>×</button>}
                    </div>
                    {f.description && <p className="text-xs whitespace-pre-wrap">{f.description}</p>}
                    <ul className="text-xs text-muted mt-0.5">
                      {f.evidence.map((ev) => (
                        <li key={ev.id}><button className="hover:text-accent text-left" onClick={() => setOpenEvent(ev.id)}>{fmtTime(ev.timestamp)} {ev.host ? `[${ev.host}] ` : ""}{ev.summary}</button></li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            ) : <p className="text-xs text-muted">Select result rows and choose “Add finding”.</p>}
          </section>
          <section>
            <h3 className="text-xs text-muted uppercase mb-0.5">Notes</h3>
            <ul className="space-y-1">
              {notes.data?.map((n) => (
                <li key={n.id} className="panel p-1.5 text-xs whitespace-pre-wrap">
                  {n.body}
                  <div className="text-muted">{fmtTime(n.created_at)}</div>
                </li>
              ))}
            </ul>
            {canWrite && (
              <form className="mt-1 space-y-1" onSubmit={(e) => { e.preventDefault(); if (noteBody.trim()) addNote.mutate(); }}>
                <textarea aria-label="New note" className="input w-full text-xs" rows={2} maxLength={10000} value={noteBody} onChange={(e) => setNoteBody(e.target.value)} />
                <button className="btn" type="submit" disabled={!noteBody.trim() || addNote.isPending}>Add note</button>
                {addNote.error && <span role="alert" className="ml-2 text-red-400 text-xs">{errMsg(addNote.error, "Failed")}</span>}
              </form>
            )}
          </section>
          <section>
            <h3 className="text-xs text-muted uppercase mb-0.5">Conclusion</h3>
            <textarea aria-label="Conclusion" className="input w-full text-xs" rows={4} value={conclusion} readOnly={!canWrite} maxLength={10000}
              onChange={(e) => setConclusion(e.target.value)}
              onBlur={() => canWrite && conclusion !== hunt.conclusion && update.mutate({ conclusion })} />
          </section>
        </aside>
      </div>

      {openEvent && (
        <EventDrawer id={openEvent} onClose={() => setOpenEvent(null)}
          onPivot={(f) => { setFilters((fs) => addFilter(fs, f)); setOpenEvent(null); }}
          onPivotQuery={pivotToText} onTimeline={openTimelineAround} />
      )}
    </div>
  );
}
