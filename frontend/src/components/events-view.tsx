"use client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Filter } from "@/lib/api-types";
import { addFilter, clampPaging, MAX_WINDOW, paramsToState, stateToParams, toRequestBody, type SearchState } from "@/lib/query";
import { RangeControl } from "./range-control";
import { QueryEditorHint } from "./query-hint";
import { AggPanel } from "./agg-panel";
import { AddToCaseDialog } from "./add-to-case-dialog";
import { EventDrawer } from "./event-drawer";
import { useAuth } from "@/lib/auth";
import { FilterBuilder, FilterChips } from "./filter-builder";
import { ChevronLeft, ChevronRight, CircleAlert, History, Search, SearchX } from "lucide-react";
import { EmptyState } from "./ui/empty-state";
import { SiemSearchCard } from "./siem-search-card";
import { PageHeader } from "./ui/page-header";
import { SkeletonRows } from "./ui/skeleton";
import { Histogram } from "./histogram";
import { ResultsTable } from "./results-table";

export function EventsView() {
  const router = useRouter();
  const pathname = usePathname();
  const sp = useSearchParams();
  const state = useMemo(() => paramsToState(new URLSearchParams(sp.toString())), [sp]);
  const [draft, setDraft] = useState(state.q);
  const [nonce, setNonce] = useState(0);
  const [dense, setDense] = useState(true);
  const [showHistory, setShowHistory] = useState(false);
  const { can } = useAuth();
  const qc = useQueryClient();
  const [caseEvent, setCaseEvent] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => setDraft(state.q), [state.q]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName)) { e.preventDefault(); searchRef.current?.focus(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const update = useCallback((patch: Partial<SearchState>, resetPage = true) => {
    const next = { ...state, ...patch, ...(resetPage && !("offset" in patch) ? { offset: 0 } : {}) };
    const qs = stateToParams(next).toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [state, router, pathname]);

  const fields = useQuery({ queryKey: ["fields"], queryFn: api.fields, staleTime: Infinity });
  // the body (with resolved "now") is computed once per applied state / explicit run
  const key = JSON.stringify([state.q, state.lang, state.range, state.filters, state.sort, state.offset, nonce]);
  const search = useQuery({
    queryKey: ["events", key],
    queryFn: () => api.search(toRequestBody({ ...state, event: null })),
    placeholderData: (prev) => prev,
  });

  // Every search also asks the whole LogRhythm SIEM (not just the collected slice) for the indicators in it, then re-runs the local search
  // once if that imported anything, so the extra logs appear in the normal results.
  const siemOn = !!(state.q.trim() || state.filters.length);
  const siem = useQuery({
    queryKey: ["siem", key], queryFn: () => api.siemSearch(toRequestBody({ ...state, event: null }, [])), enabled: siemOn,
    staleTime: Infinity, retry: false, refetchOnWindowFocus: false, refetchOnMount: false,
  });
  const imported = siem.data?.imported ?? 0;
  useEffect(() => { if (imported > 0) void qc.invalidateQueries({ queryKey: ["events"] }); }, [imported, siem.dataUpdatedAt, qc]);
  const run = () => { if (draft !== state.q) update({ q: draft }); else setNonce((n) => n + 1); };
  const addF = (f: Filter) => update({ filters: addFilter(state.filters, f) });
  const data = search.data;
  const { offset, limit } = clampPaging(state.offset, state.limit);
  const canNext = data ? offset + limit < Math.min(data.total, MAX_WINDOW) : false;
  const history = useQuery({ queryKey: ["history", "all"], queryFn: () => api.history(), enabled: showHistory });

  return (
    <div className="space-y-3">
      <PageHeader title="Events" description="Search every event ingested for this tenant. Click a value in the side panel to filter, or a row for the full event." />
      <form className="panel flex flex-wrap gap-2 p-3" onSubmit={(e) => { e.preventDefault(); run(); }} role="search" aria-label="Event search">
        <div className="relative min-w-[16rem] flex-1">
        <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <input ref={searchRef} className="input w-full pl-8 font-mono" value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={state.lang ? 2000 : 512}
          aria-label="Search query" placeholder={state.lang ? "process.name:powershell.exe -user.name:svc_*   (hunt query language)" : 'Search events…  e.g. powershell AND "-enc" · NOT chrome · power*   (press / to focus)'} />
        </div>
        <RangeControl value={state.range} onChange={(range) => update({ range })} />
        <button className="btn btn-primary" type="submit"><Search aria-hidden className="h-3.5 w-3.5" />Search</button>
      </form>

      <div className="flex flex-wrap items-center gap-3">
        {fields.data && <FilterBuilder fields={fields.data.filter((f) => f.kind !== "date")} onAdd={addF} />}
        <label className="flex items-center gap-1.5 text-sm text-ink-2"><input type="checkbox" checked={state.lang} onChange={(e) => update({ lang: e.target.checked })} /> Query language</label>
        <label className="ml-auto flex items-center gap-1.5 text-sm text-ink-2"><input type="checkbox" checked={dense} onChange={(e) => setDense(e.target.checked)} /> Dense</label>
      </div>
      {state.lang && <p className="text-xs text-muted">{QueryEditorHint}</p>}
      <div className="text-xs">
        <button className="btn btn-sm" onClick={() => setShowHistory((v) => !v)} aria-expanded={showHistory}><History aria-hidden className="h-3.5 w-3.5" />History</button>
        {showHistory && (
          <select aria-label="Query history" className="input ml-1 max-w-xl" value="" onChange={(e) => {
            const h = history.data?.find((x) => x.id === e.target.value);
            if (h) update({ q: h.query.text ?? h.query.q ?? "", lang: !!h.query.text, filters: h.query.filters ?? [] });
          }}>
            <option value="">{history.isLoading ? "loading…" : history.data?.length ? "Re-run a previous query…" : "No history yet"}</option>
            {history.data?.map((h) => <option key={h.id} value={h.id}>{(h.query.text ?? h.query.q ?? "(all events)").slice(0, 80)} · {h.total} hits</option>)}
          </select>
        )}
      </div>
      <FilterChips filters={state.filters} onRemove={(i) => update({ filters: state.filters.filter((_, j) => j !== i) })} />
      {siemOn && <SiemSearchCard query={siem} onShow={() => void qc.invalidateQueries({ queryKey: ["events"] })} />}

      {search.error && (
        <p role="alert" className="flex items-start gap-2 rounded-lg border border-sev-critical/30 bg-sev-critical-bg px-4 py-3 text-sm text-sev-critical">
          <CircleAlert aria-hidden className="mt-0.5 h-4 w-4 shrink-0" /><span>{search.error instanceof ApiError ? search.error.friendly : "Search failed"}
          {search.error instanceof ApiError && search.error.requestId ? <span className="opacity-80"> (request {search.error.requestId})</span> : null}</span>
        </p>
      )}

      {data && (
        <>
          <div className="flex items-baseline gap-3 text-sm">
            <span className="font-semibold tabular-nums">{data.total_relation === "gte" ? "≥ " : ""}{data.total.toLocaleString("en-US")} events</span>
            <span className="text-xs text-muted">{data.took_ms} ms</span>
            {search.isFetching && <span className="text-xs text-accent" role="status">Updating…</span>}
          </div>
          <div className="panel px-3 pt-2"><Histogram buckets={data.aggregations.timeline?.buckets ?? []} rangeEnd={data.time_range.end}
            onSelect={(start, end) => update({ range: { kind: "abs", start, end } })} /></div>
          <div className="flex gap-4">
            <div className="min-w-0 flex-1">
              {data.hits.length === 0 ? <div className="panel"><EmptyState icon={SearchX} title="No events match">Nothing matched this query in the selected time range. Widen the range, remove a filter, or check the query syntax.</EmptyState></div> : (
                <ResultsTable hits={data.hits} dense={dense} selected={state.event} onOpen={(id) => update({ event: id }, false)}
                  sort={state.sort} onSort={(field) => update({ sort: state.sort?.field === field ? { field, order: state.sort.order === "desc" ? "asc" : "desc" } : { field, order: "desc" } })} />
              )}
              <div className="mt-3 flex items-center gap-2 text-sm">
                <button className="btn" disabled={offset === 0} onClick={() => update({ offset: Math.max(0, offset - limit) })}><ChevronLeft aria-hidden className="h-4 w-4" />Prev</button>
                <span className="px-1 tabular-nums text-muted">{data.total ? offset + 1 : 0}–{Math.min(offset + limit, data.total)}</span>
                <button className="btn" disabled={!canNext} onClick={() => update({ offset: offset + limit })}>Next<ChevronRight aria-hidden className="h-4 w-4" /></button>
                {data.total > MAX_WINDOW && <span className="text-muted">Only the first {MAX_WINDOW.toLocaleString()} results are pageable; narrow the query.</span>}
              </div>
            </div>
            <AggPanel aggs={data.aggregations} onFilter={addF} />
          </div>
        </>
      )}
      {search.isLoading && <div className="panel p-4"><SkeletonRows rows={8} /></div>}

      {state.event && (
        <EventDrawer id={state.event} onClose={() => update({ event: null }, false)}
          onPivot={(f) => update({ filters: addFilter(state.filters, f), event: null })}
          onAddToCase={can("cases:write") ? setCaseEvent : undefined} />
      )}
      {caseEvent && <AddToCaseDialog eventIds={[caseEvent]} onClose={() => setCaseEvent(null)} />}
    </div>
  );
}
