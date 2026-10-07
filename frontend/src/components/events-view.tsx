"use client";
import { useQuery } from "@tanstack/react-query";
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

  const run = () => { if (draft !== state.q) update({ q: draft }); else setNonce((n) => n + 1); };
  const addF = (f: Filter) => update({ filters: addFilter(state.filters, f) });
  const data = search.data;
  const { offset, limit } = clampPaging(state.offset, state.limit);
  const canNext = data ? offset + limit < Math.min(data.total, MAX_WINDOW) : false;
  const history = useQuery({ queryKey: ["history", "all"], queryFn: () => api.history(), enabled: showHistory });

  return (
    <div className="space-y-2">
      <form className="flex gap-1" onSubmit={(e) => { e.preventDefault(); run(); }} role="search">
        <input ref={searchRef} className="input flex-1 font-mono" value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={state.lang ? 2000 : 512}
          aria-label="Search query" placeholder={state.lang ? "process.name:powershell.exe -user.name:svc_*   (hunt query language)" : 'Search events…  e.g. powershell AND "-enc" · NOT chrome · power*   (press / to focus)'} />
        <RangeControl value={state.range} onChange={(range) => update({ range })} />
        <button className="btn btn-primary" type="submit">Search</button>
      </form>

      <div className="flex flex-wrap items-center gap-2">
        {fields.data && <FilterBuilder fields={fields.data.filter((f) => f.kind !== "date")} onAdd={addF} />}
        <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={state.lang} onChange={(e) => update({ lang: e.target.checked })} /> Query language</label>
        <label className="ml-auto text-xs flex items-center gap-1"><input type="checkbox" checked={dense} onChange={(e) => setDense(e.target.checked)} /> Dense</label>
      </div>
      {state.lang && <p className="text-xs text-muted">{QueryEditorHint}</p>}
      <div className="text-xs">
        <button className="btn py-0" onClick={() => setShowHistory((v) => !v)} aria-expanded={showHistory}>History</button>
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

      {search.error && (
        <p role="alert" className="panel p-2 text-red-400">
          {search.error instanceof ApiError ? search.error.friendly : "Search failed"}
          {search.error instanceof ApiError && search.error.requestId ? <span className="text-muted"> (request {search.error.requestId})</span> : null}
        </p>
      )}

      {data && (
        <>
          <div className="text-xs text-muted flex gap-3">
            <span>{data.total_relation === "gte" ? "≥ " : ""}{data.total.toLocaleString()} events</span>
            <span>{data.took_ms} ms</span>
            {search.isFetching && <span>updating…</span>}
          </div>
          <Histogram buckets={data.aggregations.timeline?.buckets ?? []} rangeEnd={data.time_range.end}
            onSelect={(start, end) => update({ range: { kind: "abs", start, end } })} />
          <div className="flex gap-3">
            <div className="flex-1 min-w-0">
              {data.hits.length === 0 ? <p className="panel p-3 text-muted">No events match this query in the selected time range.</p> : (
                <ResultsTable hits={data.hits} dense={dense} selected={state.event} onOpen={(id) => update({ event: id }, false)}
                  sort={state.sort} onSort={(field) => update({ sort: state.sort?.field === field ? { field, order: state.sort.order === "desc" ? "asc" : "desc" } : { field, order: "desc" } })} />
              )}
              <div className="flex items-center gap-2 mt-2 text-xs">
                <button className="btn" disabled={offset === 0} onClick={() => update({ offset: Math.max(0, offset - limit) })}>Prev</button>
                <span className="text-muted">{data.total ? offset + 1 : 0}–{Math.min(offset + limit, data.total)}</span>
                <button className="btn" disabled={!canNext} onClick={() => update({ offset: offset + limit })}>Next</button>
                {data.total > MAX_WINDOW && <span className="text-muted">Only the first {MAX_WINDOW.toLocaleString()} results are pageable; narrow the query.</span>}
              </div>
            </div>
            <AggPanel aggs={data.aggregations} onFilter={addF} />
          </div>
        </>
      )}
      {search.isLoading && <p className="text-muted">Searching…</p>}

      {state.event && (
        <EventDrawer id={state.event} onClose={() => update({ event: null }, false)}
          onPivot={(f) => update({ filters: addFilter(state.filters, f), event: null })}
          onAddToCase={can("cases:write") ? setCaseEvent : undefined} />
      )}
      {caseEvent && <AddToCaseDialog eventIds={[caseEvent]} onClose={() => setCaseEvent(null)} />}
    </div>
  );
}
