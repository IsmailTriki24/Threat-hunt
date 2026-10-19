"use client";
import { useMutation, useQuery } from "@tanstack/react-query";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Bucket, EventDoc, Filter, SiemQueryResult, SiemSourceResult } from "@/lib/api-types";
import { addFilter, clampPaging, paramsToState, stateToParams, toRequestBody, type SearchState } from "@/lib/query";
import { useAuth } from "@/lib/auth";
import { ChevronLeft, ChevronRight, CircleAlert, CircleCheck, Info, Loader2, Search, SearchX } from "lucide-react";
import { AddToCaseDialog } from "./add-to-case-dialog";
import { AggPanel } from "./agg-panel";
import { EventDrawer } from "./event-drawer";
import { FilterBuilder, FilterChips } from "./filter-builder";
import { QueryEditorHint } from "./query-hint";
import { RangeControl } from "./range-control";
import { ResultsTable } from "./results-table";
import { EmptyState } from "./ui/empty-state";
import { PageHeader } from "./ui/page-header";
import { SkeletonRows } from "./ui/skeleton";

/** Sources are remembered in the URL as repeated `src=` so a search can be shared; none = ask every searchable source. */
const readSources = (sp: URLSearchParams): string[] => sp.getAll("src").slice(0, 20);

const pathOf = (e: EventDoc, path: string): string | number | undefined => {
  let cur: unknown = e;
  for (const part of path.split(".")) cur = cur && typeof cur === "object" ? (cur as Record<string, unknown>)[part] : undefined;
  return typeof cur === "string" || typeof cur === "number" ? cur : undefined;
};

function sortHits(hits: EventDoc[], sort: SearchState["sort"]): EventDoc[] {
  const s = sort ?? { field: "timestamp", order: "desc" as const };
  const dir = s.order === "asc" ? 1 : -1;
  return [...hits].sort((a, b) => {
    const x = pathOf(a, s.field), y = pathOf(b, s.field);
    if (x === y) return 0;
    if (x === undefined) return 1;
    if (y === undefined) return -1;
    return (x < y ? -1 : 1) * dir;
  });
}

/** The side panel's counts, taken from the results themselves (the SIEMs are not asked again). */
function countsOf(hits: EventDoc[]): Record<string, { buckets: Bucket[] }> {
  const top = (get: (e: EventDoc) => string | undefined) => {
    const m = new Map<string, number>();
    for (const e of hits) { const k = get(e); if (k) m.set(k, (m.get(k) ?? 0) + 1); }
    return { buckets: [...m].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([key, count]) => ({ key, count })) };
  };
  return {
    by_host: top((e) => e.host?.hostname), by_user: top((e) => e.user?.name), by_process: top((e) => e.process?.name),
    by_type: top((e) => e.event_type), by_dst_ip: top((e) => e.network?.dst_ip),
  };
}

const KIND_LABEL = (kind: string): string => (kind === "logrhythm" ? "LogRhythm" : `Trend · ${kind.replace("trend:", "").replace("_", " ")}`);

function SourceLine({ s }: { s: SiemSourceResult }) {
  const bad = s.status === "error";
  const Icon = bad ? CircleAlert : s.matched > 0 ? CircleCheck : Info;
  return (
    <li className={`flex flex-wrap items-start gap-x-2 text-xs ${bad ? "text-sev-critical" : "text-ink-2"}`}>
      <Icon aria-hidden className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${bad ? "" : s.matched > 0 ? "text-accent" : "text-muted"}`} />
      <span className="font-medium text-ink">{s.name}</span>
      <span className="text-muted">{KIND_LABEL(s.kind)}</span>
      <span>{bad || s.status === "not_applicable" ? s.detail : s.scanned === 0 ? <>No log found{s.searched.length ? <> for <span className="font-mono">{s.searched.slice(0, 2).join(" · ")}</span></> : null} — this source holds nothing for it in this time range</> : `${s.matched.toLocaleString("en-US")} of ${s.scanned.toLocaleString("en-US")} read match`}</span>
      {s.status === "partial" && <span className="text-sev-medium">time budget reached; not everything was searched</span>}
      {s.capped && <span className="text-sev-medium">stopped at the read limit; narrow the query or range</span>}
      <span className="text-muted tabular-nums">{s.ms} ms</span>
      {s.skipped.map((n) => <span key={n} className="basis-full pl-5 text-sev-medium">{n}</span>)}
    </li>
  );
}

export function SiemSearchView() {
  const router = useRouter();
  const pathname = usePathname();
  const sp = useSearchParams();
  const state = useMemo(() => paramsToState(new URLSearchParams(sp.toString())), [sp]);
  const sources = useMemo(() => readSources(new URLSearchParams(sp.toString())), [sp]);
  const legacyId = /^[a-f0-9]{32}$/.test(sp.get("id") ?? "") ? sp.get("id") : null; // older links use ?id=
  const openId = state.event ?? legacyId;
  const [draft, setDraft] = useState(state.q);
  const [nonce, setNonce] = useState(0);
  const [dense, setDense] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);
  const [caseEvent, setCaseEvent] = useState<string | null>(null);
  const { can } = useAuth();
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

  const update = useCallback((patch: Partial<SearchState>, opts: { sources?: string[]; resetPage?: boolean } = {}) => {
    const next = { ...state, ...patch, ...(opts.resetPage !== false && !("offset" in patch) && !("event" in patch) ? { offset: 0 } : {}) };
    const p = stateToParams(next);
    for (const id of opts.sources ?? sources) p.append("src", id);
    const qs = p.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [state, sources, router, pathname]);

  const fields = useQuery({ queryKey: ["fields"], queryFn: api.fields, staleTime: Infinity });
  const available = useQuery({ queryKey: ["siem-sources"], queryFn: api.siemSources, staleTime: 60_000 });
  const browse = sp.get("browse") === "1"; // list what LogRhythm holds for the range, with no search terms (up to the read limit)
  const hasQuery = !!(state.q.trim() || state.filters.length || browse);
  const setBrowse = (on: boolean) => {
    const p = new URLSearchParams(sp.toString());
    if (on) p.set("browse", "1"); else p.delete("browse");
    const qs = p.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };
  // The request body (with its resolved "now") is computed once per applied search / explicit run, so paging and sorting never ask the SIEMs again.
  const key = JSON.stringify([state.q, state.lang, state.range, state.filters, sources, nonce, browse]);
  const search = useQuery({
    queryKey: ["siem-query", key],
    queryFn: () => api.siemQuery({ ...toRequestBody({ ...state, event: null, offset: 0, sort: null }, []), ...(sources.length ? { sources } : {}), ...(browse ? { browse: true } : {}) }),
    enabled: hasQuery, staleTime: Infinity, retry: false, refetchOnWindowFocus: false, refetchOnMount: false,
  });
  const data: SiemQueryResult | undefined = search.data;
  const [only, setOnly] = useState<string | null>(null); // a data source id: show just what that source returned
  useEffect(() => setOnly(null), [data?.search_id]);
  const originOf = (e: EventDoc): string | undefined => data?.origins?.[e.id];
  const sourceName = (id?: string): string | undefined => {
    const src = data?.sources.find((x) => x.id === id);
    if (!src) return undefined;
    return src.kind === "logrhythm" ? "LogRhythm" : `Trend · ${src.kind.replace("trend:", "").replace("_", " ")}`;
  };
  const perSource = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of data?.hits ?? []) { const o = data?.origins?.[e.id]; if (o) m.set(o, (m.get(o) ?? 0) + 1); }
    return m;
  }, [data]);
  const visible = useMemo(() => (only ? (data?.hits ?? []).filter((e) => data?.origins?.[e.id] === only) : (data?.hits ?? [])), [data, only]);
  const sorted = useMemo(() => sortHits(visible, state.sort), [visible, state.sort]);
  const { offset, limit } = clampPaging(state.offset, state.limit);
  const page = sorted.slice(offset, offset + limit);
  const aggs = useMemo(() => countsOf(visible), [visible]);

  // Nothing is stored until an event is opened: opening one imports just that event, then the normal drawer shows it.
  const open = useMutation({
    mutationFn: async (id: string) => {
      if (data && data.hits.some((h) => h.id === id)) {
        const r = await api.siemImport(data.search_id, [id]);
        if (r.expired) throw new Error("expired");
      }
      return id;
    },
    onSuccess: (id) => { setNotice(null); update({ event: id }, { resetPage: false }); },
    onError: (e) => setNotice(e instanceof Error && e.message === "expired" ? "This result is no longer held (results are kept for 30 minutes). Search again to open the event." : e instanceof ApiError ? e.friendly : "Could not open the event"),
  });
  const run = () => { if (draft !== state.q) update({ q: draft }); else setNonce((n) => n + 1); };
  const addF = (f: Filter) => update({ filters: addFilter(state.filters, f) });
  const toggleSource = (id: string) => {
    const all = (available.data ?? []).map((s) => s.id);
    const current = sources.length ? sources : all;
    const next = current.includes(id) ? current.filter((x) => x !== id) : [...current, id];
    update({}, { sources: next.length === all.length ? [] : next });
  };
  const canNext = offset + limit < sorted.length;
  const shown = sources.length ? sources : (available.data ?? []).map((s) => s.id);
  const failed = data?.sources.filter((s) => s.status === "error") ?? [];

  return (
    <div className="space-y-3">
      <PageHeader title="SIEM Search" description="Search LogRhythm and Trend Vision One directly. Nothing is copied: results are shown from the SIEMs themselves and only an event you open or add to a case is kept." />
      <form className="panel flex flex-wrap gap-2 p-3" onSubmit={(e) => { e.preventDefault(); run(); }} role="search" aria-label="SIEM search">
        <div className="relative min-w-[16rem] flex-1">
          <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input ref={searchRef} className="input w-full pl-8 font-mono" value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={state.lang ? 2000 : 512}
            aria-label="Search query" placeholder={state.lang ? "process.name:powershell.exe user.name:bob   (hunt query language)" : "An IP, domain, hash, user, host, process or word…  e.g. 203.0.113.5 · powershell -chrome   (press / to focus)"} />
        </div>
        <RangeControl value={state.range} onChange={(range) => update({ range })} />
        <button className="btn btn-primary" type="submit" disabled={search.isFetching}><Search aria-hidden className="h-3.5 w-3.5" />Search the SIEMs</button>
      </form>

      <div className="flex flex-wrap items-center gap-3">
        {fields.data && <FilterBuilder fields={fields.data.filter((f) => f.kind !== "date")} onAdd={addF} />}
        <label className="flex items-center gap-1.5 text-sm text-ink-2"><input type="checkbox" checked={state.lang} onChange={(e) => update({ lang: e.target.checked })} /> Query language</label>
        <label className="ml-auto flex items-center gap-1.5 text-sm text-ink-2"><input type="checkbox" checked={dense} onChange={(e) => setDense(e.target.checked)} /> Dense</label>
      </div>
      {state.lang && <p className="text-xs text-muted">{QueryEditorHint}</p>}
      <FilterChips filters={state.filters} onRemove={(i) => update({ filters: state.filters.filter((_, j) => j !== i) })} />

      {available.data && available.data.length > 0 && (
        <fieldset className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm" aria-label="Sources to search">
          <legend className="sr-only">Sources to search</legend>
          <span className="text-xs text-muted">Search in</span>
          {available.data.map((s) => (
            <label key={s.id} className="flex items-center gap-1.5 text-ink-2">
              <input type="checkbox" checked={shown.includes(s.id)} onChange={() => toggleSource(s.id)} aria-label={`Search ${s.name}`} />{s.name}
            </label>
          ))}
        </fieldset>
      )}

      {notice && <p role="status" className="flex items-start gap-2 rounded-lg border border-line bg-panel px-4 py-2.5 text-sm"><Info aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-accent" />{notice}</p>}
      {search.error && (
        <p role="alert" className="flex items-start gap-2 rounded-lg border border-sev-critical/30 bg-sev-critical-bg px-4 py-3 text-sm text-sev-critical">
          <CircleAlert aria-hidden className="mt-0.5 h-4 w-4 shrink-0" /><span>{search.error instanceof ApiError ? search.error.friendly : "Search failed"}
          {search.error instanceof ApiError && search.error.requestId ? <span className="opacity-80"> (request {search.error.requestId})</span> : null}</span>
        </p>
      )}

      {!hasQuery && (
        <div className="panel"><EmptyState icon={Search} title="Search the SIEMs">
          Type an IP address, domain, hash, e-mail, host, user, process or any word, or add a filter, and the question goes straight to LogRhythm and Trend Vision One.
          Matching logs are shown here; nothing is stored until you open one.
          <span className="mt-3 block"><button type="button" className="btn btn-sm" onClick={() => setBrowse(true)}>Browse all of LogRhythm for this range</button></span>
        </EmptyState></div>
      )}

      {hasQuery && search.isFetching && !data && (
        <div role="status" className="flex flex-wrap items-start gap-x-3 gap-y-1 rounded-lg border border-accent/25 bg-accent-soft/60 px-3.5 py-2.5 text-sm">
          <Loader2 aria-hidden className="mt-0.5 h-4 w-4 animate-spin text-accent" />
          <span className="font-medium text-ink">Searching {shown.length || "the"} SIEM source{shown.length === 1 ? "" : "s"}…</span>
          <span className="text-xs text-muted">LogRhythm searches can take up to a minute.</span>
        </div>
      )}
      {search.isFetching && !data && <div className="panel p-4"><SkeletonRows rows={6} /></div>}

      {browse && !state.q.trim() && !state.filters.length && (
        <p className="flex flex-wrap items-center gap-2 text-xs text-ink-2">Browsing every log of the range (newest first within the read limit); add a search term or filter to narrow it.
          <button type="button" className="btn btn-sm" onClick={() => setBrowse(false)}>Stop browsing</button></p>
      )}

      {data?.no_sources && (
        <div className="panel"><EmptyState icon={SearchX} title="No SIEM source to search">Add a LogRhythm or Trend Vision One data source (Data Sources) to search it from here.</EmptyState></div>
      )}

      {data && !data.no_sources && !data.empty_query && (
        <>
          <ul className="panel space-y-1.5 px-3.5 py-2.5" aria-label="Sources searched">
            {data.sources.map((s) => <SourceLine key={s.id} s={s} />)}
          </ul>
          {data.note && <p className="text-xs text-sev-medium">{data.note}</p>}
          {failed.length > 0 && failed.length === data.sources.length && (
            <p role="alert" className="text-xs text-sev-critical">Every source failed, so this is not an answer; see the reasons above.</p>
          )}
          {data.hits.length > 0 && data.sources.length > 1 && (
            <div role="group" aria-label="Filter results by source" className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="text-muted">Show</span>
              <button type="button" aria-pressed={only === null} className={`btn btn-sm ${only === null ? "btn-primary" : ""}`}
                onClick={() => { setOnly(null); update({ offset: 0 }, { resetPage: false }); }}>All {data.hits.length.toLocaleString("en-US")}</button>
              {data.sources.map((src) => {
                const n = perSource.get(src.id) ?? 0;
                return (
                  <button key={src.id} type="button" aria-pressed={only === src.id} disabled={n === 0}
                    title={n === 0 ? `${src.name} returned nothing for this search` : src.name}
                    className={`btn btn-sm ${only === src.id ? "btn-primary" : ""}`}
                    onClick={() => { setOnly(only === src.id ? null : src.id); update({ offset: 0 }, { resetPage: false }); }}>
                    {sourceName(src.id)} <span className="tabular-nums opacity-80">{n.toLocaleString("en-US")}</span>
                  </button>
                );
              })}
            </div>
          )}
          <div className="flex items-baseline gap-3 text-sm">
            <span className="font-semibold tabular-nums">{only ? `${visible.length.toLocaleString("en-US")} of ${data.total.toLocaleString("en-US")}` : `${data.total.toLocaleString("en-US")}${data.truncated ? "+" : ""}`} events</span>
            <span className="text-xs text-muted">{data.took_ms} ms · held for 30 minutes, not stored</span>
            {open.isPending && <span className="text-xs text-accent" role="status">Opening…</span>}
          </div>
          <div className="flex gap-4">
            <div className="min-w-0 flex-1">
              {data.hits.length === 0 ? (
                <div className="panel"><EmptyState icon={SearchX} title="Nothing found in the SIEMs">
                  {failed.length ? "Some sources failed, so this may not be complete. " : ""}No log in the searched sources matched this query in the selected time range. Widen the range, change the terms, or check the notes above about what each source can be asked.
                </EmptyState></div>
              ) : (
                <ResultsTable hits={page} dense={dense} selected={openId} onOpen={(id) => open.mutate(id)} sourceOf={(e) => sourceName(originOf(e))}
                  sort={state.sort ?? { field: "timestamp", order: "desc" }}
                  onSort={(field) => update({ sort: state.sort?.field === field ? { field, order: state.sort.order === "desc" ? "asc" : "desc" } : { field, order: "desc" } }, { resetPage: false })} />
              )}
              {data.hits.length > 0 && (
                <div className="mt-3 flex items-center gap-2 text-sm">
                  <button className="btn" disabled={offset === 0} onClick={() => update({ offset: Math.max(0, offset - limit) }, { resetPage: false })}><ChevronLeft aria-hidden className="h-4 w-4" />Prev</button>
                  <span className="px-1 tabular-nums text-muted">{offset + 1}–{Math.min(offset + limit, sorted.length)} of {sorted.length}</span>
                  <button className="btn" disabled={!canNext} onClick={() => update({ offset: offset + limit }, { resetPage: false })}>Next<ChevronRight aria-hidden className="h-4 w-4" /></button>
                  {data.truncated && <span className="text-muted">The SIEMs returned more than is shown; narrow the query or range.</span>}
                </div>
              )}
            </div>
            {data.hits.length > 0 && <AggPanel aggs={aggs} onFilter={addF} />}
          </div>
        </>
      )}

      {openId && (
        <EventDrawer id={openId} onClose={() => update({ event: null }, { resetPage: false })}
          onPivot={(f) => update({ filters: addFilter(state.filters, f), event: null })}
          onAddToCase={can("cases:write") ? setCaseEvent : undefined} />
      )}
      {caseEvent && <AddToCaseDialog eventIds={[caseEvent]} onClose={() => setCaseEvent(null)} />}
    </div>
  );
}
