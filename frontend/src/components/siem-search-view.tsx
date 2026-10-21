"use client";
import { useIsMutating, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Bucket, EventDoc, Filter, SiemQueryResult, SiemSourceResult } from "@/lib/api-types";
import { addFilter, clampPaging, paramsToState, stateToParams, toRequestBody, type RangeSpec, type SearchState } from "@/lib/query";
import { useAuth } from "@/lib/auth";
import { ChevronLeft, ChevronRight, CircleAlert, CircleCheck, Info, Loader2, Search, SearchX } from "lucide-react";
import { AddToCaseDialog } from "./add-to-case-dialog";
import { AggPanel } from "./agg-panel";
import { EventDrawer } from "./event-drawer";
import { FilterBuilder, FilterChips } from "./filter-builder";
import { QueryEditorHint } from "./query-hint";
import { ScopePicker } from "./scope-picker";
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
      {s.found > s.scanned && <span className="text-ink">the SIEM reports {s.found_at_least ? "at least " : ""}{s.found.toLocaleString("en-US")} logs for this</span>}
      {s.capped && <span className="text-sev-medium">only the newest {s.scanned.toLocaleString("en-US")} were read; narrow the query or range for the rest</span>}
      <span className="text-muted tabular-nums">{s.ms} ms</span>
      {s.skipped.map((n) => <span key={n} className="basis-full pl-5 text-sev-medium">{n}</span>)}
    </li>
  );
}

type LastSearch = { qs: string; nonce: number };
/** What the controls can change without searching: it takes effect when "Search the SIEMs" is clicked. */
type Edits = { range: RangeSpec; filters: Filter[]; lang: boolean; sources: string[]; ent: number[]; st: number[] };
type MoreHits = { hits: EventDoc[]; origins: Record<string, string> };
const LAST_SEARCH = ["siem-last-search"];
const NO_MORE: MoreHits = { hits: [], origins: {} };
const HOLD_MS = 30 * 60_000; // the server keeps a result this long

export function SiemSearchView() {
  const router = useRouter();
  const pathname = usePathname();
  const sp = useSearchParams();
  const state = useMemo(() => paramsToState(new URLSearchParams(sp.toString())), [sp]);
  const sources = useMemo(() => readSources(new URLSearchParams(sp.toString())), [sp]);
  const legacyId = /^[a-f0-9]{32}$/.test(sp.get("id") ?? "") ? sp.get("id") : null; // older links use ?id=
  const openId = state.event ?? legacyId;
  const [draft, setDraft] = useState(state.q);
  const qc = useQueryClient();
  // A search outlives this page: the cache keeps its result (and the pages loaded after it) for as long as the server holds it, and the last
  // search is remembered so the sidebar link, which has no query in it, brings it back. logout / tenant switch clear the cache.
  const [nonce, setNonce] = useState(() => {
    const last = qc.getQueryData<LastSearch>(LAST_SEARCH);
    return last?.qs && (last.qs === sp.toString() || !sp.toString()) ? last.nonce : 0;
  });
  const restoring = useRef(false);
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
    for (const k of ["browse", "ent", "st"]) for (const v of sp.getAll(k)) p.append(k, v); // paging or sorting must not leave browse mode
    const qs = p.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [state, sources, sp, router, pathname]);

  const fields = useQuery({ queryKey: ["fields"], queryFn: api.fields, staleTime: Infinity });
  const available = useQuery({ queryKey: ["siem-sources"], queryFn: api.siemSources, staleTime: 60_000 });
  const browse = sp.get("browse") === "1"; // list what LogRhythm holds for the range, with no search terms (up to the read limit)
  const hasQuery = !!(state.q.trim() || state.filters.length || browse);
  useEffect(() => {
    const last = qc.getQueryData<LastSearch>(LAST_SEARCH);
    if (last?.qs && !hasQuery) { restoring.current = true; router.replace(`${pathname}?${last.qs}`, { scroll: false }); }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (restoring.current) { if (hasQuery) restoring.current = false; return; }
    qc.setQueryData<LastSearch>(LAST_SEARCH, hasQuery ? { qs: sp.toString(), nonce } : { qs: "", nonce: 0 }); // empty qs = nothing to bring back
  }, [hasQuery, sp, nonce, qc]);
  const numbers = (key: string): number[] => sp.getAll(key).map(Number).filter((n) => Number.isInteger(n)).slice(0, 50);
  const entityIds = useMemo(() => numbers("ent"), [sp]); // eslint-disable-line react-hooks/exhaustive-deps
  const typeIds = useMemo(() => numbers("st"), [sp]); // eslint-disable-line react-hooks/exhaustive-deps
  // Changing a filter, the time range, the sources or the scope only edits the search; nothing is sent to the SIEMs until "Search the SIEMs".
  const applied: Edits = useMemo(
    () => ({ range: state.range, filters: state.filters, lang: state.lang, sources, ent: entityIds, st: typeIds }),
    [state.range, state.filters, state.lang, sources, entityIds, typeIds],
  );
  const appliedKey = JSON.stringify([state.q, applied, browse]);
  const [edits, setEdits] = useState<Partial<Edits>>({});
  useEffect(() => setEdits({}), [appliedKey]);
  const cur: Edits = { ...applied, ...edits };
  const dirty = draft !== state.q || JSON.stringify(cur) !== JSON.stringify(applied);
  const edit = <K extends keyof Edits>(k: K, v: Edits[K]) => setEdits((e) => ({ ...e, [k]: v }));
  /** Apply the edits (and the text typed) as the search to run. The same search again is a re-run. */
  const commit = (over: { browse?: boolean } = {}) => {
    const want = { ...cur, ...(over.browse === false ? { ent: [], st: [] } : {}) };
    const on = over.browse ?? browse;
    const p = stateToParams({ ...state, q: draft, lang: want.lang, range: want.range, filters: want.filters, offset: 0, event: null });
    for (const id of want.sources) p.append("src", id);
    if (on) p.set("browse", "1");
    for (const id of want.ent) p.append("ent", String(id));
    for (const id of want.st) p.append("st", String(id));
    if (JSON.stringify([draft, want, on]) === appliedKey) { setNonce((n) => n + 1); return; }
    const qs = p.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };
  const setBrowse = (on: boolean) => commit({ browse: on }); // the two browse buttons are the search action itself
  // The request body (with its resolved "now") is computed once per applied search / explicit run, so paging and sorting never ask the SIEMs again.
  const scopes = useQuery({ queryKey: ["siem-scopes"], queryFn: api.siemScopes, staleTime: 300_000, enabled: browse });
  const key = JSON.stringify([state.q, state.lang, state.range, state.filters, sources, nonce, browse, entityIds, typeIds]);
  const search = useQuery({
    queryKey: ["siem-query", key],
    queryFn: () => api.siemQuery({ ...toRequestBody({ ...state, event: null, offset: 0, sort: null }, []), ...(sources.length ? { sources } : {}), ...(browse ? { browse: true, ...(entityIds.length ? { entity_ids: entityIds } : {}), ...(typeIds.length ? { source_type_ids: typeIds } : {}) } : {}) }),
    enabled: hasQuery, staleTime: Infinity, gcTime: HOLD_MS, retry: false, refetchOnWindowFocus: false, refetchOnMount: false,
  });
  // Further pages of the held result are fetched on demand and appended: sorting, paging, counts and aggregations all work on what is loaded.
  // They live in the cache, not in this component, so loading goes on (and what was loaded stays) while another module is open.
  const base: SiemQueryResult | undefined = search.data;
  const moreKey = ["siem-more", base?.search_id ?? ""];
  const moreQ = useQuery<MoreHits>({ queryKey: moreKey, queryFn: async () => NO_MORE, initialData: NO_MORE, staleTime: Infinity, gcTime: HOLD_MS, enabled: !!base });
  const more = moreQ.data ?? NO_MORE;
  const data: SiemQueryResult | undefined = useMemo(
    () => (base && more.hits.length ? { ...base, hits: [...base.hits, ...more.hits], origins: { ...base.origins, ...more.origins } } : base),
    [base, more],
  );
  const loadingMore = useIsMutating({ mutationKey: ["siem-more", base?.search_id ?? ""] }) > 0;
  const [moreError, setMoreError] = useState<string | null>(null);
  const loadMore = useMutation({
    mutationKey: ["siem-more", base?.search_id ?? ""],
    mutationFn: async (all: boolean) => {
      if (!base) return;
      const key = ["siem-more", base.search_id];
      for (let guard = 0; guard < 25; guard++) {
        const have = qc.getQueryData<MoreHits>(key) ?? NO_MORE;
        if (base.hits.length + have.hits.length >= base.total) break;
        const page = await api.siemHits(base.search_id, base.hits.length + have.hits.length);
        if (page.expired) throw new Error("This result is no longer held (30 minutes); search again.");
        if (page.hits.length === 0) break;
        qc.setQueryData<MoreHits>(key, { hits: [...have.hits, ...page.hits], origins: { ...have.origins, ...page.origins } });
        if (!all) break;
      }
    },
    onMutate: () => setMoreError(null),
    onError: (e: Error) => setMoreError(e.message),
  });
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
  const run = () => commit();
  const addF = (f: Filter) => edit("filters", addFilter(cur.filters, f));
  const toggleSource = (id: string) => {
    const all = (available.data ?? []).map((s) => s.id);
    const current = cur.sources.length ? cur.sources : all;
    const next = current.includes(id) ? current.filter((x) => x !== id) : [...current, id];
    edit("sources", next.length === all.length ? [] : next);
  };
  const canNext = offset + limit < sorted.length;
  const shown = cur.sources.length ? cur.sources : (available.data ?? []).map((s) => s.id);
  const failed = data?.sources.filter((s) => s.status === "error") ?? [];

  return (
    <div className="space-y-3">
      <PageHeader title="SIEM Search" description="Search LogRhythm and Trend Vision One directly. Nothing is copied: results are shown from the SIEMs themselves and only an event you open or add to a case is kept." />
      <form className="panel flex flex-wrap gap-2 p-3" onSubmit={(e) => { e.preventDefault(); run(); }} role="search" aria-label="SIEM search">
        <div className="relative min-w-[16rem] flex-1">
          <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input ref={searchRef} className="input w-full pl-8 font-mono" value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={cur.lang ? 2000 : 512}
            aria-label="Search query" placeholder={cur.lang ? "process.name:powershell.exe user.name:bob   (hunt query language)" : "An IP, domain, hash, user, host, process or word…  e.g. 203.0.113.5 · powershell -chrome   (press / to focus)"} />
        </div>
        <RangeControl value={cur.range} onChange={(range) => edit("range", range)} />
        <button className="btn btn-primary" type="submit" disabled={search.isFetching}><Search aria-hidden className="h-3.5 w-3.5" />Search the SIEMs</button>
        {dirty && <p role="status" className="w-full text-xs text-sev-medium">Changes are not applied yet: click Search the SIEMs to search with them.</p>}
      </form>

      <div className="flex flex-wrap items-center gap-3">
        {fields.data && <FilterBuilder fields={fields.data.filter((f) => f.kind !== "date")} onAdd={addF} />}
        <label className="flex items-center gap-1.5 text-sm text-ink-2"><input type="checkbox" checked={cur.lang} onChange={(e) => edit("lang", e.target.checked)} /> Query language</label>
        <label className="ml-auto flex items-center gap-1.5 text-sm text-ink-2"><input type="checkbox" checked={dense} onChange={(e) => setDense(e.target.checked)} /> Dense</label>
      </div>
      {cur.lang && <p className="text-xs text-muted">{QueryEditorHint}</p>}
      <FilterChips filters={cur.filters} onRemove={(i) => edit("filters", cur.filters.filter((_, j) => j !== i))} />

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
      {browse && !state.q.trim() && !state.filters.length && scopes.data && (
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Narrow the browse">
          <span className="text-xs text-muted">Narrow to</span>
          <ScopePicker label="Entities" options={scopes.data.entities} selected={cur.ent} onChange={(ids) => edit("ent", ids)} />
          <ScopePicker label="Log source types" options={scopes.data.source_types} selected={cur.st} onChange={(ids) => edit("st", ids)} />
          {entityIds.length > 0 && <span className="text-xs text-muted">Alarms are left out while narrowed.</span>}
          {scopes.data.errors.map((e) => <span key={e} className="text-xs text-sev-medium">{e}</span>)}
        </div>
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
                  {data.truncated && <span className="text-muted">The SIEMs returned more than can be held ({data.found_at_least ? "at least " : ""}{data.found.toLocaleString("en-US")} found); narrow the query or range to see the rest.</span>}
                </div>
              )}
              {data.hits.length > 0 && data.hits.length < data.total && (
                <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
                  <span className="tabular-nums text-muted">{data.hits.length.toLocaleString("en-US")} of {data.total.toLocaleString("en-US")} events loaded</span>
                  <button className="btn" disabled={loadingMore} onClick={() => loadMore.mutate(false)}>Load next {Math.min(500, data.total - data.hits.length).toLocaleString("en-US")}</button>
                  <button className="btn" disabled={loadingMore} onClick={() => loadMore.mutate(true)}>Load all {data.total.toLocaleString("en-US")}</button>
                  {loadingMore && <span role="status" className="text-accent">Loading…</span>}
                  {moreError && <span role="alert" className="text-sev-critical">{moreError}</span>}
                </div>
              )}
            </div>
            {data.hits.length > 0 && <AggPanel aggs={aggs} onFilter={addF} />}
          </div>
        </>
      )}

      {openId && (
        <EventDrawer id={openId} onClose={() => update({ event: null }, { resetPage: false })}
          onPivot={(f) => { addF(f); update({ event: null }, { resetPage: false }); }}
          onAddToCase={can("cases:write") ? setCaseEvent : undefined} />
      )}
      {caseEvent && <AddToCaseDialog eventIds={[caseEvent]} onClose={() => setCaseEvent(null)} />}
    </div>
  );
}
