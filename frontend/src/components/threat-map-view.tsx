"use client";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import {
  activeChips, ago, clearedFilters, CONTINENTS, customRangeError, defaultFilters, fmtInt, IOC_FILTER_TYPES, LAYER_COLOR, LAYERS, RANGES, SEVERITIES, toParams,
  type Layer, type MapData, type MapFilters, type MapStatus, type RangeKey,
} from "@/lib/threat-map";
import { ErrorLine } from "./badges";
import { ActivityTimeline, InvestigationPanel, RecentCorrelations, TopCountries, TopIps } from "./threat-map-panels";

// MapLibre needs WebGL and the DOM: load it on the client only, once.
const ThreatMapCanvas = dynamic(() => import("./threat-map-canvas"), {
  ssr: false,
  loading: () => <div className="absolute inset-0 animate-pulse bg-[#0a1018]" aria-label="Loading map" />,
});

const LIVE_MS = 30_000;

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => { const t = window.setTimeout(() => setV(value), ms); return () => window.clearTimeout(t); }, [value, ms]);
  return v;
}

function Stat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className="panel px-3 py-2" role="group" aria-label={label}>
      <div className={`text-xl font-semibold tabular-nums ${tone ?? ""}`}>{value}</div>
      <div className="text-xs text-muted">{label}</div>
      {sub && <div className="truncate text-[11px] text-muted">{sub}</div>}
    </div>
  );
}

function SummaryCards({ d }: { d: MapData | undefined }) {
  const c = d?.cards;
  const top = c?.top_indicator_country;
  return (
    <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5">
      <Stat label="Unique malicious IPs" value={fmtInt(c?.unique_malicious_ips)} sub="reported by your feeds and analysts" tone={c?.unique_malicious_ips ? "text-yellow-300" : ""} />
      <Stat label="Countries with indicators" value={fmtInt(c?.countries_with_indicators)} sub={top ? `most: ${top.name || top.iso} (${fmtInt(top.ips)} IPs) · approximate GeoIP` : "approximate GeoIP"} />
      <Stat label="Observed network events" value={fmtInt(c?.observed_events)} sub={c?.observed_remote_ips != null ? `${fmtInt(c.observed_remote_ips)} remote IPs` : "events carrying an IP address"} tone="text-sky-300" />
      <Stat label="Correlated threats" value={fmtInt(c?.correlated_threats)} sub={c?.correlated_ips != null ? `${fmtInt(c.correlated_ips)} addresses` : "telemetry unavailable"} tone={c?.correlated_threats ? "text-red-400" : ""} />
      <Stat label="High-severity detections" value={fmtInt(c?.high_severity_detections)} sub="detection-rule alerts, high or critical" tone={c?.high_severity_detections ? "text-orange-300" : ""} />
    </div>
  );
}

function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: Array<{ key: T; label: string }>; onChange: (v: T) => void; label: string }) {
  return (
    <div role="group" aria-label={label} className="inline-flex overflow-hidden rounded-sm border border-line">
      {options.map((o) => (
        <button key={o.key} aria-pressed={o.key === value} onClick={() => onChange(o.key)}
          className={`px-2.5 py-1 text-xs transition-colors ${o.key === value ? "bg-accent/15 text-accent" : "bg-panel text-muted hover:text-[#c9d1d9]"}`}>{o.label}</button>
      ))}
    </div>
  );
}

function MultiSelect({ label, options, value, onChange }: { label: string; options: string[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <select aria-label={label} className="input py-0.5 text-xs" value="" onChange={(e) => { const v = e.target.value; if (v) onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]); }}>
      <option value="">{label}{value.length ? ` (${value.length})` : ""}…</option>
      {options.map((o) => <option key={o} value={o}>{value.includes(o) ? "✓ " : ""}{o}</option>)}
    </select>
  );
}

export function ThreatMapView() {
  const sp = useSearchParams();
  const [filters, setFilters] = useState<MapFilters>(() => {
    const f = defaultFilters();
    const l = sp.get("layer");
    if (l === "intelligence" || l === "observed" || l === "correlated") f.layer = l;
    f.q = (sp.get("q") ?? "").slice(0, 120);
    const r = sp.get("range");
    if (r === "1h" || r === "24h" || r === "7d" || r === "30d") f.range = r;
    return f;
  });
  const [selected, setSelected] = useState<string | null>(sp.get("ip"));
  const [panelOpen, setPanelOpen] = useState(true);
  const [live, setLive] = useState(true);
  const [showFlows, setShowFlows] = useState(true);
  const [animate, setAnimate] = useState(false);
  const [fitNonce, setFitNonce] = useState(0);
  const [mapError, setMapError] = useState<string | null>(null);
  const [corrOffset, setCorrOffset] = useState(0);
  const [customDraft, setCustomDraft] = useState({ start: "", end: "" });

  const patch = useCallback((p: Partial<MapFilters>) => { setFilters((f) => ({ ...f, ...p })); setCorrOffset(0); }, []);
  const debouncedQ = useDebounced(filters.q, 350);
  const effective = useMemo(() => ({ ...filters, q: debouncedQ }), [filters, debouncedQ]);
  const rangeErr = customRangeError(effective);
  const qs = useMemo(() => (rangeErr ? "" : toParams(effective).toString()), [effective, rangeErr]);
  const rangeQs = useMemo(() => { const p = new URLSearchParams(qs); return new URLSearchParams({ layer: p.get("layer") ?? "intelligence", range: p.get("range") ?? "24h", ...(p.get("start") ? { start: p.get("start")!, end: p.get("end")! } : {}) }).toString(); }, [qs]);

  const status = useQuery({ queryKey: ["tm-status"], queryFn: () => api.threatMapStatus(), staleTime: 60_000 });
  const data = useQuery({
    queryKey: ["tm-data", qs], queryFn: () => api.threatMapData(qs), enabled: !!qs, placeholderData: keepPreviousData, refetchInterval: live ? LIVE_MS : false,
  });
  const flows = useQuery({
    queryKey: ["tm-flows", qs], queryFn: () => api.threatMapFlows(qs), enabled: !!qs && showFlows && filters.layer !== "intelligence", placeholderData: keepPreviousData, refetchInterval: live ? LIVE_MS : false,
  });
  const corr = useQuery({
    queryKey: ["tm-corr", qs, corrOffset], queryFn: () => api.threatMapCorrelations(`${qs}&limit=8&offset=${corrOffset}`), enabled: !!qs && corrOffset > 0, placeholderData: keepPreviousData,
  });

  const d = data.data;
  const st: MapStatus | undefined = status.data;
  const chips = activeChips(filters);
  const layer = filters.layer;
  const layerStatus = st?.layers[layer];
  const mapCountries = d?.countries ?? [];
  const mapMarkers = d?.markers ?? [];
  const countryOptions = useMemo(() => [...(d?.countries ?? [])].sort((a, b) => (a.name || a.iso).localeCompare(b.name || b.iso)), [d?.countries]);
  const feedOptions = st?.layers.intelligence.feeds ?? [];
  const logOptions = (st?.layers.observed.sources ?? []).map((s) => s.source);
  const notes = useMemo(() => {
    const out: string[] = [];
    if (d?.truncated) out.push(`Showing the ${fmtInt(d.markers.length)} highest-weight of ${fmtInt(d.total_markers)} located addresses. Narrow the filters to see the rest.`);
    if (d && d.unlocated > 0) out.push(`${fmtInt(d.unlocated)} address${d.unlocated === 1 ? "" : "es"} could not be located and ${d.unlocated === 1 ? "is" : "are"} not on the map.`);
    out.push(...(d?.notes ?? []));
    if (layer !== "intelligence" && showFlows && flows.data) {
      if (!flows.data.flows.length && flows.data.reason) out.push(flows.data.reason);
      if (flows.data.note) out.push(flows.data.note);
    }
    return out;
  }, [d, layer, showFlows, flows.data]);
  const loadingFirst = data.isLoading && !d;
  const hasArcs = layer !== "intelligence" && showFlows && (flows.data?.flows.length ?? 0) > 0;
  const empty = !!d && d.markers.length === 0 && !hasArcs && !data.isFetching;

  const select = useCallback((ip: string) => { setSelected(ip); setPanelOpen(true); }, []);
  const pickCountry = useCallback((iso: string) => setFilters((f) => ({ ...f, country: f.country.includes(iso) ? f.country : [...f.country, iso] })), []);

  const corrRows = corrOffset > 0 && corr.data ? corr.data.items : d?.recent_correlations ?? [];
  const corrTotal = corrOffset > 0 && corr.data ? corr.data.total : Math.max(d?.recent_correlations.length ?? 0, d?.cards.correlated_threats ?? 0);

  return (
    <div className="flex flex-col gap-3">
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div>
          <h1 className="text-lg font-semibold">Global Threat Map</h1>
          <p className="text-xs text-muted">External intelligence, your own telemetry, and where they meet. Locations are GeoIP estimates, not attacker locations.</p>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Segmented<RangeKey> label="Time range" value={filters.range} options={RANGES} onChange={(r) => patch({ range: r })} />
          <button className={`btn py-0.5 text-xs ${live ? "btn-primary" : ""}`} aria-pressed={live} onClick={() => setLive((v) => !v)} title="Refresh every 30 seconds">
            <span className={`mr-1 inline-block h-1.5 w-1.5 rounded-full ${live ? "bg-green-400 animate-pulse" : "bg-slate-500"}`} />{live ? "Live" : "Paused"}
          </button>
          <span className="text-xs text-muted" aria-live="off">{d ? `updated ${ago(d.generated_at)}` : ""}</span>
        </div>
      </header>

      {filters.range === "custom" && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <label>From <input aria-label="Range start" type="datetime-local" className="input" value={customDraft.start} onChange={(e) => setCustomDraft((c) => ({ ...c, start: e.target.value }))} /></label>
          <label>To <input aria-label="Range end" type="datetime-local" className="input" value={customDraft.end} onChange={(e) => setCustomDraft((c) => ({ ...c, end: e.target.value }))} /></label>
          <button className="btn btn-primary py-0.5" disabled={!customDraft.start || !customDraft.end} onClick={() => patch({ start: new Date(customDraft.start).toISOString(), end: new Date(customDraft.end).toISOString() })}>Apply</button>
          {rangeErr && <span role="alert" className="text-red-400">{rangeErr}</span>}
        </div>
      )}

      <div role="tablist" aria-label="Data layer" className="grid gap-2 md:grid-cols-3">
        {LAYERS.map((l) => {
          const on = l.key === layer;
          const ls = st?.layers[l.key];
          return (
            <button key={l.key} role="tab" aria-selected={on} onClick={() => patch({ layer: l.key })}
              className={`panel px-3 py-2 text-left transition-colors ${on ? "bg-bg" : "hover:border-accent/60"}`} style={on ? { borderColor: l.color } : undefined}>
              <div className="flex items-center gap-2 text-sm font-medium"><span className="h-2.5 w-2.5 rounded-full" style={{ background: l.color }} />{l.label}
                {ls && !ls.available && <span className="ml-auto rounded border border-line px-1 text-[10px] text-muted">needs data</span>}</div>
              <div className="text-xs text-muted">{l.blurb}</div>
            </button>
          );
        })}
      </div>

      <SummaryCards d={d} />

      <div className="panel flex flex-col gap-2 px-3 py-2" role="search" aria-label="Threat map filters">
        <div className="flex flex-wrap items-center gap-2">
          <input aria-label="Search" type="search" className="input w-72" placeholder="IP, CIDR, ASN (AS15169), country, IOC, malware, campaign…" value={filters.q} onChange={(e) => patch({ q: e.target.value })} maxLength={120} />
          <MultiSelect label="Country" options={countryOptions.map((c) => c.iso)} value={filters.country} onChange={(country) => patch({ country })} />
          <select aria-label="Region" className="input py-0.5 text-xs" value={filters.continent} onChange={(e) => patch({ continent: e.target.value })}>
            <option value="">All regions</option>{CONTINENTS.map(([c, n]) => <option key={c} value={c}>{n}</option>)}
          </select>
          <select aria-label="IOC type" className="input py-0.5 text-xs" value={filters.iocType} onChange={(e) => patch({ iocType: e.target.value })}>
            <option value="">Any IOC type</option>{IOC_FILTER_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select aria-label="Minimum severity" className="input py-0.5 text-xs" value={filters.severity} onChange={(e) => patch({ severity: e.target.value as MapFilters["severity"] })}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s === "info" ? "Any severity" : `Severity ≥ ${s}`}</option>)}
          </select>
          <label className="flex items-center gap-1 text-xs text-muted">Confidence ≥
            <input aria-label="Minimum confidence" type="number" min={0} max={100} className="input w-14 py-0.5" value={filters.minConfidence} onChange={(e) => patch({ minConfidence: Math.max(0, Math.min(100, Number(e.target.value) || 0)) })} /></label>
          <input aria-label="Threat category or malware family" className="input w-44 py-0.5 text-xs" placeholder="Malware / category" value={filters.category} onChange={(e) => patch({ category: e.target.value })} list="tm-categories" maxLength={80} />
          {layer !== "observed" && <MultiSelect label="Feed" options={feedOptions} value={filters.source} onChange={(source) => patch({ source })} />}
          {layer !== "intelligence" && <MultiSelect label="Telemetry source" options={logOptions} value={filters.logSource} onChange={(logSource) => patch({ logSource })} />}
          <select aria-label="Address scope" className="input py-0.5 text-xs" value={filters.scope} onChange={(e) => patch({ scope: e.target.value as MapFilters["scope"] })}>
            <option value="any">Internal + external</option><option value="external">External IPs only</option><option value="internal">Internal IPs only</option>
          </select>
        </div>
        {chips.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5" aria-label="Active filters">
            <span className="text-xs text-muted">Active filters:</span>
            {chips.map((c) => (
              <button key={c.key} className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs text-accent hover:bg-accent/20" onClick={() => patch(c.clear)} aria-label={`Remove filter ${c.label}`}>{c.label} <span aria-hidden>✕</span></button>
            ))}
            <button className="btn py-0 text-xs" onClick={() => { setFilters(clearedFilters(filters)); setCorrOffset(0); }}>Clear filters</button>
          </div>
        )}
      </div>

      <div className={`grid gap-3 ${panelOpen && selected ? "xl:grid-cols-[minmax(0,1fr)_380px]" : "grid-cols-1"}`}>
        <div className="panel relative overflow-hidden" style={{ height: "min(62vh, 640px)", minHeight: 420 }}>
          <ThreatMapCanvas layer={layer} markers={mapMarkers} countries={mapCountries} flows={flows.data?.flows ?? []} home={flows.data?.home ?? st?.home ?? null}
            showFlows={showFlows && layer !== "intelligence"} animate={animate} selectedIp={selected} fitNonce={fitNonce} onSelect={select} onCountry={pickCountry} onFailure={setMapError} />

          <div className="pointer-events-none absolute left-2 top-2 flex max-w-[60%] flex-col items-start gap-1">
            {st && !st.geoip.available && <Banner tone="warn">No GeoIP database is configured, so addresses cannot be placed on the map. Run <code>scripts/fetch-geoip.sh</code> and restart the backend.</Banner>}
            {d?.partial.includes("telemetry") && <Banner tone="warn">Telemetry search is unavailable: observed and correlated figures are incomplete.</Banner>}
            {notes.length > 0 && (
              <details className="pointer-events-auto rounded border border-line bg-panel/90 text-[11px] backdrop-blur">
                <summary className="cursor-pointer select-none px-2 py-1 text-muted">ⓘ Map notes ({notes.length})</summary>
                <ul className="space-y-1 border-t border-line px-2 py-1 text-muted">{notes.map((n) => <li key={n}>{n}</li>)}</ul>
              </details>
            )}
          </div>

          <div className="absolute right-2 bottom-8 flex flex-col items-end gap-1 text-xs">
            <button className="btn py-0.5" onClick={() => setFitNonce((n) => n + 1)}>Fit to results</button>
            {layer !== "intelligence" && (
              <>
                <label className="panel flex cursor-pointer items-center gap-1 px-2 py-0.5"><input type="checkbox" checked={showFlows} onChange={(e) => setShowFlows(e.target.checked)} /> Connections</label>
                <label className="panel flex cursor-pointer items-center gap-1 px-2 py-0.5"><input type="checkbox" checked={animate} disabled={!showFlows} onChange={(e) => setAnimate(e.target.checked)} /> Animate</label>
              </>
            )}
          </div>

          <Legend layer={layer} showFlows={showFlows && layer !== "intelligence"} />

          {loadingFirst && <Overlay><span className="animate-pulse">Loading map data…</span></Overlay>}
          {data.isError && !d && (
            <Overlay><div role="alert" className="space-y-2 text-center"><ErrorLine error={data.error} fallback="Could not load the threat map" /><button className="btn" onClick={() => void data.refetch()}>Retry</button></div></Overlay>
          )}
          {data.isError && d && <div role="alert" className="absolute bottom-8 left-1/2 -translate-x-1/2 rounded border border-red-500/40 bg-panel px-3 py-1 text-xs text-red-300">Update failed, showing the last good data. <button className="underline" onClick={() => void data.refetch()}>Retry</button></div>}
          {mapError && <Overlay><div role="alert" className="max-w-sm text-center text-sm">The map could not be drawn ({mapError}). The rankings and panels below still work.</div></Overlay>}
          {empty && !mapError && (
            <Overlay>
              <div className="max-w-md space-y-2 text-center" data-testid="map-empty">
                <div className="text-sm font-medium">{chips.length ? "Nothing matches these filters" : `No ${LAYERS.find((l) => l.key === layer)?.label.toLowerCase()} in this time range`}</div>
                <p className="text-xs text-muted">
                  {chips.length ? "Remove a filter or widen the time range." : (layerStatus && !layerStatus.available ? layerStatus.needs : layerStatus?.error || "Try a wider time range.")}
                </p>
                {chips.length > 0 && <button className="btn btn-primary" onClick={() => setFilters(clearedFilters(filters))}>Clear filters</button>}
                {layer === "observed" && d && d.internal.length > 0 && <p className="text-xs text-muted">{fmtInt(d.internal.length)} internal or non-routable addresses were seen; they have no geographic location.</p>}
              </div>
            </Overlay>
          )}
        </div>

        {panelOpen && selected && <div className="min-h-0 xl:h-[min(62vh,640px)]"><InvestigationPanel ip={selected} filters={effective} rangeQs={rangeQs} onClose={() => { setSelected(null); }} /></div>}
      </div>
      {selected && !panelOpen && <button className="btn self-start text-xs" onClick={() => setPanelOpen(true)}>Show investigation panel ({selected})</button>}
      {selected && panelOpen && <button className="btn self-start text-xs xl:hidden" onClick={() => setPanelOpen(false)}>Collapse panel</button>}

      <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-4">
        <TopCountries rows={d?.top_countries ?? []} layer={layer} onPick={pickCountry} active={filters.country} />
        <TopIps rows={d?.top_ips ?? []} layer={layer} onPick={select} selected={selected} />
        <div className="lg:col-span-2"><RecentCorrelations rows={corrRows} total={corrTotal} offset={corrOffset} setOffset={setCorrOffset} loading={corr.isFetching} onPick={select} /></div>
      </div>
      <ActivityTimeline points={d?.timeline.points ?? []} unit={d?.timeline.unit ?? ""} layer={layer} />

      {layer === "observed" && d && d.internal.length > 0 && (
        <section className="panel px-3 py-2" aria-label="Internal and non-routable addresses">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-muted">Internal and non-routable addresses ({d.internal.length}) — not mappable</h2>
          <ul className="mt-1 grid gap-x-4 gap-y-0.5 text-xs md:grid-cols-2 xl:grid-cols-3">
            {d.internal.slice(0, 12).map((i) => <li key={i.ip}><button className="font-mono hover:text-accent" onClick={() => select(i.ip)}>{i.ip}</button> <span className="text-muted">{i.class} · {fmtInt(i.events)} events</span></li>)}
          </ul>
        </section>
      )}

      <footer className="text-[11px] text-muted">
        Basemap: Natural Earth (public domain). {st?.geoip.attribution ? `${st.geoip.attribution}. ` : ""}Reported intelligence is third-party data and is not a confirmed attack on this organisation.
      </footer>
      <datalist id="tm-categories">{["botnet_cc", "payload_delivery", "phishing", "scanner", "ransomware"].map((c) => <option key={c} value={c} />)}</datalist>
    </div>
  );
}

function Banner({ children, tone }: { children: React.ReactNode; tone?: "warn" }) {
  return <div className={`pointer-events-auto rounded border px-2 py-1 text-[11px] backdrop-blur ${tone === "warn" ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-200" : "border-line bg-panel/90 text-muted"}`}>{children}</div>;
}
function Overlay({ children }: { children: React.ReactNode }) {
  return <div className="absolute inset-0 z-10 flex items-center justify-center bg-bg/70 p-6 text-muted">{children}</div>;
}

function Legend({ layer, showFlows }: { layer: Layer; showFlows: boolean }) {
  return (
    <div className="pointer-events-none absolute bottom-8 left-2 rounded border border-line bg-panel/90 px-2 py-1.5 text-[11px]" aria-label="Map legend">
      <div className="mb-0.5 font-medium" style={{ color: LAYER_COLOR[layer] }}>{LAYERS.find((l) => l.key === layer)?.label}</div>
      <div className="flex flex-wrap gap-x-2">
        {([["info", "#6e7681"], ["low", "#58a6ff"], ["medium", "#d29922"], ["high", "#f0883e"], ["critical", "#f85149"]] as const).map(([n, c]) => <span key={n} className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: c }} />{n}</span>)}
      </div>
      <div className="text-muted">marker size = {layer === "intelligence" ? "IOC count × confidence" : "event count"} · country shade = {layer === "observed" ? "events" : layer === "correlated" ? "correlated IPs" : "reported IPs"}</div>
      {layer === "correlated" && <div className="text-muted"><span className="mr-1 inline-block h-2 w-2 rounded-full bg-red-500/40" />red halo = matches intelligence</div>}
      {showFlows && <div className="flex gap-2 text-muted"><span style={{ color: "#f0883e" }}>━ inbound</span><span style={{ color: "#39c5cf" }}>━ outbound</span><span style={{ color: "#8b949e" }}>━ external↔external</span></div>}
    </div>
  );
}
