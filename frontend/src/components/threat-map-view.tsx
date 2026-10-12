"use client";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import {
  activeChips, ago, clearedFilters, CONTINENTS, customRangeError, defaultFilters, fmtInt, IOC_FILTER_TYPES, LAYERS, RANGES, SEVERITIES, toParams,
  type Layer, type MapData, type MapFilters, type MapStatus, type RangeKey,
} from "@/lib/threat-map";
import { Activity, ChevronDown, Flag, Link2, Maximize2, Pause, Play, Radar, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { ErrorLine } from "./badges";
import { KpiCard } from "./ui/kpi-card";
import { PageHeader } from "./ui/page-header";
import { ActivityTimeline, InvestigationPanel, RecentCorrelations, TopCountries, TopIps } from "./threat-map-panels";

// MapLibre needs WebGL and the DOM: load it on the client only, once.
const ThreatMapCanvas = dynamic(() => import("./threat-map-canvas"), {
  ssr: false,
  loading: () => <div className="absolute inset-0 animate-skeleton bg-line/60" aria-label="Loading map" />,
});

const LIVE_MS = 30_000;

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => { const t = window.setTimeout(() => setV(value), ms); return () => window.clearTimeout(t); }, [value, ms]);
  return v;
}

function SummaryCards({ d }: { d: MapData | undefined }) {
  const c = d?.cards;
  const top = c?.top_indicator_country;
  const loading = !d;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
      <KpiCard compact label="Unique malicious IPs" icon={Radar} value={fmtInt(c?.unique_malicious_ips)} loading={loading} tone={c?.unique_malicious_ips ? "medium" : undefined} hint="reported by your feeds and analysts" />
      <KpiCard compact label="Countries with indicators" icon={Flag} value={fmtInt(c?.countries_with_indicators)} loading={loading} hint={top ? `most: ${top.name || top.iso} (${fmtInt(top.ips)} IPs) · approximate GeoIP` : "approximate GeoIP"} />
      <KpiCard compact label="Observed network events" icon={Activity} value={fmtInt(c?.observed_events)} loading={loading} unavailable={!!d && c?.observed_events == null} hint={c?.observed_remote_ips != null ? `${fmtInt(c.observed_remote_ips)} remote IPs` : "events carrying an IP address"} />
      <KpiCard compact label="Correlated threats" icon={Link2} value={fmtInt(c?.correlated_threats)} loading={loading} unavailable={!!d && c?.correlated_threats == null} tone={c?.correlated_threats ? "critical" : undefined} hint={c?.correlated_ips != null ? `${fmtInt(c.correlated_ips)} addresses` : "telemetry unavailable"} />
      <KpiCard compact label="High-severity detections" icon={ShieldAlert} value={fmtInt(c?.high_severity_detections)} loading={loading} tone={c?.high_severity_detections ? "high" : undefined} hint="detection-rule alerts, high or critical" />
    </div>
  );
}

function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: Array<{ key: T; label: string }>; onChange: (v: T) => void; label: string }) {
  return (
    <div role="group" aria-label={label} className="inline-flex overflow-hidden rounded-md border border-line-strong bg-panel shadow-xs">
      {options.map((o) => (
        <button key={o.key} aria-pressed={o.key === value} onClick={() => onChange(o.key)}
          className={`border-r border-line px-3 py-1 text-sm font-medium transition-colors duration-fast last:border-r-0 ${o.key === value ? "bg-accent-soft text-accent" : "text-muted hover:bg-subtle hover:text-ink"}`}>{o.label}</button>
      ))}
    </div>
  );
}

function MultiSelect({ label, options, value, onChange }: { label: string; options: string[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <select aria-label={label} className="input max-w-[10.5rem]" value="" onChange={(e) => { const v = e.target.value; if (v) onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]); }}>
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
  const [more, setMore] = useState(false);
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

  const advanced = (filters.continent ? 1 : 0) + (filters.iocType ? 1 : 0) + (filters.minConfidence ? 1 : 0) + (filters.category.trim() ? 1 : 0);
  const layerMeta = LAYERS.find((l) => l.key === layer)!;

  return (
    <div className="flex flex-col gap-3">
      <PageHeader flush title="Global Threat Map" description="Reported intelligence, your own telemetry, and where they meet. Locations are GeoIP estimates, not attacker locations."
        actions={<>
          <Segmented<RangeKey> label="Time range" value={filters.range} options={RANGES} onChange={(r) => patch({ range: r })} />
          <button className={`btn ${live ? "border-accent/40 bg-accent-soft text-accent" : ""}`} aria-pressed={live} onClick={() => setLive((v) => !v)} title="Refresh every 30 seconds">
            {live ? <Pause aria-hidden className="h-3.5 w-3.5" /> : <Play aria-hidden className="h-3.5 w-3.5" />}
            <span className={`h-1.5 w-1.5 rounded-full ${live ? "animate-pulse bg-sev-ok" : "bg-muted"}`} aria-hidden />{live ? "Live" : "Paused"}
          </button>
          <span className="text-xs text-muted" aria-live="off">{d ? `updated ${ago(d.generated_at)}` : ""}</span>
        </>} />

      {filters.range === "custom" && (
        <div className="panel flex flex-wrap items-center gap-3 p-3 text-sm">
          <label className="flex items-center gap-2">From <input aria-label="Range start" type="datetime-local" className="input" value={customDraft.start} onChange={(e) => setCustomDraft((c) => ({ ...c, start: e.target.value }))} /></label>
          <label className="flex items-center gap-2">To <input aria-label="Range end" type="datetime-local" className="input" value={customDraft.end} onChange={(e) => setCustomDraft((c) => ({ ...c, end: e.target.value }))} /></label>
          <button className="btn btn-primary" disabled={!customDraft.start || !customDraft.end} onClick={() => patch({ start: new Date(customDraft.start).toISOString(), end: new Date(customDraft.end).toISOString() })}>Apply</button>
          {rangeErr && <span role="alert" className="text-sev-critical">{rangeErr}</span>}
        </div>
      )}

      <div role="tablist" aria-label="Data layer" className="grid gap-3 sm:grid-cols-3">
        {LAYERS.map((l) => {
          const on = l.key === layer;
          const ls = st?.layers[l.key];
          return (
            <button key={l.key} role="tab" aria-selected={on} onClick={() => patch({ layer: l.key })}
              title={l.blurb} className={`panel relative px-4 py-2.5 text-left transition duration-fast ${on ? "shadow-card" : "hover:border-line-strong"}`} style={on ? { boxShadow: `inset 0 -3px 0 ${l.color}, 0 1px 2px rgb(16 24 40 / .05)` } : undefined}>
              <div className="flex items-center gap-2 text-sm font-semibold"><span className="h-2.5 w-2.5 rounded-full" style={{ background: l.color }} aria-hidden />{l.label}
                {ls && !ls.available && <span className="ml-auto rounded border border-line-strong px-1.5 text-[11px] font-medium text-muted">needs data</span>}</div>
              <span className="sr-only">{l.blurb}</span>
            </button>
          );
        })}
      </div>

      <SummaryCards d={d} />

      <div className="panel flex flex-col gap-3 p-3" role="search" aria-label="Threat map filters">
        <div className="flex flex-wrap items-center gap-2">
          <input aria-label="Search" type="search" className="input w-72 max-w-full" placeholder="IP, CIDR, ASN, country, IOC, malware…" value={filters.q} onChange={(e) => patch({ q: e.target.value })} maxLength={120} />
          <MultiSelect label="Country" options={countryOptions.map((c) => c.iso)} value={filters.country} onChange={(country) => patch({ country })} />
          <select aria-label="Minimum severity" className="input" value={filters.severity} onChange={(e) => patch({ severity: e.target.value as MapFilters["severity"] })}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s === "info" ? "Any severity" : `Severity ≥ ${s}`}</option>)}
          </select>
          {layer !== "observed" && <MultiSelect label="Feed" options={feedOptions} value={filters.source} onChange={(source) => patch({ source })} />}
          {layer !== "intelligence" && <MultiSelect label="Telemetry source" options={logOptions} value={filters.logSource} onChange={(logSource) => patch({ logSource })} />}
          <select aria-label="Address scope" className="input" value={filters.scope} onChange={(e) => patch({ scope: e.target.value as MapFilters["scope"] })}>
            <option value="any">Internal + external</option><option value="external">External IPs only</option><option value="internal">Internal IPs only</option>
          </select>
          <button type="button" className="btn ml-auto" aria-expanded={more} aria-controls="tm-more" onClick={() => setMore((v) => !v)}>
            <SlidersHorizontal aria-hidden className="h-3.5 w-3.5" />More filters{advanced > 0 && <span className="rounded-full bg-accent px-1.5 text-[11px] text-white">{advanced}</span>}<ChevronDown aria-hidden className={`h-3.5 w-3.5 transition-transform duration-fast ${more ? "rotate-180" : ""}`} />
          </button>
        </div>
        {more && (
          <div id="tm-more" className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
            <select aria-label="Region" className="input" value={filters.continent} onChange={(e) => patch({ continent: e.target.value })}>
              <option value="">All regions</option>{CONTINENTS.map(([c, n]) => <option key={c} value={c}>{n}</option>)}
            </select>
            <select aria-label="IOC type" className="input" value={filters.iocType} onChange={(e) => patch({ iocType: e.target.value })}>
              <option value="">Any IOC type</option>{IOC_FILTER_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <label className="flex items-center gap-2 text-sm text-muted">Confidence ≥
              <input aria-label="Minimum confidence" type="number" min={0} max={100} className="input w-16" value={filters.minConfidence} onChange={(e) => patch({ minConfidence: Math.max(0, Math.min(100, Number(e.target.value) || 0)) })} /></label>
            <input aria-label="Threat category or malware family" className="input w-52" placeholder="Malware / category" value={filters.category} onChange={(e) => patch({ category: e.target.value })} list="tm-categories" maxLength={80} />
          </div>
        )}
        {chips.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5" aria-label="Active filters">
            <span className="text-xs text-muted">Active filters:</span>
            {chips.map((c) => (
              <button key={c.key} className="inline-flex items-center gap-1 rounded-full border border-accent/30 bg-accent-soft px-2.5 py-0.5 text-xs text-accent transition-colors duration-fast hover:bg-accent/15" onClick={() => patch(c.clear)} aria-label={`Remove filter ${c.label}`}>{c.label} <span aria-hidden>✕</span></button>
            ))}
            <button className="btn btn-sm" onClick={() => { setFilters(clearedFilters(filters)); setCorrOffset(0); }}>Clear filters</button>
          </div>
        )}
      </div>

      <div className={`grid gap-4 ${panelOpen && selected ? "xl:grid-cols-[minmax(0,1fr)_400px]" : "grid-cols-1"}`}>
        <section className="panel flex flex-col overflow-hidden" aria-label="Threat map view">
          <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: layerMeta.color }} aria-hidden />
            <h2 className="text-sm font-semibold">{layerMeta.label}</h2>
            <span className="hidden text-xs text-muted lg:inline">{layerMeta.blurb}</span>
            {d && <span className="text-xs text-muted">{fmtInt(d.markers.length)} shown{d.truncated ? ` of ${fmtInt(d.total_markers)}` : ""}</span>}
            {notes.length > 0 && (
              <details className="relative">
                <summary className="btn btn-sm cursor-pointer list-none">ⓘ Map notes ({notes.length})</summary>
                <ul className="absolute left-0 top-full z-20 mt-1 w-80 space-y-1.5 rounded-lg border border-line bg-panel p-3 text-xs text-ink-2 shadow-pop">{notes.map((n) => <li key={n}>{n}</li>)}</ul>
              </details>
            )}
            <div className="ml-auto flex flex-wrap items-center gap-2 text-sm">
              {layer !== "intelligence" && (
                <>
                  <label className="flex cursor-pointer items-center gap-1.5 text-ink-2"><input type="checkbox" checked={showFlows} onChange={(e) => setShowFlows(e.target.checked)} /> Connections</label>
                  <label className="flex cursor-pointer items-center gap-1.5 text-ink-2"><input type="checkbox" checked={animate} disabled={!showFlows} onChange={(e) => setAnimate(e.target.checked)} /> Animate</label>
                </>
              )}
              <button className="btn btn-sm" onClick={() => setFitNonce((n) => n + 1)}><Maximize2 aria-hidden className="h-3 w-3" />Fit to results</button>
            </div>
          </div>

          <div className="relative" style={{ height: "min(58vh, 620px)", minHeight: 400 }}>
            <ThreatMapCanvas layer={layer} markers={mapMarkers} countries={mapCountries} flows={flows.data?.flows ?? []} home={flows.data?.home ?? st?.home ?? null}
              showFlows={showFlows && layer !== "intelligence"} animate={animate} selectedIp={selected} fitNonce={fitNonce} onSelect={select} onCountry={pickCountry} onFailure={setMapError} />

            <div className="pointer-events-none absolute left-2 top-2 flex max-w-[70%] flex-col items-start gap-1">
              {st && !st.geoip.available && <Banner tone="warn">No GeoIP database is configured, so addresses cannot be placed on the map. Run <code>scripts/fetch-geoip.sh</code> and restart the backend.</Banner>}
              {d?.partial.includes("telemetry") && <Banner tone="warn">Telemetry search is unavailable: observed and correlated figures are incomplete.</Banner>}
            </div>

            {loadingFirst && <Overlay><span className="animate-pulse" role="status">Loading map data…</span></Overlay>}
            {data.isError && !d && (
              <Overlay><div role="alert" className="space-y-2 text-center"><ErrorLine error={data.error} fallback="Could not load the threat map" /><button className="btn" onClick={() => void data.refetch()}>Retry</button></div></Overlay>
            )}
            {data.isError && d && <div role="alert" className="absolute bottom-3 left-1/2 -translate-x-1/2 rounded-lg border border-sev-critical/30 bg-panel px-3 py-1.5 text-xs text-sev-critical shadow-pop">Update failed, showing the last good data. <button className="underline" onClick={() => void data.refetch()}>Retry</button></div>}
            {mapError && <Overlay><div role="alert" className="max-w-sm text-center text-sm">The map could not be drawn ({mapError}). The rankings and panels below still work.</div></Overlay>}
            {empty && !mapError && (
              <Overlay>
                <div className="max-w-md space-y-2 text-center" data-testid="map-empty">
                  <div className="text-base font-semibold text-ink">{chips.length ? "Nothing matches these filters" : `No ${layerMeta.label.toLowerCase()} in this time range`}</div>
                  <p className="text-sm text-muted">
                    {chips.length ? "Remove a filter or widen the time range." : (layerStatus && !layerStatus.available ? layerStatus.needs : layerStatus?.error || "Try a wider time range.")}
                  </p>
                  {chips.length > 0 && <button className="btn btn-primary" onClick={() => setFilters(clearedFilters(filters))}>Clear filters</button>}
                  {layer === "observed" && d && d.internal.length > 0 && <p className="text-xs text-muted">{fmtInt(d.internal.length)} internal or non-routable addresses were seen; they have no geographic location.</p>}
                </div>
              </Overlay>
            )}
          </div>
          <Legend layer={layer} showFlows={showFlows && layer !== "intelligence"} attribution={st?.geoip.attribution} />
        </section>

        {panelOpen && selected && <div className="min-h-0 xl:h-[calc(min(58vh,620px)+98px)]"><InvestigationPanel ip={selected} filters={effective} rangeQs={rangeQs} onClose={() => { setSelected(null); }} /></div>}
      </div>
      {selected && !panelOpen && <button className="btn self-start" onClick={() => setPanelOpen(true)}>Show investigation panel ({selected})</button>}
      {selected && panelOpen && <button className="btn self-start xl:hidden" onClick={() => setPanelOpen(false)}>Collapse panel</button>}

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
        <TopCountries rows={d?.top_countries ?? []} layer={layer} onPick={pickCountry} active={filters.country} />
        <TopIps rows={d?.top_ips ?? []} layer={layer} onPick={select} selected={selected} />
        <div className="lg:col-span-2"><RecentCorrelations rows={corrRows} total={corrTotal} offset={corrOffset} setOffset={setCorrOffset} loading={corr.isFetching} onPick={select} /></div>
      </div>
      <ActivityTimeline points={d?.timeline.points ?? []} unit={d?.timeline.unit ?? ""} layer={layer} />

      {layer === "observed" && d && d.internal.length > 0 && (
        <section className="panel px-4 py-3" aria-label="Internal and non-routable addresses">
          <h2 className="eyebrow">Internal and non-routable addresses ({d.internal.length}) — not mappable</h2>
          <ul className="mt-2 grid gap-x-4 gap-y-1 text-sm md:grid-cols-2 xl:grid-cols-3">
            {d.internal.slice(0, 12).map((i) => <li key={i.ip}><button className="font-mono hover:text-accent" onClick={() => select(i.ip)}>{i.ip}</button> <span className="text-muted">{i.class} · {fmtInt(i.events)} events</span></li>)}
          </ul>
        </section>
      )}
      <datalist id="tm-categories">{["botnet_cc", "payload_delivery", "phishing", "scanner", "ransomware"].map((c) => <option key={c} value={c} />)}</datalist>
    </div>
  );
}

function Banner({ children, tone }: { children: React.ReactNode; tone?: "warn" }) {
  return <div className={`pointer-events-auto rounded-md border px-2.5 py-1.5 text-xs shadow-xs ${tone === "warn" ? "border-sev-medium/30 bg-sev-medium-bg text-sev-medium" : "border-line bg-panel text-muted"}`}>{children}</div>;
}
function Overlay({ children }: { children: React.ReactNode }) {
  return <div className="absolute inset-0 z-10 flex items-center justify-center bg-panel/75 p-6 text-muted backdrop-blur-[1px]">{children}</div>;
}

/** Legend lives under the map (not on top of it) so it never hides data. */
function Legend({ layer, showFlows, attribution }: { layer: Layer; showFlows: boolean; attribution?: string }) {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-line bg-subtle px-3 py-2 text-xs text-muted" aria-label="Map legend">
      <span className="flex items-center gap-2"><span className="font-medium text-ink-2">Severity</span>
        {([["info", "#667085"], ["low", "#2E6FE0"], ["medium", "#D58A0A"], ["high", "#E0561B"], ["critical", "#D92D20"]] as const).map(([n, c]) => <span key={n} className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full border border-white shadow-xs" style={{ background: c }} />{n}</span>)}
      </span>
      <span>Marker size = {layer === "intelligence" ? "IOC count × confidence" : "event count"}</span>
      <span>Country shade = {layer === "observed" ? "events" : layer === "correlated" ? "correlated IPs" : "reported IPs"}</span>
      {layer === "correlated" && <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-sev-critical/30 ring-1 ring-sev-critical/50" />halo = matches intelligence</span>}
      {showFlows && <span className="flex items-center gap-2"><span style={{ color: "#C2410C" }}>━ inbound</span><span style={{ color: "#0E7490" }}>━ outbound</span><span>━ external↔external</span></span>}
      <span className="ml-auto">Basemap: Natural Earth. {attribution ? `${attribution}.` : ""}</span>
    </div>
  );
}
