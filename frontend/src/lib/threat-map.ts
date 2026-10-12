/** Threat map: types for /api/v1/threat-map, filter state <-> query string, and the small pure helpers the map and panels share. */

import { fieldSearchHref } from "./global-search";

export type Layer = "intelligence" | "observed" | "correlated";
export type RangeKey = "1h" | "24h" | "7d" | "30d" | "custom";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Scope = "any" | "external" | "internal";

export const LAYERS: Array<{ key: Layer; label: string; blurb: string; color: string }> = [
  { key: "intelligence", label: "Global threat intelligence", blurb: "Indicators your feeds report. Reported, not confirmed against you.", color: "#B7791F" },
  { key: "observed", label: "Observed network activity", blurb: "Addresses seen in your own telemetry.", color: "#7568E9" },
  { key: "correlated", label: "Correlated threats", blurb: "Observed activity that matches intelligence or an IOC hunt.", color: "#D92D20" },
];
export const LAYER_COLOR: Record<Layer, string> = { intelligence: "#B7791F", observed: "#7568E9", correlated: "#D92D20" };
export const RANGES: Array<{ key: RangeKey; label: string }> = [
  { key: "1h", label: "1 h" }, { key: "24h", label: "24 h" }, { key: "7d", label: "7 d" }, { key: "30d", label: "30 d" }, { key: "custom", label: "Custom" },
];
export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
export const SEVERITY_COLOR: Record<Severity, string> = { info: "#667085", low: "#2E6FE0", medium: "#D58A0A", high: "#E0561B", critical: "#D92D20" };
export const SEVERITY_TEXT: Record<string, string> = {
  info: "text-sev-info", low: "text-sev-low", medium: "text-sev-medium", high: "text-sev-high", critical: "text-sev-critical",
};
export const CONTINENTS: Array<[string, string]> = [["AF", "Africa"], ["AN", "Antarctica"], ["AS", "Asia"], ["EU", "Europe"], ["NA", "North America"], ["OC", "Oceania"], ["SA", "South America"]];
export const IOC_FILTER_TYPES = ["ip", "domain", "url", "sha256", "sha1", "md5", "email"];

export interface Geo {
  country: string; country_name: string; continent: string; city: string; region: string; lat: number | null; lon: number | null; asn: number | null; org: string;
}
export interface IntelSummary {
  iocs: number; confidence: number; severity: Severity; sources: string[]; threat_types: string[]; malware: string[]; threats: string[]; tags: string[];
  statuses: string[]; first_seen: string | null; last_seen: string | null; stale: boolean; references: string[]; ioc_ids: string[];
}
export interface Activity {
  events: number; as_source: number; as_destination: number; as_signin_source: number; first_seen: string | null; last_seen: string | null;
  max_severity: Severity; sources: string[]; ports: number[];
}
export interface MapMarker {
  ip: string; geo: Geo | null; layers: Layer[]; severity: Severity; weight: number; last_seen: string | null;
  intel: IntelSummary | null; observed: Activity | null; hunt_matches: number;
}
export interface CountryRow { iso: string; name: string; ips: number; events: number; correlated: number; iocs: number; value: number }
export interface Correlation {
  id: string; kind: "ip_match" | "hunt_match"; ip: string; ioc_type: string; ioc_value: string; reason: string; source: string; confidence: number;
  severity: Severity; threat: string; first_seen: string | null; last_seen: string | null; events: number; event_ids: string[]; host: string;
  matched_field: string; status: string; case_id: string | null; country: string | null; ioc_ids: string[];
  case?: { id: string; case_id: string; title: string; status: string } | null;
}
export interface InternalAddr extends Activity { ip: string; class: string }
export interface MapData {
  layer: Layer; range: { start: string; end: string }; active_filters: Record<string, unknown>;
  cards: {
    unique_malicious_ips: number; countries_with_indicators: number; top_indicator_country: { iso: string; name: string; ips: number } | null;
    observed_events: number | null; observed_remote_ips: number | null; internal_addresses: number;
    correlated_threats: number | null; correlated_ips: number | null; high_severity_detections: number;
  };
  countries: CountryRow[]; markers: MapMarker[]; unlocated: number; truncated: boolean; total_markers: number;
  top_countries: CountryRow[]; top_ips: MapMarker[]; internal: InternalAddr[]; recent_correlations: Correlation[]; partial: string[];
  timeline: { points: Array<{ t: string; count: number }>; unit: string; layer: Layer }; notes: string[]; generated_at: string;
}
export interface FlowEnd { ip: string; class: string; lat: number; lon: number; country: string; city: string }
export interface Flow {
  src: FlowEnd; dst: FlowEnd; direction: "inbound" | "outbound" | "external"; events: number; first_seen: string | null; last_seen: string | null;
  severity: Severity; ports: number[]; sources: string[]; protocols: string[];
}
export interface Home { lat: number; lon: number; label: string }
export interface FlowsResponse { flows: Flow[]; home: Home | null; reason: string; note?: string }
export interface LayerStatus { available: boolean; needs: string; feeds?: string[]; sources?: Array<{ source: string; events: number }>; error?: string }
export interface MapStatus {
  geoip: { provider: string; available: boolean; asn: boolean; attribution: string; built_epoch?: number };
  home: Home | null; layers: Record<Layer, LayerStatus>; mappable_ioc_types: string[]; disclaimer: string;
}
export interface IndicatorIoc {
  id: string; source: string; confidence: number; severity: Severity; threat_type: string; malware: string; threat: string; threat_id: string | null; tags: string[];
  first_seen: string; last_seen: string; status: string; description: string; reference: string; case_id: string | null; stale: boolean;
}
export interface IndicatorDetail {
  ip: string; class: string; geo: Geo | null; geo_note: string; intel: IndicatorIoc[];
  related_iocs: Array<{ id: string; type: string; value: string; confidence: number; source: string }>;
  observed: Activity | null;
  events: Array<{ id: string; timestamp: string; source: string; event_type: string; severity: number; summary: string; src_ip: string | null; dst_ip: string | null; dst_port: number | null; protocol: string | null; host: string | null }>;
  events_total: number; peers: Array<{ src_ip: string; dst_ip: string; events: number; last_seen: string | null; ports: number[]; sources: string[] }>;
  hunt_matches: Array<{ ioc_type: string; ioc_value: string; event_id: string; timestamp: string; matched_field: string; host: string }>;
  alerts: Array<{ id: string; rule: string; severity: string; status: string; event_id: string; timestamp: string }>;
  cases: Array<{ id: string; case_id: string; title: string; status: string }>;
  correlated: boolean; correlation_reason: string;
  actions: { investigate: boolean; intel_lookup: boolean; hunt: boolean; add_to_watchlist: boolean; add_to_case: boolean };
}

// ---- filter state ---------------------------------------------------------------------------------------
export interface MapFilters {
  layer: Layer; range: RangeKey; start: string; end: string; country: string[]; continent: string; iocType: string; severity: Severity;
  minConfidence: number; category: string; source: string[]; logSource: string[]; scope: Scope; q: string;
}
export const defaultFilters = (): MapFilters => ({
  layer: "intelligence", range: "24h", start: "", end: "", country: [], continent: "", iocType: "", severity: "info", minConfidence: 0,
  category: "", source: [], logSource: [], scope: "any", q: "",
});

/** Query string for the API. Only non-default values are sent, so the URL (and the server's `active_filters`) stay meaningful. */
export function toParams(f: MapFilters): URLSearchParams {
  const p = new URLSearchParams({ layer: f.layer, range: f.range });
  if (f.range === "custom") { p.set("start", new Date(f.start).toISOString()); p.set("end", new Date(f.end).toISOString()); }
  if (f.country.length) p.set("country", f.country.join(","));
  if (f.continent) p.set("continent", f.continent);
  if (f.iocType) p.set("ioc_type", f.iocType);
  if (f.severity !== "info") p.set("severity", f.severity);
  if (f.minConfidence > 0) p.set("min_confidence", String(f.minConfidence));
  if (f.category.trim()) p.set("category", f.category.trim());
  if (f.source.length) p.set("source", f.source.join(","));
  if (f.logSource.length) p.set("log_source", f.logSource.join(","));
  if (f.scope !== "any") p.set("scope", f.scope);
  if (f.q.trim()) p.set("q", f.q.trim());
  return p;
}

export function customRangeError(f: MapFilters): string | null {
  if (f.range !== "custom") return null;
  const s = Date.parse(f.start), e = Date.parse(f.end);
  if (Number.isNaN(s) || Number.isNaN(e)) return "Pick a start and an end";
  if (e <= s) return "End must be after start";
  if (e - s > 90 * 86_400_000) return "Range is limited to 90 days";
  return null;
}

export interface Chip { key: string; label: string; clear: Partial<MapFilters> }
/** One removable chip per active filter (the time range and layer are always visible controls, not filters). */
export function activeChips(f: MapFilters): Chip[] {
  const chips: Chip[] = [];
  if (f.q.trim()) chips.push({ key: "q", label: `Search: ${f.q.trim()}`, clear: { q: "" } });
  if (f.country.length) chips.push({ key: "country", label: `Country: ${f.country.join(", ")}`, clear: { country: [] } });
  if (f.continent) chips.push({ key: "continent", label: `Region: ${CONTINENTS.find(([c]) => c === f.continent)?.[1] ?? f.continent}`, clear: { continent: "" } });
  if (f.iocType) chips.push({ key: "iocType", label: `IOC type: ${f.iocType}`, clear: { iocType: "" } });
  if (f.severity !== "info") chips.push({ key: "severity", label: `Severity ≥ ${f.severity}`, clear: { severity: "info" } });
  if (f.minConfidence > 0) chips.push({ key: "minConfidence", label: `Confidence ≥ ${f.minConfidence}`, clear: { minConfidence: 0 } });
  if (f.category.trim()) chips.push({ key: "category", label: `Category: ${f.category.trim()}`, clear: { category: "" } });
  if (f.source.length) chips.push({ key: "source", label: `Feed: ${f.source.join(", ")}`, clear: { source: [] } });
  if (f.logSource.length) chips.push({ key: "logSource", label: `Telemetry: ${f.logSource.join(", ")}`, clear: { logSource: [] } });
  if (f.scope !== "any") chips.push({ key: "scope", label: `Scope: ${f.scope}`, clear: { scope: "any" } });
  return chips;
}
export const clearedFilters = (f: MapFilters): MapFilters => ({ ...defaultFilters(), layer: f.layer, range: f.range, start: f.start, end: f.end });

// ---- presentation helpers -------------------------------------------------------------------------------
export const fmtInt = (n: number | null | undefined): string => (n === null || n === undefined ? "—" : n.toLocaleString("en-US"));

export function fmtTs(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().slice(0, 16).replace("T", " ") + "Z";
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (Number.isNaN(s)) return "—";
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 129_600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86_400)}d ago`;
}

/** Defang for sharing in tickets/chat so a pasted indicator cannot be clicked: 1.2.3.4 -> 1[.]2[.]3[.]4 */
export const defang = (ip: string): string => ip.replace(/\./g, "[.]").replace(/:/g, "[:]");

export function flagEmoji(iso: string): string {
  if (!/^[A-Z]{2}$/.test(iso)) return "";
  return String.fromCodePoint(...[...iso].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

export interface RoleLink { key: "dst" | "src" | "auth"; label: string; count: number; href: string }

/** Event searches for an address, one per role it plays (the hunt query language cannot OR across fields). Only roles with events are listed;
 *  with no observation at all the default (destination) search is returned so "Investigate" still works. Sorted busiest-first. */
export function ipRoleLinks(ip: string, range: RangeKey, start: string, end: string, observed: Pick<Activity, "as_source" | "as_destination" | "as_signin_source"> | null): RoleLink[] {
  const win = { range, start, end };
  const all: RoleLink[] = [
    { key: "dst", label: "As destination", count: observed?.as_destination ?? 0, href: fieldSearchHref("network.dst_ip", ip, win) },
    { key: "src", label: "As source", count: observed?.as_source ?? 0, href: fieldSearchHref("network.src_ip", ip, win) },
    { key: "auth", label: "As sign-in source", count: observed?.as_signin_source ?? 0, href: fieldSearchHref("auth.source_ip", ip, win) },
  ];
  const present = all.filter((r) => r.count > 0).sort((a, b) => b.count - a.count);
  return present.length ? present : [all[0]];
}

/** Great-circle path between two points as [lon, lat] samples. Longitudes are unwrapped so the line never jumps across the map. */
export function arcPoints(a: [number, number], b: [number, number], steps = 48): Array<[number, number]> {
  const rad = Math.PI / 180;
  const [lo1, la1, lo2, la2] = [a[0] * rad, a[1] * rad, b[0] * rad, b[1] * rad];
  const d = 2 * Math.asin(Math.sqrt(Math.sin((la2 - la1) / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin((lo2 - lo1) / 2) ** 2));
  if (!Number.isFinite(d) || d < 1e-6) return [a, b];
  const pts: Array<[number, number]> = [];
  let prev = a[0];
  for (let i = 0; i <= steps; i++) {
    const f = i / steps;
    const A = Math.sin((1 - f) * d) / Math.sin(d), B = Math.sin(f * d) / Math.sin(d);
    const x = A * Math.cos(la1) * Math.cos(lo1) + B * Math.cos(la2) * Math.cos(lo2);
    const y = A * Math.cos(la1) * Math.sin(lo1) + B * Math.cos(la2) * Math.sin(lo2);
    const z = A * Math.sin(la1) + B * Math.sin(la2);
    let lon = Math.atan2(y, x) / rad;
    const lat = Math.atan2(z, Math.sqrt(x * x + y * y)) / rad;
    while (lon - prev > 180) lon -= 360;
    while (lon - prev < -180) lon += 360;
    prev = lon;
    pts.push([lon, lat]);
  }
  return pts;
}

/** Fill colour per country for the choropleth: sqrt-scaled so one very busy country does not flatten the rest. */
/** Country fill with no data. */
export const LAND = "#F6F7FB";

export function choroplethExpression(rows: CountryRow[], layer: Layer): unknown {
  const max = Math.max(0, ...rows.map((r) => r.value));
  const ramp = { intelligence: ["#FCF4E0", "#E3AE4B"], observed: ["#EFECFD", "#8E83EE"], correlated: ["#FDEDEB", "#E8756B"] }[layer];
  const mix = (t: number): string => {
    const h = (s: string, i: number) => parseInt(s.slice(1 + i * 2, 3 + i * 2), 16);
    const c = [0, 1, 2].map((i) => Math.round(h(ramp[0], i) + (h(ramp[1], i) - h(ramp[0], i)) * t));
    return `rgb(${c[0]},${c[1]},${c[2]})`;
  };
  if (!max) return LAND;
  const expr: unknown[] = ["match", ["get", "iso"]];
  for (const r of rows) if (r.value > 0 && r.iso) expr.push(r.iso, mix(0.16 + 0.84 * Math.pow(r.value / max, 0.7)));
  expr.push(LAND);
  return expr.length <= 4 ? LAND : expr;
}

export function markerRadius(weight: number, maxWeight: number): number {
  if (maxWeight <= 0) return 5;
  return 4 + 6 * Math.sqrt(Math.max(0, weight) / maxWeight);
}

export function timelineMax(points: Array<{ count: number }>): number {
  return Math.max(1, ...points.map((p) => p.count));
}
