import { defang } from "./cases";

export interface IocItem {
  id: string; source: string; type: string; value: string; confidence: number; first_seen: string; last_seen: string; valid_until: string | null;
  threat_type: string; malware: string; description: string; reference: string; tags: string[]; techniques: string[]; status: string;
  status_reason: string; seen_count: number; validated_at: string | null; case_id: string | null; last_hunted_at: string | null;
}
export interface IocPage { total: number; items: IocItem[]; facets: Record<string, Record<string, number>> }
export interface IocFeed {
  id: string; name: string; feed_type: string; config: Record<string, unknown>; has_secrets: boolean; secret_keys: string[]; enabled: boolean;
  interval_minutes: number; max_age_days: number; min_confidence: number; max_items: number; last_run_at: string | null; last_status: string;
  last_detail: string; last_new: number; last_seen_total: number; ioc_count: number;
}
export interface FeedType { type: string; name: string; description: string; needs_secret: boolean; secret_names: string[]; config_schema: Record<string, unknown> }
export interface Coverage { source: string; kind: string; status: string; detail: string; iocs_searched: number; hits: number; ms: number }
export interface IocMatch { id: string; ioc_id: string; ioc_value: string; ioc_type: string; event_id: string; event_timestamp: string; source: string; matched_field: string; host: string; user: string; summary: string }
export interface IocHunt {
  id: string; name: string; hypothesis: string; mode: string; status: string; lookback_days: number; window_start: string | null; window_end: string | null;
  ioc_count: number; case_id: string | null; case_number: number | null; case_status: string | null; hunt_id: string | null; match_count: number;
  new_match_count: number; coverage: Coverage[]; error: string; created_at: string; started_at: string | null; finished_at: string | null;
  threat_id?: string | null; threat_name?: string | null; signal_count?: number;
}
export interface IocHuntDetail extends IocHunt { matches: IocMatch[]; signal_matches: SignalMatch[] }
export interface IocOverview {
  threats_by_status?: Record<string, number>; new_threats_24h?: number;
  iocs_by_status: Record<string, number>; new_last_24h: number; seen_in_environment: number; feeds: number; feeds_failing: number;
  hunts_by_status: Record<string, number>; open_ioc_cases: number;
}
export interface AllowEntry { id: string; type: string; value: string; reason: string; created_at: string }

export const IOC_TYPES = ["ip", "domain", "url", "sha256", "sha1", "md5", "email"] as const;
export const defangIoc = (type: string, value: string): string => defang(type, value);

/** Plain-language age ("3h", "2d") used in the queue so staleness is obvious at a glance. */
export function age(iso: string, now: number = Date.now()): string {
  const m = Math.max(0, Math.round((now - new Date(iso).getTime()) / 60000));
  if (m < 60) return `${m}m`;
  if (m < 60 * 48) return `${Math.round(m / 60)}h`;
  return `${Math.round(m / 1440)}d`;
}

/** Hunt status chips: always shown with their text label, so colour is reinforcement and not the signal. */
export const HUNT_STATUS_CLASS: Record<string, string> = {
  PENDING: "badge border-line-strong bg-subtle text-muted", RUNNING: "badge border-sev-low/30 bg-sev-low-bg text-sev-low",
  COMPLETED: "badge border-sev-ok/30 bg-sev-ok-bg text-sev-ok", PARTIAL: "badge border-sev-high/30 bg-sev-high-bg text-sev-high",
  FAILED: "badge border-sev-critical/30 bg-sev-critical-bg text-sev-critical",
};

export const COVERAGE_CLASS: Record<string, string> = { ok: "text-sev-ok font-medium", truncated: "text-sev-high font-medium", skipped: "text-sev-high font-medium", "n/a": "text-muted", error: "text-sev-critical font-medium" };

/** What the admin is about to commit to: shown in the confirmation so a validation is never a blind click. */
export function validationSummary(items: IocItem[]): string {
  const types = [...new Set(items.map((i) => i.type))].join(", ");
  const seen = items.filter((i) => i.seen_count > 0).length;
  const sources = [...new Set(items.map((i) => i.source))].join(", ");
  return `${items.length} indicator(s) (${types}) from ${sources}` + (seen ? `; ${seen} already appear in your telemetry` : "");
}

export function selectable(i: IocItem): boolean {
  return i.status === "NEW" || i.status === "REJECTED";
}


export interface ThreatRow {
  id: string; name: string; kind: string; aliases: string[]; mitre_id: string; severity: string; confidence: number; status: string;
  first_seen: string | null; last_updated: string | null; ioc_count: number; ioc_types: Record<string, number>; new_ioc_count: number;
  ioa_count: number; ttp_count: number; seen_count: number; sources: string[]; case_id: string | null; case_number: number | null;
  case_status: string | null; last_hunted_at: string | null;
}
export interface ThreatPage { total: number; items: ThreatRow[]; facets: Record<string, Record<string, number>> }
export interface Ttp { technique_id: string; name: string; tactics: string[]; url: string; source: string; confidence: string; note: string }
export interface Ioa { id: string; name: string; description: string; technique_id: string; severity: string; source: string; query_text: string; trend_query: string; rule_id: string | null }
export interface Bulletin extends ThreatRow { description: string; references: string[]; status_reason: string; ttps: Ttp[]; ioas: Ioa[]; iocs: IocItem[]; hunts: IocHunt[] }
export interface SignalMatch { id: string; kind: string; ref: string; label: string; event_id: string; event_timestamp: string; source: string; host: string; user: string; summary: string }

export const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "badge border-sev-critical/30 bg-sev-critical-bg text-sev-critical", HIGH: "badge border-sev-high/30 bg-sev-high-bg text-sev-high", MEDIUM: "badge border-sev-medium/30 bg-sev-medium-bg text-sev-medium",
  LOW: "badge border-sev-low/30 bg-sev-low-bg text-sev-low", INFO: "badge border-sev-info/25 bg-sev-info-bg text-sev-info",
};
export const KIND_LABEL: Record<string, string> = { malware: "Malware", actor: "Threat actor", campaign: "Campaign", report: "Report", other: "Other" };
export const TTP_SOURCE_NOTE: Record<string, string> = {
  mitre: "Documented by MITRE ATT&CK", feed: "Declared by the intelligence feed", derived: "Inferred from the indicator's role", manual: "Added by an analyst",
};

/** "12 ip · 3 domain" — the composition of a bulletin at a glance, largest first. */
export function typeBreakdown(types: Record<string, number>): string {
  return Object.entries(types).sort((a, b) => b[1] - a[1]).map(([t, n]) => `${n} ${t}`).join(" · ");
}

/** What validating this bulletin will hunt, spelled out for the confirmation panel. */
export function bulletinPlan(b: Pick<Bulletin, "ioc_count" | "new_ioc_count" | "ioa_count" | "ttp_count">, excludedIocs: number, excludedIoas: number, withSignals: boolean, batch = 500): string {
  const pending = Math.max(0, (b.new_ioc_count || b.ioc_count) - excludedIocs);
  const now = Math.min(pending, batch);
  const parts = [`${pending} indicator(s)` + (pending > now ? ` (${now} highest-priority now, the rest in follow-up batches)` : "")];
  if (withSignals) parts.push(`${Math.max(0, b.ioa_count - excludedIoas)} behaviour(s)`, `${b.ttp_count} technique(s)`);
  return parts.join(", ");
}
