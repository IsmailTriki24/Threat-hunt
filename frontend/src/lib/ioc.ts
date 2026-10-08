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
}
export interface IocHuntDetail extends IocHunt { matches: IocMatch[] }
export interface IocOverview {
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

export const HUNT_STATUS_CLASS: Record<string, string> = {
  PENDING: "text-muted border border-line", RUNNING: "bg-blue-900/50 text-blue-200", COMPLETED: "bg-green-900/40 text-green-300",
  PARTIAL: "bg-orange-900/50 text-orange-300", FAILED: "bg-red-900/60 text-red-200",
};

export const COVERAGE_CLASS: Record<string, string> = { ok: "text-green-300", truncated: "text-orange-300", skipped: "text-muted", error: "text-red-400" };

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
