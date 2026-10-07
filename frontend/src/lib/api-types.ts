export type Op =
  | "eq" | "neq" | "in" | "exists" | "not_exists" | "prefix" | "contains" | "gt" | "gte" | "lt" | "lte";

export interface Filter {
  field: string;
  op: Op;
  value?: string | number | boolean | Array<string | number> | null;
  negate?: boolean;
}

export interface TenantRef { id: string; slug: string; name: string }

export interface SessionInfo {
  user_id: string;
  email: string;
  full_name: string;
  role: string;
  permissions: string[];
  tenant: TenantRef | null;
  available_tenants: TenantRef[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  session: SessionInfo;
}

export interface TimeRangeBody { start: string; end: string }

export interface Aggregation {
  name: string;
  type?: "terms" | "date_histogram";
  field?: string;
  size?: number;
}

export interface EventQueryBody {
  q?: string;
  /** Hunt query language source; parsed and validated server-side. */
  text?: string;
  time_range: TimeRangeBody;
  filters: Filter[];
  sort: Array<{ field: string; order: "asc" | "desc" }>;
  offset: number;
  limit: number;
  aggregations: Aggregation[];
}

export interface Bucket { key: string | number; count: number }

export interface SearchResult {
  total: number;
  total_relation: "eq" | "gte";
  took_ms: number;
  hits: EventDoc[];
  aggregations: Record<string, { buckets: Bucket[] }>;
  time_range: TimeRangeBody;
}

export interface Hashes { md5?: string; sha1?: string; sha256?: string }

export interface EventDoc {
  id: string;
  timestamp: string;
  source: string;
  event_type: string;
  action?: string;
  outcome?: string;
  severity?: number;
  message?: string;
  host?: { id?: string; hostname?: string; ip?: string[]; os?: string };
  user?: { id?: string; name?: string; domain?: string };
  process?: {
    name?: string; pid?: number; executable?: string; command_line?: string; hash?: Hashes;
    parent?: { name?: string; pid?: number; command_line?: string };
  };
  network?: {
    protocol?: string; direction?: string; src_ip?: string; src_port?: number;
    dst_ip?: string; dst_port?: number; dst_domain?: string; bytes?: number;
  };
  dns?: { question?: string; query_type?: string; answers?: string[] };
  file?: { name?: string; path?: string; hash?: Hashes };
  auth?: { logon_type?: string; method?: string; source_ip?: string };
  registry?: { key?: string; value?: string };
  tags?: string[];
  labels?: Record<string, string>;
  raw?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface FieldInfo { name: string; kind: "keyword" | "text" | "ip" | "integer" | "long" | "date"; sortable: boolean; aggregatable: boolean }

export interface Pivot { label: string; field: string; value: string | number; entity: string }
export interface EventDetail { event: EventDoc; pivots: Pivot[] }

export interface MemberOut {
  user_id: string; email: string; full_name: string; role: string; is_active: boolean; last_login_at: string | null;
}
export interface TenantOut {
  id: string; slug: string; name: string; is_active: boolean; retention_days: number; created_at: string;
}
export interface UserCreate { email: string; full_name: string; password: string; role: string }

export interface ReadyResponse {
  status: string;
  components: Record<string, { status: string; cluster_status?: string }>;
}

export interface ApiErrorBody { error: { code: string; message: string; request_id?: string | null; details?: unknown } }

// ---- hunts (milestone 2) -------------------------------------------------------------
export type HuntStatus = "DRAFT" | "ACTIVE" | "COMPLETED" | "ARCHIVED";
export type FindingSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Hunt {
  id: string; title: string; hypothesis: string; status: HuntStatus;
  time_start: string | null; time_end: string | null; data_sources: string[]; conclusion: string;
  created_by: string | null; created_at: string; updated_at: string; finding_count: number; query_count: number;
}
export interface HuntCreate {
  title: string; hypothesis?: string; status?: HuntStatus; time_start?: string; time_end?: string; data_sources?: string[];
}
export type HuntUpdate = Partial<Pick<Hunt, "title" | "hypothesis" | "status" | "conclusion" | "data_sources">> & {
  time_start?: string | null; time_end?: string | null;
};
export interface SavedQuery {
  id: string; name: string; description: string; hunt_id: string | null; query: Partial<EventQueryBody>;
  created_by: string | null; created_at: string;
}
export interface HistoryEntry {
  id: string; hunt_id: string | null; query: Partial<EventQueryBody>; total: number; took_ms: number; executed_at: string;
}
export interface Evidence { id: string; timestamp: string; summary: string; host?: string | null }
export interface Finding {
  id: string; hunt_id: string; title: string; description: string; severity: FindingSeverity;
  evidence: Evidence[]; created_by: string | null; created_at: string;
}
export interface FindingCreate { title: string; description?: string; severity: FindingSeverity; event_ids: string[] }
export interface Note { id: string; hunt_id: string; body: string; author_id: string | null; created_at: string }
export interface ParsedQuery { q: string | null; filters: Filter[] }

export interface Periodicity { median_interval_s: number; jitter_pct: number }
export interface TimelineEntry {
  id: string; timestamp: string; end_timestamp: string | null; count: number; event_type: string; title: string;
  severity: number; host: string | null; user: string | null; process: string | null; pid: number | null;
  destination: string | null; parent_event_id: string | null; process_event_id: string | null;
  event_ids: string[]; periodicity: Periodicity | null;
}
export interface Timeline { entries: TimelineEntry[]; total_events: number; truncated: boolean }
export type TimelineScope = "host" | "user" | "host_user";
