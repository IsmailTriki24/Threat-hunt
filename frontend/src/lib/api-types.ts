export type Op =
  | "eq" | "neq" | "in" | "exists" | "not_exists" | "prefix" | "contains" | "gt" | "gte" | "lt" | "lte";

export interface Filter {
  field: string;
  op: Op;
  value?: string | number | boolean | Array<string | number> | null;
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
