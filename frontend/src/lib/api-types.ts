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

// ---- cases, assets, data sources, audit (milestone 3) ------------------------------------
export type CaseSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type CasePriority = "P1" | "P2" | "P3" | "P4";
export type CaseStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE" | "CLOSED";
export const CASE_STATUSES: CaseStatus[] = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"];
export const CASE_SEVERITIES: CaseSeverity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const CASE_PRIORITIES: CasePriority[] = ["P1", "P2", "P3", "P4"];

export interface PersonRef { id: string; email: string; full_name: string }
export interface CaseOut {
  id: string; case_id: string; number: number; title: string; description: string; severity: CaseSeverity;
  priority: CasePriority; status: CaseStatus; resolution: string; assignee: PersonRef | null; hunt_id: string | null;
  created_by: string | null; created_at: string; updated_at: string; closed_at: string | null;
  evidence_count: number; ioc_count: number; asset_count: number; allowed_transitions: CaseStatus[];
}
export interface CaseCreate {
  title: string; description?: string; severity?: CaseSeverity; priority?: CasePriority; assignee_id?: string | null;
  hunt_id?: string; finding_id?: string; event_ids?: string[];
}
export interface CaseUpdate {
  title?: string; description?: string; severity?: CaseSeverity; priority?: CasePriority; assignee_id?: string; unassign?: boolean;
}
export interface CaseEvidence {
  id: string; event_id: string; comment: string; snapshot: EventDoc; summary: string; added_by: string | null; created_at: string;
}
export type IocType = "ip" | "domain" | "url" | "sha256" | "sha1" | "md5" | "email";
export const IOC_TYPES: IocType[] = ["ip", "domain", "url", "sha256", "sha1", "md5", "email"];
export interface CaseIoc { id: string; type: IocType; value: string; source: string; occurrences: number; context: string; created_at: string }
export interface CaseActivity {
  id: string; kind: string; body: string; details: Record<string, unknown>; actor_id: string | null; actor_email: string | null; created_at: string;
}
export interface CaseReport { id: string; version: number; content: string; created_by: string | null; created_at: string }
export interface CaseAssetRef { id: string; type: string; key: string; display_name: string; criticality: string; last_seen: string | null }
export interface AuditRow {
  id: string; created_at: string; action: string; outcome: string; actor: string | null; actor_id?: string | null;
  resource_type?: string | null; resource_id?: string | null; ip: string | null; request_id?: string | null; details: Record<string, unknown>;
}

export type AssetType = "host" | "server" | "user" | "ip" | "domain" | "application" | "cloud";
export const ASSET_TYPES: AssetType[] = ["host", "server", "user", "ip", "domain", "application", "cloud"];
export type Criticality = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const CRITICALITIES: Criticality[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
export interface Asset {
  id: string; type: AssetType; key: string; display_name: string; criticality: Criticality; owner: string; tags: string[];
  attributes: Record<string, unknown>; event_count: number; first_seen: string | null; last_seen: string | null; created_at: string;
}
export interface AssetCreate {
  type: AssetType; key: string; display_name?: string; criticality?: Criticality; owner?: string; tags?: string[];
}
export interface AssetUpdate { display_name?: string; criticality?: Criticality; owner?: string; tags?: string[] }
export interface AssetEvents { total: number; hits: EventDoc[] }
export type AssetRelated = Record<string, Array<{ key: string | number; count: number }>>;
export interface AssetCaseRef { id: string; number: number; title: string; status: string; severity: string }

export interface ConnectorInfo { type: string; display_name: string; supports_collect: boolean; config_schema: JsonSchema }
export interface JsonSchema {
  type?: string; title?: string; description?: string; properties?: Record<string, JsonSchemaProp>; required?: string[];
  $defs?: Record<string, JsonSchema>;
}
export interface JsonSchemaProp {
  type?: string; title?: string; description?: string; default?: unknown; enum?: unknown[]; format?: string; pattern?: string;
  anyOf?: JsonSchemaProp[]; $ref?: string; minimum?: number; maximum?: number; exclusiveMinimum?: number;
}
export interface DataSource {
  id: string; name: string; connector_type: string; config: Record<string, unknown>; has_secrets: boolean; secret_keys: string[];
  enabled: boolean; supports_collect: boolean; health_status: string; health_detail: string; health_checked_at: string | null;
  last_ingest_at: string | null; events_total: number; created_at: string; ingest_key?: string | null;
}
export interface DataSourceCreate {
  name: string; connector_type: string; config: Record<string, unknown>; secrets: Record<string, string>; enabled: boolean;
}

// ---- threat intelligence ---------------------------------------------------------------------------
export type EntityType = "ip" | "domain" | "url" | "sha256" | "sha1" | "md5" | "email" | "certificate" | "malware" | "threat_actor" | "campaign";
export const ENTITY_TYPES: EntityType[] = ["ip", "domain", "url", "sha256", "sha1", "md5", "email", "certificate", "malware", "threat_actor", "campaign"];
export type Verdict = "unknown" | "benign" | "suspicious" | "malicious";
export type WatchVerdict = "malicious" | "suspicious" | "benign";
export interface IntelEntity {
  id: string; type: EntityType; value: string; verdict: Verdict; score: number; watch_verdict: WatchVerdict | null;
  watch_confidence: number; notes: string; tags: string[]; source: string; last_enriched_at: string | null;
  created_at: string; updated_at: string;
}
export interface ScoreSignal { provider: string; verdict: string; confidence: number; weight: number; contribution: number; summary: string }
export interface IntelObservation {
  provider: string; status: "ok" | "not_found" | "error" | "unavailable"; verdict: string; confidence: number; summary: string;
  data: Record<string, unknown>; fetched_at: string;
}
export interface IntelRelation { id: string; kind: string; direction: "out" | "in"; other: IntelEntity; source: string }
export interface IntelCoverage { answered: number; failed: number; not_found: number; skipped: Array<{ provider: string; reason: string }> }
export interface IntelDetail {
  entity: IntelEntity; score_breakdown: ScoreSignal[]; observations: IntelObservation[]; relations: IntelRelation[];
  coverage: IntelCoverage | null;
}
export interface IntelProvider {
  key: string; display_name: string; description: string; supported_types: string[]; offline: boolean; secret_keys: string[];
  config_schema: JsonSchema; configured: boolean; enabled: boolean; last_status: string; last_detail: string; last_checked_at: string | null;
}
export interface Sightings {
  total: number; by_field: Record<string, number>; days: number; hosts: Array<{ key: string; count: number }>;
  first_seen: string | null; last_seen: string | null; recent: EventDoc[];
}
export interface LookupBody { value: string; type?: EntityType; refresh?: boolean; providers?: string[] }
export interface EntityUpdate {
  watch_verdict?: WatchVerdict; clear_watch?: boolean; watch_confidence?: number; notes?: string; tags?: string[];
}
export interface BatchVerdict { type: string; value: string; entity_id: string | null; verdict: Verdict | null; score: number | null }
export interface EnrichCaseResult {
  checked: number; malicious: number; results: Array<{ type: string; value: string; verdict: Verdict; score: number; entity_id: string }>;
}
export interface StixImportResult { created: number; updated: number; named_objects: number; relations: number; skipped: number }

// ---- MITRE ATT&CK ----------------------------------------------------------------------------------
export type Confidence = "LOW" | "MEDIUM" | "HIGH";
export const CONFIDENCES: Confidence[] = ["LOW", "MEDIUM", "HIGH"];
export type MitreObjectType = "hunt" | "case" | "finding" | "detection";
export interface MitreTactic { id: string; shortname: string; name: string; position: number }
export interface MitreTechnique {
  id: string; name: string; parent_id: string | null; is_subtechnique: boolean; tactics: string[]; description: string; url: string; source: string;
  subtechniques?: MitreTechnique[];
}
export interface MatrixTechnique { id: string; name: string; mapping_count: number; top_confidence: Confidence | null; subtechniques: MatrixTechnique[] }
export interface MatrixColumn { tactic: MitreTactic; techniques: MatrixTechnique[] }
export interface MitreSuggestion {
  technique_id: string; name: string; tactics: string[]; confidence: Confidence; reasoning: string[]; event_ids: string[];
  event_count: number; hosts: string[]; users: string[]; mapped: boolean;
}
export interface SuggestResponse { analyzed_events: number; suggestions: MitreSuggestion[] }
export interface MitreMapping {
  id: string; technique_id: string; technique_name: string; tactics: string[]; object_type: MitreObjectType; object_id: string;
  confidence: Confidence; reasoning: string; evidence_event_ids: string[]; evidence_count: number; source: string;
  created_by: string | null; created_at: string;
}
export interface MappingCreate {
  technique_id: string; object_type: MitreObjectType; object_id: string; confidence: Confidence; reasoning: string;
  evidence_event_ids: string[]; source: "analyst" | "suggestion";
}
export interface TechniqueSummary {
  technique: MitreTechnique; mappings: number; objects: Array<{ object_type: string; object_id: string; title: string; confidence: Confidence }>;
  evidence_events: number; hosts: { count: number; names: string[] }; users: { count: number; names: string[] };
  risk: "HIGH" | "MEDIUM" | "LOW"; risk_reasons: string[];
}
