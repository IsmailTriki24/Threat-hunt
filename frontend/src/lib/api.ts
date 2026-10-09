import type { AllowEntry, Bulletin, FeedType, Ioa, IocFeed, IocHunt, IocHuntDetail, IocItem, IocOverview, IocPage, ThreatPage, Ttp } from "./ioc";
import type { AiRun, AiRunBody, AiStatus } from "./ai";
import type { EvPoint } from "./ai-stream";
import type { Alert, AlertStatus, Backtest, DetectionOverview, Rule, RuleStatus, TestCase, TestResult } from "./detections";
import type {
  EventDetail, EventQueryBody, FieldInfo, MemberOut, ReadyResponse, SearchResult, TenantOut, TokenResponse,
  UserCreate, ApiErrorBody, Finding, FindingCreate, HistoryEntry, Hunt, HuntCreate, HuntUpdate, Note, ParsedQuery,
  SavedQuery, Timeline, TimelineScope,
  Asset, AssetCaseRef, AssetCreate, AssetEvents, AssetRelated, AssetUpdate, AuditRow, CaseActivity, CaseAssetRef, CaseCreate,
  CaseEvidence, CaseIoc, CaseOut, CaseReport, CaseUpdate, ConnectorInfo, DataSource, DataSourceCreate, IocType,
  BatchVerdict, EnrichCaseResult, EntityUpdate, IntelDetail, IntelEntity, IntelProvider, LookupBody, Sightings, StixImportResult,
  MappingCreate, MatrixColumn, MitreMapping, MitreTactic, MitreTechnique, SuggestResponse, TechniqueSummary,
} from "./api-types";

const CSRF = { "X-Requested-With": "threat-hunt" };

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string | null) {
    super(message);
    this.name = "ApiError";
  }

  /** Human-friendly message for common statuses. */
  get friendly(): string {
    if (this.status === 403) return "You do not have permission to do that.";
    if (this.status === 429) return "Rate limit reached. Wait a moment and try again.";
    if (this.status === 401) return "Your session has expired. Please sign in again.";
    return this.message;
  }
}

// Access token lives in module memory only: never localStorage/sessionStorage/cookies.
let accessToken: string | null = null;
let onSessionLost: (() => void) | null = null;
let refreshing: Promise<TokenResponse | null> | null = null;

export const setAccessToken = (t: string | null): void => { accessToken = t; };
export const getAccessToken = (): string | null => accessToken;
export const setSessionLostHandler = (fn: (() => void) | null): void => { onSessionLost = fn; };

/** 422 validation errors carry per-field `details`; surface their messages (e.g. `query text: unknown field`). */
export function errorMessage(e: ApiErrorBody["error"] | undefined, status: number): string {
  const details = Array.isArray(e?.details) ? (e?.details as Array<{ msg?: string }>) : [];
  const msgs = details.map((d) => (d.msg ?? "").replace(/^Value error, /, "")).filter(Boolean);
  if (msgs.length) return msgs.slice(0, 3).join("; ");
  return e?.message ?? `Request failed (${status})`;
}

async function parseError(res: Response): Promise<ApiError> {
  let body: Partial<ApiErrorBody> | null = null;
  try { body = (await res.json()) as ApiErrorBody; } catch { /* non-JSON error */ }
  const e = body?.error;
  return new ApiError(res.status, e?.code ?? "http_error", errorMessage(e, res.status), e?.request_id);
}

/** Single-flight refresh using the httpOnly cookie. Resolves null if the session cannot be restored. */
export function refreshSession(): Promise<TokenResponse | null> {
  refreshing ??= (async () => {
    try {
      const res = await fetch("/api/v1/auth/refresh", { method: "POST", headers: CSRF, credentials: "same-origin" });
      if (!res.ok) { accessToken = null; return null; }
      const tr = (await res.json()) as TokenResponse;
      accessToken = tr.access_token;
      return tr;
    } catch {
      accessToken = null;
      return null;
    } finally {
      setTimeout(() => { refreshing = null; }, 0);
    }
  })();
  return refreshing;
}

interface ReqOpts { method?: string; body?: unknown; csrf?: boolean; auth?: boolean }

export async function request<T>(path: string, opts: ReqOpts = {}): Promise<T> {
  const { method = "GET", body, csrf = false, auth = true } = opts;
  const send = (): Promise<Response> => {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) Object.assign(headers, CSRF);
    if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
    return fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
  };
  let res = await send();
  if (res.status === 401 && auth) {
    const refreshed = await refreshSession();
    if (refreshed) res = await send();
    if (res.status === 401) { accessToken = null; onSessionLost?.(); }
  }
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** POST that returns the response body as a Blob (exports). Mirrors `request` auth/refresh handling. */
export async function requestBlob(path: string, body: unknown): Promise<Blob> {
  const send = () => fetch(path, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
    body: JSON.stringify(body),
  });
  let res = await send();
  if (res.status === 401 && (await refreshSession())) res = await send();
  if (res.status === 401) { accessToken = null; onSessionLost?.(); }
  if (!res.ok) throw await parseError(res);
  return res.blob();
}

/** POST that returns the raw streaming Response (Server-Sent Events). Mirrors `request` auth/refresh handling. */
export async function requestStream(path: string, body: unknown, signal?: AbortSignal): Promise<Response> {
  const send = () => fetch(path, {
    method: "POST", credentials: "same-origin", signal,
    headers: { "Content-Type": "application/json", Accept: "text/event-stream", ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
    body: JSON.stringify(body),
  });
  let res = await send();
  if (res.status === 401 && (await refreshSession())) res = await send();
  if (res.status === 401) { accessToken = null; onSessionLost?.(); }
  if (!res.ok) throw await parseError(res);
  return res;
}

const J = (body: unknown) => ({ method: "POST", body });
const enc = encodeURIComponent;

export const api = {
  login: async (email: string, password: string): Promise<TokenResponse> => {
    const tr = await request<TokenResponse>("/api/v1/auth/login", { method: "POST", body: { email, password }, auth: false });
    accessToken = tr.access_token;
    return tr;
  },
  logout: async (): Promise<void> => {
    try { await request<void>("/api/v1/auth/logout", { method: "POST", csrf: true, auth: false }); } finally { accessToken = null; }
  },
  switchTenant: async (tenantId: string): Promise<TokenResponse> => {
    const tr = await request<TokenResponse>("/api/v1/auth/switch-tenant", { method: "POST", csrf: true, body: { tenant_id: tenantId } });
    accessToken = tr.access_token;
    return tr;
  },
  fields: () => request<FieldInfo[]>("/api/v1/events/fields"),
  search: (body: EventQueryBody) => request<SearchResult>("/api/v1/events/search", { method: "POST", body }),
  getEvent: (id: string) => request<EventDetail>(`/api/v1/events/${encodeURIComponent(id)}`),
  listHunts: () => request<Hunt[]>("/api/v1/hunts"),
  getHunt: (id: string) => request<Hunt>(`/api/v1/hunts/${enc(id)}`),
  createHunt: (b: HuntCreate) => request<Hunt>("/api/v1/hunts", J(b)),
  updateHunt: (id: string, b: HuntUpdate) => request<Hunt>(`/api/v1/hunts/${enc(id)}`, { method: "PATCH", body: b }),
  deleteHunt: (id: string) => request<void>(`/api/v1/hunts/${enc(id)}`, { method: "DELETE" }),
  runHunt: (id: string, query: EventQueryBody) => request<SearchResult>(`/api/v1/hunts/${enc(id)}/run`, J({ query })),
  listFindings: (id: string) => request<Finding[]>(`/api/v1/hunts/${enc(id)}/findings`),
  addFinding: (id: string, b: FindingCreate) => request<Finding>(`/api/v1/hunts/${enc(id)}/findings`, J(b)),
  deleteFinding: (id: string, fid: string) => request<void>(`/api/v1/hunts/${enc(id)}/findings/${enc(fid)}`, { method: "DELETE" }),
  listNotes: (id: string) => request<Note[]>(`/api/v1/hunts/${enc(id)}/notes`),
  addNote: (id: string, body: string) => request<Note>(`/api/v1/hunts/${enc(id)}/notes`, J({ body })),
  listSavedQueries: (huntId?: string) => request<SavedQuery[]>(`/api/v1/saved-queries${huntId ? `?hunt_id=${enc(huntId)}` : ""}`),
  saveQuery: (b: { name: string; description?: string; hunt_id?: string; query: Partial<EventQueryBody> }) =>
    request<SavedQuery>("/api/v1/saved-queries", J(b)),
  deleteSavedQuery: (id: string) => request<void>(`/api/v1/saved-queries/${enc(id)}`, { method: "DELETE" }),
  history: (huntId?: string) => request<HistoryEntry[]>(`/api/v1/query-history${huntId ? `?hunt_id=${enc(huntId)}` : ""}`),
  parseQuery: (text: string) => request<ParsedQuery>("/api/v1/queries/parse", J({ text })),
  exportEvents: (query: Partial<EventQueryBody>, format: "csv" | "json", maxRows: number) =>
    requestBlob("/api/v1/events/export", { query, format, max_rows: maxRows }),
  timeline: (query: Partial<EventQueryBody>, collapse: boolean, limit = 500) =>
    request<Timeline>("/api/v1/timeline", J({ query, collapse, limit })),
  timelineAround: (event_id: string, scope: TimelineScope, window_minutes: number, collapse: boolean) =>
    request<Timeline>("/api/v1/timeline/around", J({ event_id, scope, window_minutes, collapse })),
  // cases
  listCases: (qs = "") => request<CaseOut[]>(`/api/v1/cases${qs}`),
  getCase: (id: string) => request<CaseOut>(`/api/v1/cases/${enc(id)}`),
  createCase: (b: CaseCreate) => request<CaseOut>("/api/v1/cases", J(b)),
  updateCase: (id: string, b: CaseUpdate) => request<CaseOut>(`/api/v1/cases/${enc(id)}`, { method: "PATCH", body: b }),
  transitionCase: (id: string, status: string, comment: string) =>
    request<CaseOut>(`/api/v1/cases/${enc(id)}/transition`, J({ status, comment })),
  caseActivity: (id: string) => request<CaseActivity[]>(`/api/v1/cases/${enc(id)}/activity`),
  addCaseNote: (id: string, body: string) => request<CaseActivity>(`/api/v1/cases/${enc(id)}/notes`, J({ body })),
  caseEvidence: (id: string) => request<CaseEvidence[]>(`/api/v1/cases/${enc(id)}/evidence`),
  addCaseEvidence: (id: string, event_ids: string[], comment = "") =>
    request<CaseEvidence[]>(`/api/v1/cases/${enc(id)}/evidence`, J({ event_ids, comment })),
  removeCaseEvidence: (id: string, eid: string) => request<void>(`/api/v1/cases/${enc(id)}/evidence/${enc(eid)}`, { method: "DELETE" }),
  caseIocs: (id: string) => request<CaseIoc[]>(`/api/v1/cases/${enc(id)}/iocs`),
  addCaseIoc: (id: string, type: IocType, value: string) => request<CaseIoc>(`/api/v1/cases/${enc(id)}/iocs`, J({ type, value })),
  removeCaseIoc: (id: string, iid: string) => request<void>(`/api/v1/cases/${enc(id)}/iocs/${enc(iid)}`, { method: "DELETE" }),
  extractCaseIocs: (id: string) => request<{ extracted: number }>(`/api/v1/cases/${enc(id)}/iocs/extract`, { method: "POST" }),
  caseAssets: (id: string) => request<CaseAssetRef[]>(`/api/v1/cases/${enc(id)}/assets`),
  linkCaseAsset: (id: string, asset_id: string) => request<{ status: string }>(`/api/v1/cases/${enc(id)}/assets`, J({ asset_id })),
  unlinkCaseAsset: (id: string, aid: string) => request<void>(`/api/v1/cases/${enc(id)}/assets/${enc(aid)}`, { method: "DELETE" }),
  caseTimeline: (id: string, collapse: boolean) => request<Timeline>(`/api/v1/cases/${enc(id)}/timeline?collapse=${collapse}`),
  caseReports: (id: string) => request<CaseReport[]>(`/api/v1/cases/${enc(id)}/reports`),
  generateReport: (id: string) => request<CaseReport>(`/api/v1/cases/${enc(id)}/reports`, { method: "POST" }),
  caseAudit: (id: string) => request<AuditRow[]>(`/api/v1/cases/${enc(id)}/audit`),
  // assets
  listAssets: (qs = "") => request<Asset[]>(`/api/v1/assets${qs}`),
  getAsset: (id: string) => request<Asset>(`/api/v1/assets/${enc(id)}`),
  createAsset: (b: AssetCreate) => request<Asset>("/api/v1/assets", J(b)),
  updateAsset: (id: string, b: AssetUpdate) => request<Asset>(`/api/v1/assets/${enc(id)}`, { method: "PATCH", body: b }),
  discoverAssets: (days: number) => request<{ created: number; updated: number }>("/api/v1/assets/discover", J({ days })),
  assetEvents: (id: string, days = 7, limit = 50) => request<AssetEvents>(`/api/v1/assets/${enc(id)}/events?days=${days}&limit=${limit}`),
  assetRelated: (id: string, days = 7) => request<AssetRelated>(`/api/v1/assets/${enc(id)}/related?days=${days}`),
  assetCases: (id: string) => request<AssetCaseRef[]>(`/api/v1/assets/${enc(id)}/cases`),
  // data sources
  connectors: () => request<ConnectorInfo[]>("/api/v1/data-sources/connectors"),
  listDataSources: () => request<DataSource[]>("/api/v1/data-sources"),
  createDataSource: (b: DataSourceCreate) => request<DataSource>("/api/v1/data-sources", J(b)),
  updateDataSource: (id: string, b: { enabled?: boolean; name?: string }) =>
    request<DataSource>(`/api/v1/data-sources/${enc(id)}`, { method: "PATCH", body: b }),
  deleteDataSource: (id: string) => request<void>(`/api/v1/data-sources/${enc(id)}`, { method: "DELETE" }),
  setDataSourceSecret: (id: string, name: string, value: string) =>
    request<void>(`/api/v1/data-sources/${enc(id)}/secrets/${enc(name)}`, { method: "PUT", body: { value } }),
  rotateKey: (id: string) => request<DataSource>(`/api/v1/data-sources/${enc(id)}/rotate-key`, { method: "POST" }),
  testDataSource: (id: string) => request<{ ok: boolean; detail: string }>(`/api/v1/data-sources/${enc(id)}/test`, { method: "POST" }),
  collectDataSource: (id: string) => request<{ accepted: number; status: string; detail: string }>(`/api/v1/data-sources/${enc(id)}/collect`, { method: "POST" }),
  // threat intelligence
  intelProviders: () => request<IntelProvider[]>("/api/v1/intel/providers"),
  configureProvider: (key: string, b: { enabled: boolean; config: Record<string, unknown>; secrets?: Record<string, string> }) =>
    request<IntelProvider>(`/api/v1/intel/providers/${enc(key)}`, { method: "PUT", body: b }),
  testProvider: (key: string) => request<{ ok: boolean; detail: string }>(`/api/v1/intel/providers/${enc(key)}/test`, { method: "POST" }),
  taxiiPull: () => request<StixImportResult>("/api/v1/intel/taxii/pull", { method: "POST" }),
  importStix: (bundle: unknown) => request<StixImportResult>("/api/v1/intel/import/stix", J(bundle)),
  detOverview: () => request<DetectionOverview>("/api/v1/detections/overview"),
  listRules: (qs = "") => request<Rule[]>(`/api/v1/detections/rules${qs}`),
  getRule: (id: string) => request<Rule>(`/api/v1/detections/rules/${enc(id)}`),
  createRule: (b: { format: string; content: string; hunt_id?: string }) => request<Rule>("/api/v1/detections/rules", J(b)),
  ruleFromQuery: (b: { title: string; text: string; severity: string; hunt_id?: string }) => request<Rule>("/api/v1/detections/rules/from-query", J(b)),
  updateRule: (id: string, b: { content: string; note?: string }) => request<Rule>(`/api/v1/detections/rules/${enc(id)}`, { method: "PUT", body: b }),
  transitionRule: (id: string, to: RuleStatus) => request<Rule>(`/api/v1/detections/rules/${enc(id)}/transition`, J({ to })),
  deleteRule: (id: string) => request<void>(`/api/v1/detections/rules/${enc(id)}`, { method: "DELETE" }),
  ruleTests: (id: string) => request<TestCase[]>(`/api/v1/detections/rules/${enc(id)}/tests`),
  addRuleTest: (id: string, b: { name: string; event: Record<string, unknown>; expect_match: boolean }) => request<TestCase>(`/api/v1/detections/rules/${enc(id)}/tests`, J(b)),
  deleteRuleTest: (id: string, caseId: string) => request<void>(`/api/v1/detections/rules/${enc(id)}/tests/${enc(caseId)}`, { method: "DELETE" }),
  runRuleTests: (id: string) => request<{ passed: boolean; results: TestResult[] }>(`/api/v1/detections/rules/${enc(id)}/tests/run`, J({})),
  backtestRule: (id: string) => request<Backtest>(`/api/v1/detections/rules/${enc(id)}/backtest`, J({})),
  listAlerts: (qs = "") => request<Alert[]>(`/api/v1/detections/alerts${qs}`),
  updateAlert: (id: string, status: AlertStatus) => request<Alert>(`/api/v1/detections/alerts/${enc(id)}`, { method: "PATCH", body: { status } }),
  alertToCase: (id: string) => request<Alert>(`/api/v1/detections/alerts/${enc(id)}/case`, J({})),
  aiStatus: () => request<AiStatus>("/api/v1/ai/status"),
  aiTranslate: (question: string) => request<{ query: string | null; note: string }>("/api/v1/ai/translate", J({ question })),
  aiRuns: () => request<AiRun[]>("/api/v1/ai/runs"),
  aiRun: (b: { goal: string; hunt_id?: string; hours_back: number }) => request<AiRun>("/api/v1/ai/runs", J(b)),
  aiRunStream: (b: AiRunBody, signal?: AbortSignal) => requestStream("/api/v1/ai/runs/stream", b, signal),
  aiResumeStream: (id: string, signal?: AbortSignal) => requestStream(`/api/v1/ai/runs/${enc(id)}/resume/stream`, {}, signal),
  aiStop: (id: string) => request<{ status: string }>(`/api/v1/ai/runs/${enc(id)}/stop`, J({})),
  aiRunEvidence: (id: string) => request<EvPoint[]>(`/api/v1/ai/runs/${enc(id)}/evidence`),
  aiSave: (id: string, finding_indexes: number[], hunt_id?: string) => request<AiRun>(`/api/v1/ai/runs/${enc(id)}/save`, J({ finding_indexes, ...(hunt_id ? { hunt_id } : {}) })),
  threats: (qs = "") => request<ThreatPage>(`/api/v1/ioc/threats${qs}`),
  bulletin: (id: string) => request<Bulletin>(`/api/v1/ioc/threats/${enc(id)}`),
  threatIocs: (id: string, qs = "") => request<IocPage>(`/api/v1/ioc/threats/${enc(id)}/iocs${qs}`),
  validateThreat: (id: string, b: { lookback_days: number; name?: string; exclude_ioc_ids: string[]; exclude_ioa_ids: string[]; include_signals: boolean }) => request<IocHunt>(`/api/v1/ioc/threats/${enc(id)}/validate`, J(b)),
  rejectThreat: (id: string, reason: string) => request<{ rejected: number }>(`/api/v1/ioc/threats/${enc(id)}/reject`, J({ reason })),
  addIoa: (id: string, b: { name: string; query_text: string; technique_id?: string; severity: string; description?: string }) => request<Ioa>(`/api/v1/ioc/threats/${enc(id)}/ioas`, J(b)),
  deleteIoa: (id: string, ioaId: string) => request<void>(`/api/v1/ioc/threats/${enc(id)}/ioas/${enc(ioaId)}`, { method: "DELETE" }),
  addTtp: (id: string, technique_id: string) => request<Ttp>(`/api/v1/ioc/threats/${enc(id)}/ttps`, J({ technique_id })),
  regroupThreats: () => request<{ threats: number }>("/api/v1/ioc/threats/regroup", J({})),
  iocOverview: () => request<IocOverview>("/api/v1/ioc/overview"),
  iocFeedTypes: () => request<FeedType[]>("/api/v1/ioc/feed-types"),
  iocFeeds: () => request<IocFeed[]>("/api/v1/ioc/feeds"),
  createIocFeed: (b: Record<string, unknown>) => request<IocFeed>("/api/v1/ioc/feeds", J(b)),
  updateIocFeed: (id: string, b: Record<string, unknown>) => request<IocFeed>(`/api/v1/ioc/feeds/${enc(id)}`, { method: "PATCH", body: b }),
  deleteIocFeed: (id: string) => request<void>(`/api/v1/ioc/feeds/${enc(id)}`, { method: "DELETE" }),
  runIocFeed: (id: string) => request<IocFeed>(`/api/v1/ioc/feeds/${enc(id)}/run`, J({})),
  setIocFeedSecret: (id: string, name: string, value: string) => request<void>(`/api/v1/ioc/feeds/${enc(id)}/secrets/${enc(name)}`, { method: "PUT", body: { value } }),
  iocs: (qs = "") => request<IocPage>(`/api/v1/ioc/iocs${qs}`),
  addIoc: (b: { type: string; value: string; confidence?: number; description?: string }) => request<IocItem>("/api/v1/ioc/iocs", J(b)),
  validateIocs: (b: { ioc_ids: string[]; name?: string; lookback_days: number }) => request<IocHunt>("/api/v1/ioc/iocs/validate", J(b)),
  rejectIocs: (ioc_ids: string[], reason: string) => request<{ rejected: number }>("/api/v1/ioc/iocs/reject", J({ ioc_ids, reason })),
  iocHunts: () => request<IocHunt[]>("/api/v1/ioc/hunts"),
  iocHunt: (id: string) => request<IocHuntDetail>(`/api/v1/ioc/hunts/${enc(id)}`),
  retryIocHunt: (id: string) => request<IocHunt>(`/api/v1/ioc/hunts/${enc(id)}/retry`, J({})),
  iocAllowlist: () => request<AllowEntry[]>("/api/v1/ioc/allowlist"),
  addIocAllow: (b: { type: string; value: string; reason: string }) => request<AllowEntry>("/api/v1/ioc/allowlist", J(b)),
  deleteIocAllow: (id: string) => request<void>(`/api/v1/ioc/allowlist/${enc(id)}`, { method: "DELETE" }),
  intelLookup: (b: LookupBody) => request<IntelDetail>("/api/v1/intel/lookup", J(b)),
  listEntities: (qs = "") => request<IntelEntity[]>(`/api/v1/intel/entities${qs}`),
  getEntity: (id: string) => request<IntelDetail>(`/api/v1/intel/entities/${enc(id)}`),
  updateEntity: (id: string, b: EntityUpdate) => request<IntelDetail>(`/api/v1/intel/entities/${enc(id)}`, { method: "PATCH", body: b }),
  deleteEntity: (id: string) => request<void>(`/api/v1/intel/entities/${enc(id)}`, { method: "DELETE" }),
  enrichEntity: (id: string, refresh: boolean) => request<IntelDetail>(`/api/v1/intel/entities/${enc(id)}/enrich?refresh=${refresh}`, { method: "POST" }),
  sightings: (id: string, days = 30) => request<Sightings>(`/api/v1/intel/entities/${enc(id)}/sightings?days=${days}`),
  addRelation: (id: string, dst_id: string, kind: string) => request<{ status: string }>(`/api/v1/intel/entities/${enc(id)}/relations`, J({ dst_id, kind })),
  removeRelation: (rid: string) => request<void>(`/api/v1/intel/relations/${enc(rid)}`, { method: "DELETE" }),
  lookupBatch: (items: Array<{ type: string; value: string }>) => request<BatchVerdict[]>("/api/v1/intel/lookup-batch", J({ items })),
  enrichCase: (caseId: string, refresh = false) => request<EnrichCaseResult>(`/api/v1/intel/enrich-case/${enc(caseId)}?refresh=${refresh}`, { method: "POST" }),
  // MITRE ATT&CK
  mitreTactics: () => request<MitreTactic[]>("/api/v1/mitre/tactics"),
  mitreMatrix: () => request<MatrixColumn[]>("/api/v1/mitre/matrix"),
  mitreTechnique: (id: string) => request<MitreTechnique>(`/api/v1/mitre/techniques/${enc(id)}`),
  mitreSummary: (id: string) => request<TechniqueSummary>(`/api/v1/mitre/techniques/${enc(id)}/summary`),
  mitreSuggest: (source: { case_id: string } | { hunt_id: string }) => request<SuggestResponse>("/api/v1/mitre/suggest", J(source)),
  mitreMappings: (qs = "") => request<MitreMapping[]>(`/api/v1/mitre/mappings${qs}`),
  createMapping: (b: MappingCreate) => request<MitreMapping>("/api/v1/mitre/mappings", J(b)),
  deleteMapping: (id: string) => request<void>(`/api/v1/mitre/mappings/${enc(id)}`, { method: "DELETE" }),
  // audit
  audit: (qs = "") => request<AuditRow[]>(`/api/v1/audit${qs}`),
  listUsers: () => request<MemberOut[]>("/api/v1/users"),
  createUser: (u: UserCreate) => request<MemberOut>("/api/v1/users", { method: "POST", body: u }),
  currentTenant: () => request<TenantOut>("/api/v1/tenants/current"),
  ready: async (): Promise<ReadyResponse> => {
    const res = await fetch("/backend-health/ready", { headers: { Accept: "application/json" } });
    // 503 still carries a useful body
    return (await res.json()) as ReadyResponse;
  },
};
