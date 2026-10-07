import type {
  EventDetail, EventQueryBody, FieldInfo, MemberOut, ReadyResponse, SearchResult, TenantOut, TokenResponse,
  UserCreate, ApiErrorBody,
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

async function parseError(res: Response): Promise<ApiError> {
  let body: Partial<ApiErrorBody> | null = null;
  try { body = (await res.json()) as ApiErrorBody; } catch { /* non-JSON error */ }
  const e = body?.error;
  return new ApiError(res.status, e?.code ?? "http_error", e?.message ?? `Request failed (${res.status})`, e?.request_id);
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
  listUsers: () => request<MemberOut[]>("/api/v1/users"),
  createUser: (u: UserCreate) => request<MemberOut>("/api/v1/users", { method: "POST", body: u }),
  currentTenant: () => request<TenantOut>("/api/v1/tenants/current"),
  ready: async (): Promise<ReadyResponse> => {
    const res = await fetch("/backend-health/ready", { headers: { Accept: "application/json" } });
    // 503 still carries a useful body
    return (await res.json()) as ReadyResponse;
  },
};
