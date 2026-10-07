import { api, ApiError, getAccessToken, request, setAccessToken, setSessionLostHandler } from "@/lib/api";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const tokenResp = (t: string) => ({ access_token: t, token_type: "bearer", expires_in: 900, session: { email: "a@b.c" } });

afterEach(() => { vi.restoreAllMocks(); setAccessToken(null); setSessionLostHandler(null); });

it("refreshes once on 401 and retries with the new token", async () => {
  setAccessToken("old");
  const calls: Array<{ url: string; auth: string | null }> = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    const auth = (init.headers as Record<string, string>).Authorization ?? null;
    calls.push({ url, auth });
    if (url.endsWith("/auth/refresh")) {
      expect((init.headers as Record<string, string>)["X-Requested-With"]).toBe("threat-hunt");
      return json(200, tokenResp("new"));
    }
    return auth === "Bearer new" ? json(200, { ok: 1 }) : json(401, { error: { code: "unauthorized", message: "expired" } });
  }));
  await expect(request("/api/v1/x")).resolves.toEqual({ ok: 1 });
  expect(calls.map((c) => c.auth)).toEqual(["Bearer old", null, "Bearer new"]);
  expect(getAccessToken()).toBe("new");
});

it("signals session loss when refresh fails", async () => {
  setAccessToken("old");
  const lost = vi.fn();
  setSessionLostHandler(lost);
  vi.stubGlobal("fetch", vi.fn(async () => json(401, { error: { code: "unauthorized", message: "nope" } })));
  await expect(request("/api/v1/x")).rejects.toMatchObject({ status: 401 });
  expect(lost).toHaveBeenCalled();
  expect(getAccessToken()).toBeNull();
});

it("maps error bodies and friendly messages", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(429, { error: { code: "rate_limited", message: "slow", request_id: "r1" } })));
  const err = await api.fields().catch((e: unknown) => e);
  expect(err).toBeInstanceOf(ApiError);
  expect((err as ApiError).requestId).toBe("r1");
  expect((err as ApiError).friendly).toMatch(/rate limit/i);
});

it("keeps the access token in memory only", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, tokenResp("tok"))));
  await api.login("a@b.c", "pw");
  expect(getAccessToken()).toBe("tok");
  expect(JSON.stringify({ ...localStorage })).not.toContain("tok");
  expect(JSON.stringify({ ...sessionStorage })).not.toContain("tok");
});
