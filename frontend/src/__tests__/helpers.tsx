import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";

type Handler = (body: unknown, url: string) => unknown | { __status: number; body: unknown } | Blob;
export const status = (code: number, body: unknown) => ({ __status: code, body });

/** Route-based fetch mock: keys are `METHOD /path` (query string ignored unless the key includes `?`). */
export function mockFetch(routes: Record<string, Handler>) {
  const calls: Array<{ key: string; body: unknown }> = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const key = [`${method} ${url}`, `${method} ${url.split("?")[0]}`].find((k) => k in routes);
    calls.push({ key: key ?? `${method} ${url}`, body });
    if (!key) return new Response(JSON.stringify({ error: { code: "not_found", message: `no mock for ${method} ${url}` } }), { status: 404 });
    const out = routes[key](body, url);
    if (out instanceof Blob) return new Response(out, { status: 200 });
    if (out && typeof out === "object" && "__status" in out) {
      const o = out as { __status: number; body: unknown };
      return new Response(o.__status === 204 ? null : JSON.stringify(o.body), { status: o.__status });
    }
    return new Response(JSON.stringify(out), { status: 200 });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls, bodiesFor: (key: string) => calls.filter((c) => c.key === key).map((c) => c.body) };
}

export function renderWithQuery(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}
