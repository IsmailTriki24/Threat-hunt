import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EventsView } from "@/components/events-view";
import { SiemSearchCard } from "@/components/siem-search-card";
import { searchedSummary, siemHeadline, windowLabel, type SiemResult } from "@/lib/siem";
import { windowFor } from "@/lib/threat-map";
import { mockFetch, renderWithQuery, status } from "./helpers";

let params = "";
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams(params), useRouter: () => ({ push: vi.fn(), replace: vi.fn() }), usePathname: () => "/events" }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: () => true }), useOptionalAuth: () => null }));

const res = (o: Partial<SiemResult> = {}): SiemResult => ({
  source: "LogRhythm SIEM", configured: true, status: "ok", detail: "1 search(es) over the whole SIEM, 24 h", searched: [{ kind: "ip", values: ["51.89.20.151"], logs: 3 }],
  skipped: [], matched: 2, imported: 2, duplicates: 0, truncated: false, window: { start: "2026-10-11T00:00:00Z", end: "2026-10-12T00:00:00Z" },
  samples: [{ id: "a".repeat(32), timestamp: "2026-10-11T10:00:00Z", summary: "AIE: C2: Blacklisted Egress Port", host: "10.240.136.2" }], ...o,
});
const q = (o: object = {}) => ({ data: undefined as SiemResult | undefined, isFetching: false, isError: false, error: null, refetch: vi.fn(), ...o });

describe("wording", () => {
  it("states exactly what was found, imported and searched", () => {
    expect(searchedSummary(res())).toBe("51.89.20.151");
    expect(searchedSummary(res({ searched: [{ kind: "ip", values: ["1.1.1.1", "2.2.2.2", "3.3.3.3"], logs: 0 }] }))).toBe("3 ips");
    expect(siemHeadline(res())).toBe("2 logs for 51.89.20.151 found across the whole LogRhythm SIEM, 2 new in your platform");
    expect(siemHeadline(res({ imported: 0 }))).toMatch(/all already in your platform/);
    expect(siemHeadline(res({ matched: 1, imported: 1 }))).toMatch(/^1 log for/);
    expect(siemHeadline(res({ matched: 0, imported: 0 }))).toBe("No logs for 51.89.20.151 in the whole LogRhythm SIEM (last 24 h)");
    expect(windowLabel({ start: "2026-10-01T00:00:00Z", end: "2026-10-08T00:00:00Z" })).toBe("last 7 days");
  });
  it("turns the map's range into an absolute window", () => {
    const now = Date.parse("2026-10-12T12:00:00Z");
    expect(windowFor({ range: "24h", start: "", end: "" }, now)).toEqual({ start: "2026-10-11T12:00:00.000Z", end: "2026-10-12T12:00:00.000Z" });
    expect(windowFor({ range: "custom", start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" }, now)?.start).toBe("2026-10-01T00:00:00.000Z");
    expect(windowFor({ range: "custom", start: "", end: "" }, now)).toBeUndefined();
  });
});

describe("SiemSearchCard states", () => {
  it("searching: says it is the whole SIEM and that it can take a while", () => {
    render(<SiemSearchCard query={q({ isFetching: true })} />);
    expect(screen.getByRole("status")).toHaveTextContent(/Searching the whole LogRhythm SIEM/);
    expect(screen.getByRole("status")).toHaveTextContent(/up to a minute/);
  });
  it("found: headline, honest detail, samples that link to the events, and a way to show them", async () => {
    const onShow = vi.fn();
    render(<SiemSearchCard query={q({ data: res() })} onShow={onShow} />);
    expect(screen.getByText(/2 logs for 51.89.20.151 found across the whole LogRhythm SIEM, 2 new in your platform/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /2026-10-11 10:00/ })).toHaveAttribute("href", `/events?event=${"a".repeat(32)}`);
    expect(screen.getByText("AIE: C2: Blacklisted Egress Port")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show in results" }));
    expect(onShow).toHaveBeenCalled();
  });
  it("nothing found is stated as such, with the window it covered", () => {
    render(<SiemSearchCard query={q({ data: res({ matched: 0, imported: 0, samples: [] }) })} />);
    expect(screen.getByText(/No logs for 51.89.20.151 in the whole LogRhythm SIEM \(last 24 h\)/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show in results" })).toBeNull();
  });
  it("what could not be searched and truncation are shown, not hidden", () => {
    render(<SiemSearchCard query={q({ data: res({ skipped: ["LogRhythm can't be searched by process.name; those filters are applied to the logs it returns"], truncated: true }) })} />);
    expect(screen.getByText(/can't be searched by process.name/)).toBeInTheDocument();
    expect(screen.getByText(/Only part of the SIEM result/)).toBeInTheDocument();
  });
  it("a failure is an alert with the reason, says what the results below do contain, and can retry", async () => {
    const refetch = vi.fn();
    render(<SiemSearchCard query={q({ data: res({ status: "error", detail: "LogRhythm search failed", matched: 0, imported: 0 }), refetch })} />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("LogRhythm search failed");
    expect(alert).toHaveTextContent(/only include what was already collected/);
    await userEvent.click(within(alert).getByRole("button", { name: /Retry/ }));
    expect(refetch).toHaveBeenCalled();
  });
  it("a request failure is also an alert", () => {
    render(<SiemSearchCard query={q({ isError: true, error: new Error("Network down") })} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Network down");
  });
  it("renders nothing when the SIEM is not configured or switched off, and one muted line when the query has nothing to look up", () => {
    const { container, rerender } = render(<SiemSearchCard query={q({ data: res({ status: "unconfigured", configured: false }) })} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<SiemSearchCard query={q({ data: res({ status: "disabled" }) })} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<SiemSearchCard query={q({ data: res({ status: "not_applicable", detail: "Nothing in this search can be looked up in LogRhythm." }) })} />);
    expect(container).toHaveTextContent("Nothing in this search can be looked up in LogRhythm.");
    rerender(<SiemSearchCard compact query={q({ data: res({ status: "not_applicable" }) })} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("Events page runs the whole-SIEM search alongside the normal one", () => {
  const search = { total: 0, total_relation: "eq", took_ms: 1, hits: [], aggregations: {}, time_range: { start: "2026-10-11T00:00:00Z", end: "2026-10-12T00:00:00Z" } };
  const routes = (siem: () => unknown) => ({
    "GET /api/v1/events/fields": () => [{ name: "network.dst_ip", kind: "ip", sortable: false, aggregatable: true }],
    "POST /api/v1/events/search": () => search, "POST /api/v1/events/siem-search": siem, "GET /api/v1/query-history": () => [],
  });

  it("sends the query (without aggregations), shows the result, and re-runs the local search once when logs were imported", async () => {
    params = "lang=1&q=network.dst_ip%3A51.89.20.151";
    const m = mockFetch(routes(() => res()));
    renderWithQuery(<EventsView />);
    expect(await screen.findByText(/2 logs for 51.89.20.151 found across the whole LogRhythm SIEM/)).toBeInTheDocument();
    const body = m.bodiesFor("POST /api/v1/events/siem-search")[0] as { text: string; aggregations: unknown[]; filters: unknown[] };
    expect(body.text).toBe("network.dst_ip:51.89.20.151");
    expect(body.aggregations).toEqual([]);
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/events/search").length).toBeGreaterThanOrEqual(2)); // initial + the re-run after the import
    const calls = m.bodiesFor("POST /api/v1/events/search").length;
    await new Promise((r) => setTimeout(r, 300));
    expect(m.bodiesFor("POST /api/v1/events/search").length).toBe(calls); // exactly once: no refetch loop
    expect(m.bodiesFor("POST /api/v1/events/siem-search")).toHaveLength(1);
  });

  it("does not re-run when nothing new was imported", async () => {
    params = "lang=1&q=network.dst_ip%3A51.89.20.151";
    const m = mockFetch(routes(() => res({ imported: 0, duplicates: 2 })));
    renderWithQuery(<EventsView />);
    expect(await screen.findByText(/all already in your platform/)).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 300));
    expect(m.bodiesFor("POST /api/v1/events/search")).toHaveLength(1);
  });

  it("is not called for an empty search (the default dashboard view)", async () => {
    params = "";
    const m = mockFetch(routes(() => res()));
    renderWithQuery(<EventsView />);
    await screen.findByText(/0 events/);
    expect(m.bodiesFor("POST /api/v1/events/siem-search")).toHaveLength(0);
  });

  it("a SIEM failure shows an error but leaves the normal results working", async () => {
    params = "q=evil.example";
    mockFetch(routes(() => status(500, { error: { code: "x", message: "boom" } })));
    renderWithQuery(<EventsView />);
    expect(await screen.findByText(/The whole-SIEM search failed/)).toBeInTheDocument();
    expect(screen.getByText(/0 events/)).toBeInTheDocument();
  });
});

describe("hunt workspace and investigation panel", () => {
  it("the threat-map panel asks the whole SIEM about a public IP over the map's window, and not about a private one", async () => {
    const { InvestigationPanel } = await import("@/components/threat-map-panels");
    const detail = (cls: string) => ({
      ip: "51.89.20.151", class: cls, geo: null, geo_note: "", intel: [], related_iocs: [], observed: null, events: [], events_total: 0, peers: [], hunt_matches: [], alerts: [], cases: [],
      correlated: false, correlation_reason: "", actions: { investigate: true, intel_lookup: false, hunt: false, add_to_watchlist: false, add_to_case: false },
    });
    const filters = { layer: "intelligence", range: "7d", start: "", end: "", country: [], continent: "", iocType: "", severity: "info", minConfidence: 0, category: "", source: [], logSource: [], scope: "any", q: "" } as never;
    let cls = "public";
    const m = mockFetch({ "GET /api/v1/threat-map/indicator": () => detail(cls), "POST /api/v1/events/siem-lookup": () => res() });
    const { unmount } = renderWithQuery(<InvestigationPanel ip="51.89.20.151" filters={filters} rangeQs="layer=intelligence&range=7d" onClose={() => undefined} />);
    expect(await screen.findByText(/2 logs for 51.89.20.151 found across the whole LogRhythm SIEM/)).toBeInTheDocument();
    const body = m.bodiesFor("POST /api/v1/events/siem-lookup")[0] as { kind: string; value: string; time_range: { start: string; end: string } };
    expect(body).toMatchObject({ kind: "ip", value: "51.89.20.151" });
    expect((Date.parse(body.time_range.end) - Date.parse(body.time_range.start)) / 86_400_000).toBeCloseTo(7, 1);
    expect(screen.getByRole("region", { name: "LogRhythm SIEM" })).toBeInTheDocument();
    unmount();
    cls = "private";
    const m2 = mockFetch({ "GET /api/v1/threat-map/indicator": () => detail(cls), "POST /api/v1/events/siem-lookup": () => res() });
    renderWithQuery(<InvestigationPanel ip="10.0.0.5" filters={filters} rangeQs="layer=intelligence&range=7d" onClose={() => undefined} />);
    await screen.findByTestId("panel-ip");
    await new Promise((r) => setTimeout(r, 200));
    expect(m2.bodiesFor("POST /api/v1/events/siem-lookup")).toHaveLength(0);
  });
});
