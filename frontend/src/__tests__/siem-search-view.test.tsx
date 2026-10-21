import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SiemSearchView } from "@/components/siem-search-view";
import type { SiemQueryResult } from "@/lib/api-types";
import { mockFetch, renderWithQuery } from "./helpers";

let params = "";
const replace = vi.fn();
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams(params), useRouter: () => ({ push: vi.fn(), replace }), usePathname: () => "/events" }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: () => true }), useOptionalAuth: () => null }));
beforeEach(() => { replace.mockClear(); });

const ID = (c: string) => c.repeat(32);
const hit = (c: string, host: string, ts: string, extra: object = {}) => ({ id: ID(c), timestamp: ts, source: "logrhythm", event_type: "network_connection", host: { hostname: host }, outcome: "unknown", severity: 0, message: `from ${host}`, ...extra });
const result = (o: Partial<SiemQueryResult> = {}): SiemQueryResult => ({
  search_id: "s".repeat(32), origins: { [ID("a")]: "l1", [ID("b")]: "t1" }, hits: [hit("a", "srv9", "2026-10-13T10:00:00Z"), hit("b", "srv8", "2026-10-13T11:00:00Z", { user: { name: "bob" } })], total: 2, truncated: false, found: 2, found_at_least: false, empty_query: false, no_sources: false, note: "",
  sources: [
    { id: "l1", name: "LogRhythm SIEM", kind: "logrhythm", status: "ok", detail: "", searched: ["ip: 203.0.113.5"], skipped: [], scanned: 5, matched: 2, capped: false, found: 5, found_at_least: false, ms: 900 },
    { id: "t1", name: "Trend endpoint", kind: "trend:endpoint_activity", status: "error", detail: "Trend returned 500", searched: [], skipped: [], scanned: 0, matched: 0, capped: false, found: 0, found_at_least: false, ms: 80 },
  ],
  time_range: { start: "2026-10-12T00:00:00Z", end: "2026-10-13T00:00:00Z" }, took_ms: 950, ...o,
});
const routes = (extra: Record<string, () => unknown> = {}) => ({
  "GET /api/v1/events/fields": () => [{ name: "network.dst_ip", kind: "ip", sortable: false, aggregatable: true }],
  "GET /api/v1/events/siem-sources": () => [{ id: "l1", name: "LogRhythm SIEM", kind: "logrhythm" }, { id: "t1", name: "Trend endpoint", kind: "trend:endpoint_activity" }],
  "POST /api/v1/events/siem-query": () => result(),
  ...extra,
});

describe("SIEM Search", () => {
  it("an empty page asks the SIEMs nothing and explains what to type", async () => {
    params = "";
    const m = mockFetch(routes());
    renderWithQuery(<SiemSearchView />);
    expect(await screen.findByText(/Browse all of LogRhythm/)).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 150));
    expect(m.bodiesFor("POST /api/v1/events/siem-query")).toHaveLength(0);
  });

  it("browsing can be narrowed to entities and log source types, which are sent as ids", async () => {
    params = "browse=1&ent=7&st=1000639&st=86";
    const m = mockFetch(routes({
      "GET /api/v1/events/siem-scopes": () => ({ entities: [{ id: 7, name: "DC/System Devices" }], source_types: [{ id: 86, name: "Cisco Router", sources: 13 }, { id: 1000639, name: "Windows Security", sources: 44 }], errors: [] }),
    }));
    renderWithQuery(<SiemSearchView />);
    expect(await screen.findByText("Entities · 1 selected")).toBeInTheDocument();
    expect(screen.getByText("Log source types · 2 selected")).toBeInTheDocument();
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/events/siem-query")).toHaveLength(1));
    const body = m.bodiesFor("POST /api/v1/events/siem-query")[0] as { browse: boolean; entity_ids: number[]; source_type_ids: number[] };
    expect(body).toMatchObject({ browse: true, entity_ids: [7], source_type_ids: [1000639, 86] });
  });

  it("sends the query straight to the SIEMs (no aggregations, no stored search) and shows each source's answer, including a failure", async () => {
    params = "q=203.0.113.5";
    const m = mockFetch(routes());
    renderWithQuery(<SiemSearchView />);
    expect(await screen.findByText("2 events")).toBeInTheDocument();
    const body = m.bodiesFor("POST /api/v1/events/siem-query")[0] as { q: string; aggregations: unknown[]; sources?: string[] };
    expect(body.q).toBe("203.0.113.5");
    expect(body.aggregations).toEqual([]);
    expect(body.sources).toBeUndefined(); // every source
    expect(m.bodiesFor("POST /api/v1/events/search")).toHaveLength(0); // the stored index is not searched
    const list = screen.getByRole("list", { name: "Sources searched" });
    expect(within(list).getByText("2 of 5 read match")).toBeInTheDocument();
    expect(within(list).getByText("Trend returned 500")).toBeInTheDocument();
    expect(screen.getByText(/held for 30 minutes, not stored/)).toBeInTheDocument();
  });

  it("opening a row imports just that event first, then shows it in the drawer", async () => {
    params = "q=203.0.113.5";
    const m = mockFetch(routes({
      "POST /api/v1/events/siem-import": () => ({ requested: 1, imported: 1, duplicates: 0, expired: 0 }),
    }));
    renderWithQuery(<SiemSearchView />);
    await screen.findByText("2 events");
    await userEvent.click(within(screen.getByRole("table")).getByText("srv9"));
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/events/siem-import")).toHaveLength(1));
    expect(m.bodiesFor("POST /api/v1/events/siem-import")[0]).toEqual({ search_id: "s".repeat(32), ids: [ID("a")] });
    await waitFor(() => expect(replace).toHaveBeenCalledWith(expect.stringContaining(`event=${ID("a")}`), expect.anything()));
  });

  it("says so when a held result has expired instead of opening nothing", async () => {
    params = "q=203.0.113.5";
    mockFetch(routes({ "POST /api/v1/events/siem-import": () => ({ requested: 1, imported: 0, expired: 1 }) }));
    renderWithQuery(<SiemSearchView />);
    await screen.findByText("2 events");
    await userEvent.click(within(screen.getByRole("table")).getByText("srv8"));
    expect(await screen.findByText(/no longer held/)).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });

  it("zero results is stated with the reasons to check, and what a source could not be asked is shown", async () => {
    params = "q=zzz";
    mockFetch(routes({ "POST /api/v1/events/siem-query": () => result({ hits: [], total: 0, sources: [{ id: "l1", name: "LogRhythm SIEM", kind: "logrhythm", status: "ok", detail: "", searched: [], skipped: ["LogRhythm can't be searched by process.parent.name; they are applied to the logs it returns"], scanned: 0, matched: 0, capped: false, found: 0, found_at_least: false, ms: 5 }] }) }));
    renderWithQuery(<SiemSearchView />);
    expect(await screen.findByText("Nothing found in the SIEMs")).toBeInTheDocument();
    expect(screen.getByText(/can't be searched by process.parent.name/)).toBeInTheDocument();
  });

  it("a search can be limited to some sources (kept in the URL)", async () => {
    params = "q=x";
    mockFetch(routes());
    renderWithQuery(<SiemSearchView />);
    await screen.findByText("2 events");
    await userEvent.click(screen.getByLabelText("Search Trend endpoint"));
    expect(replace).toHaveBeenCalledWith(expect.stringContaining("src=l1"), expect.anything());
    expect(replace.mock.calls[0][0]).not.toContain("src=t1");
  });

  it("with no SIEM source configured it says how to add one", async () => {
    params = "q=x";
    mockFetch(routes({ "POST /api/v1/events/siem-query": () => result({ no_sources: true, hits: [], total: 0, sources: [] }) }));
    renderWithQuery(<SiemSearchView />);
    expect(await screen.findByText("No SIEM source to search")).toBeInTheDocument();
  });

  it("the side panel counts come from the results themselves", async () => {
    params = "q=x";
    mockFetch(routes());
    renderWithQuery(<SiemSearchView />);
    await screen.findByText("2 events");
    const aside = document.querySelector("aside") as HTMLElement;
    expect(within(aside).getByText("bob")).toBeInTheDocument();
  });
});

describe("an empty source is a clear answer, not a silent zero", () => {
  it("says what was searched and that the source holds nothing, while another source's hits are shown", async () => {
    params = "q=102.152.15.254";
    mockFetch(routes({ "POST /api/v1/events/siem-query": () => result({
      sources: [
        { id: "l1", name: "LogRhythm SIEM", kind: "logrhythm", status: "ok", detail: "", searched: ["ip: 102.152.15.254"], skipped: [], scanned: 0, matched: 0, capped: false, found: 0, found_at_least: false, ms: 4800 },
        { id: "t1", name: "Trend Vision One - Identity activity (Entra ID)", kind: "trend:identity_activity", status: "ok", detail: "", searched: [], skipped: [], scanned: 3, matched: 3, capped: false, found: 3, found_at_least: false, ms: 1200 },
      ],
    }) }));
    renderWithQuery(<SiemSearchView />);
    const list = await screen.findByRole("list", { name: "Sources searched" });
    expect(within(list).getByText(/No log found/)).toHaveTextContent("ip: 102.152.15.254");
    expect(within(list).getByText(/holds nothing for it in this time range/)).toBeInTheDocument();
    expect(within(list).getByText("3 of 3 read match")).toBeInTheDocument();
  });
});

describe("source filter on the results", () => {
  it("shows which source each row came from and narrows the table to one source, with counts", async () => {
    params = "q=x";
    mockFetch(routes());
    renderWithQuery(<SiemSearchView />);
    await screen.findByText("2 events");
    const table = screen.getByRole("table");
    expect(within(table).getByRole("columnheader", { name: "Source" })).toBeInTheDocument();
    const rowOf = (host: string) => within(table).getByText(host).closest("tr") as HTMLElement;
    expect(within(rowOf("srv9")).getByText("LogRhythm")).toBeInTheDocument();
    expect(within(rowOf("srv8")).getByText("Trend · endpoint activity")).toBeInTheDocument();
    const group = screen.getByRole("group", { name: "Filter results by source" });
    expect(within(group).getByRole("button", { name: /^All 2/ })).toHaveAttribute("aria-pressed", "true");
    expect(within(group).getByRole("button", { name: /LogRhythm 1/ })).toBeEnabled();
    await userEvent.click(within(group).getByRole("button", { name: /LogRhythm 1/ }));
    expect(within(screen.getByRole("table")).queryByText("srv8")).toBeNull();
    expect(within(screen.getByRole("table")).getByText("srv9")).toBeInTheDocument();
    expect(screen.getByText("1 of 2 events")).toBeInTheDocument();
    await userEvent.click(within(group).getByRole("button", { name: /LogRhythm 1/ })); // pressing it again clears the filter
    expect(screen.getByText("2 events")).toBeInTheDocument();
  });

  it("a source that returned nothing cannot be selected", async () => {
    params = "q=x";
    mockFetch(routes({ "POST /api/v1/events/siem-query": () => result({ origins: { [ID("a")]: "l1", [ID("b")]: "l1" } }) }));
    renderWithQuery(<SiemSearchView />);
    await screen.findByText("2 events");
    const group = screen.getByRole("group", { name: "Filter results by source" });
    expect(within(group).getByRole("button", { name: /Trend · endpoint activity 0/ })).toBeDisabled();
  });
});

describe("SIEM Search: a result larger than the first page", () => {
  const SID = "s".repeat(32);
  const url = (offset: number) => `GET /api/v1/events/siem-query/${SID}/hits?offset=${offset}&limit=500`;
  const big = () => result({
    total: 5, truncated: true, found: 27741, found_at_least: true,
    sources: [{ id: "l1", name: "LogRhythm SIEM", kind: "logrhythm", status: "ok", detail: "", searched: ["ip: 10.210.152.249"], skipped: [], scanned: 5, matched: 5, capped: true, found: 27741, found_at_least: true, ms: 900 }],
  });
  const page = (offset: number, ...cs: string[]) => ({
    expired: false, total: 5, offset,
    hits: cs.map((c, i) => hit(c, `srv-${c}`, `2026-10-13T0${8 - i}:00:00Z`)),
    origins: Object.fromEntries(cs.map((c) => [ID(c), "l1"])),
  });

  it("says how much the SIEM reported and how much was read, instead of silently stopping", async () => {
    params = "q=10.210.152.249";
    mockFetch(routes({ "POST /api/v1/events/siem-query": big }));
    renderWithQuery(<SiemSearchView />);
    await screen.findByText("5+ events");
    const list = screen.getByRole("list", { name: "Sources searched" });
    expect(within(list).getByText(/the SIEM reports at least 27,741 logs/)).toBeInTheDocument();
    expect(within(list).getByText(/only the newest 5 were read/)).toBeInTheDocument();
    expect(screen.getByText(/more than can be held \(at least 27,741 found\)/)).toBeInTheDocument();
  });

  it("loads the next page of the held result on demand and appends it, without searching again", async () => {
    params = "q=10.210.152.249";
    const m = mockFetch(routes({ "POST /api/v1/events/siem-query": () => ({ ...big(), total: 5 }), [url(2)]: () => page(2, "c", "d", "e") }));
    renderWithQuery(<SiemSearchView />);
    expect(await screen.findByText(/2 of 5 events loaded/)).toBeInTheDocument();
    expect(screen.queryByText("srv-c")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Load next 3" }));
    await waitFor(() => expect(within(screen.getByRole("table")).getByText("srv-c")).toBeInTheDocument());
    expect(within(screen.getByRole("table")).getByText("srv-e")).toBeInTheDocument();
    expect(screen.queryByText(/events loaded/)).not.toBeInTheDocument(); // everything held is on the page now
    expect(m.bodiesFor("POST /api/v1/events/siem-query")).toHaveLength(1); // the SIEMs were not asked again
  });

  it("'Load all' keeps fetching pages until everything held is loaded", async () => {
    params = "q=10.210.152.249";
    const m = mockFetch(routes({ "POST /api/v1/events/siem-query": big, [url(2)]: () => page(2, "c", "d"), [url(4)]: () => page(4, "e") }));
    renderWithQuery(<SiemSearchView />);
    await userEvent.click(await screen.findByRole("button", { name: "Load all 5" }));
    await waitFor(() => expect(within(screen.getByRole("table")).getByText("srv-e")).toBeInTheDocument());
    expect(m.calls.filter((c) => c.key.includes("/hits?offset=")).map((c) => c.key)).toEqual([url(2), url(4)]);
  });

  it("tells you when the held result has expired instead of showing a half-loaded table as complete", async () => {
    params = "q=10.210.152.249";
    mockFetch(routes({ "POST /api/v1/events/siem-query": big, [url(2)]: () => ({ expired: true, hits: [], origins: {}, total: 0, offset: 2 }) }));
    renderWithQuery(<SiemSearchView />);
    await userEvent.click(await screen.findByRole("button", { name: "Load next 3" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/no longer held/);
    expect(screen.getByText(/2 of 5 events loaded/)).toBeInTheDocument();
  });
});

describe("SIEM Search: a search outlives the page", () => {
  const SID = "s".repeat(32);
  const client = () => new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 5 * 60_000 } } });
  const mount = (qc: QueryClient) => render(<QueryClientProvider client={qc}><SiemSearchView /></QueryClientProvider>);

  it("a search still running when you leave is finished and shown when you come back by the plain sidebar link", async () => {
    const qc = client();
    params = "q=10.210.152.249";
    const m = mockFetch(routes({ "POST /api/v1/events/siem-query": (() => { let n = 0; return () => { n++; return n === 1 ? new Promise((r) => setTimeout(() => r(result()), 300)) : result(); }; })() as never }));
    const first = mount(qc);
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/events/siem-query")).toHaveLength(1));
    first.unmount(); // another module opens while the SIEM is still answering
    await new Promise((r) => setTimeout(r, 450));
    params = ""; replace.mockClear(); // the sidebar link carries no query
    const back = mount(qc);
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/events?q=10.210.152.249", expect.anything()));
    params = "q=10.210.152.249"; back.unmount(); mount(qc);
    expect(await screen.findByText("2 events")).toBeInTheDocument(); // the result is there ...
    expect(m.bodiesFor("POST /api/v1/events/siem-query")).toHaveLength(1); // ... and the SIEMs were not asked again
  });

  it("brings back the same search after a re-run (the nonce) and the pages already loaded", async () => {
    const qc = client();
    params = "q=10.210.152.249";
    const page = { expired: false, total: 5, offset: 2, hits: [hit("c", "srv-c", "2026-10-13T08:00:00Z")], origins: { [ID("c")]: "l1" } };
    const m = mockFetch(routes({
      "POST /api/v1/events/siem-query": () => result({ total: 5, truncated: true }),
      [`GET /api/v1/events/siem-query/${SID}/hits?offset=2&limit=500`]: () => page,
    }));
    const first = mount(qc);
    await userEvent.click(await screen.findByRole("button", { name: "Search the SIEMs" }));
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/events/siem-query")).toHaveLength(2));
    await userEvent.click(await screen.findByRole("button", { name: "Load next 3" }));
    await waitFor(() => expect(within(screen.getByRole("table")).getByText("srv-c")).toBeInTheDocument());
    first.unmount();
    params = ""; replace.mockClear();
    mount(qc).unmount();
    await waitFor(() => expect(replace).toHaveBeenCalled());
    params = "q=10.210.152.249"; mount(qc);
    await waitFor(() => expect(within(screen.getByRole("table")).getByText("srv-c")).toBeInTheDocument()); // the loaded page survived
    expect(m.bodiesFor("POST /api/v1/events/siem-query")).toHaveLength(2); // no third search
  });

  it("'Load all' keeps going after you leave, and what it fetched is there on return", async () => {
    const qc = client();
    params = "q=10.210.152.249";
    const p2 = () => new Promise((r) => setTimeout(() => r({ expired: false, total: 5, offset: 2, hits: [hit("c", "srv-c", "2026-10-13T08:00:00Z"), hit("d", "srv-d", "2026-10-13T07:00:00Z")], origins: {} }), 200)) as never;
    const p4 = () => ({ expired: false, total: 5, offset: 4, hits: [hit("e", "srv-e", "2026-10-13T06:00:00Z")], origins: {} });
    const m = mockFetch(routes({
      "POST /api/v1/events/siem-query": () => result({ total: 5, truncated: true }),
      [`GET /api/v1/events/siem-query/${SID}/hits?offset=2&limit=500`]: p2,
      [`GET /api/v1/events/siem-query/${SID}/hits?offset=4&limit=500`]: p4,
    }));
    const first = mount(qc);
    await userEvent.click(await screen.findByRole("button", { name: "Load all 5" }));
    first.unmount(); // leaves while the first page is still being fetched
    await waitFor(() => expect(m.calls.filter((c) => c.key.includes("offset=4"))).toHaveLength(1), { timeout: 2000 }); // the loop went on without the page
    mount(qc);
    await waitFor(() => expect(within(screen.getByRole("table")).getByText("srv-e")).toBeInTheDocument());
    expect(screen.queryByText(/events loaded/)).not.toBeInTheDocument();
  });

  it("clearing the search forgets it, so the next visit starts empty", async () => {
    const qc = client();
    params = "q=10.210.152.249";
    mockFetch(routes());
    const first = mount(qc);
    await screen.findByText("2 events");
    params = ""; first.rerender(<QueryClientProvider client={qc}><SiemSearchView /></QueryClientProvider>);
    first.unmount(); replace.mockClear();
    mount(qc);
    await new Promise((r) => setTimeout(r, 100));
    expect(replace).not.toHaveBeenCalled();
    expect(screen.getByText(/Browse all of LogRhythm/)).toBeInTheDocument();
  });
});
