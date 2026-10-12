import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { CanvasProps } from "@/components/threat-map-canvas";
import { ThreatMapView } from "@/components/threat-map-view";
import type { IndicatorDetail, MapData, MapMarker, MapStatus } from "@/lib/threat-map";
import { mockFetch, renderWithQuery, status } from "./helpers";

let perms: string[] = [];
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => perms.includes(p) }), useOptionalAuth: () => null }));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams(), useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));

// WebGL is not available in jsdom: the canvas is replaced by a stub that exposes the same props and callbacks the real map uses.
let lastProps: CanvasProps | null = null;
vi.mock("@/components/threat-map-canvas", () => ({
  default: (p: CanvasProps) => {
    lastProps = p;
    return (
      <div data-testid="canvas">
        {p.markers.map((m) => <button key={m.ip} onClick={() => p.onSelect(m.ip)}>marker {m.ip}</button>)}
        <button onClick={() => p.onCountry("DE")}>country DE</button>
      </div>
    );
  },
}));

beforeEach(() => { perms = ["intel:read", "events:read"]; lastProps = null; });

const marker = (ip: string, o: Partial<MapMarker> = {}): MapMarker => ({
  ip, geo: { country: "DE", country_name: "Germany", continent: "EU", city: "Berlin", region: "Berlin", lat: 52.5, lon: 13.4, asn: 64496, org: "Example Hosting" },
  layers: ["intelligence"], severity: "high", weight: 10, last_seen: "2026-10-12T09:00:00Z",
  intel: { iocs: 1, confidence: 90, severity: "high", sources: ["MISP"], threat_types: ["botnet_cc"], malware: ["Emotet"], threats: [], tags: [], statuses: ["VALIDATED"], first_seen: "2026-10-10T00:00:00Z", last_seen: "2026-10-12T09:00:00Z", stale: false, references: [], ioc_ids: ["i1"] },
  observed: null, hunt_matches: 0, ...o,
});
const data = (o: Partial<MapData> = {}): MapData => ({
  layer: "intelligence", range: { start: "2026-10-11T09:00:00Z", end: "2026-10-12T09:00:00Z" }, active_filters: {},
  cards: { unique_malicious_ips: 2, countries_with_indicators: 1, top_indicator_country: { iso: "DE", name: "Germany", ips: 2 }, observed_events: 1234, observed_remote_ips: 7, internal_addresses: 0, correlated_threats: 1, correlated_ips: 1, high_severity_detections: 3 },
  countries: [{ iso: "DE", name: "Germany", ips: 2, events: 0, correlated: 0, iocs: 2, value: 2 }], markers: [marker("185.220.101.5"), marker("185.220.101.6")], unlocated: 0, truncated: false, total_markers: 2,
  top_countries: [{ iso: "DE", name: "Germany", ips: 2, events: 0, correlated: 0, iocs: 2, value: 2 }], top_ips: [marker("185.220.101.5")], internal: [],
  recent_correlations: [], partial: [], timeline: { points: [{ t: "2026-10-12T08:00:00Z", count: 3 }], unit: "1h", layer: "intelligence" }, notes: [], generated_at: new Date().toISOString(), ...o,
});
const st = (o: Partial<MapStatus> = {}): MapStatus => ({
  geoip: { provider: "DBIP-City-Lite", available: true, asn: true, attribution: "IP geolocation by DB-IP (CC BY 4.0)" }, home: null,
  layers: {
    intelligence: { available: true, needs: "", feeds: ["MISP", "OTX"] }, observed: { available: true, needs: "", sources: [{ source: "firewall", events: 10 }] },
    correlated: { available: true, needs: "" },
  }, mappable_ioc_types: ["ip"], disclaimer: "approximate", ...o,
});
const detail = (o: Partial<IndicatorDetail> = {}): IndicatorDetail => ({
  ip: "185.220.101.5", class: "public", geo: marker("x").geo, geo_note: "Approximate location of the address from a GeoIP database; not the location of whoever operates it.",
  intel: [{ id: "i1", source: "MISP", confidence: 90, severity: "high", threat_type: "botnet_cc", malware: "Emotet", threat: "Emotet", threat_id: null, tags: [], first_seen: "2026-10-10T00:00:00Z", last_seen: "2026-10-12T09:00:00Z", status: "VALIDATED", description: "C2 node", reference: "https://example.org/report", case_id: null, stale: false }],
  related_iocs: [{ id: "r1", type: "domain", value: "bad.example", confidence: 80, source: "MISP" }], observed: { events: 4, as_source: 0, as_destination: 4, as_signin_source: 0, first_seen: "2026-10-12T08:00:00Z", last_seen: "2026-10-12T09:00:00Z", max_severity: "medium", sources: ["firewall"], ports: [443] },
  events: [{ id: "e".repeat(32), timestamp: "2026-10-12T09:00:00Z", source: "firewall", event_type: "network_connection", severity: 40, summary: "10.0.0.5 -> 185.220.101.5:443", src_ip: "10.0.0.5", dst_ip: "185.220.101.5", dst_port: 443, protocol: "tcp", host: "WS-1" }],
  events_total: 4, peers: [], hunt_matches: [], alerts: [], cases: [], correlated: true, correlation_reason: "185.220.101.5 is reported by MISP and appears in 4 of your events.",
  actions: { investigate: true, intel_lookup: true, hunt: true, add_to_watchlist: false, add_to_case: true }, ...o,
});
const base = (over: Record<string, () => unknown> = {}) => mockFetch({
  "GET /api/v1/threat-map/status": () => st(), "GET /api/v1/threat-map/data": () => data(), "GET /api/v1/threat-map/flows": () => ({ flows: [], home: null, reason: "" }),
  "GET /api/v1/threat-map/indicator": () => detail(), ...over,
});
const urls = (m: ReturnType<typeof mockFetch>, part: string) => m.fn.mock.calls.map((c) => String(c[0])).filter((u) => u.includes(part));

it("shows real metrics from the API and the three layers", async () => {
  base();
  renderWithQuery(<ThreatMapView />);
  await waitFor(() => expect(screen.getByRole("group", { name: "Unique malicious IPs" })).toHaveTextContent("2"));
  expect(screen.getByRole("group", { name: "Observed network events" })).toHaveTextContent("1,234");
  expect(screen.getByRole("group", { name: "High-severity detections" })).toHaveTextContent("3");
  const tabs = screen.getAllByRole("tab");
  expect(tabs.map((t) => t.textContent)).toEqual([
    expect.stringContaining("Global threat intelligence"), expect.stringContaining("Observed network activity"), expect.stringContaining("Correlated threats"),
  ]);
  expect(tabs[0]).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText(/not attacker locations/i)).toBeInTheDocument();
  await waitFor(() => expect(lastProps?.markers).toHaveLength(2));
  expect(lastProps?.showFlows).toBe(false); // intelligence has no source/destination relationship
});

it("switching layer and range changes the backend query", async () => {
  const m = base();
  renderWithQuery(<ThreatMapView />);
  await screen.findByRole("group", { name: "Unique malicious IPs" });
  await userEvent.click(screen.getByRole("tab", { name: /Observed network activity/ }));
  await waitFor(() => expect(urls(m, "/threat-map/data").some((u) => u.includes("layer=observed"))).toBe(true));
  await userEvent.click(screen.getByRole("button", { name: "7 d" }));
  await waitFor(() => expect(urls(m, "/threat-map/data").some((u) => u.includes("layer=observed") && u.includes("range=7d"))).toBe(true));
  await waitFor(() => expect(urls(m, "/threat-map/flows").length).toBeGreaterThan(0)); // arcs are only requested for layers that can have them
  expect(urls(m, "/threat-map/flows").every((u) => u.includes("layer=observed"))).toBe(true);
});

it("filters are real: they reach the API, show as removable chips, and can be cleared", async () => {
  const m = base();
  renderWithQuery(<ThreatMapView />);
  await screen.findByRole("group", { name: "Unique malicious IPs" });
  await userEvent.selectOptions(screen.getByLabelText("Minimum severity"), "high");
  await userEvent.click(screen.getByRole("button", { name: /More filters/ })); // advanced filters are behind progressive disclosure
  await userEvent.selectOptions(screen.getByLabelText("Region"), "EU");
  await userEvent.type(screen.getByLabelText("Minimum confidence"), "{backspace}70");
  await waitFor(() => expect(urls(m, "/threat-map/data").some((u) => u.includes("severity=high") && u.includes("continent=EU") && u.includes("min_confidence=70"))).toBe(true));
  const chips = screen.getByLabelText("Active filters");
  expect(within(chips).getByRole("button", { name: /Severity ≥ high/ })).toBeInTheDocument();
  expect(within(chips).getByRole("button", { name: /Region: Europe/ })).toBeInTheDocument();
  await userEvent.click(within(chips).getByRole("button", { name: /Remove filter Severity/ }));
  await waitFor(() => expect(screen.queryByRole("button", { name: /Remove filter Severity/ })).toBeNull());
  await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
  await waitFor(() => expect(screen.queryByLabelText("Active filters")).toBeNull());
  const last = urls(m, "/threat-map/data").at(-1)!;
  expect(last).toContain("layer=intelligence"); expect(last).not.toContain("severity="); expect(last).not.toContain("continent=");
});

it("debounces the text search: one request for a typed word, not one per keystroke", async () => {
  const m = base();
  renderWithQuery(<ThreatMapView />);
  await screen.findByRole("group", { name: "Unique malicious IPs" });
  const before = urls(m, "/threat-map/data").length;
  await userEvent.type(screen.getByLabelText("Search"), "AS15169");
  await waitFor(() => expect(urls(m, "/threat-map/data").some((u) => u.includes("q=AS15169"))).toBe(true));
  const withQ = urls(m, "/threat-map/data").filter((u) => u.includes("q="));
  expect(withQ).toHaveLength(1);
  expect(urls(m, "/threat-map/data").length - before).toBe(1);
});

it("clicking a country on the map or in the ranking applies a country filter", async () => {
  const m = base();
  renderWithQuery(<ThreatMapView />);
  await userEvent.click(await screen.findByRole("button", { name: "country DE" }));
  await waitFor(() => expect(urls(m, "/threat-map/data").some((u) => u.includes("country=DE"))).toBe(true));
  expect(screen.getByRole("button", { name: /Remove filter Country: DE/ })).toBeInTheDocument();
});

it("an invalid custom range is reported and no request is made for it", async () => {
  const m = base();
  renderWithQuery(<ThreatMapView />);
  await screen.findByRole("group", { name: "Unique malicious IPs" });
  await userEvent.click(screen.getByRole("button", { name: "Custom" }));
  await userEvent.type(screen.getByLabelText("Range start"), "2026-10-02T00:00");
  await userEvent.type(screen.getByLabelText("Range end"), "2026-10-01T00:00");
  await userEvent.click(screen.getByRole("button", { name: "Apply" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/after start/i);
  expect(urls(m, "/threat-map/data").every((u) => !u.includes("range=custom"))).toBe(true);
});

describe("states", () => {
  it("empty with no filters explains which integration is missing", async () => {
    base({ "GET /api/v1/threat-map/data": () => data({ markers: [], countries: [], top_countries: [], top_ips: [], total_markers: 0 }),
      "GET /api/v1/threat-map/status": () => st({ layers: { intelligence: { available: false, needs: "Add an IOC feed (IOC Hunting → Feeds)", feeds: [] }, observed: { available: false, needs: "Connect a firewall" }, correlated: { available: false, needs: "Needs both" } } }) });
    renderWithQuery(<ThreatMapView />);
    const empty = await screen.findByTestId("map-empty");
    expect(empty).toHaveTextContent(/No global threat intelligence in this time range/i);
    expect(empty).toHaveTextContent("Add an IOC feed");
    expect(screen.getAllByText("needs data").length).toBeGreaterThan(0);
  });

  it("empty with filters says so and offers to clear them", async () => {
    base({ "GET /api/v1/threat-map/data": () => data({ markers: [], total_markers: 0 }) });
    renderWithQuery(<ThreatMapView />);
    await screen.findByRole("group", { name: "Unique malicious IPs" });
    await userEvent.selectOptions(screen.getByLabelText("Minimum severity"), "critical");
    const empty = await screen.findByTestId("map-empty");
    expect(empty).toHaveTextContent("Nothing matches these filters");
    await userEvent.click(within(empty).getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(screen.queryByLabelText("Active filters")).toBeNull());
  });

  it("a failed request shows an error with retry, and never shows data that does not match the new filters", async () => {
    let fail = true;
    const m = base({ "GET /api/v1/threat-map/data": () => (fail ? status(500, { error: { code: "internal", message: "boom" } }) : data()) });
    renderWithQuery(<ThreatMapView />);
    const alert = (await screen.findAllByRole("alert"))[0];
    expect(alert).toHaveTextContent(/boom|Could not load/i);
    fail = false;
    await userEvent.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("marker 185.220.101.5")).toBeInTheDocument();
    fail = true;
    await userEvent.click(screen.getByRole("button", { name: "7 d" }));
    await waitFor(() => expect(urls(m, "/threat-map/data").length).toBeGreaterThan(2));
    expect((await screen.findAllByRole("alert"))[0]).toHaveTextContent(/boom|Could not load/i); // not the 24h data under a 7d label
    expect(screen.queryByText("marker 185.220.101.5")).toBeNull();
  });

  it("warns when there is no GeoIP database, when telemetry is down, and when the map is truncated", async () => {
    base({
      "GET /api/v1/threat-map/status": () => st({ geoip: { provider: "none", available: false, asn: false, attribution: "" } }),
      "GET /api/v1/threat-map/data": () => data({ partial: ["telemetry"], truncated: true, total_markers: 5000, unlocated: 3, notes: ["Showing the busiest 3,000 addresses per field"] }),
    });
    renderWithQuery(<ThreatMapView />);
    expect(await screen.findByText(/No GeoIP database is configured/)).toBeInTheDocument();
    expect(screen.getByText(/Telemetry search is unavailable/)).toBeInTheDocument();
    // informational notes are folded into one disclosure instead of stacking over the map
    const notes = screen.getByText(/Map notes \(3\)/);
    await userEvent.click(notes);
    expect(screen.getByText(/of 5,000 located addresses/)).toBeVisible();
    expect(screen.getByText(/3 addresses could not be located/)).toBeVisible();
    expect(screen.getByText(/busiest 3,000/)).toBeVisible();
  });

  it("shows internal addresses separately, labelled as not mappable", async () => {
    base({ "GET /api/v1/threat-map/data": () => data({ layer: "observed", markers: [], total_markers: 0, internal: [{ ip: "10.0.0.5", class: "private", events: 9, as_source: 9, as_destination: 0, as_signin_source: 0, first_seen: null, last_seen: null, max_severity: "info", sources: [], ports: [] }] }) });
    renderWithQuery(<ThreatMapView />);
    await screen.findByRole("group", { name: "Unique malicious IPs" });
    await userEvent.click(screen.getByRole("tab", { name: /Observed network activity/ }));
    const sec = await screen.findByRole("region", { name: "Internal and non-routable addresses" });
    expect(sec).toHaveTextContent("not mappable");
    expect(sec).toHaveTextContent("10.0.0.5");
  });
});

describe("marker -> investigation panel", () => {
  it("opens beside the map without leaving the page and shows provenance and the approximation note", async () => {
    const m = base();
    renderWithQuery(<ThreatMapView />);
    await userEvent.click(await screen.findByRole("button", { name: "marker 185.220.101.5" }));
    const panel = await screen.findByRole("complementary", { name: "Indicator investigation" });
    expect((await within(panel).findAllByText("MISP")).length).toBeGreaterThan(0);
    expect(panel).toHaveTextContent("Emotet");
    expect(panel).toHaveTextContent("AS64496");
    expect(panel).toHaveTextContent(/not the location of whoever operates it/);
    expect(panel).toHaveTextContent(/not evidence of an attack on your organisation/);
    expect(panel).toHaveTextContent("reported by intelligence");
    expect(panel).toHaveTextContent("seen in your telemetry");
    expect(panel).toHaveTextContent("185.220.101.5 is reported by MISP and appears in 4 of your events.");
    expect(urls(m, "/threat-map/indicator")[0]).toContain("ip=185.220.101.5");
    expect(screen.getByTestId("canvas")).toBeInTheDocument(); // the map stays mounted
    await userEvent.click(within(panel).getByRole("button", { name: "Close investigation panel" }));
    expect(screen.queryByRole("complementary", { name: "Indicator investigation" })).toBeNull();
  });

  it("offers only the actions this user may perform, wired to the existing workflows", async () => {
    perms = ["intel:read", "events:read", "iochunt:validate"];
    const m = base({
      "POST /api/v1/ioc/iocs/validate": () => ({ id: "abcdef1234567890", name: "h", status: "RUNNING" }),
    });
    renderWithQuery(<ThreatMapView />);
    await userEvent.click(await screen.findByRole("button", { name: "marker 185.220.101.5" }));
    const panel = await screen.findByRole("complementary", { name: "Indicator investigation" });
    const inv = await within(panel).findByRole("link", { name: "Investigate this IP" });
    const href = new URL(inv.getAttribute("href")!, "http://x");
    expect(href.pathname).toBe("/events");
    expect(href.searchParams.get("q")).toBe("network.dst_ip:185.220.101.5"); // a single valid field search, not an OR the server would reject
    const roles = within(panel).getByRole("group", { name: "View related events" });
    expect(within(roles).getByRole("link", { name: "As destination (4)" })).toHaveAttribute("href", expect.stringContaining("network.dst_ip"));
    expect(within(roles).queryByRole("link", { name: /As source/ })).toBeNull(); // only roles that have events are offered
    expect(within(panel).getByRole("button", { name: /^Copy IOC/ })).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: /^Copy defanged/ })).toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: "Add to IOC queue" })).toBeNull(); // it is already an IOC
    await userEvent.click(within(panel).getByRole("button", { name: "Launch threat hunt" }));
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/ioc/iocs/validate")[0]).toMatchObject({ ioc_ids: ["i1"], lookback_days: 7 }));
    expect(await within(panel).findByRole("status")).toHaveTextContent(/Hunt started/);
    expect(within(panel).getByRole("link", { name: "Open IOC Hunting" })).toHaveAttribute("href", "/ioc-hunting");
  });

  it("hides actions the server did not authorise", async () => {
    base({ "GET /api/v1/threat-map/indicator": () => detail({ actions: { investigate: true, intel_lookup: false, hunt: false, add_to_watchlist: false, add_to_case: false } }) });
    renderWithQuery(<ThreatMapView />);
    await userEvent.click(await screen.findByRole("button", { name: "marker 185.220.101.5" }));
    const panel = await screen.findByRole("complementary", { name: "Indicator investigation" });
    await within(panel).findByRole("link", { name: "Investigate this IP" });
    for (const n of ["Launch threat hunt", "Add to case", "Add to IOC queue", "Open intelligence record"]) expect(within(panel).queryByRole("button", { name: n })).toBeNull();
  });

  it("an unreported address can be queued as an IOC when allowed", async () => {
    const m = base({
      "GET /api/v1/threat-map/indicator": () => detail({ intel: [], correlated: false, correlation_reason: "", actions: { investigate: true, intel_lookup: false, hunt: false, add_to_watchlist: true, add_to_case: false } }),
      "POST /api/v1/ioc/iocs": () => ({ id: "n1", type: "ip", value: "185.220.101.5" }),
    });
    renderWithQuery(<ThreatMapView />);
    await userEvent.click(await screen.findByRole("button", { name: "marker 185.220.101.5" }));
    const panel = await screen.findByRole("complementary", { name: "Indicator investigation" });
    await userEvent.click(await within(panel).findByRole("button", { name: "Add to IOC queue" }));
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/ioc/iocs")[0]).toMatchObject({ type: "ip", value: "185.220.101.5" }));
    expect(within(panel).getByText(/No feed or analyst record reports this address/)).toBeInTheDocument();
  });

  it("renders feed-supplied text as text, and only http(s) source links", async () => {
    const evil = '<img src=x onerror="window.__pwned=1">';
    base({ "GET /api/v1/threat-map/indicator": () => detail({ intel: [{ ...detail().intel[0], malware: evil, description: evil, reference: "https://example.org/r" }] }) });
    renderWithQuery(<ThreatMapView />);
    await userEvent.click(await screen.findByRole("button", { name: "marker 185.220.101.5" }));
    const panel = await screen.findByRole("complementary", { name: "Indicator investigation" });
    await within(panel).findAllByText("MISP");
    expect(panel.querySelector("img")).toBeNull();
    expect(panel.textContent).toContain(evil);
    const link = within(panel).getByRole("link", { name: /Source report/ });
    expect(link).toHaveAttribute("href", "https://example.org/r");
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });

  it("shows an error with retry when the indicator cannot be loaded", async () => {
    let fail = true;
    base({ "GET /api/v1/threat-map/indicator": () => (fail ? status(503, { error: { code: "upstream", message: "Search backend unavailable" } }) : detail()) });
    renderWithQuery(<ThreatMapView />);
    await userEvent.click(await screen.findByRole("button", { name: "marker 185.220.101.5" }));
    const panel = await screen.findByRole("complementary", { name: "Indicator investigation" });
    expect(await within(panel).findByText(/Search backend unavailable/)).toBeInTheDocument();
    fail = false;
    await userEvent.click(within(panel).getByRole("button", { name: "Retry" }));
    expect((await within(panel).findAllByText("MISP")).length).toBeGreaterThan(0);
  });
});

it("recent correlated detections are paginated from the API", async () => {
  const c = (n: number) => ({ id: `ip:1.1.1.${n}`, kind: "ip_match" as const, ip: `1.1.1.${n}`, ioc_type: "ip", ioc_value: `1.1.1.${n}`, reason: `reason ${n}`, source: "MISP", confidence: 90, severity: "high" as const, threat: "", first_seen: null, last_seen: "2026-10-12T09:00:00Z", events: 2, event_ids: [], host: "", matched_field: "", status: "NEW", case_id: null, country: "DE", ioc_ids: [] });
  const m = base({
    "GET /api/v1/threat-map/data": () => data({ cards: { ...data().cards, correlated_threats: 12 }, recent_correlations: [1, 2, 3, 4, 5, 6, 7, 8].map(c) }),
    "GET /api/v1/threat-map/correlations": () => ({ total: 12, limit: 8, offset: 8, items: [9, 10, 11, 12].map(c) }),
  });
  renderWithQuery(<ThreatMapView />);
  expect(await screen.findByText("reason 1")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Older correlations" }));
  expect(await screen.findByText("reason 9")).toBeInTheDocument();
  expect(urls(m, "/threat-map/correlations")[0]).toContain("offset=8");
  expect(screen.queryByText("reason 1")).toBeNull();
});
