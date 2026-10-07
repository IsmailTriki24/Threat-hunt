import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IocsTab } from "@/components/case-tabs";
import { EntityView } from "@/components/entity-view";
import { MatrixView, TechniqueView } from "@/components/mitre-views";
import { MitrePanel } from "@/components/mitre-panel";
import { ThreatIntelView } from "@/components/threat-intel-view";
import type { IntelDetail, IntelProvider, MatrixColumn, MitreSuggestion } from "@/lib/api-types";
import { mockFetch, renderWithQuery, status } from "./helpers";

let perms: string[] = [];
const push = vi.fn();
vi.mock("@/lib/auth", () => ({
  useAuth: () => ({ can: (p: string) => perms.includes(p), session: { user_id: "u1", email: "me@x" } }),
  useOptionalAuth: () => ({ can: (p: string) => perms.includes(p) }),
}));
vi.mock("next/link", () => ({ default: ({ href, children, ...r }: { href: string; children: React.ReactNode }) => <a href={href} {...r}>{children}</a> }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
beforeEach(() => { perms = ["intel:read", "intel:write", "intel:manage", "events:read", "mitre:read", "mitre:write", "cases:write", "cases:read"]; push.mockClear(); });

const EID = "e".repeat(32);
const ent = (o: object = {}) => ({
  id: "ent1", type: "ip", value: "203.0.113.45", verdict: "malicious", score: 92, watch_verdict: "malicious", watch_confidence: 90, notes: "n", tags: ["c2"],
  source: "lookup", last_enriched_at: "2026-03-01T10:00:00Z", created_at: "2026-03-01T10:00:00Z", updated_at: "2026-03-01T10:00:00Z", ...o,
});
const detail = (o: Partial<IntelDetail> = {}): IntelDetail => ({
  entity: ent() as never,
  score_breakdown: [{ provider: "watchlist", verdict: "malicious", confidence: 90, weight: 1, contribution: 90, summary: "Tenant watch-list" },
    { provider: "otx", verdict: "suspicious", confidence: 50, weight: 0.6, contribution: 15, summary: "1 pulse" }],
  observations: [
    { provider: "otx", status: "ok", verdict: "suspicious", confidence: 50, summary: "Referenced by 1 OTX pulse(s)", data: { pulses: ["<b>Campaign</b>"] }, fetched_at: "2026-03-01T10:00:00Z" },
    { provider: "virustotal", status: "error", verdict: "unknown", confidence: 0, summary: "rate limited by provider (HTTP 429)", data: {}, fetched_at: "2026-03-01T10:00:00Z" }],
  relations: [{ id: "r1", kind: "indicates", direction: "out", other: ent({ id: "m1", type: "malware", value: "emotet" }) as never, source: "threatfox" }],
  coverage: { answered: 2, failed: 1, not_found: 0, skipped: [{ provider: "misp", reason: "not configured" }] }, ...o,
});

describe("lookup & providers", () => {
  it("looks up an indicator with type override + refresh and navigates to the entity page", async () => {
    const m = mockFetch({ "POST /api/v1/intel/lookup": () => detail(), "GET /api/v1/intel/entities": () => [] });
    renderWithQuery(<ThreatIntelView />);
    await userEvent.type(screen.getByLabelText("Indicator"), " 203.0.113.45 ");
    await userEvent.selectOptions(screen.getByLabelText("Indicator type"), "ip");
    await userEvent.click(screen.getByLabelText("force refresh"));
    await userEvent.click(screen.getByRole("button", { name: "Look up" }));
    await waitFor(() => expect(push).toHaveBeenCalledWith("/threat-intel/ent1"));
    expect(m.bodiesFor("POST /api/v1/intel/lookup")[0]).toEqual({ value: "203.0.113.45", type: "ip", refresh: true });
  });

  it("viewers cannot run lookups", async () => {
    perms = ["intel:read"];
    mockFetch({ "GET /api/v1/intel/entities": () => [] });
    renderWithQuery(<ThreatIntelView />);
    expect(screen.getByLabelText("Indicator")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Look up" })).toBeDisabled();
  });

  it("entities tab renders verdict badge, score and watch-list; filters hit the API", async () => {
    const m = mockFetch({ "GET /api/v1/intel/entities": () => [ent()] });
    renderWithQuery(<ThreatIntelView />);
    expect(await screen.findByRole("link", { name: "203.0.113.45" })).toHaveAttribute("href", "/threat-intel/ent1");
    expect(screen.getByText("malicious (90)")).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: "Threat score" })).toHaveAttribute("aria-valuenow", "92");
    await userEvent.selectOptions(screen.getByLabelText("Filter verdict"), "malicious");
    await waitFor(() => expect(m.fn.mock.calls.some((c) => String(c[0]).includes("verdict=malicious"))).toBe(true));
  });

  const providers: IntelProvider[] = [
    { key: "heuristics", display_name: "Local heuristics", description: "d", supported_types: ["ip"], offline: true, secret_keys: [], config_schema: {}, configured: true, enabled: true, last_status: "ok", last_detail: "", last_checked_at: null },
    { key: "otx", display_name: "AlienVault OTX", description: "d", supported_types: ["ip"], offline: false, secret_keys: ["api_key"], config_schema: {}, configured: false, enabled: false, last_status: "unknown", last_detail: "", last_checked_at: null },
  ];

  it("shows the graceful-degradation banner and a write-only secret form that never echoes values", async () => {
    const m = mockFetch({
      "GET /api/v1/intel/entities": () => [], "GET /api/v1/intel/providers": () => providers,
      "PUT /api/v1/intel/providers/otx": () => ({ ...providers[1], configured: true, enabled: true }),
      "POST /api/v1/intel/providers/otx/test": () => ({ ok: true, detail: "HTTP 200" }),
    });
    renderWithQuery(<ThreatIntelView />);
    await userEvent.click(screen.getByRole("tab", { name: "providers" }));
    expect(await screen.findByRole("status")).toHaveTextContent(/not configured \(AlienVault OTX\).*local heuristics and your tenant watch-list/s);
    expect(screen.getByRole("region", { name: "Local heuristics" })).toHaveTextContent("offline");
    await userEvent.click(screen.getByRole("button", { name: "Configure AlienVault OTX" }));
    const key = screen.getByLabelText("api key");
    expect(key).toHaveAttribute("type", "password");
    await userEvent.type(key, "S3CRET");
    await userEvent.click(screen.getByRole("button", { name: "Test" }));
    expect(await screen.findByText("OK: HTTP 200")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(m.bodiesFor("PUT /api/v1/intel/providers/otx")).toHaveLength(1));
    expect(m.bodiesFor("PUT /api/v1/intel/providers/otx")[0]).toEqual({ enabled: true, config: {}, secrets: { api_key: "S3CRET" } });
    expect(document.body.textContent).not.toContain("S3CRET");
  });

  it("only intel:manage users can configure providers", async () => {
    perms = ["intel:read", "intel:write"];
    mockFetch({ "GET /api/v1/intel/entities": () => [], "GET /api/v1/intel/providers": () => providers });
    renderWithQuery(<ThreatIntelView />);
    await userEvent.click(screen.getByRole("tab", { name: "providers" }));
    expect(await screen.findByRole("button", { name: "Configure AlienVault OTX" })).toBeDisabled();
  });

  it("imports a STIX bundle and shows counts; rejects non-bundles locally", async () => {
    const m = mockFetch({ "GET /api/v1/intel/entities": () => [], "POST /api/v1/intel/import/stix": () => ({ created: 2, updated: 1, named_objects: 1, relations: 1, skipped: 4 }) });
    renderWithQuery(<ThreatIntelView />);
    await userEvent.click(screen.getByRole("tab", { name: "import" }));
    const box = screen.getByLabelText("STIX bundle JSON");
    await userEvent.click(box);
    await userEvent.paste('{"type":"nope"}');
    await userEvent.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Not a STIX/);
    expect(m.bodiesFor("POST /api/v1/intel/import/stix")).toHaveLength(0);
    await userEvent.clear(box);
    await userEvent.click(box);
    await userEvent.paste('{"type":"bundle","objects":[]}');
    await userEvent.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByText(/2 new · 1 updated · 1 named objects · 1 relations · 4 skipped/)).toBeInTheDocument();
  });
});

describe("entity page", () => {
  const routes = (extra: Record<string, () => unknown> = {}) => ({
    "GET /api/v1/intel/entities/ent1": () => detail({ coverage: null }),
    "GET /api/v1/intel/entities/ent1/sightings": () => ({ total: 3, by_field: { "network.dst_ip": 3 }, days: 30, hosts: [{ key: "ws-01", count: 3 }], first_seen: "2026-03-01T09:00:00Z", last_seen: "2026-03-01T10:00:00Z", recent: [] }),
    ...extra,
  });

  it("renders the score breakdown, model note, observations (as text) and provider errors without implying clean", async () => {
    mockFetch(routes());
    renderWithQuery(<EntityView id="ent1" />);
    expect(await screen.findByRole("heading", { name: "203[.]0[.]113[.]45" })).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("watchlist")).toBeInTheDocument();
    expect(within(table).getByText("+90")).toBeInTheDocument();
    expect(screen.getByText(/“Unknown” means no evidence either way/)).toBeInTheDocument();
    const otx = screen.getByRole("article", { name: "Observation otx" });
    expect(otx).toHaveTextContent("<b>Campaign</b>");
    expect(otx.querySelector("b")).toBeNull();
    expect(screen.getByRole("article", { name: "Observation virustotal" })).toHaveTextContent(/Provider failed.*does not mean the indicator is clean/);
  });

  it("toggles defang and shows sightings with Events links", async () => {
    mockFetch(routes());
    renderWithQuery(<EntityView id="ent1" />);
    await userEvent.click(await screen.findByLabelText("defang"));
    expect(screen.getByRole("heading", { name: "203.0.113.45" })).toBeInTheDocument();
    const link = await screen.findByRole("link", { name: /network.dst_ip ×3/ });
    expect(link).toHaveAttribute("href", "/events?f=network.dst_ip%7Ceq%7C203.0.113.45");
    expect(screen.getByRole("link", { name: "ws-01 (3)" })).toHaveAttribute("href", "/events?f=host.hostname%7Ceq%7Cws-01");
  });

  it("saves watch-list edits with the exact PATCH payload and enrich shows coverage", async () => {
    const m = mockFetch(routes({
      "PATCH /api/v1/intel/entities/ent1": () => detail({ coverage: null }),
      "POST /api/v1/intel/entities/ent1/enrich": () => detail(),
    }));
    renderWithQuery(<EntityView id="ent1" />);
    await screen.findByLabelText("Watch-list verdict");
    await userEvent.selectOptions(screen.getByLabelText("Watch-list verdict"), "suspicious");
    await userEvent.clear(screen.getByLabelText("Watch-list confidence"));
    await userEvent.type(screen.getByLabelText("Watch-list confidence"), "60");
    await userEvent.clear(screen.getByLabelText("Tags"));
    await userEvent.type(screen.getByLabelText("Tags"), "a, b");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(m.bodiesFor("PATCH /api/v1/intel/entities/ent1")).toHaveLength(1));
    expect(m.bodiesFor("PATCH /api/v1/intel/entities/ent1")[0]).toEqual({ watch_verdict: "suspicious", watch_confidence: 60, notes: "n", tags: ["a", "b"] });
    await userEvent.click(screen.getByRole("button", { name: "Force refresh" }));
    expect(await screen.findByLabelText("Provider coverage")).toHaveTextContent("2 answered · 0 had no record · 1 failed · not run: misp (not configured)");
    expect(m.calls.some((c) => c.key === "POST /api/v1/intel/entities/ent1/enrich")).toBe(true);
  });

  it("is read-only for viewers and hides sightings without events:read; shows relations", async () => {
    perms = ["intel:read"];
    mockFetch(routes());
    renderWithQuery(<EntityView id="ent1" />);
    expect(await screen.findByRole("button", { name: "Enrich" })).toBeDisabled();
    expect(screen.getByLabelText("Watch-list verdict")).toBeDisabled();
    expect(screen.queryByText(/Sightings in your telemetry/)).toBeNull();
    expect(screen.getByRole("link", { name: "emotet" })).toHaveAttribute("href", "/threat-intel/m1");
  });

  it("shows a clear 404", async () => {
    mockFetch({ "GET /api/v1/intel/entities/ent1": () => status(404, { error: { code: "not_found", message: "Entity not found" } }) });
    renderWithQuery(<EntityView id="ent1" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Entity not found.");
  });
});

describe("case IOC integration", () => {
  const iocs = [{ id: "i1", type: "ip", value: "203.0.113.45", source: "extracted", occurrences: 2, context: "network.dst_ip", created_at: "2026-03-01T10:00:00Z" },
    { id: "i2", type: "domain", value: "x.example", source: "manual", occurrences: 1, context: "manual", created_at: "2026-03-01T10:00:00Z" }];
  it("badges IOCs from cached verdicts, offers lookup for unknown ones, and enriches the case", async () => {
    const m = mockFetch({
      "GET /api/v1/cases/c1/iocs": () => iocs,
      "POST /api/v1/intel/lookup-batch": () => [
        { type: "ip", value: "203.0.113.45", entity_id: "ent1", verdict: "malicious", score: 92 }, { type: "domain", value: "x.example", entity_id: null, verdict: null, score: null }],
      "POST /api/v1/intel/enrich-case/c1": () => ({ checked: 2, malicious: 1, results: [] }),
      "GET /api/v1/cases/c1/activity": () => [],
    });
    renderWithQuery(<IocsTab caseId="c1" mutable />);
    const link = await screen.findByRole("link", { name: /Intel for 203.0.113.45/ });
    expect(link).toHaveAttribute("href", "/threat-intel/ent1");
    expect(within(link).getByText("malicious")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Look up x.example/ })).toBeInTheDocument();
    expect(m.bodiesFor("POST /api/v1/intel/lookup-batch")[0]).toEqual({ items: [{ type: "ip", value: "203.0.113.45" }, { type: "domain", value: "x.example" }] });
    await userEvent.click(screen.getByRole("button", { name: "Enrich IOCs" }));
    expect(await screen.findByText(/Enrichment finished: 2 indicators checked · 1 malicious/)).toBeInTheDocument();
  });
  it("does not call intel endpoints without intel:read", async () => {
    perms = ["cases:read"];
    const m = mockFetch({ "GET /api/v1/cases/c1/iocs": () => iocs });
    renderWithQuery(<IocsTab caseId="c1" mutable />);
    await screen.findByText("203[.]0[.]113[.]45");
    expect(m.calls.some((c) => c.key.includes("/intel/"))).toBe(false);
    expect(screen.getByRole("button", { name: "Enrich IOCs" })).toBeDisabled();
  });
});

const matrix = (): MatrixColumn[] => [{ tactic: { id: "TA0002", shortname: "execution", name: "Execution", position: 3 }, techniques: [
  { id: "T1059", name: "Command and Scripting Interpreter", mapping_count: 1, top_confidence: "HIGH", subtechniques: [{ id: "T1059.001", name: "PowerShell", mapping_count: 1, top_confidence: "HIGH", subtechniques: [] }] },
  { id: "T1204", name: "User Execution", mapping_count: 0, top_confidence: null, subtechniques: [] }] }];

describe("MITRE views", () => {
  it("renders the matrix with colours, expandable sub-techniques, filter and mapped-only", async () => {
    mockFetch({ "GET /api/v1/mitre/matrix": matrix });
    renderWithQuery(<MatrixView />);
    const col = await screen.findByRole("region", { name: "Execution" });
    const mapped = within(col).getByRole("link", { name: /T1059 Command/ });
    expect(mapped.parentElement?.className).toContain("red");
    expect(within(col).getByRole("link", { name: /T1204/ }).parentElement?.className).toContain("text-muted");
    expect(screen.queryByRole("link", { name: /T1059.001/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Expand sub-techniques of T1059" }));
    expect(screen.getByRole("link", { name: /T1059.001/ })).toHaveAttribute("href", "/mitre/techniques/T1059.001");
    await userEvent.click(screen.getByLabelText("mapped only"));
    expect(screen.queryByRole("link", { name: /T1204/ })).toBeNull();
    expect(screen.getByText("2 of 3 techniques mapped in this tenant")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Filter techniques"), "zzz");
    expect(screen.queryByRole("link", { name: /T1059/ })).toBeNull();
  });

  it("technique page shows the exact evidence summary, risk reasons and linked objects", async () => {
    mockFetch({
      "GET /api/v1/mitre/techniques/T1059.001": () => ({ id: "T1059.001", name: "PowerShell", parent_id: "T1059", is_subtechnique: true, tactics: ["execution"], description: "Abuse of <script>PowerShell</script>", url: "", source: "builtin", subtechniques: [] }),
      "GET /api/v1/mitre/techniques/T1059.001/summary": () => ({ technique: {}, mappings: 1, objects: [{ object_type: "case", object_id: "c1", title: "Suspicious PS", confidence: "HIGH" }],
        evidence_events: 17, hosts: { count: 4, names: ["ws-01"] }, users: { count: 2, names: ["alice"] }, risk: "HIGH", risk_reasons: ["HIGH-confidence mapping and 4 hosts"] }),
    });
    renderWithQuery(<TechniqueView id="T1059.001" />);
    const sum = await screen.findByLabelText("Technique summary");
    expect(sum).toHaveTextContent("Evidence: 17 events · Hosts: 4 · Users: 2 · Risk: HIGH");
    expect(screen.getByText("HIGH-confidence mapping and 4 hosts")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Suspicious PS" })).toHaveAttribute("href", "/cases/c1");
    const ext = screen.getByRole("link", { name: /attack.mitre.org/ });
    expect(ext).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/001/");
    expect(ext).toHaveAttribute("rel", "noopener noreferrer");
    expect(document.querySelector("script")).toBeNull();
  });
});

describe("MITRE suggestions in the case workflow", () => {
  const suggestion: MitreSuggestion = { technique_id: "T1059.001", name: "PowerShell", tactics: ["execution"], confidence: "HIGH", reasoning: ["encoded command", "hidden window"],
    event_ids: [EID], event_count: 1, hosts: ["WS-01"], users: ["alice"], mapped: false };
  const base = () => ({
    "GET /api/v1/mitre/mappings": () => [],
    "POST /api/v1/mitre/suggest": () => ({ analyzed_events: 11, suggestions: [suggestion, { ...suggestion, technique_id: "T1027", name: "Obfuscated Files", confidence: "MEDIUM" }] }),
  });
  const panel = () => renderWithQuery(<MitrePanel source={{ case_id: "c1" }} targets={[{ type: "case", id: "c1", label: "Case" }]} mutable />);

  it("states suggestions are hints, lists reasoning, and accept posts the prefilled mapping", async () => {
    const m = mockFetch({ ...base(), "POST /api/v1/mitre/mappings": (b) => ({ id: "m1", ...(b as object) }) });
    panel();
    expect(screen.getByText(/rule-based hints.*not verdicts/s)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Suggest techniques" }));
    expect(await screen.findByText("Analysed 11 events · 2 suggestions")).toBeInTheDocument();
    expect(m.bodiesFor("POST /api/v1/mitre/suggest")[0]).toEqual({ case_id: "c1" });
    await userEvent.click(screen.getByRole("button", { name: "Accept T1059.001" }));
    const dlg = screen.getByRole("dialog");
    expect(within(dlg).getByLabelText("Confidence")).toHaveValue("HIGH");
    expect(within(dlg).getByLabelText("Reasoning")).toHaveValue("• encoded command\n• hidden window");
    await userEvent.click(within(dlg).getByRole("button", { name: "Accept mapping" }));
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/mitre/mappings")).toHaveLength(1));
    expect(m.bodiesFor("POST /api/v1/mitre/mappings")[0]).toEqual({ technique_id: "T1059.001", object_type: "case", object_id: "c1", confidence: "HIGH",
      reasoning: "• encoded command\n• hidden window", evidence_event_ids: [EID], source: "suggestion" });
  });

  it("blocks short reasoning client-side and dismiss is local only", async () => {
    const m = mockFetch({ ...base(), "POST /api/v1/mitre/mappings": () => ({}) });
    panel();
    await userEvent.click(screen.getByRole("button", { name: "Suggest techniques" }));
    await userEvent.click(await screen.findByRole("button", { name: "Accept T1027" }));
    const dlg = screen.getByRole("dialog");
    await userEvent.clear(within(dlg).getByLabelText("Reasoning"));
    await userEvent.type(within(dlg).getByLabelText("Reasoning"), "short");
    await userEvent.click(within(dlg).getByRole("button", { name: "Accept mapping" }));
    expect(await within(dlg).findByRole("alert")).toHaveTextContent(/at least 10 characters/);
    expect(m.bodiesFor("POST /api/v1/mitre/mappings")).toHaveLength(0);
    await userEvent.click(within(dlg).getByRole("button", { name: "Cancel" }));
    const before = m.calls.length;
    await userEvent.click(screen.getByRole("button", { name: "Dismiss T1027" }));
    expect(screen.queryByRole("button", { name: "Accept T1027" })).toBeNull();
    expect(m.calls.length).toBe(before);
  });

  it("lists mapped techniques with reasoning and evidence count; viewers cannot accept or remove", async () => {
    perms = ["mitre:read", "events:read"];
    mockFetch({
      ...base(),
      "GET /api/v1/mitre/mappings": () => [{ id: "m1", technique_id: "T1003.001", technique_name: "LSASS Memory", tactics: ["credential-access"], object_type: "case", object_id: "c1",
        confidence: "HIGH", reasoning: "comsvcs MiniDump against lsass", evidence_event_ids: [EID, "f".repeat(32)], evidence_count: 2, source: "suggestion", created_by: null, created_at: "2026-03-01T10:00:00Z" }],
    });
    panel();
    expect(await screen.findByText("comsvcs MiniDump against lsass")).toBeInTheDocument();
    expect(screen.getByText(/Evidence: 2 events/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove mapping T1003.001" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Suggest techniques" })).toBeDisabled();
  });
});
