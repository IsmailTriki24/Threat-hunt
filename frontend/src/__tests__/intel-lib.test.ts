import type { IntelProvider, MatrixColumn, MitreSuggestion } from "@/lib/api-types";
import {
  acceptDraft, buildProviderPayload, cellClass, clampScore, coverageLine, defangEntity, degradationMessage, enrichSummary, eventIndicators,
  filterMatrix, mappingPayload, matrixTotals, parseStixText, scoreBand, sightingsHref, stixSummary, summaryLine, validateDraft, verdictFor,
  watchPayload,
} from "@/lib/intel";

describe("defang & verdict helpers", () => {
  it("defangs display values by type and leaves hashes/names alone", () => {
    expect(defangEntity("ip", "203.0.113.45")).toBe("203[.]0[.]113[.]45");
    expect(defangEntity("domain", "evil.example")).toBe("evil[.]example");
    expect(defangEntity("url", "http://evil.example/a")).toBe("hxxp://evil[.]example/a");
    expect(defangEntity("email", "a@b.example")).toBe("a[@]b[.]example");
    expect(defangEntity("sha256", "a".repeat(64))).toBe("a".repeat(64));
    expect(defangEntity("malware", "emotet")).toBe("emotet");
  });
  it("maps scores to verdicts and bands, clamping out-of-range values", () => {
    expect(verdictFor(70)).toBe("malicious"); expect(verdictFor(69)).toBe("suspicious"); expect(verdictFor(35)).toBe("suspicious");
    expect(verdictFor(34)).toBe("unknown"); expect(verdictFor(10, true)).toBe("benign");
    expect(scoreBand(90)).toBe("high"); expect(scoreBand(40)).toBe("mid"); expect(scoreBand(5)).toBe("low");
    expect(clampScore(150)).toBe(100); expect(clampScore(-3)).toBe(0); expect(clampScore(41.6)).toBe(42);
  });
  it("describes coverage including providers that did not run", () => {
    expect(coverageLine({ answered: 2, failed: 1, not_found: 3, skipped: [{ provider: "otx", reason: "not configured" }] }))
      .toBe("2 answered · 3 had no record · 1 failed · not run: otx (not configured)");
    expect(coverageLine(null)).toBe("");
  });
});

const provider = (o: Partial<IntelProvider>): IntelProvider => ({
  key: "otx", display_name: "AlienVault OTX", description: "", supported_types: ["ip"], offline: false, secret_keys: ["api_key"],
  config_schema: {}, configured: false, enabled: false, last_status: "unknown", last_detail: "", last_checked_at: null, ...o,
});

describe("graceful degradation & provider payloads", () => {
  it("names unconfigured online providers and ignores offline/config-only ones", () => {
    const msg = degradationMessage([
      provider({ key: "heuristics", offline: true, configured: true }), provider({ display_name: "OTX" }),
      provider({ key: "taxii", supported_types: [], display_name: "TAXII" }), provider({ key: "vt", display_name: "VirusTotal", configured: true }),
    ]);
    expect(msg).toContain("1 external provider is not configured (OTX)");
    expect(msg).toContain("local heuristics and your tenant watch-list");
    expect(degradationMessage([provider({ configured: true })])).toBeNull();
  });
  it("omits blank secrets (keep stored value) and validates config fields", () => {
    const misp = provider({ key: "misp", config_schema: { type: "object", required: ["url"], properties: { url: { type: "string", format: "uri", title: "Url" } } } });
    expect(buildProviderPayload(misp, true, { url: "https://misp.example.org" }, { api_key: "  " }).body)
      .toEqual({ enabled: true, config: { url: "https://misp.example.org" } });
    expect(buildProviderPayload(misp, true, { url: "https://misp.example.org" }, { api_key: " K " }).body.secrets).toEqual({ api_key: "K" });
    expect(buildProviderPayload(misp, true, {}, {}).errors).toEqual(["Url is required"]);
  });
});

describe("sightings, watch-list, STIX", () => {
  it("builds Events deep links in the app's filter encoding", () => {
    expect(sightingsHref("network.dst_ip", "203.0.113.45")).toBe("/events?f=network.dst_ip%7Ceq%7C203.0.113.45");
    expect(sightingsHref("free_text", "http://x.example/a")).toBe(`/events?q=${encodeURIComponent('"http://x.example/a"')}`);
  });
  it("watch payloads set or clear the verdict and normalise tags", () => {
    expect(watchPayload("malicious", 90, "n", " c2, ,demo ")).toEqual({ watch_verdict: "malicious", watch_confidence: 90, notes: "n", tags: ["c2", "demo"] });
    expect(watchPayload("", 90, "", "")).toEqual({ clear_watch: true, notes: "", tags: [] });
  });
  it("validates STIX bundles and summarises import results", () => {
    expect(parseStixText("{").error).toBe("Invalid JSON");
    expect(parseStixText('{"type":"indicator"}').error).toMatch(/Not a STIX/);
    expect(parseStixText('{"type":"bundle","objects":[]}').error).toBeNull();
    expect(stixSummary({ created: 2, updated: 1, skipped: 3, relations: 1, named_objects: 1 })).toBe("2 new · 1 updated · 1 named objects · 1 relations · 3 skipped");
    expect(enrichSummary({ checked: 1, malicious: 0, results: [] })).toBe("1 indicator checked · 0 malicious");
  });
  it("extracts only public IPs, domains and hashes from events", () => {
    const got = eventIndicators({ network: { src_ip: "10.0.0.5", dst_ip: "203.0.113.5", dst_domain: "evil.example" }, dns: { question: "evil.example", answers: ["203.0.113.5", "alias.example"] },
      process: { hash: { sha256: "a".repeat(64) } } } as never);
    expect(got.map((g) => `${g.type}:${g.value}`)).toEqual(["ip:203.0.113.5", "domain:evil.example", `sha256:${"a".repeat(64)}`]);
  });
});

const col = (): MatrixColumn[] => [{ tactic: { id: "TA0002", shortname: "execution", name: "Execution", position: 3 }, techniques: [
  { id: "T1059", name: "Command and Scripting Interpreter", mapping_count: 2, top_confidence: "HIGH", subtechniques: [
    { id: "T1059.001", name: "PowerShell", mapping_count: 2, top_confidence: "HIGH", subtechniques: [] },
    { id: "T1059.003", name: "Windows Command Shell", mapping_count: 0, top_confidence: null, subtechniques: [] }] },
  { id: "T1204", name: "User Execution", mapping_count: 0, top_confidence: null, subtechniques: [] }] }];

describe("MITRE matrix", () => {
  it("colours cells by top confidence and keeps unmapped neutral", () => {
    expect(cellClass({ mapping_count: 0, top_confidence: null })).toContain("text-muted");
    expect(cellClass({ mapping_count: 1, top_confidence: "HIGH" })).toContain("red");
    expect(cellClass({ mapping_count: 1, top_confidence: "MEDIUM" })).toContain("orange");
    expect(cellClass({ mapping_count: 1, top_confidence: "LOW" })).toContain("yellow");
  });
  it("filters by text and mapped-only, surfacing parents of matching sub-techniques", () => {
    const names = (c: MatrixColumn[]) => c[0].techniques.map((t) => `${t.id}[${t.subtechniques.map((s) => s.id).join(",")}]`);
    expect(names(filterMatrix(col(), "", false))).toEqual(["T1059[T1059.001,T1059.003]", "T1204[]"]);
    expect(names(filterMatrix(col(), "", true))).toEqual(["T1059[T1059.001]"]);
    expect(names(filterMatrix(col(), "powershell", false))).toEqual(["T1059[T1059.001]"]);
    expect(names(filterMatrix(col(), "user exec", false))).toEqual(["T1204[]"]);
    expect(filterMatrix(col(), "zzz", false)[0].techniques).toEqual([]);
    expect(matrixTotals(col())).toEqual({ techniques: 4, mapped: 2 });
  });
  it("formats the technique summary exactly as specified", () => {
    expect(summaryLine({ evidence_events: 17, hosts: { count: 4, names: [] }, users: { count: 2, names: [] }, risk: "HIGH" }))
      .toBe("Evidence: 17 events · Hosts: 4 · Users: 2 · Risk: HIGH");
  });
});

const sug = (o: Partial<MitreSuggestion> = {}): MitreSuggestion => ({
  technique_id: "T1059.001", name: "PowerShell", tactics: ["execution"], confidence: "HIGH", reasoning: ["encoded command in process.command_line", "hidden window"],
  event_ids: ["a".repeat(32), "b".repeat(32)], event_count: 2, hosts: ["WS-01"], users: ["alice"], mapped: false, ...o,
});

describe("suggestion acceptance", () => {
  it("prefills confidence, reasoning bullets and evidence ids", () => {
    const d = acceptDraft(sug());
    expect(d.confidence).toBe("HIGH");
    expect(d.reasoning).toBe("• encoded command in process.command_line\n• hidden window");
    expect(d.evidence).toHaveLength(2);
    expect(validateDraft(d)).toBeNull();
  });
  it("enforces the backend rules client-side: reasoning length and evidence for MEDIUM/HIGH", () => {
    const d = acceptDraft(sug());
    expect(validateDraft({ ...d, reasoning: "short" })).toMatch(/at least 10/);
    expect(validateDraft({ ...d, evidence: [] })).toMatch(/at least one evidence/);
    expect(validateDraft({ ...d, evidence: [], confidence: "LOW" })).toBeNull();
  });
  it("builds the mapping request body", () => {
    const s = sug();
    expect(mappingPayload(s, { ...acceptDraft(s), reasoning: "  edited reasoning text  ", confidence: "MEDIUM" }, "case", "c1")).toEqual({
      technique_id: "T1059.001", object_type: "case", object_id: "c1", confidence: "MEDIUM", reasoning: "edited reasoning text",
      evidence_event_ids: s.event_ids, source: "suggestion",
    });
  });
});
