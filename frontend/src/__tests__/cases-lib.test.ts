import {
  auditQuery, buildConfig, caseListQuery, defang, defaultAuditFilters, defaultCaseFilters, describeActivity, fieldsFromSchema, ingestCurl,
  mergeJournal, relatedPivotHref, transitionNeedsComment, assetListQuery,
} from "@/lib/cases";
import type { CaseActivity, Timeline, TimelineEntry } from "@/lib/api-types";

describe("defang", () => {
  it("neutralises urls, domains, ips and emails for display only", () => {
    expect(defang("url", "https://evil.example/a.ps1?x=1.2")).toBe("hxxps://evil[.]example/a.ps1?x=1.2");
    expect(defang("url", "http://203.0.113.5:8080/x")).toBe("hxxp://203[.]0[.]113[.]5:8080/x");
    expect(defang("domain", "cdn-update-check.example")).toBe("cdn-update-check[.]example");
    expect(defang("ip", "203.0.113.45")).toBe("203[.]0[.]113[.]45");
    expect(defang("email", "bob@corp.example")).toBe("bob[@]corp[.]example");
    expect(defang("sha256", "a".repeat(64))).toBe("a".repeat(64));
  });
});

describe("workflow rules", () => {
  it("requires a comment for terminal states and for reopening a closed case", () => {
    for (const to of ["RESOLVED", "FALSE_POSITIVE", "CLOSED"]) expect(transitionNeedsComment("INVESTIGATING", to)).toBe(true);
    expect(transitionNeedsComment("CLOSED", "INVESTIGATING")).toBe(true);
    expect(transitionNeedsComment("OPEN", "INVESTIGATING")).toBe(false);
    expect(transitionNeedsComment("INVESTIGATING", "CONTAINED")).toBe(false);
  });
});

const entry = (id: string, ts: string): TimelineEntry => ({
  id, timestamp: ts, end_timestamp: null, count: 1, event_type: "process_creation", title: `t-${id}`, severity: 0, host: null,
  user: null, process: null, pid: null, destination: null, parent_event_id: null, process_event_id: null, event_ids: [id], periodicity: null,
});
const act = (id: string, ts: string, kind = "note", body = "n"): CaseActivity => ({ id, kind, body, details: {}, actor_id: null, actor_email: "a@x", created_at: ts });

describe("mergeJournal", () => {
  it("interleaves telemetry and journal chronologically, telemetry first on ties", () => {
    const tl: Timeline = { entries: [entry("e1", "2026-03-01T10:00:00Z"), entry("e2", "2026-03-01T10:10:00Z")], total_events: 2, truncated: false };
    const merged = mergeJournal(tl, [act("j2", "2026-03-01T10:10:00Z"), act("j1", "2026-03-01T10:05:00Z"), act("j0", "2026-03-01T09:00:00+00:00")]);
    expect(merged.map((m) => m.entry?.id ?? m.activity?.id)).toEqual(["j0", "e1", "j1", "e2", "j2"]);
    expect(mergeJournal(undefined, undefined)).toEqual([]);
  });
  it("describes activity as plain text", () => {
    expect(describeActivity({ ...act("x", "t", "status_change", "done"), details: { from: "OPEN", to: "INVESTIGATING" } })).toBe("Status OPEN → INVESTIGATING: done");
    expect(describeActivity(act("x", "t", "note", "<b>hi</b>"))).toBe("<b>hi</b>");
  });
});

describe("query-string mapping", () => {
  it("maps case filters", () => {
    expect(caseListQuery(defaultCaseFilters())).toBe("?limit=100");
    expect(caseListQuery({ status: "OPEN", severity: "HIGH", mine: true, q: " phish " })).toBe("?status=OPEN&severity=HIGH&mine=true&q=phish&limit=100");
  });
  it("maps audit filters, treating datetime-local as UTC, plus paging", () => {
    expect(auditQuery(defaultAuditFilters(), 0, 50)).toBe("?limit=50&offset=0");
    const qs = new URLSearchParams(auditQuery({ action: "case.", outcome: "denied", actor_id: " u1 ", resource_type: "case", since: "2026-03-01T10:00", until: "2026-03-02T00:00" }, 100, 50));
    expect(Object.fromEntries(qs)).toEqual({
      action: "case.", outcome: "denied", actor_id: "u1", resource_type: "case", since: "2026-03-01T10:00:00.000Z", until: "2026-03-02T00:00:00.000Z", limit: "50", offset: "100",
    });
  });
  it("maps asset filters", () => {
    expect(assetListQuery({ type: "host", criticality: "HIGH", q: "ws" })).toBe("?type=host&criticality=HIGH&q=ws&limit=200");
  });
  it("turns related buckets into Events pivots", () => {
    expect(relatedPivotHref("users", "alice")).toBe(`/events?f=${encodeURIComponent("user.name|eq|alice")}`);
    expect(relatedPivotHref("destinations", "203.0.113.5")).toContain(encodeURIComponent("network.dst_ip|eq|203.0.113.5"));
    expect(relatedPivotHref("unknown", "x")).toBeNull();
  });
});

describe("schema-driven forms", () => {
  const schema = {
    required: ["url"],
    properties: {
      url: { type: "string", format: "uri", title: "Url" },
      records_path: { type: "string", default: "", title: "Records Path" },
      since_param: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Since Param" },
      timeout_s: { type: "number", default: 15, title: "Timeout S" },
      keep_raw: { type: "boolean", default: true, title: "Keep Raw" },
      port: { type: "integer", title: "Port" },
      mapping: { $ref: "#/$defs/GenericJsonConfig", title: "Mapping" },
      mode: { enum: ["a", "b"], title: "Mode" },
    },
  };
  it("derives typed fields, resolving optional (anyOf) and $ref properties", () => {
    const f = Object.fromEntries(fieldsFromSchema(schema).map((x) => [x.name, x]));
    expect(f.url).toMatchObject({ kind: "string", required: true, placeholder: "https://…" });
    expect(f.since_param.kind).toBe("string");
    expect(f.timeout_s).toMatchObject({ kind: "number", placeholder: "15" });
    expect(f.keep_raw.kind).toBe("boolean");
    expect(f.mapping.kind).toBe("json");
    expect(f.mode).toMatchObject({ kind: "enum", options: ["a", "b"] });
  });
  it("builds a config, omitting empty optionals and reporting errors", () => {
    const fields = fieldsFromSchema(schema);
    const ok = buildConfig(fields, { url: "https://siem.example.com/x", timeout_s: "20", port: "9200", mapping: '{"source":"siem"}', records_path: "" });
    expect(ok.errors).toEqual([]);
    expect(ok.config).toEqual({ url: "https://siem.example.com/x", timeout_s: 20, port: 9200, mapping: { source: "siem" } });
    const bad = buildConfig(fields, { url: "", port: "1.5", timeout_s: "abc", mapping: "{nope" });
    expect(bad.errors).toEqual(expect.arrayContaining(["Url is required", "Port must be a integer", "Timeout S must be a number", "Mapping must be valid JSON"]));
  });
  it("renders a curl example without any real key", () => {
    expect(ingestCurl("http://localhost:3000", "abc")).toContain("/api/v1/ingest/abc");
    expect(ingestCurl("http://x", "abc")).toContain("<INGEST_KEY>");
  });
});
