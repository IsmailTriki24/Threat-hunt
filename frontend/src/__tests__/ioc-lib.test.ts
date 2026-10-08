import { age, defangIoc, selectable, validationSummary, type IocItem } from "@/lib/ioc";

const item = (o: Partial<IocItem> = {}): IocItem => ({
  id: "1", source: "urlhaus", type: "url", value: "http://bad.example/a", confidence: 75, first_seen: "", last_seen: "", valid_until: null, threat_type: "", malware: "",
  description: "", reference: "", tags: [], techniques: [], status: "NEW", status_reason: "", seen_count: 0, validated_at: null, case_id: null, last_hunted_at: null, ...o,
});

describe("age", () => {
  const now = Date.parse("2026-10-08T12:00:00Z");
  it("prints minutes, hours and days", () => {
    expect(age("2026-10-08T11:30:00Z", now)).toBe("30m");
    expect(age("2026-10-08T06:00:00Z", now)).toBe("6h");
    expect(age("2026-10-05T12:00:00Z", now)).toBe("3d");
    expect(age("2026-10-08T13:00:00Z", now)).toBe("0m");
  });
});

describe("queue rules", () => {
  it("defangs indicators for display only", () => {
    expect(defangIoc("ip", "203.0.113.5")).toBe("203[.]0[.]113[.]5");
    expect(defangIoc("url", "http://bad.example/a")).toBe("hxxp://bad[.]example/a");
    expect(defangIoc("sha256", "a".repeat(64))).toBe("a".repeat(64));
  });
  it("only new or rejected indicators can be selected for validation", () => {
    expect(selectable(item())).toBe(true);
    expect(selectable(item({ status: "REJECTED" }))).toBe(true);
    for (const s of ["VALIDATED", "EXPIRED"]) expect(selectable(item({ status: s }))).toBe(false);
  });
  it("summarises exactly what is being committed to", () => {
    const s = validationSummary([item(), item({ id: "2", type: "ip", value: "203.0.113.5", seen_count: 3, source: "feodo" })]);
    expect(s).toContain("2 indicator(s)");
    expect(s).toContain("url, ip");
    expect(s).toContain("urlhaus, feodo");
    expect(s).toContain("1 already appear in your telemetry");
  });
});
