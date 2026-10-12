import {
  activeChips, ago, LAND, arcPoints, choroplethExpression, clearedFilters, customRangeError, defang, defaultFilters, ipRoleLinks, flagEmoji, fmtInt, fmtTs, markerRadius, toParams,
  type CountryRow,
} from "@/lib/threat-map";

const row = (iso: string, value: number): CountryRow => ({ iso, name: iso, ips: value, events: 0, correlated: 0, iocs: 0, value });

describe("filters -> query string", () => {
  it("sends only what differs from the defaults", () => {
    expect(toParams(defaultFilters()).toString()).toBe("layer=intelligence&range=24h");
    const f = { ...defaultFilters(), layer: "observed" as const, country: ["DE", "US"], severity: "high" as const, minConfidence: 60, source: ["MISP"], logSource: ["ids"], scope: "external" as const, q: "  AS15169 ", iocType: "ip", continent: "EU", category: "emotet" };
    const p = toParams(f);
    expect(Object.fromEntries(p)).toEqual({
      layer: "observed", range: "24h", country: "DE,US", continent: "EU", ioc_type: "ip", severity: "high", min_confidence: "60", category: "emotet",
      source: "MISP", log_source: "ids", scope: "external", q: "AS15169",
    });
  });

  it("encodes a custom range as ISO instants", () => {
    const p = toParams({ ...defaultFilters(), range: "custom", start: "2026-10-01T00:00:00Z", end: "2026-10-02T12:30:00Z" });
    expect(p.get("start")).toBe("2026-10-01T00:00:00.000Z");
    expect(p.get("end")).toBe("2026-10-02T12:30:00.000Z");
  });

  it("validates a custom range before any request is made", () => {
    const f = { ...defaultFilters(), range: "custom" as const };
    expect(customRangeError(f)).toMatch(/start and an end/);
    expect(customRangeError({ ...f, start: "2026-10-02T00:00:00Z", end: "2026-10-01T00:00:00Z" })).toMatch(/after start/);
    expect(customRangeError({ ...f, start: "2026-01-01T00:00:00Z", end: "2026-10-01T00:00:00Z" })).toMatch(/90 days/);
    expect(customRangeError({ ...f, start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" })).toBeNull();
    expect(customRangeError(defaultFilters())).toBeNull();
  });
});

describe("active filter chips", () => {
  it("lists exactly the active filters and each chip clears only its own filter", () => {
    expect(activeChips(defaultFilters())).toEqual([]);
    const f = { ...defaultFilters(), country: ["DE"], severity: "medium" as const, q: "emotet", source: ["OTX"] };
    const chips = activeChips(f);
    expect(chips.map((c) => c.key)).toEqual(["q", "country", "severity", "source"]);
    const after = { ...f, ...chips.find((c) => c.key === "country")!.clear };
    expect(after.country).toEqual([]);
    expect(activeChips(after).map((c) => c.key)).toEqual(["q", "severity", "source"]);
  });

  it("clearing keeps the layer and time range", () => {
    const f = { ...defaultFilters(), layer: "correlated" as const, range: "7d" as const, country: ["FR"], q: "x" };
    const c = clearedFilters(f);
    expect(c).toMatchObject({ layer: "correlated", range: "7d", country: [], q: "" });
    expect(activeChips(c)).toEqual([]);
  });
});

describe("arcs", () => {
  it("runs from the source to the destination along a great circle", () => {
    const pts = arcPoints([10, 50], [-120, 35], 40);
    expect(pts).toHaveLength(41);
    expect(pts[0][0]).toBeCloseTo(10, 5); expect(pts[0][1]).toBeCloseTo(50, 5);
    expect(pts[40][0]).toBeCloseTo(-120, 5); expect(pts[40][1]).toBeCloseTo(35, 5);
    expect(Math.max(...pts.map((p) => p[1]))).toBeGreaterThan(50); // bows toward the pole, as great circles do
  });

  it("never jumps across the antimeridian", () => {
    const pts = arcPoints([170, 10], [-170, 20], 30);
    for (let i = 1; i < pts.length; i++) expect(Math.abs(pts[i][0] - pts[i - 1][0])).toBeLessThan(10);
    expect(pts[30][0]).toBeCloseTo(190, 4); // unwrapped, so the line stays continuous
  });

  it("degenerates safely for identical points", () => {
    expect(arcPoints([5, 5], [5, 5])).toEqual([[5, 5], [5, 5]]);
  });
});

describe("choropleth", () => {
  it("is a flat colour with no data and shades busier countries stronger", () => {
    expect(choroplethExpression([], "observed")).toBe(LAND);
    expect(choroplethExpression([row("DE", 0)], "observed")).toBe(LAND);
    const e = choroplethExpression([row("DE", 100), row("FR", 4), row("XX", 0)], "intelligence") as unknown[];
    expect(e.slice(0, 2)).toEqual(["match", ["get", "iso"]]);
    expect(e).toContain("DE"); expect(e).toContain("FR"); expect(e).not.toContain("XX");
    const colour = (iso: string) => String(e[e.indexOf(iso) + 1]);
    const lum = (c: string) => c.match(/\d+/g)!.map(Number).reduce((a, b) => a + b, 0);
    expect(lum(colour("DE"))).toBeLessThan(lum(colour("FR"))); // busier = more saturated (darker on the light basemap)
    expect(e[e.length - 1]).toBe(LAND);
  });

  it("scales markers between a floor and a ceiling", () => {
    expect(markerRadius(0, 0)).toBe(5);
    expect(markerRadius(0, 10)).toBe(4);
    expect(markerRadius(10, 10)).toBe(10);
    expect(markerRadius(2.5, 10)).toBeGreaterThan(4);
  });
});

describe("formatting and links", () => {
  it("defangs indicators for safe sharing", () => {
    expect(defang("185.220.101.5")).toBe("185[.]220[.]101[.]5");
    expect(defang("2606:4700::1111")).toBe("2606[:]4700[:][:]1111");
  });
  it("renders a flag only for a valid country code", () => {
    expect(flagEmoji("DE")).toBe("🇩🇪");
    expect(flagEmoji("")).toBe(""); expect(flagEmoji("Germany")).toBe("");
  });
  it("builds one valid single-field events search per role (the query language cannot OR across fields)", () => {
    const q = (href: string) => new URL(href, "http://x").searchParams;
    const none = ipRoleLinks("8.8.8.8", "7d", "", "", null);
    expect(none).toHaveLength(1); // nothing observed: still offer the default so "Investigate" works
    expect(q(none[0].href).get("q")).toBe("network.dst_ip:8.8.8.8");
    expect(q(none[0].href).get("lang")).toBe("1"); expect(q(none[0].href).get("range")).toBe("7d");
    const roles = ipRoleLinks("8.8.8.8", "24h", "", "", { as_destination: 4, as_source: 9, as_signin_source: 0 });
    expect(roles.map((r) => [r.label, r.count])).toEqual([["As source", 9], ["As destination", 4]]); // busiest first, empty roles omitted
    expect(roles.map((r) => q(r.href).get("q"))).toEqual(["network.src_ip:8.8.8.8", "network.dst_ip:8.8.8.8"]);
    for (const r of ipRoleLinks("8.8.8.8", "7d", "", "", { as_destination: 1, as_source: 1, as_signin_source: 1 })) expect(q(r.href).get("q")).not.toMatch(/\bOR\b|\bAND\b/);
    const c = ipRoleLinks("2606:4700::1111", "custom", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", null)[0];
    expect(q(c.href).get("start")).toBe("2026-10-01T00:00:00.000Z");
    expect(q(c.href).get("q")).toBe("network.dst_ip:2606:4700::1111");
  });
  it("formats numbers and times, tolerating nulls and garbage", () => {
    expect(fmtInt(1234567)).toBe("1,234,567"); expect(fmtInt(null)).toBe("—"); expect(fmtInt(undefined)).toBe("—");
    expect(fmtTs("2026-10-12T09:41:32Z")).toBe("2026-10-12 09:41Z"); expect(fmtTs(null)).toBe("—"); expect(fmtTs("nope")).toBe("—");
    const now = Date.parse("2026-10-12T12:00:00Z");
    expect(ago("2026-10-12T11:59:30Z", now)).toBe("30s ago"); expect(ago("2026-10-12T11:00:00Z", now)).toBe("60m ago");
    expect(ago("2026-10-10T12:00:00Z", now)).toBe("2d ago"); expect(ago(null, now)).toBe("—"); expect(ago("x", now)).toBe("—");
  });
});
