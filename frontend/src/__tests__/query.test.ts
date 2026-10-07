import { addFilter, clampPaging, decodeFilter, defaultState, encodeFilter, paramsToState, stateToParams, toRequestBody } from "@/lib/query";

describe("toRequestBody", () => {
  const now = new Date("2026-03-01T12:00:00Z");
  it("resolves relative ranges and omits empty q", () => {
    const b = toRequestBody(defaultState(), [], now);
    expect(b.time_range).toEqual({ start: "2026-02-28T12:00:00.000Z", end: "2026-03-01T12:00:00.000Z" });
    expect(b.q).toBeUndefined();
    expect(b.limit).toBe(50);
  });
  it("passes q, filters and sort", () => {
    const s = { ...defaultState(), q: " power* ", filters: [{ field: "host.hostname", op: "eq" as const, value: "ws" }], sort: { field: "timestamp", order: "asc" as const } };
    const b = toRequestBody(s, [], now);
    expect(b.q).toBe("power*");
    expect(b.filters).toHaveLength(1);
    expect(b.sort).toEqual([{ field: "timestamp", order: "asc" }]);
  });
  it("keeps absolute ranges verbatim", () => {
    const s = { ...defaultState(), range: { kind: "abs" as const, start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" } };
    expect(toRequestBody(s, [], now).time_range.start).toBe("2026-01-01T00:00:00Z");
  });
  it("never exceeds backend paging window", () => {
    expect(clampPaging(9990, 50)).toEqual({ offset: 9950, limit: 50 });
    expect(clampPaging(-5, 0)).toEqual({ offset: 0, limit: 50 });
    expect(clampPaging(0, 5000)).toEqual({ offset: 0, limit: 200 });
    const b = toRequestBody({ ...defaultState(), offset: 20000 }, [], now);
    expect(b.offset + b.limit).toBeLessThanOrEqual(10000);
  });
});

describe("URL state", () => {
  it("round-trips", () => {
    const s = {
      ...defaultState(), q: 'powershell AND "-enc"', range: { kind: "rel" as const, value: "7d" },
      filters: [{ field: "host.hostname", op: "eq" as const, value: "ws|01" }, { field: "network.dst_domain", op: "exists" as const }],
      sort: { field: "severity", order: "desc" as const }, offset: 100, event: "a".repeat(32),
    };
    const back = paramsToState(new URLSearchParams(stateToParams(s).toString()));
    expect(back).toEqual(s);
  });
  it("rejects garbage safely", () => {
    const p = new URLSearchParams("range=bogus&f=nofield&f=x|evil|y&sort=a:sideways&offset=99999999&event=../etc&start=nope&end=nope");
    const s = paramsToState(p);
    expect(s.range).toEqual({ kind: "rel", value: "24h" });
    expect(s.filters).toEqual([]);
    expect(s.sort).toBeNull();
    expect(s.offset + s.limit).toBeLessThanOrEqual(10000);
    expect(s.event).toBeNull();
  });
  it("encodes filters and dedupes", () => {
    const f = { field: "a", op: "eq" as const, value: "b" };
    expect(decodeFilter(encodeFilter(f))).toEqual(f);
    expect(addFilter([f], { ...f })).toHaveLength(1);
  });
});
