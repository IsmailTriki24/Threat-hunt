import { appendPivot, downloadBlob, entryForEvent, isBeaconLike, lineageDepths, periodicityLabel, pivotTerm, quoteValue } from "@/lib/hunt-query";
import type { Timeline, TimelineEntry } from "@/lib/api-types";

const entry = (o: Partial<TimelineEntry>): TimelineEntry => ({
  id: "e", timestamp: "2026-03-01T10:00:00Z", end_timestamp: null, count: 1, event_type: "process_creation", title: "t", severity: 0,
  host: null, user: null, process: null, pid: null, destination: null, parent_event_id: null, process_event_id: null,
  event_ids: [o.id ?? "e"], periodicity: null, ...o,
});

describe("pivot text helpers", () => {
  it("quotes values containing spaces, parens, pipes, quotes, wildcards or reserved words", () => {
    expect(quoteValue("powershell.exe")).toBe("powershell.exe");
    expect(quoteValue("C:\\Program Files\\x.exe")).toBe('"C:\\Program Files\\x.exe"');
    expect(quoteValue("a|b")).toBe('"a|b"');
    expect(quoteValue("f(x)")).toBe('"f(x)"');
    expect(quoteValue("*evil*")).toBe('"*evil*"'); // a literal asterisk must not become a wildcard
    expect(quoteValue("OR")).toBe('"OR"');
    expect(quoteValue('say "hi" now')).toBe(`"say 'hi' now"`); // the language has no escape for "
    expect(quoteValue("")).toBe('""');
    expect(pivotTerm("process.command_line", "-enc AAAA")).toBe('process.command_line:"-enc AAAA"');
    expect(pivotTerm("network.dst_port", 443)).toBe("network.dst_port:443");
  });

  it("appends with single spacing and skips duplicates", () => {
    expect(appendPivot("", "host.hostname", "WS-01")).toBe("host.hostname:WS-01");
    expect(appendPivot("process.name:cmd.exe  \n", "user.name", "a b")).toBe('process.name:cmd.exe user.name:"a b"');
    expect(appendPivot("host.hostname:WS-01", "host.hostname", "WS-01")).toBe("host.hostname:WS-01");
  });
});

describe("beacon observation", () => {
  const p = (jitter: number, count = 20) => ({ count, periodicity: { median_interval_s: 60, jitter_pct: jitter } });
  it("requires count >= 10 and jitter < 20%", () => {
    expect(isBeaconLike(p(4))).toBe(true);
    expect(isBeaconLike(p(19.9))).toBe(true);
    expect(isBeaconLike(p(20))).toBe(false);
    expect(isBeaconLike(p(4, 9))).toBe(false);
    expect(isBeaconLike({ count: 50, periodicity: null })).toBe(false);
  });
  it("formats the interval", () => {
    expect(periodicityLabel({ periodicity: { median_interval_s: 60.4, jitter_pct: 3.6 } })).toBe("every ~60s, jitter 4%");
    expect(periodicityLabel({ periodicity: { median_interval_s: 600, jitter_pct: 10 } })).toBe("every ~10m, jitter 10%");
    expect(periodicityLabel({ periodicity: null })).toBeNull();
  });
});

describe("lineage", () => {
  const tl: Timeline = {
    total_events: 4, truncated: false,
    entries: [
      entry({ id: "w" }),
      entry({ id: "p", parent_event_id: "w" }),
      entry({ id: "n", event_type: "network_connection", process_event_id: "p", event_ids: ["n", "n2"] }),
      entry({ id: "loop-a", parent_event_id: "loop-b" }), entry({ id: "loop-b", parent_event_id: "loop-a" }),
    ],
  };
  it("computes depth and survives cycles", () => {
    const d = lineageDepths(tl);
    expect(d.get("w")).toBe(0);
    expect(d.get("p")).toBe(1);
    expect(d.get("n")).toBe(2);
    expect(d.has("loop-a") && d.has("loop-b")).toBe(true);
  });
  it("finds the entry holding an event id (including collapsed members)", () => {
    expect(entryForEvent(tl, "n2")?.id).toBe("n");
    expect(entryForEvent(tl, "zzz")).toBeUndefined();
  });
});

it("downloadBlob clicks a temporary anchor with the filename and revokes the URL", () => {
  const create = vi.fn(() => "blob:x");
  const revoke = vi.fn();
  Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.download).toBe("events.csv");
    expect(this.href).toContain("blob:x");
  });
  downloadBlob(new Blob(["a"]), "events.csv");
  expect(click).toHaveBeenCalledOnce();
  expect(document.querySelector("a[download]")).toBeNull();
  click.mockRestore();
});
