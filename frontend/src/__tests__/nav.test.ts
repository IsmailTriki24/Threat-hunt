import { existsSync } from "node:fs";
import { join } from "node:path";
import { eventsHref, scopesFor, targets } from "@/lib/global-search";
import { detectType } from "@/lib/indicator";
import { breadcrumbs, isActive, NAV, NAV_GROUPS, visibleGroups } from "@/lib/nav";

describe("navigation model", () => {
  it("every item points at a real route and appears once", () => {
    const hrefs = NAV.map((n) => n.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
    for (const h of hrefs) {
      const dir = join(process.cwd(), "src/app/(app)", h === "/" ? "" : h);
      expect(existsSync(join(dir, "page.tsx")), `${h} has no page`).toBe(true);
    }
  });
  it("every group has a label and items; every item has an icon and a hint", () => {
    for (const g of NAV_GROUPS) { expect(g.label).toBeTruthy(); expect(g.items.length).toBeGreaterThan(0); }
    for (const n of NAV) { expect(n.icon).toBeTruthy(); expect(n.hint.length).toBeGreaterThan(5); }
  });
  it("shows platform-only entries to the platform administrator alone", () => {
    const hrefs = (can: (p: string) => boolean) => visibleGroups(can).flatMap((g) => g.items.map((i) => i.href));
    expect(hrefs(() => true)).toContain("/tenants");
    expect(hrefs((p) => p !== "tenants:manage")).not.toContain("/tenants");
    expect(hrefs((p) => p !== "tenants:manage")).toContain("/data-sources");
    expect(visibleGroups(() => false).every((g) => g.items.length > 0)).toBe(true); // empty groups are dropped
  });
  it("matches by prefix at a path boundary, never by substring", () => {
    expect(isActive("/hunts", "/hunts/123")).toBe(true);
    expect(isActive("/hunts", "/hunts")).toBe(true);
    expect(isActive("/hunts", "/hunts-archive")).toBe(false);
    expect(isActive("/", "/")).toBe(true);
    expect(isActive("/", "/cases")).toBe(false);
  });
  it("builds Section > Page (> Details) breadcrumbs", () => {
    expect(breadcrumbs("/")).toEqual([{ label: "Investigate" }, { label: "Overview" }]);
    expect(breadcrumbs("/ioc-hunting")).toEqual([{ label: "Intelligence" }, { label: "IOC Hunting" }]);
    expect(breadcrumbs("/cases/abc")).toEqual([{ label: "Investigate" }, { label: "Cases", href: "/cases" }, { label: "Details" }]);
    expect(breadcrumbs("/mitre/techniques/T1059")[2]).toEqual({ label: "Technique" });
  });
});

describe("indicator detection and search routing", () => {
  it("classifies what was typed", () => {
    expect(detectType("8.8.8.8")).toBe("ip");
    expect(detectType("2606:4700:4700::1111")).toBe("ip");
    expect(detectType("a".repeat(64))).toBe("sha256");
    expect(detectType("a".repeat(40))).toBe("sha1");
    expect(detectType("a".repeat(32))).toBe("md5");
    expect(detectType("sub.evil-site.example")).toBe("domain");
    for (const bad of ["999.1.1.1", "not a domain", "powershell", "", "a".repeat(63)]) expect(detectType(bad)).toBeNull();
  });
  it("search queries are single-field (valid in the hunt query language) for indicators and plain text otherwise", () => {
    const q = (s: string) => new URL(eventsHref(s), "http://x").searchParams;
    expect(q("evil.example").get("q")).toBe("network.dst_domain:evil.example");
    expect(q("8.8.8.8").get("q")).toBe("network.dst_ip:8.8.8.8");
    expect(q("  8.8.8.8  ").get("q")).toBe("network.dst_ip:8.8.8.8");
    expect(q("a".repeat(64)).get("q")).toBe(`process.hash.sha256:${"a".repeat(64)}`);
    expect(q("whoami /all").get("lang")).toBeNull();
    expect(q("whoami /all").get("q")).toBe("whoami /all");
  });
  it("no generated query ever contains a cross-field OR/AND (the server rejects it with a 422)", () => {
    const samples = ["185.220.101.5", "2606:4700:4700::1111", "a".repeat(64), "b".repeat(40), "c".repeat(32), "sub.evil-site.example"];
    for (const v of samples) for (const t of targets(v, true)) {
      const q = new URL(t.href, "http://x").searchParams.get("q");
      if (t.kind === "events") { expect(q, t.href).not.toMatch(/\s(OR|AND)\s/); expect(q!.trim().split(/\s+/), t.href).toHaveLength(1); } // exactly one field:value term
    }
  });
  it("each role of an indicator is its own search", () => {
    expect(scopesFor("ip").map((s) => s.field)).toEqual(["network.dst_ip", "network.src_ip", "auth.source_ip", "host.ip"]);
    expect(scopesFor("sha256").map((s) => s.field)).toEqual(["process.hash.sha256", "file.hash.sha256"]);
    expect(scopesFor("domain").map((s) => s.field)).toEqual(["network.dst_domain", "dns.question"]);
    expect(scopesFor(null)).toEqual([]);
  });
  it("offers an intel lookup only for indicators and only when allowed", () => {
    expect(targets("", true)).toEqual([]);
    expect(targets("hello world", true)).toHaveLength(1);
    expect(targets("8.8.8.8", false).map((t) => t.kind)).toEqual(["events", "events", "events", "events"]);
    expect(targets("8.8.8.8", true).map((t) => t.kind)).toEqual(["events", "events", "events", "events", "intel"]);
  });
});
