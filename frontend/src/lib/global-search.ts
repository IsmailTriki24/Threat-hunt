import { pivotTerm } from "./hunt-query";
import { detectType, type IndicatorKind } from "./indicator";

export interface SearchTarget { href: string; label: string; kind: "events" | "intel" }
export interface EventScope { key: string; field: string; role: string }

/** Where an indicator can appear in an event. The hunt query language has no cross-field OR (only `field:(a|b)` within one field), so each
 *  role is its own valid single-field search instead of one invalid combined query. The first scope is the default. */
const SCOPES: Record<Exclude<IndicatorKind, null>, EventScope[]> = {
  ip: [
    { key: "dst", field: "network.dst_ip", role: "destination" }, { key: "src", field: "network.src_ip", role: "source" },
    { key: "auth", field: "auth.source_ip", role: "sign-in source" }, { key: "host", field: "host.ip", role: "host address" },
  ],
  sha256: [{ key: "process", field: "process.hash.sha256", role: "process hash" }, { key: "file", field: "file.hash.sha256", role: "file hash" }],
  sha1: [{ key: "process", field: "process.hash.sha1", role: "process hash" }],
  md5: [{ key: "process", field: "process.hash.md5", role: "process hash" }],
  domain: [{ key: "dst", field: "network.dst_domain", role: "connection destination" }, { key: "dns", field: "dns.question", role: "DNS query" }],
};

export const scopesFor = (kind: IndicatorKind): EventScope[] => (kind ? SCOPES[kind] : []);

/** `/events` link for one field:value search (hunt query language), optionally over a time window. */
export function fieldSearchHref(field: string, value: string, window?: { range?: string; start?: string; end?: string }): string {
  const p = new URLSearchParams({ lang: "1", q: pivotTerm(field, value.trim()) });
  if (window?.range === "custom" && window.start && window.end) { p.set("start", new Date(window.start).toISOString()); p.set("end", new Date(window.end).toISOString()); }
  else if (window?.range) p.set("range", window.range);
  return `/events?${p.toString()}`;
}

/** The default events search for what was typed: the primary role for an indicator, otherwise plain text. */
export function eventsHref(input: string): string {
  const v = input.trim();
  const scopes = scopesFor(detectType(v));
  return scopes.length ? fieldSearchHref(scopes[0].field, v) : `/events?${new URLSearchParams({ q: v }).toString()}`;
}

export function targets(input: string, canLookup: boolean): SearchTarget[] {
  const v = input.trim();
  if (!v) return [];
  const kind = detectType(v);
  const short = v.length > 40 ? `${v.slice(0, 39)}…` : v;
  const out: SearchTarget[] = kind
    ? scopesFor(kind).map((s) => ({ href: fieldSearchHref(s.field, v), label: `Events where “${short}” is the ${s.role}`, kind: "events" as const }))
    : [{ href: eventsHref(v), label: `Search events for “${short}”`, kind: "events" }];
  if (canLookup && kind) out.push({ href: `/threat-intel?lookup=${encodeURIComponent(v)}`, label: `Look up ${kind} in threat intelligence`, kind: "intel" });
  return out;
}
