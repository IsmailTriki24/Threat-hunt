import type { Timeline, TimelineEntry } from "./api-types";

/** Quote a hunt-query-language value when it contains whitespace or characters that would change parsing. */
export function quoteValue(v: string | number): string {
  const s = String(v);
  if (s === "") return '""';
  if (/[\s"()|]/.test(s) || s.startsWith("*") || s.endsWith("*") || s === "AND" || s === "OR" || s === "NOT") {
    return `"${s.replace(/"/g, "'")}"`; // the language has no escape for ", so swap it
  }
  return s;
}

export function pivotTerm(field: string, value: string | number): string {
  return `${field}:${quoteValue(value)}`;
}

/** Append `field:value` to existing query text, skipping exact duplicates. */
export function appendPivot(text: string, field: string, value: string | number): string {
  const term = pivotTerm(field, value);
  if (text.split(/\s+/).includes(term)) return text;
  const base = text.replace(/\s+$/, "");
  return base ? `${base} ${term}` : term;
}

export const BEACON_MIN_COUNT = 10;
export const BEACON_MAX_JITTER = 20;

export function isBeaconLike(e: Pick<TimelineEntry, "count" | "periodicity">): boolean {
  return !!e.periodicity && e.count >= BEACON_MIN_COUNT && e.periodicity.jitter_pct < BEACON_MAX_JITTER;
}

export function periodicityLabel(e: Pick<TimelineEntry, "periodicity">): string | null {
  if (!e.periodicity) return null;
  const { median_interval_s: s, jitter_pct: j } = e.periodicity;
  const every = s >= 3600 ? `${(s / 3600).toFixed(1)}h` : s >= 120 ? `${Math.round(s / 60)}m` : `${Math.round(s)}s`;
  return `every ~${every}, jitter ${Math.round(j)}%`;
}

export const BEACON_WORDING = "Regular interval observed — consistent with automated (beacon-like) activity; verify before concluding.";

/** Depth of each entry in the process lineage (via parent_event_id / process_event_id) within this timeline. */
export function lineageDepths(tl: Timeline): Map<string, number> {
  const byEvent = new Map<string, TimelineEntry>();
  for (const e of tl.entries) for (const id of e.event_ids) byEvent.set(id, e);
  const depth = new Map<string, number>();
  const calc = (e: TimelineEntry, seen: Set<string>): number => {
    if (depth.has(e.id)) return depth.get(e.id)!;
    if (seen.has(e.id)) return 0;
    seen.add(e.id);
    const parentId = e.parent_event_id ?? e.process_event_id;
    const parent = parentId ? byEvent.get(parentId) : undefined;
    const d = parent && parent !== e ? calc(parent, seen) + 1 : 0;
    depth.set(e.id, d);
    return d;
  };
  tl.entries.forEach((e) => calc(e, new Set()));
  return depth;
}

/** Entry (in this timeline) that holds the given underlying event id. */
export function entryForEvent(tl: Timeline, eventId: string): TimelineEntry | undefined {
  return tl.entries.find((e) => e.event_ids.includes(eventId));
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
