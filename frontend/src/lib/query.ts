import type { Aggregation, EventQueryBody, Filter, Op } from "./api-types";

export const MAX_WINDOW = 10_000;
export const PAGE_SIZE = 50;

export const RELATIVE_RANGES: Record<string, number> = {
  "15m": 15 * 60_000, "1h": 3_600_000, "6h": 6 * 3_600_000, "24h": 24 * 3_600_000,
  "7d": 7 * 86_400_000, "30d": 30 * 86_400_000,
};

export type RangeSpec = { kind: "rel"; value: string } | { kind: "abs"; start: string; end: string };

export interface SearchState {
  q: string;
  /** true: `q` is hunt query language and is sent as `text` instead of free text. */
  lang: boolean;
  range: RangeSpec;
  filters: Filter[];
  sort: { field: string; order: "asc" | "desc" } | null;
  offset: number;
  limit: number;
  event: string | null;
}

export const defaultState = (): SearchState => ({
  q: "", lang: false, range: { kind: "rel", value: "24h" }, filters: [], sort: null, offset: 0, limit: PAGE_SIZE, event: null,
});

export function clampPaging(offset: number, limit: number): { offset: number; limit: number } {
  const l = Math.min(Math.max(Math.trunc(limit) || PAGE_SIZE, 1), 200);
  const o = Math.min(Math.max(Math.trunc(offset) || 0, 0), MAX_WINDOW - l);
  return { offset: o, limit: l };
}

export function resolveRange(r: RangeSpec, now: Date = new Date()): { start: string; end: string } {
  if (r.kind === "abs") return { start: r.start, end: r.end };
  const span = RELATIVE_RANGES[r.value] ?? RELATIVE_RANGES["24h"];
  return { start: new Date(now.getTime() - span).toISOString(), end: now.toISOString() };
}

export const OVERVIEW_AGGS: Aggregation[] = [
  { name: "by_host", field: "host.hostname", size: 10 },
  { name: "by_type", field: "event_type", size: 10 },
];

export const SEARCH_AGGS: Aggregation[] = [
  { name: "by_host", field: "host.hostname", size: 8 },
  { name: "by_user", field: "user.name", size: 8 },
  { name: "by_process", field: "process.name", size: 8 },
  { name: "by_type", field: "event_type", size: 8 },
  { name: "by_dst_ip", field: "network.dst_ip", size: 8 },
  { name: "timeline", type: "date_histogram" },
];

export function toRequestBody(s: SearchState, aggregations: Aggregation[] = SEARCH_AGGS, now?: Date): EventQueryBody {
  const { offset, limit } = clampPaging(s.offset, s.limit);
  const body: EventQueryBody = {
    time_range: resolveRange(s.range, now),
    filters: s.filters,
    sort: s.sort ? [s.sort] : [],
    offset, limit, aggregations,
  };
  if (s.q.trim()) body[s.lang ? "text" : "q"] = s.q.trim();
  return body;
}

// ---- URL (de)serialisation --------------------------------------------------------------
const NO_VALUE: Op[] = ["exists", "not_exists"];
const OPS: Op[] = ["eq", "neq", "in", "exists", "not_exists", "prefix", "contains", "gt", "gte", "lt", "lte"];

export function encodeFilter(f: Filter): string {
  const v = NO_VALUE.includes(f.op) ? "" : Array.isArray(f.value) ? f.value.join(",") : String(f.value ?? "");
  return `${f.field}|${f.op}|${v}`;
}

export function decodeFilter(s: string): Filter | null {
  const [field, op, ...rest] = s.split("|");
  if (!field || !OPS.includes(op as Op)) return null;
  const value = rest.join("|");
  if (NO_VALUE.includes(op as Op)) return { field, op: op as Op };
  return { field, op: op as Op, value: op === "in" ? value.split(",") : value };
}

export function stateToParams(s: SearchState): URLSearchParams {
  const p = new URLSearchParams();
  if (s.q) p.set("q", s.q);
  if (s.lang) p.set("lang", "1");
  if (s.range.kind === "rel") { if (s.range.value !== "24h") p.set("range", s.range.value); }
  else { p.set("start", s.range.start); p.set("end", s.range.end); }
  s.filters.forEach((f) => p.append("f", encodeFilter(f)));
  if (s.sort) p.set("sort", `${s.sort.field}:${s.sort.order}`);
  if (s.offset) p.set("offset", String(s.offset));
  if (s.event) p.set("event", s.event);
  return p;
}

export function paramsToState(p: URLSearchParams): SearchState {
  const st = defaultState();
  st.lang = p.get("lang") === "1";
  st.q = (p.get("q") ?? "").slice(0, st.lang ? 2000 : 512);
  const start = p.get("start"), end = p.get("end");
  const range = p.get("range");
  if (start && end && !Number.isNaN(Date.parse(start)) && !Number.isNaN(Date.parse(end))) st.range = { kind: "abs", start, end };
  else if (range && range in RELATIVE_RANGES) st.range = { kind: "rel", value: range };
  st.filters = p.getAll("f").map(decodeFilter).filter((f): f is Filter => f !== null).slice(0, 25);
  const sort = p.get("sort");
  if (sort) {
    const [field, order] = sort.split(":");
    if (field && (order === "asc" || order === "desc")) st.sort = { field, order };
  }
  st.offset = clampPaging(Number(p.get("offset")) || 0, st.limit).offset;
  st.event = /^[a-f0-9]{32}$/.test(p.get("event") ?? "") ? p.get("event") : null;
  return st;
}

export function operatorsFor(kind: string): Op[] {
  switch (kind) {
    case "keyword": return ["eq", "neq", "prefix", "contains", "exists", "not_exists"];
    case "text": return ["contains", "eq", "neq", "exists", "not_exists"];
    case "ip": return ["eq", "neq", "exists", "not_exists"];
    case "integer": case "long": return ["eq", "neq", "gt", "gte", "lt", "lte", "exists", "not_exists"];
    case "date": return ["gte", "lt"];
    default: return ["eq"];
  }
}

export const OP_LABEL: Record<Op, string> = {
  eq: "is", neq: "is not", in: "in", exists: "exists", not_exists: "missing", prefix: "starts with",
  contains: "contains", gt: ">", gte: "≥", lt: "<", lte: "≤",
};

export function addFilter(filters: Filter[], f: Filter): Filter[] {
  if (filters.some((x) => encodeFilter(x) === encodeFilter(f))) return filters;
  return [...filters, f].slice(0, 25);
}

export const fmtTime = (iso: string): string => iso.replace("T", " ").replace(/\.\d+/, "").replace(/(Z|\+00:00)$/, "");
