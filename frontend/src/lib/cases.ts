import type {
  AuditRow, CaseActivity, CaseStatus, IocType, JsonSchema, JsonSchemaProp, Timeline, TimelineEntry,
} from "./api-types";

export const TERMINAL_STATUSES: ReadonlySet<string> = new Set(["RESOLVED", "FALSE_POSITIVE", "CLOSED"]);

/** Terminal states need a resolution; reopening a CLOSED case needs a reason (mirrors backend workflow). */
export function transitionNeedsComment(from: CaseStatus | string, to: CaseStatus | string): boolean {
  return TERMINAL_STATUSES.has(to) || from === "CLOSED";
}

export const isLocked = (status: string): boolean => status === "CLOSED";

/** Display-only defanging so indicators can be copied into tickets/chat without becoming live links. */
export function defang(type: IocType | string, value: string): string {
  switch (type) {
    case "url": return value.replace(/^http/i, (m) => (m.toLowerCase() === "http" ? "hxxp" : m)).replace(/^(hxxps?:\/\/[^/?#]*)/i, (h) => h.replace(/\./g, "[.]"));
    case "domain": case "ip": return value.replace(/\./g, "[.]");
    case "email": return value.replace("@", "[@]").replace(/\./g, "[.]");
    default: return value;
  }
}

export interface MergedItem {
  kind: "telemetry" | "journal";
  at: string;
  entry?: TimelineEntry;
  activity?: CaseActivity;
}

/** Interleave telemetry and journal chronologically; on equal timestamps telemetry comes first (cause before note). */
export function mergeJournal(tl: Timeline | undefined, activity: CaseActivity[] | undefined): MergedItem[] {
  const items: MergedItem[] = [
    ...(tl?.entries ?? []).map((entry): MergedItem => ({ kind: "telemetry", at: entry.timestamp, entry })),
    ...(activity ?? []).map((a): MergedItem => ({ kind: "journal", at: a.created_at, activity: a })),
  ];
  const ms = (s: string) => Date.parse(s);
  return items
    .map((it, i) => ({ it, i }))
    .sort((a, b) => ms(a.it.at) - ms(b.it.at) || (a.it.kind === b.it.kind ? a.i - b.i : a.it.kind === "telemetry" ? -1 : 1))
    .map((x) => x.it);
}

export function describeActivity(a: CaseActivity): string {
  const d = a.details as Record<string, unknown>;
  switch (a.kind) {
    case "created": return "Case created";
    case "status_change": return `Status ${String(d.from ?? "?")} → ${String(d.to ?? "?")}${a.body ? `: ${a.body}` : ""}`;
    case "note": return a.body;
    case "updated": return `Updated ${Object.keys(d).join(", ")}`;
    case "evidence_added": return `Evidence added (${Array.isArray(d.events) ? d.events.length : 0} events)${a.body ? `: ${a.body}` : ""}`;
    case "evidence_removed": return "Evidence removed";
    case "ioc_added": return `IOC added: ${String(d.type)} ${String(d.value)}`;
    case "ioc_removed": return `IOC removed: ${String(d.type)} ${String(d.value)}`;
    case "iocs_extracted": return `IOCs re-extracted (${String(d.count)})`;
    case "asset_linked": return `Asset linked: ${String(d.asset)}`;
    case "asset_unlinked": return "Asset unlinked";
    case "report_generated": return `Report v${String(d.version)} generated`;
    default: return a.kind.replace(/_/g, " ");
  }
}

// ---- query-string mapping ---------------------------------------------------------------------
export interface CaseFilters { status: string; severity: string; mine: boolean; q: string }
export const defaultCaseFilters = (): CaseFilters => ({ status: "", severity: "", mine: false, q: "" });

export function caseListQuery(f: CaseFilters, limit = 100, offset = 0): string {
  const p = new URLSearchParams();
  if (f.status) p.set("status", f.status);
  if (f.severity) p.set("severity", f.severity);
  if (f.mine) p.set("mine", "true");
  if (f.q.trim()) p.set("q", f.q.trim());
  p.set("limit", String(limit));
  if (offset) p.set("offset", String(offset));
  return `?${p.toString()}`;
}

export interface AuditFilters { action: string; outcome: string; actor_id: string; resource_type: string; since: string; until: string }
export const defaultAuditFilters = (): AuditFilters => ({ action: "", outcome: "", actor_id: "", resource_type: "", since: "", until: "" });

/** `datetime-local` values are interpreted as UTC (the whole UI is UTC). */
const toIso = (v: string): string => new Date(v.length === 16 ? `${v}:00Z` : v).toISOString();

export function auditQuery(f: AuditFilters, offset: number, limit: number): string {
  const p = new URLSearchParams();
  if (f.action.trim()) p.set("action", f.action.trim());
  if (f.outcome) p.set("outcome", f.outcome);
  if (f.actor_id.trim()) p.set("actor_id", f.actor_id.trim());
  if (f.resource_type.trim()) p.set("resource_type", f.resource_type.trim());
  if (f.since) p.set("since", toIso(f.since));
  if (f.until) p.set("until", toIso(f.until));
  p.set("limit", String(limit));
  p.set("offset", String(offset));
  return `?${p.toString()}`;
}

export interface AssetFilters { type: string; criticality: string; q: string }
export function assetListQuery(f: AssetFilters, limit = 200): string {
  const p = new URLSearchParams();
  if (f.type) p.set("type", f.type);
  if (f.criticality) p.set("criticality", f.criticality);
  if (f.q.trim()) p.set("q", f.q.trim());
  p.set("limit", String(limit));
  return `?${p.toString()}`;
}

/** Relationship bucket → Events filter (the aggregation name tells us which telemetry field it came from). */
export const RELATED_FIELD: Record<string, string> = {
  users: "user.name", hosts: "host.hostname", destinations: "network.dst_ip", sources: "network.src_ip",
  processes: "process.name", ports: "network.dst_port",
};
export function relatedPivotHref(group: string, key: string | number): string | null {
  const field = RELATED_FIELD[group];
  return field ? `/events?f=${encodeURIComponent(`${field}|eq|${key}`)}` : null;
}

export function ingestCurl(origin: string, id: string): string {
  return `curl -X POST ${origin}/api/v1/ingest/${id} \\\n  -H "Authorization: Bearer <INGEST_KEY>" \\\n  -H "Content-Type: application/json" \\\n  -d '{"events":[{ ... }]}'`;
}

// ---- JSON-schema → form ------------------------------------------------------------------------
export interface FormField {
  name: string; label: string; kind: "string" | "integer" | "number" | "boolean" | "json" | "enum";
  required: boolean; placeholder?: string; description?: string; options?: string[]; defaultValue?: unknown;
}

function resolve(p: JsonSchemaProp): JsonSchemaProp {
  // Optional fields arrive as anyOf [X, null]; pick the first non-null branch, keep metadata.
  if (p.anyOf) {
    const branch = p.anyOf.find((b) => b.type !== "null") ?? p.anyOf[0];
    return { ...branch, title: p.title ?? branch.title, description: p.description ?? branch.description, default: p.default };
  }
  return p;
}

export function fieldsFromSchema(schema: JsonSchema | undefined): FormField[] {
  const required = new Set(schema?.required ?? []);
  return Object.entries(schema?.properties ?? {}).map(([name, raw]) => {
    const p = resolve(raw);
    let kind: FormField["kind"] = "json";
    if (p.enum) kind = "enum";
    else if (p.type === "string") kind = "string";
    else if (p.type === "integer") kind = "integer";
    else if (p.type === "number") kind = "number";
    else if (p.type === "boolean") kind = "boolean";
    return {
      name, label: p.title ?? name, kind, required: required.has(name), description: p.description,
      options: p.enum?.map(String), defaultValue: p.default,
      placeholder: p.default !== undefined && p.default !== null && kind !== "json" ? String(p.default) : p.format === "uri" ? "https://…" : undefined,
    };
  });
}

/** Turn raw form strings into a config object. Empty optional values are omitted so server defaults apply. */
export function buildConfig(fields: FormField[], values: Record<string, string | boolean>): { config: Record<string, unknown>; errors: string[] } {
  const config: Record<string, unknown> = {};
  const errors: string[] = [];
  for (const f of fields) {
    const v = values[f.name];
    if (f.kind === "boolean") { if (v !== undefined) config[f.name] = Boolean(v); continue; }
    const s = typeof v === "string" ? v.trim() : "";
    if (!s) { if (f.required) errors.push(`${f.label} is required`); continue; }
    if (f.kind === "integer" || f.kind === "number") {
      const n = Number(s);
      if (!Number.isFinite(n) || (f.kind === "integer" && !Number.isInteger(n))) { errors.push(`${f.label} must be a ${f.kind}`); continue; }
      config[f.name] = n;
    } else if (f.kind === "json") {
      try { config[f.name] = JSON.parse(s); } catch { errors.push(`${f.label} must be valid JSON`); }
    } else config[f.name] = s;
  }
  return { config, errors };
}

export const auditSummary = (r: AuditRow): string => [r.resource_type, r.resource_id?.slice(0, 8)].filter(Boolean).join(" ");
