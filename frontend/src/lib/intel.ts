import type {
  EventDoc, Confidence, EntityType, EnrichCaseResult, IntelCoverage, IntelProvider, MatrixColumn, MatrixTechnique, MitreSuggestion,
  MappingCreate, MitreObjectType, TechniqueSummary, Verdict,
} from "./api-types";
import { defang as baseDefang, buildConfig, fieldsFromSchema, type FormField } from "./cases";

/** Display-only defanging for any entity type (extends the case-IOC helper to hashes/named objects: unchanged). */
export const defangEntity = (type: EntityType | string, value: string): string => baseDefang(type, value);

export const VERDICT_CLASS: Record<Verdict, string> = {
  malicious: "bg-red-900/60 text-red-200", suspicious: "bg-orange-900/50 text-orange-300",
  benign: "bg-green-900/40 text-green-300", unknown: "text-muted border border-line",
};
export const VERDICT_NOTE: Record<Verdict, string> = {
  malicious: "Score ≥ 70", suspicious: "Score 35–69", benign: "A trusted benign signal and no threat signal",
  unknown: "No evidence either way — unknown is not the same as safe",
};
export const verdictFor = (score: number, hasBenign = false): Verdict =>
  score >= 70 ? "malicious" : score >= 35 ? "suspicious" : hasBenign ? "benign" : "unknown";

/** Colour band for the score bar. */
export const scoreBand = (score: number): "high" | "mid" | "low" => (score >= 70 ? "high" : score >= 35 ? "mid" : "low");
export const clampScore = (n: number): number => Math.max(0, Math.min(100, Math.round(n)));

export const MODEL_NOTE =
  "Each source adds a weighted signal; independent sources combine (noisy-OR), so one weak source cannot convict. " +
  "“Unknown” means no evidence either way — it is not the same as safe.";

export function coverageLine(c: IntelCoverage | null | undefined): string {
  if (!c) return "";
  const parts = [`${c.answered} answered`, `${c.not_found} had no record`, `${c.failed} failed`];
  const skipped = c.skipped.map((s) => `${s.provider} (${s.reason})`);
  return parts.join(" · ") + (skipped.length ? ` · not run: ${skipped.join(", ")}` : "");
}

/** Providers that need credentials/config but are not usable yet — drives the graceful-degradation banner. */
export const unconfiguredProviders = (ps: IntelProvider[]): IntelProvider[] =>
  ps.filter((p) => !p.offline && !p.configured && p.supported_types.length > 0);

export function degradationMessage(ps: IntelProvider[]): string | null {
  const missing = unconfiguredProviders(ps);
  if (!missing.length) return null;
  return `${missing.length} external provider${missing.length > 1 ? "s are" : " is"} not configured (${missing.map((p) => p.display_name).join(", ")}). ` +
    "Lookups still work: only the local heuristics and your tenant watch-list run until API keys are added.";
}

/** Provider form: config fields from the JSON schema plus one write-only input per required secret. */
export function providerFields(p: Pick<IntelProvider, "config_schema">): FormField[] { return fieldsFromSchema(p.config_schema); }
export function buildProviderPayload(
  p: IntelProvider, enabled: boolean, values: Record<string, string | boolean>, secrets: Record<string, string>,
): { body: { enabled: boolean; config: Record<string, unknown>; secrets?: Record<string, string> }; errors: string[] } {
  const { config, errors } = buildConfig(providerFields(p), values);
  // Blank secret inputs mean “keep the stored value” (secrets are never echoed back): omit them entirely.
  const supplied = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v.trim()).map(([k, v]) => [k, v.trim()]));
  const body: { enabled: boolean; config: Record<string, unknown>; secrets?: Record<string, string> } = { enabled, config };
  if (Object.keys(supplied).length) body.secrets = supplied;
  return { body, errors };
}

/** Sightings field → Events deep link using the app's `f=field|op|value` URL filter encoding. */
export function sightingsHref(field: string, value: string): string {
  if (field === "free_text") return `/events?q=${encodeURIComponent(`"${value}"`)}`;
  return `/events?f=${encodeURIComponent(`${field}|eq|${value}`)}`;
}

export function enrichSummary(r: EnrichCaseResult): string {
  return `${r.checked} indicator${r.checked === 1 ? "" : "s"} checked · ${r.malicious} malicious`;
}

export const watchPayload = (verdict: string, confidence: number, notes: string, tags: string): import("./api-types").EntityUpdate => ({
  ...(verdict ? { watch_verdict: verdict as "malicious" | "suspicious" | "benign", watch_confidence: confidence } : { clear_watch: true }),
  notes, tags: tags.split(",").map((t) => t.trim()).filter(Boolean).slice(0, 20),
});

export function parseStixText(text: string): { bundle: unknown; error: string | null } {
  try {
    const bundle = JSON.parse(text) as { type?: string; objects?: unknown };
    if (bundle?.type !== "bundle" || !Array.isArray(bundle.objects)) return { bundle: null, error: "Not a STIX 2.x bundle (needs type: \"bundle\" and an objects list)" };
    return { bundle, error: null };
  } catch { return { bundle: null, error: "Invalid JSON" }; }
}
export const stixSummary = (r: { created: number; updated: number; skipped: number; relations: number; named_objects: number }): string =>
  `${r.created} new · ${r.updated} updated · ${r.named_objects} named objects · ${r.relations} relations · ${r.skipped} skipped`;

// ---- MITRE -------------------------------------------------------------------------------------------
export const CONF_RANK: Record<Confidence, number> = { LOW: 1, MEDIUM: 2, HIGH: 3 };

/** Restrained palette: unmapped cells stay neutral; colour encodes the strongest confidence, opacity-free. */
export function cellClass(t: Pick<MatrixTechnique, "mapping_count" | "top_confidence">): string {
  if (!t.mapping_count || !t.top_confidence) return "border-line text-muted";
  return { HIGH: "border-red-700 bg-red-900/40 text-red-100", MEDIUM: "border-orange-700 bg-orange-900/30 text-orange-100", LOW: "border-yellow-700 bg-yellow-900/20 text-yellow-100" }[t.top_confidence];
}

export function filterMatrix(cols: MatrixColumn[], query: string, mappedOnly: boolean): MatrixColumn[] {
  const q = query.trim().toLowerCase();
  const matches = (t: MatrixTechnique): boolean =>
    (!mappedOnly || t.mapping_count > 0) && (!q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q));
  const keep = (t: MatrixTechnique): MatrixTechnique | null => {
    const subs = t.subtechniques.filter(matches);
    if (!matches(t) && !subs.length) return null;
    // A matching parent keeps its sub-techniques (only dropping unmapped ones in mapped-only mode).
    return { ...t, subtechniques: matches(t) ? t.subtechniques.filter((x) => !mappedOnly || x.mapping_count > 0) : subs };
  };
  return cols.map((c) => ({ ...c, techniques: c.techniques.map(keep).filter((t): t is MatrixTechnique => t !== null) }));
}

export const matrixTotals = (cols: MatrixColumn[]): { techniques: number; mapped: number } => {
  const seen = new Map<string, number>();
  const walk = (t: MatrixTechnique) => { seen.set(t.id, t.mapping_count); t.subtechniques.forEach(walk); };
  cols.forEach((c) => c.techniques.forEach(walk));
  return { techniques: seen.size, mapped: [...seen.values()].filter((n) => n > 0).length };
};

/** The brief's exact summary shape. */
export const summaryLine = (s: Pick<TechniqueSummary, "evidence_events" | "hosts" | "users" | "risk">): string =>
  `Evidence: ${s.evidence_events} events · Hosts: ${s.hosts.count} · Users: ${s.users.count} · Risk: ${s.risk}`;

export const RISK_CLASS = { HIGH: "text-red-300", MEDIUM: "text-orange-300", LOW: "text-yellow-300" } as const;

export const mapHref = (objectType: string, id: string): string | null =>
  objectType === "case" ? `/cases/${id}` : objectType === "hunt" ? `/hunts/${id}` : null;

export interface AcceptDraft { confidence: Confidence; reasoning: string; evidence: string[] }
export function acceptDraft(s: MitreSuggestion): AcceptDraft {
  return { confidence: s.confidence, reasoning: s.reasoning.map((r) => `• ${r}`).join("\n").slice(0, 5000), evidence: s.event_ids.slice(0, 100) };
}
/** Mirrors backend rules: reasoning ≥ 10 chars; MEDIUM/HIGH must cite evidence. */
export function validateDraft(d: AcceptDraft): string | null {
  if (d.reasoning.trim().length < 10) return "Reasoning must be at least 10 characters — say why this technique applies.";
  if ((d.confidence === "MEDIUM" || d.confidence === "HIGH") && d.evidence.length === 0) return "MEDIUM and HIGH confidence mappings must cite at least one evidence event.";
  return null;
}
export const mappingPayload = (s: MitreSuggestion, d: AcceptDraft, objectType: MitreObjectType, objectId: string): MappingCreate => ({
  technique_id: s.technique_id, object_type: objectType, object_id: objectId, confidence: d.confidence,
  reasoning: d.reasoning.trim(), evidence_event_ids: d.evidence, source: "suggestion",
});

export const ENTITY_LABEL: Record<string, string> = { threat_actor: "threat actor", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5" };

const PRIVATE_IP = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|::1$|fe80:|fc|fd)/i;
/** Indicators worth a threat-intel lookup in an event (public IPs, domains, hashes). Values are only ever used as lookup input. */
export function eventIndicators(e: EventDoc): Array<{ type: EntityType; value: string; label: string }> {
  const out: Array<{ type: EntityType; value: string; label: string }> = [];
  const add = (type: EntityType, value: string | undefined | null, label: string) => {
    if (value && !out.some((o) => o.value === value)) out.push({ type, value, label });
  };
  const ip = (v: string | undefined | null, label: string) => { if (v && !PRIVATE_IP.test(v)) add("ip", v, label); };
  ip(e.network?.dst_ip, "dst ip"); ip(e.network?.src_ip, "src ip"); ip(e.auth?.source_ip, "auth source ip");
  (e.dns?.answers ?? []).forEach((a) => { if (/^[\d.]+$|:/.test(a)) ip(a, "dns answer"); });
  add("domain", e.network?.dst_domain, "dst domain"); add("domain", e.dns?.question, "dns question");
  add("sha256", e.process?.hash?.sha256, "process sha256"); add("sha256", e.file?.hash?.sha256, "file sha256");
  add("md5", e.process?.hash?.md5, "process md5");
  return out.slice(0, 8);
}
