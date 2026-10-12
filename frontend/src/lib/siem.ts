/** Whole-SIEM search (LogRhythm): result shape from /api/v1/events/siem-search and /siem-lookup, and the wording the UI uses for each state. */
export type SiemStatus = "ok" | "partial" | "error" | "not_applicable" | "unconfigured" | "disabled";

export interface SiemSample { id: string; timestamp: string; summary: string; host: string | null }
export interface SiemResult {
  source: string; configured: boolean; status: SiemStatus; detail: string; searched: Array<{ kind: string; values: string[]; logs: number }>;
  skipped: string[]; matched: number; imported: number; duplicates: number; truncated: boolean; samples?: SiemSample[]; logs_scanned?: number;
  window?: { start: string; end: string }; ms?: number;
}

/** Statuses that need no space on screen: nothing was asked, or there is nothing to ask. */
export const SIEM_QUIET: SiemStatus[] = ["unconfigured", "disabled"];

export function searchedSummary(r: Pick<SiemResult, "searched">): string {
  const parts = r.searched.map((s) => `${s.values.length > 2 ? `${s.values.length} ${s.kind}s` : s.values.join(", ")}`);
  return parts.join(" · ");
}

/** One sentence for the card. Never claims a result the SIEM did not give: zero means zero logs matched in the searched window. */
export function siemHeadline(r: SiemResult): string {
  const what = searchedSummary(r) || "this search";
  if (r.status === "error") return "The whole-SIEM search failed";
  if (r.matched === 0) return `No logs for ${what} in the whole LogRhythm SIEM${r.window ? ` (${windowLabel(r.window)})` : ""}`;
  const fresh = r.imported > 0 ? `, ${r.imported} new in your platform` : ", all already in your platform";
  return `${r.matched.toLocaleString("en-US")} log${r.matched === 1 ? "" : "s"} for ${what} found across the whole LogRhythm SIEM${fresh}`;
}

export function windowLabel(w: { start: string; end: string }): string {
  const h = Math.round((Date.parse(w.end) - Date.parse(w.start)) / 3_600_000);
  return h >= 48 ? `last ${Math.round(h / 24)} days` : `last ${h} h`;
}
