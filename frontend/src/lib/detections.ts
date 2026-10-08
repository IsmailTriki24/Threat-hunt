export type RuleStatus = "DRAFT" | "TESTING" | "ACTIVE" | "DISABLED" | "ARCHIVED";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "CLOSED";

export interface Rule {
  id: string; title: string; description: string; format: string; content: string; version: number; status: RuleStatus;
  severity: string; executable: boolean; unsupported: string[]; warnings: string[]; techniques: string[]; tactics: string[];
  hunt_id: string | null; tests_passed: boolean | null; tests_run_at: string | null; last_evaluated_at: string | null;
  last_run_status: string; last_run_error: string; updated_at: string; test_count: number; open_alerts: number;
}
export interface TestCase { id: string; name: string; event: Record<string, unknown>; expect_match: boolean }
export interface TestResult { case_id: string | null; name: string; expect_match: boolean; matched: boolean; passed: boolean; explanation: string[] }
export interface Alert {
  id: string; rule_id: string; rule_version: number; rule_title: string; severity: string; event_id: string;
  event_timestamp: string; snapshot: Record<string, unknown>; status: AlertStatus; case_id: string | null;
}
export interface Backtest { total: number; hits: Record<string, unknown>[]; run: { took_ms: number; window_start: string; window_end: string } }
export interface DetectionOverview { rules_by_status: Record<string, number>; open_alerts: number; alerts_by_severity: Record<string, number>; coverage: string[] }

export const STATUS_CLASS: Record<RuleStatus, string> = {
  DRAFT: "text-muted border border-line", TESTING: "bg-blue-900/50 text-blue-200", ACTIVE: "bg-green-900/40 text-green-300",
  DISABLED: "bg-orange-900/50 text-orange-300", ARCHIVED: "text-muted border border-line",
};

/** Next states offered in the UI; the server remains the authority (tests must pass before ACTIVE). */
export const NEXT_STATES: Record<RuleStatus, RuleStatus[]> = {
  DRAFT: ["TESTING", "ARCHIVED"], TESTING: ["ACTIVE", "DRAFT", "ARCHIVED"], ACTIVE: ["DISABLED", "ARCHIVED"],
  DISABLED: ["ACTIVE", "TESTING", "ARCHIVED"], ARCHIVED: ["DRAFT"],
};

export function activationBlocker(r: Rule): string | null {
  if (!r.executable) return r.unsupported.join("; ") || "The rule did not compile";
  if (r.test_count === 0) return "Add at least one test case that must match";
  if (r.tests_passed !== true) return r.tests_passed === false ? "Some test cases fail" : "Run the tests for this version";
  return null;
}

export const SAMPLE_EVENT = JSON.stringify(
  { timestamp: new Date().toISOString(), source: "sysmon", event_type: "process_creation",
    process: { name: "powershell.exe", executable: "C:\\Windows\\System32\\powershell.exe", command_line: "powershell.exe -enc AAAA" } }, null, 2);

/** Parse a JSON sample event; returns an error string instead of throwing. */
export function parseEvent(text: string): { event?: Record<string, unknown>; error?: string } {
  try {
    const v: unknown = JSON.parse(text);
    if (v === null || typeof v !== "object" || Array.isArray(v)) return { error: "The event must be a JSON object" };
    return { event: v as Record<string, unknown> };
  } catch (e) { return { error: `Invalid JSON: ${(e as Error).message}` }; }
}
