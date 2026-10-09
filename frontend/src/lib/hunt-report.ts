/** The structured hunt report (backend `HuntReport.to_dict()`): everything the presentation draws, with no Markdown parsing. */
export type Verdict = "findings" | "suspicious" | "clean" | "clean_with_gaps" | "inconclusive";

export interface HrSection { title: string; description: string; tool: string; query: string; status: "SUCCEEDED" | "PARTIAL" | "FAILED"; results: number | null; error: string; rows: { time: string; host: string; user: string; summary: string; id: string }[]; purpose: string; ref: string }
export interface HrFinding { title: string; description: string; severity: string; classification?: string; event_ids: string[]; queries?: string[]; alternative_explanations?: string[]; techniques?: string[] }
export interface HrPlaybook { id: string; title: string; attack: string[]; feasibility: string; total: number; run: number; steps: { purpose: string; tool: string; goal: string; done: boolean }[] }
export interface HrIntel { kind?: string; value?: string; verdict: string; score?: number; providers: { provider: string; status: string; verdict: string | null; summary?: string }[]; unavailable?: string[]; web?: number }
export interface HrAttack { id: string; name: string; source: "finding" | "playbook" | "sensor tag"; tactics: string[]; url: string }
export interface HrTimelinePoint { id: string; timestamp: string; host: string | null; user?: string | null; event_type: string | null; summary: string; cited: boolean }

export interface HuntReportData {
  schema_version: number; title: string; scope: string; days: number; verdict: Verdict; verdict_line: string; summary: string; background: string;
  severity: string; priority: string; confidence: string; model: string; run_id: string; mode: string; hours_back: number; window_start: string; window_end: string;
  attack: HrAttack[]; findings: HrFinding[]; observations: HrFinding[]; sections: HrSection[]; omitted_sections: number; intel: HrIntel[]; playbooks: HrPlaybook[];
  gaps: string[]; notes: string[]; recommendations: string[]; references: { title: string; url: string }[];
  stats: Record<"queries" | "with_results" | "no_results" | "failed" | "events_reviewed" | "hosts" | "findings" | "observations" | "techniques" | "gaps" | "playbook_steps" | "playbook_steps_run", number>;
  hosts: { host: string; events: number }[]; timeline: HrTimelinePoint[];
}

/** Each verdict wears an icon and a label as well as a colour, so it never relies on colour alone. */
export const VERDICT_META: Record<Verdict, { label: string; icon: "alert" | "check" | "help" | "half"; tone: "critical" | "warning" | "good" | "neutral" }> = {
  findings: { label: "Action required", icon: "alert", tone: "critical" },
  suspicious: { label: "Review required", icon: "alert", tone: "warning" },
  clean: { label: "All clear", icon: "check", tone: "good" },
  clean_with_gaps: { label: "Clean, with gaps", icon: "half", tone: "warning" },
  inconclusive: { label: "Inconclusive", icon: "help", tone: "neutral" },
};

/** Enterprise ATT&CK tactics in kill-chain order (shortnames as stored in the reference data). */
export const TACTICS: { id: string; label: string }[] = [
  { id: "reconnaissance", label: "Reconnaissance" }, { id: "resource-development", label: "Resource development" }, { id: "initial-access", label: "Initial access" },
  { id: "execution", label: "Execution" }, { id: "persistence", label: "Persistence" }, { id: "privilege-escalation", label: "Privilege escalation" },
  { id: "defense-evasion", label: "Defense evasion" }, { id: "credential-access", label: "Credential access" }, { id: "discovery", label: "Discovery" },
  { id: "lateral-movement", label: "Lateral movement" }, { id: "collection", label: "Collection" }, { id: "command-and-control", label: "Command and control" },
  { id: "exfiltration", label: "Exfiltration" }, { id: "impact", label: "Impact" },
];

/** Validated against the app's dark surface with the dataviz checker: the first three categorical slots (all-pairs) and a one-hue ordinal ramp. */
export const VIZ = {
  series: ["#3987e5", "#d95926", "#199e70"], gray: "#6e7681", surface: "#161b22",
  ramp: ["#184f95", "#256abf", "#3987e5", "#6da7ec"],
  good: "#0ca30c", warning: "#fab219", serious: "#ec835a", critical: "#d03b3b",
} as const;

export const SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const fmtNum = (n: number): string => (n >= 10000 ? `${(n / 1000).toFixed(n >= 100000 ? 0 : 1)}K` : n.toLocaleString());
/** The search backend stops counting at 10,000: that figure is "at least", not a measured total. */
export const fmtCount = (n: number): string => (n === 10000 ? "10K+" : fmtNum(n));
