export interface AiStatus { enabled: boolean; provider: string; model: string; max_steps: number }
export interface AiFinding {
  title: string; description: string; severity: string; event_ids: string[]; rejected_event_ids: string[];
  techniques: string[]; rejected_techniques: string[]; supported: boolean;
}
export interface AiConclusion {
  summary: string; confidence: "LOW" | "MEDIUM" | "HIGH"; model_confidence: string; findings: AiFinding[];
  next_steps: string[]; validation_notes: string[]; events_reviewed: number;
}
export interface AiStep { type: "tool" | "assistant"; name?: string; input?: Record<string, unknown>; error?: string | null; result_preview?: string; text?: string; ms?: number }
export interface AiRun {
  id: string; hunt_id: string | null; goal: string; status: "COMPLETED" | "INCOMPLETE" | "FAILED"; provider: string; model: string;
  hours_back: number; steps: AiStep[]; conclusion: AiConclusion | null; saved_findings: string[];
  input_tokens: number; output_tokens: number; error: string; created_at: string;
}

export const AI_DISCLAIMER =
  "AI-generated analysis. Every cited event was retrieved from your telemetry and verified to exist, but the interpretation can be wrong — review the evidence before acting.";

/** A finding can be saved only when it cites at least one verified event. */
export const canSave = (f: AiFinding, run: AiRun): boolean => f.supported && f.event_ids.length > 0 && run.status === "COMPLETED";

export function describeStep(s: AiStep): string {
  if (s.type === "assistant") return s.text ?? "";
  const args = s.input ? Object.entries(s.input).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(" ") : "";
  return `${s.name}(${args})`;
}
