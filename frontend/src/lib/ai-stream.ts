import type { AiRun, AiStep } from "./ai";

/** One Server-Sent Event as the backend emits it (`POST /ai/runs/stream`). */
export interface StartInfo { goal: string; mode: string; hours_back: number; provider: string; model: string; limits: { steps: number; tool_calls: number; seconds: number } }
export interface HypView { id: string; statement: string; status: "open" | "supported" | "refuted" | "inconclusive"; priority: number; supporting: number; contradicting: number }
export interface Progress {
  hypotheses: HypView[]; queries: number; events: number; entities: number; redundant: number; gate_rejections: number; tokens: number;
  remaining: { steps: number; tool_calls: number; tokens: number; seconds: number };
  limits: { steps: number; tool_calls: number; seconds: number };
}
export type StreamEvent =
  | { type: "start"; data: StartInfo }
  | { type: "thinking"; data: { step: number; final: boolean; reason: string } }
  | { type: "tool_start"; data: { ref: string; name: string; input: Record<string, unknown>; purpose?: string | null; hypothesis?: string | null } }
  | { type: "step"; data: { index: number; step: AiStep } }
  | { type: "progress"; data: Progress }
  | { type: "done"; data: AiRun }
  | { type: "error"; data: { message: string } };

/** Incremental SSE parser: feed it the text received so far, get complete events and the unconsumed remainder. */
export function parseSse(buffer: string): { events: { event: string; data: unknown }[]; rest: string } {
  const text = buffer.replace(/\r\n/g, "\n");
  const blocks = text.split("\n\n");
  const rest = blocks.pop() ?? "";
  const events: { event: string; data: unknown }[] = [];
  for (const block of blocks) {
    let event = "message";
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue; // comment / keep-alive
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
    }
    if (!data.length) continue;
    try { events.push({ event, data: JSON.parse(data.join("\n")) }); } catch { /* ignore a malformed frame */ }
  }
  return { events, rest };
}

export interface NotebookOp { op: string; id?: string | null; statement?: string | null; status?: string | null; text?: string | null; entity?: string | null; test_plan?: string | null; alternatives?: string[] }

export type FeedItem =
  | { id: string; kind: "reasoning"; text: string }
  | { id: string; kind: "tool"; name: string; input: Record<string, unknown>; running: boolean; step?: AiStep; ref?: string; purpose?: string | null; hypothesis?: string | null }
  | { id: string; kind: "notebook"; ops: NotebookOp[]; step: AiStep }
  | { id: string; kind: "gate"; reasons: string[]; attempt: number };

export function stepToItem(step: AiStep, index: number): FeedItem {
  const id = `s${index}`;
  if (step.type === "assistant") return { id, kind: "reasoning", text: step.text ?? "" };
  if (step.type === "gate") return { id, kind: "gate", reasons: step.rejected ?? [], attempt: step.attempt ?? 0 };
  if (step.name === "update_notebook") return { id, kind: "notebook", ops: ((step.input?.ops as NotebookOp[] | undefined) ?? []), step };
  return { id, kind: "tool", name: step.name ?? "tool", input: step.input ?? {}, running: false, step, ref: step.ref, purpose: step.purpose, hypothesis: step.hypothesis };
}

export const itemsFromSteps = (steps: AiStep[]): FeedItem[] => steps.map(stepToItem);

export interface LiveState {
  phase: "idle" | "connecting" | "running" | "done" | "error" | "detached";
  start: StartInfo | null;
  items: FeedItem[];
  progress: Progress | null;
  thinking: { step: number; final: boolean; reason: string } | null;
  run: AiRun | null;
  error: string | null;
  startedAt: number | null;
  endedAt: number | null;
}

export const initialLive: LiveState = { phase: "idle", start: null, items: [], progress: null, thinking: null, run: null, error: null, startedAt: null, endedAt: null };

export type LiveAction = (StreamEvent | { type: "begin" } | { type: "reset" } | { type: "detach" }) & { at?: number };

export function liveReducer(s: LiveState, a: LiveAction): LiveState {
  switch (a.type) {
    case "reset": return initialLive;
    case "begin": return { ...initialLive, phase: "connecting", startedAt: a.at ?? null };
    case "detach": return { ...s, phase: "detached", thinking: null, endedAt: a.at ?? s.endedAt, items: s.items.map((i) => (i.kind === "tool" && i.running ? { ...i, running: false } : i)) };
    case "start": return { ...s, phase: "running", start: a.data };
    case "thinking": return { ...s, phase: "running", thinking: a.data };
    case "progress": return { ...s, progress: a.data, thinking: null };
    case "tool_start": {
      const d = a.data;
      const item: FeedItem = { id: `r:${d.ref}`, kind: "tool", name: d.name, input: d.input, running: true, ref: d.ref, purpose: d.purpose, hypothesis: d.hypothesis };
      return { ...s, thinking: null, items: [...s.items, item] };
    }
    case "step": {
      const { index, step } = a.data;
      const next = stepToItem(step, index);
      if (step.type === "tool" && step.ref && !step.cached) {
        const at = s.items.findIndex((i) => i.kind === "tool" && i.running && i.ref === step.ref);
        if (at >= 0) return { ...s, items: s.items.map((i, k) => (k === at ? { ...next, id: i.id } : i)) };
      }
      return { ...s, items: [...s.items, next] };
    }
    case "done": return { ...s, phase: "done", run: a.data, thinking: null, endedAt: a.at ?? s.endedAt };
    case "error": return { ...s, phase: "error", error: a.data.message, thinking: null, endedAt: a.at ?? s.endedAt };
    default: return s;
  }
}
