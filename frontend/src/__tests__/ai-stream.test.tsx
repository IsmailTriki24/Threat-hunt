import { render, screen } from "@testing-library/react";
import { Feed } from "@/components/ai-live";
import type { AiRun, AiStep } from "@/lib/ai";
import { initialLive, itemsFromSteps, liveReducer, parseSse, type LiveAction, type Progress } from "@/lib/ai-stream";

const sse = (event: string, data: unknown) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
const prog: Progress = { hypotheses: [{ id: "H1", statement: "s", status: "open", priority: 3, supporting: 0, contradicting: 0 }], queries: 1, events: 5, entities: 2, redundant: 0, gate_rejections: 0, tokens: 10, remaining: { steps: 9, tool_calls: 14, tokens: 1, seconds: 100 }, limits: { steps: 10, tool_calls: 15, seconds: 120 } };
const run = (s: LiveAction[]) => s.reduce(liveReducer, initialLive);

describe("parseSse", () => {
  it("returns complete events and keeps a partial frame for the next chunk", () => {
    const first = sse("start", { a: 1 }) + "event: step\ndata: {\"in";
    const a = parseSse(first);
    expect(a.events).toEqual([{ event: "start", data: { a: 1 } }]);
    const b = parseSse(a.rest + "dex\":2}\n\n");
    expect(b.events).toEqual([{ event: "step", data: { index: 2 } }]);
    expect(b.rest).toBe("");
  });
  it("ignores keep-alive comments, CRLF and malformed frames", () => {
    const r = parseSse(": keep-alive\n\n" + sse("done", { ok: true }).replace(/\n/g, "\r\n") + "event: x\ndata: {nope\n\n");
    expect(r.events).toEqual([{ event: "done", data: { ok: true } }]);
  });
});

describe("liveReducer", () => {
  const search = { name: "search_events", input: { query: "process.name:cmd.exe" }, ref: "q1" };
  it("shows a running tool card, then completes it in place", () => {
    let s = run([{ type: "begin", at: 1 }, { type: "start", data: { goal: "g", mode: "quick", hours_back: 24, provider: "p", model: "m", limits: { steps: 10, tool_calls: 15, seconds: 120 } } }, { type: "thinking", data: { step: 1, final: false, reason: "" } }]);
    expect(s.phase).toBe("running");
    expect(s.thinking?.step).toBe(1);
    s = liveReducer(s, { type: "tool_start", data: { ...search } });
    expect(s.thinking).toBeNull();
    expect(s.items).toHaveLength(1);
    expect(s.items[0]).toMatchObject({ kind: "tool", running: true });
    const step: AiStep = { type: "tool", ...search, status: "ok", total: 30, returned: 10, ms: 42 };
    s = liveReducer(s, { type: "step", data: { index: 3, step } });
    expect(s.items).toHaveLength(1); // replaced, not duplicated
    expect(s.items[0]).toMatchObject({ kind: "tool", running: false, step: { total: 30 } });
  });
  it("appends cached, notebook, gate and reasoning steps as their own items", () => {
    const s = run([
      { type: "step", data: { index: 0, step: { type: "assistant", text: "thinking out loud" } } },
      { type: "step", data: { index: 1, step: { type: "tool", name: "update_notebook", input: { ops: [{ op: "add_hypothesis", statement: "x" }] } } } },
      { type: "step", data: { index: 2, step: { type: "tool", ...search, cached: true, status: "cached" } } },
      { type: "step", data: { index: 3, step: { type: "gate", name: "submit_conclusion", rejected: ["no refutation"], attempt: 1 } } },
    ]);
    expect(s.items.map((i) => i.kind)).toEqual(["reasoning", "notebook", "tool", "gate"]);
  });
  it("tracks progress and finishes with the saved run", () => {
    const final = { id: "r1", status: "COMPLETED", steps: [] } as unknown as AiRun;
    const s = run([{ type: "begin", at: 5 }, { type: "progress", data: prog }, { type: "done", data: final, at: 9 }]);
    expect(s).toMatchObject({ phase: "done", endedAt: 9, startedAt: 5, run: { id: "r1" }, progress: { events: 5 } });
  });
  it("detaching stops spinners and error keeps what was seen", () => {
    let s = run([{ type: "tool_start", data: { ref: "q1", name: "search_events", input: {} } }]);
    s = liveReducer(s, { type: "detach", at: 3 });
    expect(s.phase).toBe("detached");
    expect(s.items[0]).toMatchObject({ running: false });
    s = liveReducer(s, { type: "error", data: { message: "boom" } });
    expect(s).toMatchObject({ phase: "error", error: "boom" });
    expect(s.items).toHaveLength(1);
  });
});

describe("Feed", () => {
  it("renders the agent's reasoning, tool calls with their query, results and notebook entries", () => {
    const steps: AiStep[] = [
      { type: "assistant", text: "Start with PowerShell executions." },
      { type: "tool", name: "update_notebook", input: { ops: [{ op: "add_hypothesis", statement: "Encoded PowerShell is malicious" }] } },
      { type: "tool", name: "search_events", input: { query: "process.name:powershell.exe", purpose: "test", hypothesis: "H1" }, status: "ok", total: 30, returned: 10, new_events: 10, new_entities: 3, ms: 120, result_preview: "{}" },
      { type: "tool", name: "pivot_entity", input: { type: "hash", value: "zz" }, status: "error", error: "hash must be a hex digest" },
      { type: "gate", name: "submit_conclusion", rejected: ["Hypothesis H1 has no refutation attempt"], attempt: 1 },
    ];
    render(<Feed items={itemsFromSteps(steps)} animate={false} />);
    expect(screen.getByText("Start with PowerShell executions.")).toBeInTheDocument();
    expect(screen.getByText(/New hypothesis: Encoded PowerShell is malicious/)).toBeInTheDocument();
    expect(screen.getByText("Search events")).toBeInTheDocument();
    expect(screen.getByText("process.name")).toBeInTheDocument(); // query is syntax-highlighted into field / value parts
    expect(screen.getByText("+10 new events")).toBeInTheDocument();
    expect(screen.getByText("hash must be a hex digest")).toBeInTheDocument();
    expect(screen.getByText(/Conclusion sent back/)).toBeInTheDocument();
    expect(screen.getByText("Hypothesis H1 has no refutation attempt")).toBeInTheDocument();
  });
});
