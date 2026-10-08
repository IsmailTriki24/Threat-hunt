import { canSave, describeStep, type AiFinding, type AiRun } from "@/lib/ai";

const f = (over: Partial<AiFinding> = {}): AiFinding => ({ title: "t", description: "", severity: "HIGH", event_ids: ["a"], rejected_event_ids: [], techniques: [], rejected_techniques: [], supported: true, ...over });
const run = { status: "COMPLETED" } as AiRun;

describe("canSave", () => {
  it("requires verified evidence and a completed run", () => {
    expect(canSave(f(), run)).toBe(true);
    expect(canSave(f({ supported: false, event_ids: [] }), run)).toBe(false);
    expect(canSave(f({ event_ids: [] }), run)).toBe(false);
    expect(canSave(f(), { ...run, status: "INCOMPLETE" } as AiRun)).toBe(false);
  });
});

describe("describeStep", () => {
  it("renders tool calls compactly", () => {
    expect(describeStep({ type: "tool", name: "search_events", input: { query: "x", limit: 5 } })).toBe("search_events(query=x limit=5)");
    expect(describeStep({ type: "assistant", text: "hi" })).toBe("hi");
  });
});
