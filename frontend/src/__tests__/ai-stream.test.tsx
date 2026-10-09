import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ErrorBoundary } from "@/components/error-boundary";
import { EvidenceTimeline } from "@/components/ai-evidence";
import { Feed, QueryLog } from "@/components/ai-live";
import { AgentWindow, WindowPill } from "@/components/ai-window";
import { RunReport } from "@/components/ai-report";
import type { AiRun, AiStep } from "@/lib/ai";
import { renderWithQuery } from "./helpers";
import { initialLive, itemsFromSteps, liveFromRun, liveReducer, parseSse, type EvPoint, type LiveAction, type Progress } from "@/lib/ai-stream";

const sse = (event: string, data: unknown) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
const prog: Progress = { hypotheses: [{ id: "H1", statement: "s", status: "open", priority: 3, supporting: 0, contradicting: 0 }], queries: 1, events: 5, entities: 2, redundant: 0, gate_rejections: 0, tokens: 10, remaining: { steps: 9, tool_calls: 14, tokens: 1, seconds: 100 }, limits: { steps: 10, tool_calls: 15, seconds: 120 } };
const run = (s: LiveAction[]) => s.reduce(liveReducer, initialLive);

vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: () => true }) }));
vi.mock("next/link", () => ({ default: ({ href, children, ...r }: { href: string; children?: React.ReactNode }) => <a href={href} {...r}>{children}</a> }));

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

describe("liveReducer: evidence and resume", () => {
  const e = (id: string, t = "2026-03-01T10:00:00Z"): EvPoint => ({ id, timestamp: t, host: "WS-02", event_type: "process_creation", summary: id });
  it("accumulates reviewed events once each", () => {
    const s = run([{ type: "evidence", data: { events: [e("a"), e("b")] } }, { type: "evidence", data: { events: [e("b"), e("c")] } }]);
    expect(s.evidence.map((x) => x.id)).toEqual(["a", "b", "c"]);
  });
  it("a resumed run keeps its earlier steps and numbers new ones after them", () => {
    const old: AiStep[] = [{ type: "assistant", text: "before" }, { type: "tool", name: "search_events", input: {}, ref: "q1", status: "ok" }, { type: "resume", mode: "quick" }];
    const seed = { items: itemsFromSteps(old.slice(0, 2)), evidence: [e("a")] };
    let s = liveReducer(initialLive, { type: "begin", seed });
    s = liveReducer(s, { type: "start", data: { run_id: "r1", resumed: true, step_offset: 3, goal: "g", mode: "quick", hours_back: 24, provider: "p", model: "m", limits: { steps: 1, tool_calls: 1, seconds: 1 } } });
    s = liveReducer(s, { type: "step", data: { index: 0, step: { type: "assistant", text: "after" } } });
    expect(s.runId).toBe("r1");
    expect(s.evidence).toHaveLength(1);
    expect(s.items.map((i) => i.id)).toEqual(["s0", "s1", "s2", "s3"]); // ... marker at 2, first new step at 3 (no id collision)
    expect(s.items[2].kind).toBe("marker");
  });
});

const steps: AiStep[] = [
  { type: "assistant", text: "Start with PowerShell executions." },
  { type: "tool", name: "update_notebook", input: { ops: [{ op: "add_hypothesis", statement: "Encoded PowerShell is malicious" }] } },
  { type: "tool", name: "search_events", ref: "q1", input: { query: "process.name:powershell.exe", purpose: "test", hypothesis: "H1" }, status: "ok", total: 30, returned: 10, new_events: 10, new_entities: 3, ms: 120, result_preview: "{raw}" },
  { type: "tool", name: "pivot_entity", ref: "q2", input: { type: "hash", value: "zz", hypothesis: "H2" }, status: "error", error: "hash must be a hex digest" },
  { type: "gate", name: "submit_conclusion", rejected: ["Hypothesis H1 has no refutation attempt"], attempt: 1 },
];

describe("Feed", () => {
  it("collapses finished steps to one line and opens them on demand", async () => {
    render(<Feed items={itemsFromSteps(steps)} animate={false} />);
    expect(screen.getByText("Search events")).toBeInTheDocument();
    expect(screen.getByText("process.name:powershell.exe")).toBeInTheDocument(); // the gist, plain text
    expect(screen.queryByText("{raw}")).toBeNull(); // details are folded away
    expect(screen.getByText(/Conclusion sent back/)).toBeInTheDocument(); // but a bounced conclusion is never hidden
    await userEvent.click(screen.getByRole("button", { name: /Search events/ }));
    expect(screen.getByText("{raw}")).toBeInTheDocument();
    expect(screen.getByText("+10 new events")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Expand all" }));
    expect(screen.getByText("hash must be a hex digest")).toBeInTheDocument();
  });
  it("filters to the steps that test one hypothesis", () => {
    render(<Feed items={itemsFromSteps(steps)} animate={false} hypothesis="H2" />);
    expect(screen.getByText("Pivot")).toBeInTheDocument();
    expect(screen.queryByText("Search events")).toBeNull();
    expect(screen.queryByText("Start with PowerShell executions.")).toBeNull();
  });
  it("opens the step a finding points at", () => {
    vi.useFakeTimers();
    render(<Feed items={itemsFromSteps(steps)} animate={false} focus={{ ref: "q1", n: 1 }} />);
    expect(screen.getByText("{raw}")).toBeInTheDocument();
    vi.useRealTimers();
  });
});

describe("EvidenceTimeline", () => {
  it("draws a lane per host and rings the events a finding cites", () => {
    const evs: EvPoint[] = [
      { id: "e1", timestamp: "2026-03-01T10:00:00Z", host: "WS-02", event_type: "process_creation", summary: "winword.exe started" },
      { id: "e2", timestamp: "2026-03-01T10:05:00Z", host: "WS-03", event_type: "network_connection", summary: "beacon" },
    ];
    render(<EvidenceTimeline events={evs} cited={new Set(["e2"])} />);
    expect(screen.getByText("WS-02")).toBeInTheDocument();
    expect(screen.getByText("WS-03")).toBeInTheDocument();
    expect(screen.getByLabelText(/network on WS-03: beacon/).className).toContain("ring-2");
    expect(screen.getByLabelText(/process on WS-02/).className).not.toContain("ring-2");
    expect(screen.getByLabelText(/network on WS-03/)).toHaveAttribute("href", "/events?id=e2");
  });
});

describe("RunReport", () => {
  const base = {
    id: "r1", hunt_id: null, goal: "hunt", status: "INCOMPLETE", provider: "p", model: "m", hours_back: 24, resumable: true, steps, saved_findings: [],
    input_tokens: 1, output_tokens: 1, error: "Stopped by the analyst", created_at: "2026-03-01T10:00:00Z",
    conclusion: {
      summary: "Encoded PowerShell spawned by Word.", confidence: "MEDIUM", model_confidence: "MEDIUM", next_steps: ["Isolate WS-02"], validation_notes: [], events_reviewed: 12,
      findings: [{ title: "Macro dropper", description: "d", severity: "HIGH", classification: "strongly_supported", event_ids: ["e1"], rejected_event_ids: [], techniques: [], rejected_techniques: [], supported: true, queries: ["q1"], alternative_explanations: ["IT automation"] }],
      hypotheses: [{ id: "H1", statement: "Encoded PowerShell is malicious", status: "supported", priority: 1, supporting_event_ids: ["e1"], contradicting_event_ids: [], alternatives_considered: [], queries: ["q1"], note: "" }],
      unresolved_questions: ["Did the implant persist?"], coverage: { queries: 2, ok: 1, empty: 0, errors: 1, redundant_calls: 0, events_reviewed: 12, gaps: ["no registry telemetry in the window"] },
    },
  } as unknown as AiRun;
  it("leads with the conclusion, shows provenance and gaps, and offers Resume", async () => {
    const onResume = vi.fn();
    renderWithQuery(<RunReport run={base} evidence={[]} onResume={onResume} />);
    expect(screen.getByText("Encoded PowerShell spawned by Word.")).toBeInTheDocument();
    expect(screen.getByText("Macro dropper")).toBeInTheDocument();
    expect(screen.getByText(/Benign explanations considered: IT automation/)).toBeInTheDocument();
    expect(screen.getByText("Did the implant persist?")).toBeInTheDocument();
    expect(screen.getByText("no registry telemetry in the window")).toBeInTheDocument();
    expect(screen.getByText(/2 queries · 12 events · 5 steps · 1 failed/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Resume/ }));
    expect(onResume).toHaveBeenCalled();
  });
  it("jumps from a finding's query to that step in the trace", async () => {
    renderWithQuery(<RunReport run={base} evidence={[]} />);
    await userEvent.click(screen.getAllByRole("button", { name: "q1" })[0]);
    expect(await screen.findByText("{raw}")).toBeInTheDocument(); // trace opened and the step expanded
  });
  it("does not offer Resume for a finished run", () => {
    renderWithQuery(<RunReport run={{ ...base, status: "COMPLETED", resumable: false } as AiRun} evidence={[]} onResume={vi.fn()} />);
    expect(screen.queryByRole("button", { name: /Resume/ })).toBeNull();
  });
});

describe("QueryLog", () => {
  it("shows the exact query of every call, live state included, and expands to the raw call", async () => {
    const items = [...itemsFromSteps(steps.slice(2, 4)), ...liveReducer(initialLive, { type: "tool_start", data: { ref: "q3", name: "search_events", input: { query: "dns.question:evil.example", limit: 5 } } }).items];
    render(<QueryLog items={items} />);
    expect(screen.getByLabelText("Live queries")).toBeInTheDocument();
    expect(screen.getByText("process.name")).toBeInTheDocument(); // full query text, highlighted - not truncated to a gist
    expect(screen.getByText("dns.question")).toBeInTheDocument();
    expect(screen.getByText(/3 calls/)).toBeInTheDocument();
    expect(screen.getByText(/1 running/)).toBeInTheDocument();
    expect(screen.getByText(/1 failed/)).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument(); // returned / total
    await userEvent.click(screen.getByRole("button", { name: /pivot_entity/ }));
    expect(screen.getByText(/\$ pivot_entity/)).toBeInTheDocument();
    expect(screen.getByText(/hash must be a hex digest/)).toBeInTheDocument();
  });
  it("says what it is waiting for before the first query", () => {
    const state = liveReducer(initialLive, { type: "begin" });
    render(<QueryLog items={[]} state={state} />);
    expect(screen.getByText(/Waiting for the agent's first query/)).toBeInTheDocument();
  });
});

describe("AgentWindow", () => {
  const fin = {
    id: "r1", hunt_id: null, goal: "hunt it", status: "COMPLETED", provider: "p", model: "m", hours_back: 24, mode: "quick", resumable: false, steps, saved_findings: [],
    input_tokens: 5, output_tokens: 5, error: "", created_at: "2026-03-01T10:00:00Z",
    conclusion: { summary: "All clear.", confidence: "LOW", model_confidence: "LOW", findings: [], next_steps: [], validation_notes: [], events_reviewed: 2, coverage: { queries: 2, ok: 1, empty: 0, errors: 1, redundant_calls: 0, events_reviewed: 2, gaps: [] } },
  } as unknown as AiRun;
  it("is one dialog holding activity, live queries, hypotheses and the evidence timeline; Escape closes it", async () => {
    const onClose = vi.fn();
    let st = liveReducer(initialLive, { type: "begin", at: 0 });
    st = liveReducer(st, { type: "start", data: { run_id: "r1", goal: "hunt it", mode: "quick", hours_back: 24, provider: "p", model: "m", limits: { steps: 10, tool_calls: 15, seconds: 120 } } });
    st = liveReducer(st, { type: "tool_start", data: { ref: "q1", name: "search_events", input: { query: "process.name:cmd.exe" } } });
    st = liveReducer(st, { type: "progress", data: prog });
    st = liveReducer(st, { type: "evidence", data: { events: [{ id: "e1", timestamp: "2026-03-01T10:00:00Z", host: "WS-02", event_type: "process_creation", summary: "x" }] } });
    const stop = vi.fn();
    renderWithQuery(<AgentWindow state={st} onClose={onClose} onStop={stop} />);
    expect(screen.getByRole("dialog", { name: "AI investigation" })).toBeInTheDocument();
    expect(screen.getByText("hunt it")).toBeInTheDocument();
    expect(screen.getByLabelText("Live queries")).toBeInTheDocument();
    expect(screen.getByLabelText("Evidence timeline")).toBeInTheDocument();
    expect(screen.getByText("Hypotheses")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Minimize" })).toBeInTheDocument(); // running: hiding is not stopping
    await userEvent.click(screen.getByRole("button", { name: /Stop/ }));
    expect(stop).toHaveBeenCalled();
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
    expect(document.body.style.overflow).toBe("hidden"); // the page behind never scrolls
  });
  it("shows the report for a finished run, including past runs opened from history", () => {
    renderWithQuery(<AgentWindow state={liveFromRun(fin, [])} onClose={vi.fn()} />);
    expect(screen.getByText("All clear.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
    expect(screen.getByLabelText("Live queries")).toBeInTheDocument(); // the queries it ran stay inspectable
    expect(screen.queryByRole("button", { name: /Stop/ })).toBeNull();
  });
  it("the minimized pill reports progress and reopens the window", async () => {
    const onOpen = vi.fn();
    let st = liveReducer(initialLive, { type: "begin", at: 0 });
    st = liveReducer(st, { type: "progress", data: prog });
    render(<WindowPill state={st} onOpen={onOpen} onDismiss={vi.fn()} />);
    expect(screen.getByText(/1 queries · 5 events/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /open/ }));
    expect(onOpen).toHaveBeenCalled();
  });
});

describe("web search steps", () => {
  const web: AiStep = { type: "tool", name: "web_search", ref: "q4", input: { query: "CVE-2024-3400 exploitation" }, status: "ok", total: 2, returned: 2, ms: 900, result_preview: "{}",
    sources: [{ title: "Palo Alto advisory", url: "https://example.org/a", domain: "example.org" }, { title: "Analysis", url: "https://blog.example.net/b", domain: "blog.example.net" }] };
  it("lists the sources as safe external links and labels them untrusted", async () => {
    render(<Feed items={itemsFromSteps([web])} animate={false} />);
    expect(screen.getByText("Web search")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Web search/ }));
    const link = screen.getByRole("link", { name: "Palo Alto advisory" });
    expect(link).toHaveAttribute("href", "https://example.org/a");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAttribute("target", "_blank");
    expect(screen.getByText(/untrusted context, not evidence/)).toBeInTheDocument();
  });
  it("appears in the live query log with the exact query sent out", () => {
    render(<QueryLog items={itemsFromSteps([web])} />);
    expect(screen.getByText("web_search")).toBeInTheDocument();
    expect(screen.getByText("CVE-2024-3400 exploitation")).toBeInTheDocument();
  });
});

describe("threat-intel enrichment steps", () => {
  const intel = { kind: "ip", value: "45.77.65.211", verdict: "malicious" as const, score: 81, answered: 1, providers: [{ provider: "virustotal", status: "ok", verdict: "malicious" }], unavailable: ["otx"], web: 0 };
  const auto: AiStep = { type: "tool", name: "enrich_indicator", auto: true, ref: "q7", input: { kind: "ip", value: "45.77.65.211" }, status: "ok", total: 1, returned: 1, ms: 700, intel };
  const unknown: AiStep = { type: "tool", name: "enrich_indicator", ref: "q8", input: { kind: "domain", value: "x.example.org" }, status: "empty", total: 0, returned: 0, ms: 90,
    intel: { ...intel, kind: "domain", value: "x.example.org", verdict: "unknown", score: 0, answered: 0, providers: [] } };
  it("shows the verdict and the automatic origin on the collapsed line, and the providers when opened", async () => {
    render(<Feed items={itemsFromSteps([auto])} animate={false} />);
    expect(screen.getByText("Threat intel")).toBeInTheDocument();
    expect(screen.getByText("auto")).toBeInTheDocument();
    expect(screen.getByText("malicious · 81")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Threat intel/ }));
    expect(screen.getByText("virustotal: malicious")).toBeInTheDocument();
    expect(screen.getByText(/Not queried \(disabled or no API key\): otx/)).toBeInTheDocument();
  });
  it("never presents 'unknown' as safe", async () => {
    render(<Feed items={itemsFromSteps([unknown])} animate={false} />);
    await userEvent.click(screen.getByRole("button", { name: /Threat intel/ }));
    expect(screen.getByText("no answer")).toBeInTheDocument(); // neutral, never green
    expect(screen.getByText(/not benign/)).toBeInTheDocument();
  });
  it("shows what a provider actually said when it answered with no detections, and 'never seen' when it did not know the file", async () => {
    const clean: AiStep = { ...auto, auto: true, input: { kind: "hash", value: "ab" }, ref: "q9",
      intel: { kind: "hash", value: "ab", verdict: "unknown", score: 0, answered: 1, providers: [{ provider: "virustotal", status: "ok", verdict: "unknown", summary: "0/75 engines flag as malicious" }], unavailable: [], web: 0 } };
    const unseen: AiStep = { ...auto, ref: "q10", input: { kind: "hash", value: "cd" },
      intel: { kind: "hash", value: "cd", verdict: "unknown", score: 0, answered: 0, providers: [{ provider: "virustotal", status: "not_found", verdict: null, summary: "Unknown to VirusTotal" }], unavailable: [], web: 4 } };
    render(<Feed items={itemsFromSteps([clean, unseen])} animate={false} />);
    expect(screen.getByText("undetected")).toBeInTheDocument();
    expect(screen.getByText("never seen")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: /Threat intel/ })[0]);
    expect(screen.getByText("0/75 engines flag as malicious")).toBeInTheDocument();
    expect(screen.getByText(/not proof of safety/)).toBeInTheDocument();
  });
  it("is visible in the live query log", () => {
    render(<QueryLog items={itemsFromSteps([auto])} />);
    expect(screen.getByText("enrich_indicator")).toBeInTheDocument();
    expect(screen.getByText("malicious · 81")).toBeInTheDocument();
  });
  it("the report lists intel on the indicators met, worst first, with the caveat", () => {
    const run = { id: "r1", status: "COMPLETED", provider: "p", model: "m", goal: "g", hours_back: 24, steps: [], saved_findings: [], input_tokens: 1, output_tokens: 1, error: "", created_at: "2026-03-01T10:00:00Z",
      conclusion: { summary: "s", confidence: "LOW", model_confidence: "LOW", findings: [], next_steps: [], validation_notes: [], events_reviewed: 1,
        intel: { "domain:x.example.org": unknown.intel, "ip:45.77.65.211": intel } } } as unknown as AiRun;
    renderWithQuery(<RunReport run={run} evidence={[]} />);
    const rows = screen.getAllByRole("listitem").filter((li) => li.textContent?.includes(":"));
    expect(rows[0].textContent).toContain("ip:45.77.65.211");
    expect(rows[0].textContent).toContain("virustotal: malicious");
    expect(rows[1].textContent).toContain("no provider answered");
    expect(screen.getByText(/not that it is safe/)).toBeInTheDocument();
  });
});

describe("malformed model output cannot break the page", () => {
  const odd: AiStep[] = [
    { type: "tool", name: "update_notebook", input: { ops: "add a hypothesis please" } as never },
    { type: "tool", name: "update_notebook", input: { ops: { op: "note" } } as never },
    { type: "tool", name: "update_notebook", input: { ops: [null, 7, "x", { op: "add_hypothesis", statement: { nested: true } }, { op: "note", text: ["a"] }] } as never },
    { type: "tool", name: "update_notebook", input: null as never },
    { type: "tool", name: "update_notebook", input: "garbage" as never, error: "rejected" },
    { type: "tool", name: "search_events", input: "not an object" as never, status: "ok" },
    { type: "tool", name: "search_events", input: ["x"] as never, status: "ok" },
    { type: "gate", name: "submit_conclusion", rejected: "just one string" as never, attempt: 1 },
  ];
  it("sanitises every shape instead of throwing", () => {
    const items = itemsFromSteps(odd);
    expect(items).toHaveLength(odd.length);
    expect(items.filter((i) => i.kind === "notebook").every((i) => Array.isArray(i.ops))).toBe(true);
    expect((items[2] as { ops: unknown[] }).ops).toHaveLength(2); // only real objects survive
  });
  it("renders all of them", () => {
    render(<Feed items={itemsFromSteps(odd)} animate={false} />);
    expect(screen.getAllByText(/Notebook (updated|update was rejected)/).length).toBeGreaterThan(0);
    expect(screen.getByText(/New hypothesis: \{"nested":true\}/)).toBeInTheDocument();
  });
  it("an error boundary contains a render failure", async () => {
    const Boom = () => { throw new Error("boom"); };
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(<ErrorBoundary fallback={(reset) => <button onClick={reset}>recover</button>}><Boom /></ErrorBoundary>);
    expect(screen.getByRole("button", { name: "recover" })).toBeInTheDocument();
    spy.mockRestore();
  });
});
