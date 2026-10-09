import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CaseWorkspace } from "@/components/case-workspace";
import { HuntReportView } from "@/components/hunt-report-view";
import { HBars, Meter, StackedBar, TacticStrip, TimelineChart } from "@/components/viz/charts";
import { VIZ, type HuntReportData } from "@/lib/hunt-report";
import { mockFetch, renderWithQuery } from "./helpers";

vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: () => true, session: { user_id: "u1", email: "me@x" } }) }));
vi.mock("next/link", () => ({ default: ({ href, children, ...r }: { href: string; children?: React.ReactNode }) => <a href={href} {...r}>{children}</a> }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

const data = (over: Partial<HuntReportData> = {}): HuntReportData => ({
  schema_version: 1, title: "Passkey phishing - October 2026", scope: "September 07, 2026 through October 08, 2026 (UTC) - Total Days: 31", days: 31,
  verdict: "findings", verdict_line: "Threat indicators observed - investigation and response are required",
  summary: "Two hosts ran encoded PowerShell launched by Word.\n\nThe activity began at 09:01 and reached the domain controller.", background: "Attackers abuse passkey lures.",
  severity: "HIGH", priority: "P2", confidence: "HIGH", model: "m-1", run_id: "run-1", mode: "standard", hours_back: 744,
  window_start: "2026-09-07T12:00:00+00:00", window_end: "2026-10-08T12:00:00+00:00",
  attack: [
    { id: "T1059.001", name: "PowerShell", source: "finding", tactics: ["execution"], url: "https://attack.mitre.org/techniques/T1059/001/" },
    { id: "T1047", name: "WMI", source: "playbook", tactics: ["execution", "lateral-movement"], url: "https://attack.mitre.org/techniques/T1047/" },
    { id: "T1566", name: "", source: "sensor tag", tactics: [], url: "https://attack.mitre.org/techniques/T1566/" },
  ],
  findings: [
    { title: "Encoded PowerShell from Word", description: "winword spawned powershell -enc", severity: "HIGH", classification: "strongly_supported", event_ids: ["e1abcdef12", "e2"], queries: ["q2"], alternative_explanations: ["Software deployment"] },
    { title: "Beacon to rare domain", description: "periodic connections", severity: "MEDIUM", classification: "suspicious", event_ids: ["e3"] },
  ],
  observations: [{ title: "Office never appears on servers", description: "no winword on DCs", severity: "INFO", event_ids: [] }],
  sections: [
    { title: "Find PowerShell launched with an encoded command", description: "What to look for: long Base64", tool: "search_events", query: "process.name:*powershell.exe* process.command_line:encodedcommand", status: "SUCCEEDED", results: 12, error: "", rows: [{ time: "2026-10-08 09:01:02", host: "WS-02", user: "bob", summary: "powershell.exe -enc ...", id: "e1" }], purpose: "test", ref: "q2" },
    { title: "WMI children", description: "children of wmiprvse", tool: "aggregate_events", query: "process.parent.name:*wmiprvse.exe*", status: "SUCCEEDED", results: 0, error: "", rows: [], purpose: "scope", ref: "q3" },
    { title: "Slow search", description: "x", tool: "search_events", query: "x:1", status: "FAILED", results: null, error: "timed out", rows: [], purpose: "test", ref: "q4" },
  ],
  omitted_sections: 2,
  intel: [
    { kind: "ip", value: "45.77.65.211", verdict: "malicious", providers: [{ provider: "virustotal", status: "ok", verdict: "malicious", summary: "41/70 engines flag as malicious" }] },
    { kind: "hash", value: "a".repeat(64), verdict: "unknown", providers: [] },
  ],
  playbooks: [{ id: "p1", title: "Suspicious PowerShell execution", attack: ["T1059.001"], feasibility: "ready", total: 6, run: 4, steps: [{ purpose: "test", tool: "search_events", goal: "Find encoded PowerShell", done: true }, { purpose: "refute", tool: "search_events", goal: "Rule out management tooling", done: false }] }],
  gaps: ["A search could not be completed (timed out); its result is unknown: Slow search"], notes: ["no dns_query telemetry in the window"],
  recommendations: ["Isolate WS-02 and reset bob's credentials.", "Enforce phishing-resistant MFA."],
  references: [{ title: "MITRE ATT&CK T1059.001", url: "https://attack.mitre.org/techniques/T1059/001/" }],
  stats: { queries: 3, with_results: 1, no_results: 1, failed: 1, events_reviewed: 120, hosts: 3, findings: 2, observations: 1, techniques: 3, gaps: 1, playbook_steps: 6, playbook_steps_run: 4 },
  hosts: [{ host: "WS-02", events: 80 }, { host: "WS-03", events: 30 }, { host: "dc1.example", events: 10 }],
  timeline: [
    { id: "e1", timestamp: "2026-10-08T09:01:02Z", host: "WS-02", user: "bob", event_type: "process_creation", summary: "powershell.exe -enc", cited: true },
    { id: "e2", timestamp: "2026-10-08T09:30:00Z", host: "WS-03", event_type: "network_connection", summary: "beacon", cited: false },
    { id: "e3", timestamp: "2026-10-08T10:15:00Z", host: "dc1.example", event_type: "authentication", summary: "logon", cited: false },
  ],
  ...over,
});

describe("HuntReportView", () => {
  it("leads with the verdict in words, the title and the scope", () => {
    render(<HuntReportView data={data()} />);
    expect(screen.getByRole("heading", { level: 1, name: "Passkey phishing - October 2026" })).toBeInTheDocument();
    const status = screen.getByRole("status");
    expect(within(status).getByText("Verdict · Action required")).toBeInTheDocument(); // the verdict is a label, not only a colour
    expect(within(status).getByText(/investigation and response are required/)).toBeInTheDocument();
    expect(screen.getByText(/Sep 7, 2026 → Oct 8, 2026 · 31 days/)).toBeInTheDocument();
    expect(screen.getByText("severity high · P2")).toBeInTheDocument();
  });

  it("shows only the first paragraph of a long summary until asked", async () => {
    render(<HuntReportView data={data()} />);
    expect(screen.getByText(/Two hosts ran encoded PowerShell/)).toBeInTheDocument();
    expect(screen.queryByText(/reached the domain controller/)).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Read the full summary/ }));
    expect(screen.getByText(/reached the domain controller/)).toBeInTheDocument();
  });

  it("states each verdict honestly, including the clean one with gaps and the inconclusive one", () => {
    const { rerender } = render(<HuntReportView data={data({ verdict: "clean_with_gaps", verdict_line: "No threat indicators observed in the telemetry that was searched - but some checks could not be completed" })} />);
    expect(screen.getByText("Verdict · Clean, with gaps")).toBeInTheDocument();
    rerender(<HuntReportView data={data({ verdict: "inconclusive", verdict_line: "Inconclusive - this is not a clean result" })} />);
    expect(screen.getByText("Verdict · Inconclusive")).toBeInTheDocument();
    rerender(<HuntReportView data={data({ verdict: "clean", verdict_line: "No Threat Indicators Observed - No further action is required", findings: [] })} />);
    expect(screen.getByText("No verified threat finding came out of this hunt.")).toBeInTheDocument();
  });

  it("puts the headline numbers in stat tiles, stated outright (never animated up from zero)", () => {
    render(<HuntReportView data={data()} />);
    for (const [label, value] of [["Searches run", "3"], ["Events reviewed", "120"], ["Threat findings", "2"], ["ATT&CK techniques", "3"], ["Playbook steps run", "4"], ["Open gaps", "1"]] as const) {
      const tile = screen.getByText(label).closest("div")?.parentElement as HTMLElement;
      expect(within(tile).getByText(value)).toBeInTheDocument();
    }
    expect(screen.getByText("1 failed")).toBeInTheDocument();
    expect(screen.getByText("of 6 planned")).toBeInTheDocument();
  });

  it("draws labelled charts, each with a data table behind it", async () => {
    render(<HuntReportView data={data()} />);
    expect(screen.getByRole("img", { name: "Searches by outcome" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Timeline of 3 reviewed events across 3 host lanes, 1 cited by findings/ })).toBeInTheDocument();
    const card = screen.getByText("How the searches turned out").closest("section") as HTMLElement;
    await userEvent.click(within(card).getByRole("button", { name: "Show data table" }));
    expect(within(card).getByRole("cell", { name: "Returned results" })).toBeInTheDocument();
    await userEvent.click(within(card).getByRole("button", { name: "Show chart" }));
    expect(within(card).getByRole("img", { name: "Searches by outcome" })).toBeInTheDocument();
  });

  it("orders findings by severity and links their evidence", () => {
    render(<HuntReportView data={data({ findings: [{ title: "Medium one", description: "d", severity: "MEDIUM", event_ids: [] }, { title: "High one", description: "d", severity: "HIGH", event_ids: ["e1abcdef12"] }] })} />);
    const titles = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent).filter((t) => t === "High one" || t === "Medium one");
    expect(titles).toEqual(["High one", "Medium one"]);
    expect(screen.getByRole("link", { name: "e1abcdef" })).toHaveAttribute("href", "/events?id=e1abcdef12");
  });

  it("lists every search with its status, and opens one to show the query and sample events", async () => {
    render(<HuntReportView data={data()} />);
    const queries = document.getElementById("hr-queries") as HTMLElement;
    const table = within(queries).getByText("Find PowerShell launched with an encoded command").closest("li") as HTMLElement;
    expect(within(table).getByText("Succeeded")).toBeInTheDocument();
    await userEvent.click(within(table).getByText("Find PowerShell launched with an encoded command"));
    expect(within(table).getByText("process.name:*powershell.exe* process.command_line:encodedcommand")).toBeInTheDocument();
    expect(within(table).getByRole("cell", { name: "WS-02" })).toBeInTheDocument();
    const failed = within(queries).getByText("Slow search").closest("li") as HTMLElement;
    expect(within(failed).getByText("Failed")).toBeInTheDocument();
    await userEvent.click(within(failed).getByText("Slow search"));
    expect(within(failed).getByText(/its result is unknown, not empty/)).toBeInTheDocument();
    expect(screen.getByText(/2 further search\(es\)/)).toBeInTheDocument();
  });

  it("shows the playbook progress and the intelligence, with unknown never styled as safe", () => {
    render(<HuntReportView data={data()} />);
    expect(screen.getByRole("meter", { name: /Suspicious PowerShell execution: 4 of 6 steps/ })).toBeInTheDocument();
    expect(screen.getByText("41/70 engines flag as malicious")).toBeInTheDocument();
    expect(screen.getAllByText("unknown").length).toBeGreaterThan(0);
    expect(screen.getByText(/not that it is safe/)).toBeInTheDocument();
  });

  it("separates what could not be checked from environment limits, and says so when nothing is open", () => {
    const { rerender } = render(<HuntReportView data={data()} />);
    expect(screen.getByText("Could not be checked or left open")).toBeInTheDocument();
    expect(screen.getByText(/its result is unknown: Slow search/)).toBeInTheDocument();
    expect(screen.getByText("no dns_query telemetry in the window")).toBeInTheDocument();
    rerender(<HuntReportView data={data({ gaps: [], stats: { ...data().stats, gaps: 0 } })} />);
    expect(screen.getByText("Every planned check was completed")).toBeInTheDocument();
  });

  it("numbers the recommendations and lists safe references", () => {
    render(<HuntReportView data={data()} />);
    expect(screen.getAllByRole("listitem").filter((li) => /Isolate WS-02/.test(li.textContent ?? ""))).toHaveLength(1);
    const ref = screen.getByRole("link", { name: "MITRE ATT&CK T1059.001" });
    expect(ref).toHaveAttribute("rel", "noopener noreferrer");
    expect(ref).toHaveAttribute("target", "_blank");
  });

  it("offers a section index that scrolls to a section, and export", async () => {
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    render(<HuntReportView data={data()} markdown="# x" caseNumber="CASE-9" />);
    const nav = screen.getByRole("navigation", { name: "Report sections" });
    await userEvent.click(within(nav).getByRole("link", { name: "Hunt queries" }));
    expect(scroll).toHaveBeenCalled();
    expect(within(nav).getByRole("button", { name: /Markdown/ })).toBeInTheDocument();
    expect(within(nav).getByRole("button", { name: /Print \/ PDF/ })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Intelligence" })).not.toBeNull();
    const { unmount } = render(<HuntReportView data={data({ intel: [], playbooks: [], attack: [] })} />);
    const nav2 = screen.getAllByRole("navigation", { name: "Report sections" })[1];
    expect(within(nav2).queryByRole("link", { name: "Intelligence" })).toBeNull();
    expect(within(nav2).queryByRole("link", { name: "Playbooks" })).toBeNull();
    unmount();
  });
});

describe("chart primitives", () => {
  it("StackedBar keeps zero classes in the legend but out of the bar, and reports each share", () => {
    render(<StackedBar ariaLabel="x" segments={[{ key: "a", label: "Alpha", value: 3, color: VIZ.series[0] }, { key: "b", label: "Beta", value: 0, color: VIZ.gray }, { key: "c", label: "Gamma", value: 1, color: VIZ.critical, mark: "✕" }]} />);
    expect(screen.getAllByLabelText(/: \d/)).toHaveLength(2); // two drawn segments
    expect(screen.getByText("Beta")).toBeInTheDocument();
    expect(screen.getByText("(75%)")).toBeInTheDocument();
    expect(screen.getByText("✕")).toBeInTheDocument(); // failure is marked as well as coloured
  });

  it("HBars shows each value at the tip", () => {
    render(<HBars rows={[{ label: "WS-02", value: 80 }, { label: "WS-03", value: 12000 }]} />);
    expect(screen.getByText("80")).toBeInTheDocument();
    expect(screen.getByText("12.0K")).toBeInTheDocument();
  });

  it("Meter turns amber when fewer than three quarters of the steps ran", () => {
    const { rerender } = render(<Meter label="PB" value={5} total={6} />);
    expect(screen.getByRole("meter")).toHaveAttribute("aria-valuenow", "5");
    rerender(<Meter label="PB" value={2} total={6} />);
    expect(screen.getByText("2/6")).toBeInTheDocument();
  });

  it("TimelineChart shows a hovered event's details and caps hue use at three types", () => {
    const pts = ["process_creation", "network_connection", "authentication", "file_event", "dns_query"].map((t, i) => ({ id: `e${i}`, timestamp: `2026-10-08T0${i}:00:00Z`, host: "WS-02", event_type: t, summary: `ev ${i}`, cited: i === 0 }));
    render(<TimelineChart points={pts} />);
    expect(screen.getByText("other types")).toBeInTheDocument(); // 5 types: three hues + gray, never more
    fireEvent.mouseEnter(screen.getAllByRole("img", { name: /ev 2/ })[0]);
    expect(screen.getByText(/ev 2/, { selector: "span" })).toBeInTheDocument();
  });

  it("TacticStrip groups techniques under their tactics, with unmapped ones last", () => {
    render(<TacticStrip attack={data().attack} />);
    expect(screen.getByLabelText("Execution: 2 technique(s)")).toBeInTheDocument();
    expect(screen.getByLabelText("Lateral movement: 1 technique(s)")).toBeInTheDocument();
    expect(screen.getByLabelText("Unmapped: 1 technique(s)")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /T1047/ })).toHaveLength(2); // one in each tactic it belongs to
  });
});

describe("the case page", () => {
  const kase = {
    id: "c1", case_id: "CASE-0001", number: 1, title: "Passkey phishing", description: "", severity: "HIGH", priority: "P2", status: "OPEN", resolution: "",
    assignee: null, hunt_id: null, created_by: null, created_at: "2026-10-08T12:00:00Z", updated_at: "2026-10-08T12:00:00Z", closed_at: null,
    evidence_count: 2, ioc_count: 1, asset_count: 0, allowed_transitions: ["INVESTIGATING"],
  };
  const report = { id: "rp1", version: 1, kind: "hunt", data: data(), content: "# md", created_by: null, created_at: "2026-10-08T12:00:00Z" };

  it("opens on the hunt report when the case came from an AI hunt", async () => {
    mockFetch({ "GET /api/v1/cases/c1": () => kase, "GET /api/v1/cases/c1/reports": () => [report] });
    renderWithQuery(<CaseWorkspace id="c1" />);
    expect(await screen.findByRole("heading", { level: 1, name: "Passkey phishing - October 2026" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Hunt report" })).toHaveAttribute("aria-selected", "true");
  });

  it("keeps the ordinary landing tab for a case without a hunt report", async () => {
    mockFetch({ "GET /api/v1/cases/c1": () => kase, "GET /api/v1/cases/c1/reports": () => [] });
    renderWithQuery(<CaseWorkspace id="c1" />);
    expect(await screen.findByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("tab", { name: "Hunt report" })).toBeNull();
  });
});

describe("honest numbers and first paint", () => {
  it("shows the search backend's 10,000 cap as '10K+', never as an exact total", () => {
    render(<HBars rows={[{ label: "capped", value: 10000 }, { label: "exact", value: 9999 }]} />);
    expect(screen.getByText("10K+")).toBeInTheDocument();
    expect(screen.getByText("9,999")).toBeInTheDocument();
    expect(screen.getByTitle(/stops counting at 10,000/)).toBeInTheDocument();
  });

  it("draws every bar at its true width on first paint, with no dependence on an animation frame", () => {
    const raf = vi.spyOn(window, "requestAnimationFrame").mockImplementation(() => 0); // a hidden tab never fires frames
    const { container } = render(<><HBars rows={[{ label: "a", value: 100 }, { label: "b", value: 50 }]} /><Meter label="m" value={3} total={4} /><StackedBar ariaLabel="s" segments={[{ key: "x", label: "X", value: 1, color: VIZ.series[0] }, { key: "y", label: "Y", value: 3, color: VIZ.gray }]} /></>);
    const widths = [...container.querySelectorAll<HTMLElement>("[style*='width']")].map((e) => e.style.width);
    expect(widths).toEqual(expect.arrayContaining(["100%", "50%", "75%", "25%"]));
    expect(widths.every((w) => w !== "0%")).toBe(true);
    raf.mockRestore();
  });

  it("stat tiles show their value immediately, even when animation frames never run", () => {
    const raf = vi.spyOn(window, "requestAnimationFrame").mockImplementation(() => 0);
    render(<HuntReportView data={data()} />);
    expect(screen.getByText("120")).toBeInTheDocument(); // events reviewed, not 0
    raf.mockRestore();
  });
});

describe("the ATT&CK strip stays readable", () => {
  it("gives tactics with techniques room for the full id and shrinks the empty ones", () => {
    const { container } = render(<TacticStrip attack={data().attack} />);
    const grid = container.querySelector<HTMLElement>("[role='list']") as HTMLElement;
    const cols = grid.style.gridTemplateColumns.split(" minmax").length - 1; // active tactics
    expect(cols).toBe(3); // execution, lateral movement, unmapped
    expect(grid.style.gridTemplateColumns).toContain("1.6rem");
    expect(screen.getAllByRole("link", { name: /T1059\.001/ })[0].textContent).toContain("T1059.001"); // not truncated
  });
});

describe("report layout details", () => {
  it("breaks the searches down by kind", () => {
    render(<HuntReportView data={data()} />);
    const card = screen.getByText("How the searches turned out").closest("section") as HTMLElement;
    expect(within(card).getByText("By kind of search")).toBeInTheDocument();
    expect(within(card).getByText("Event searches")).toBeInTheDocument(); // two of the three fixture searches
    expect(within(card).getByText("Aggregations")).toBeInTheDocument();
  });

  it("charts only measured result sets and says how many hit the counting limit", () => {
    const sec = (title: string, results: number) => ({ title, description: "", tool: "search_events", query: "q", status: "SUCCEEDED" as const, results, error: "", rows: [], purpose: "test", ref: title });
    render(<HuntReportView data={data({ sections: [sec("small one", 40), sec("capped A", 10000), sec("capped B", 10000)] })} />);
    const card = screen.getByText("Largest result sets").closest("section") as HTMLElement;
    expect(within(card).getByText("small one")).toBeInTheDocument();
    expect(within(card).queryByText("capped A")).toBeNull(); // a capped count is not a measurement
    expect(within(card).getByText(/2 searches matched at least 10,000 events/)).toBeInTheDocument();
  });

  it("does not draw an uninformative chart when every result set is capped", () => {
    const sec = (title: string) => ({ title, description: "", tool: "search_events", query: "q", status: "SUCCEEDED" as const, results: 10000, error: "", rows: [], purpose: "test", ref: title });
    render(<HuntReportView data={data({ sections: [sec("a"), sec("b")] })} />);
    const card = screen.getByText("Largest result sets").closest("section") as HTMLElement;
    expect(within(card).queryAllByRole("listitem")).toHaveLength(0);
    expect(within(card).getByText(/their true size is unknown/)).toBeInTheDocument();
  });

  it("folds a wall-of-text summary until asked", async () => {
    render(<HuntReportView data={data({ summary: "word ".repeat(150).trim() })} />);
    const p = screen.getByText(/^word word/);
    expect(p.className).toContain("line-clamp-4");
    await userEvent.click(screen.getByRole("button", { name: "Read the full summary" }));
    expect(screen.getByText(/^word word/).className).not.toContain("line-clamp-4");
    expect(screen.getByRole("button", { name: "Show less" })).toBeInTheDocument();
  });

  it("labels every tactic with its full name, including the collapsed ones", () => {
    render(<TacticStrip attack={data().attack} />);
    expect(screen.getByText("Privilege escalation")).toBeInTheDocument();
    expect(screen.getByText("Command and control")).toBeInTheDocument();
  });
});

describe("long lists stay readable", () => {
  const sec = (i: number) => ({ title: `search ${i}`, description: "", tool: "search_events", query: `q${i}`, status: "SUCCEEDED" as const, results: i, error: "", rows: [], purpose: "test", ref: `q${i}` });
  it("folds a long searches table to a dozen rows and shows the rest on request", async () => {
    render(<HuntReportView data={data({ sections: Array.from({ length: 30 }, (_, i) => sec(i + 1)), omitted_sections: 0 })} />);
    const queries = document.getElementById("hr-queries") as HTMLElement;
    expect(within(queries).getAllByRole("listitem")).toHaveLength(12);
    await userEvent.click(within(queries).getByRole("button", { name: "Show all 30 searches" }));
    expect(within(queries).getAllByRole("listitem")).toHaveLength(30);
    await userEvent.click(within(queries).getByRole("button", { name: "Show fewer searches" }));
    expect(within(queries).getAllByRole("listitem")).toHaveLength(12);
  });

  it("wraps very long values in the gaps list instead of spilling out of the card", () => {
    render(<HuntReportView data={data({ gaps: ["unexplored lead hash:" + "a".repeat(120)] })} />);
    const li = screen.getByText(/unexplored lead hash:a+/);
    expect(li.parentElement?.className).toContain("[overflow-wrap:anywhere]");
  });
});

describe("no React warnings", () => {
  it("renders a whole report - including repeated searches and repeated labels - without a single console error", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const dup = { title: "Event aggregation: host.hostname:x", description: "d", tool: "aggregate_events", query: "q", status: "SUCCEEDED" as const, results: 7, error: "", rows: [], purpose: "scope", ref: "q1" };
    render(<HuntReportView data={data({ sections: [dup, { ...dup }, { ...dup, results: 3 }, ...data().sections], hosts: [{ host: "WS-02", events: 4 }, { host: "WS-02", events: 2 }] })} markdown="# x" />);
    expect(err.mock.calls.map((c) => String(c[0]).slice(0, 80))).toEqual([]);
    err.mockRestore();
  });

  it("HBars keeps rows that share a label", () => {
    render(<HBars rows={[{ label: "same", value: 5 }, { label: "same", value: 9 }, { label: "same", value: 1 }]} />);
    expect(screen.getAllByText("same")).toHaveLength(3);
  });
});
