import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReportsTab } from "@/components/case-tabs";
import { Markdown } from "@/components/markdown";
import { RunReport } from "@/components/ai-report";
import type { AiRun } from "@/lib/ai";
import { mockFetch, renderWithQuery } from "./helpers";

const auth = vi.hoisted(() => ({ cases: true }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => p !== "cases:write" || auth.cases }) }));
vi.mock("next/link", () => ({ default: ({ href, children, ...r }: { href: string; children?: React.ReactNode }) => <a href={href} {...r}>{children}</a> }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

beforeEach(() => { auth.cases = true; });

const REPORT = `# Passkey phishing - October 2026

## Hunting Summary

**Scope of Hunt:** September 07, 2026 through October 08, 2026 (UTC) - Total Days: 31

> **No Threat Indicators Observed - No further action is required**

## Hunt Queries

| Search | Status | Results |
|---|---|---|
| Alerts \\| passkey | SUCCEEDED | 0 |

Query: \`process.name:*powershell.exe*\`

_No results returned for this query_

- [x] done step
- [ ] open step
- see [MITRE T1059](https://attack.mitre.org/techniques/T1059/)
`;

describe("Markdown (report renderer)", () => {
  it("renders the structure of a hunt report", () => {
    render(<Markdown source={REPORT} />);
    expect(screen.getByRole("heading", { level: 1, name: "Passkey phishing - October 2026" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Hunting Summary" })).toBeInTheDocument();
    expect(screen.getByText("Scope of Hunt:").tagName).toBe("STRONG");
    expect(screen.getByText(/No Threat Indicators Observed/).closest("blockquote")).not.toBeNull();
    expect(screen.getByRole("columnheader", { name: "Status" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "Alerts | passkey" })).toBeInTheDocument(); // an escaped pipe stays inside its cell
    expect(screen.getByText("process.name:*powershell.exe*").tagName).toBe("CODE");
    expect(screen.getByText("No results returned for this query").tagName).toBe("EM");
    expect(screen.getByLabelText("done")).toBeInTheDocument();
    expect(screen.getByLabelText("not done")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "MITRE T1059" });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("never interprets HTML, scripts or non-http links", () => {
    const { container } = render(<Markdown source={'<script>alert(1)</script> <img src=x onerror=alert(1)> [x](javascript:alert(1)) [ok](https://example.org/a) ![i](https://evil.example/p.png)'} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>"); // shown as text, inert
    const anchors = [...container.querySelectorAll("a")];
    expect(anchors.map((a) => a.getAttribute("href"))).toEqual(["https://example.org/a", "https://evil.example/p.png"]);
    expect(anchors.every((a) => a.getAttribute("href")?.startsWith("https://"))).toBe(true);
    expect(container.textContent).toContain("x (javascript:alert(1))"); // the unsafe link is plain text
  });

  it("handles ordered lists, fenced code and rules", () => {
    render(<Markdown source={"1. first\n2. second\n\n```\nraw <b>text</b>\n```\n\n---\n"} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("raw <b>text</b>").tagName).toBe("PRE");
  });
});

const baseRun = {
  id: "r1", hunt_id: null, goal: "g", status: "COMPLETED", provider: "p", model: "m", hours_back: 24, steps: [], saved_findings: [], input_tokens: 1, output_tokens: 1,
  error: "", created_at: "2026-03-01T10:00:00Z", conclusion: { summary: "s", confidence: "LOW", model_confidence: "LOW", findings: [], next_steps: [], validation_notes: [], events_reviewed: 1 },
} as unknown as AiRun;

describe("opening a case from a hunt", () => {
  it("links to the case the run already opened", () => {
    renderWithQuery(<RunReport run={{ ...baseRun, case_id: "c-9", case_number: 12 }} evidence={[]} />);
    const link = screen.getByRole("link", { name: /Case #12 opened with this hunt report/ });
    expect(link).toHaveAttribute("href", "/cases/c-9");
    expect(screen.queryByRole("button", { name: "Open case" })).toBeNull();
  });

  it("offers to open one, and shows the link once it exists", async () => {
    const api = mockFetch({ "POST /api/v1/ai/runs/r1/case": () => ({ case_id: "c-3", number: 3, created: true }) });
    renderWithQuery(<RunReport run={baseRun} evidence={[]} />);
    await userEvent.click(screen.getByRole("button", { name: "Open case" }));
    expect(await screen.findByRole("link", { name: /Case #3 opened/ })).toHaveAttribute("href", "/cases/c-3");
    expect(api.calls.some((c) => c.key === "POST /api/v1/ai/runs/r1/case")).toBe(true);
  });

  it("shows a failure instead of pretending", async () => {
    mockFetch({ "POST /api/v1/ai/runs/r1/case": () => ({ __status: 400, body: { error: { code: "bad", message: "This investigation has no conclusion to report yet" } } }) });
    renderWithQuery(<RunReport run={baseRun} evidence={[]} />);
    await userEvent.click(screen.getByRole("button", { name: "Open case" }));
    expect(await screen.findByText(/no conclusion to report yet/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /opened/ })).toBeNull();
  });

  it("does not offer it to someone who cannot create cases", () => {
    auth.cases = false;
    renderWithQuery(<RunReport run={baseRun} evidence={[]} />);
    expect(screen.queryByRole("button", { name: "Open case" })).toBeNull();
  });
});

describe("the case's Reports tab", () => {
  it("shows an AI hunt report rendered, with the source one click away", async () => {
    mockFetch({ "GET /api/v1/cases/c1/reports": () => [{ id: "rp1", version: 1, kind: "hunt", content: REPORT, created_by: null, created_at: "2026-03-01T10:00:00Z" }] });
    renderWithQuery(<ReportsTab caseId="c1" canWrite caseNumber="CASE-1" />);
    expect(await screen.findByText("AI hunt report")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Passkey phishing - October 2026" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Source" }));
    await waitFor(() => expect(screen.queryByRole("heading", { level: 1 })).toBeNull());
    expect(screen.getByText(/# Passkey phishing - October 2026/)).toBeInTheDocument();
  });
});
