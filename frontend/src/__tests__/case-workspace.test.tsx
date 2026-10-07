import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CaseWorkspace } from "@/components/case-workspace";
import { TimelineTab } from "@/components/case-tabs";
import type { CaseOut } from "@/lib/api-types";
import { mockFetch, renderWithQuery } from "./helpers";

let perms: string[] = [];
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => perms.includes(p), session: { user_id: "u1", email: "me@x" } }) }));
vi.mock("next/link", () => ({ default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a> }));
beforeEach(() => { perms = ["cases:read", "cases:write", "audit:read"]; });

const kase = (o: Partial<CaseOut>): CaseOut => ({
  id: "c1", case_id: "CASE-0001", number: 1, title: "Suspicious PS", description: "<i>desc</i>", severity: "HIGH", priority: "P2", status: "INVESTIGATING",
  resolution: "", assignee: { id: "u1", email: "me@x", full_name: "" }, hunt_id: null, created_by: null, created_at: "2026-03-01T10:00:00Z",
  updated_at: "2026-03-01T10:00:00Z", closed_at: null, evidence_count: 2, ioc_count: 1, asset_count: 1, allowed_transitions: ["CONTAINED"], ...o,
});

it("renders the case as text with counts and an audit tab for audit:read", async () => {
  mockFetch({ "GET /api/v1/cases/c1": () => kase({}) });
  renderWithQuery(<CaseWorkspace id="c1" />);
  expect(await screen.findByText("Suspicious PS")).toBeInTheDocument();
  expect(screen.getByText("<i>desc</i>")).toBeInTheDocument();
  expect(document.querySelector("i")).toBeNull();
  expect(screen.getByRole("tab", { name: "Evidence (2)" })).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Audit" })).toBeInTheDocument();
});

it("hides the audit tab without audit:read", async () => {
  perms = ["cases:read"];
  mockFetch({ "GET /api/v1/cases/c1": () => kase({}) });
  renderWithQuery(<CaseWorkspace id="c1" />);
  await screen.findByText("Suspicious PS");
  expect(screen.queryByRole("tab", { name: "Audit" })).toBeNull();
  expect(screen.getByText(/Read-only/)).toBeInTheDocument();
});

it("closed cases show a lock banner and disable mutating controls but keep notes enabled", async () => {
  mockFetch({
    "GET /api/v1/cases/c1": () => kase({ status: "CLOSED", allowed_transitions: ["INVESTIGATING"], closed_at: "2026-03-02T10:00:00Z" }),
    "GET /api/v1/cases/c1/evidence": () => [], "GET /api/v1/cases/c1/iocs": () => [], "GET /api/v1/cases/c1/assets": () => [],
    "GET /api/v1/cases/c1/activity": () => [],
  });
  renderWithQuery(<CaseWorkspace id="c1" />);
  expect(await screen.findByRole("status")).toHaveTextContent(/closed and locked/);
  expect(screen.getByRole("button", { name: "Edit" })).toBeDisabled();

  await userEvent.click(screen.getByRole("tab", { name: /Evidence/ }));
  expect(await screen.findByRole("button", { name: "Add evidence" })).toBeDisabled();
  expect(screen.getByLabelText("Event ids")).toBeDisabled();

  await userEvent.click(screen.getByRole("tab", { name: /IOCs/ }));
  expect(await screen.findByRole("button", { name: "Add IOC" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Re-extract from evidence" })).toBeDisabled();

  await userEvent.click(screen.getByRole("tab", { name: /Assets/ }));
  expect(await screen.findByLabelText("Search assets to link")).toBeDisabled();

  await userEvent.click(screen.getByRole("tab", { name: /Notes/ }));
  expect(await screen.findByLabelText("Note")).toBeEnabled();
});

it("merged timeline interleaves journal entries with telemetry in time order", async () => {
  const entry = (id: string, ts: string, title: string) => ({ id, timestamp: ts, end_timestamp: null, count: 1, event_type: "process_creation", title, severity: 0, host: "WS-01", user: null,
    process: null, pid: null, destination: null, parent_event_id: null, process_event_id: null, event_ids: [id], periodicity: null });
  mockFetch({
    "GET /api/v1/cases/c1/timeline": () => ({ entries: [entry("e1", "2026-03-01T10:00:00Z", "WINWORD.EXE started"), entry("e2", "2026-03-01T10:10:00Z", "powershell.exe started")], total_events: 2, truncated: false }),
    "GET /api/v1/cases/c1/activity": () => [{ id: "j1", kind: "note", body: "Isolated the host", details: {}, actor_id: null, actor_email: "me@x", created_at: "2026-03-01T10:05:00Z" }],
    "GET /api/v1/cases/c1/evidence": () => [],
  });
  renderWithQuery(<TimelineTab caseId="c1" />);
  const list = await screen.findByLabelText("Merged timeline");
  const items = within(list).getAllByRole("listitem");
  expect(items.map((i) => i.getAttribute("data-testid"))).toEqual(["telemetry-item", "journal-item", "telemetry-item"]);
  expect(items[1]).toHaveTextContent("Isolated the host");
  expect(items[0]).toHaveTextContent("WINWORD.EXE started");
});
