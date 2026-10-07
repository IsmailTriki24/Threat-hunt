import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AssetsList, AssetView } from "@/components/assets-view";
import { AuditView } from "@/components/audit-view";
import { CasesList } from "@/components/cases-list";
import { mockFetch, renderWithQuery } from "./helpers";

let perms: string[] = [];
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => perms.includes(p), session: { user_id: "u1", email: "me@x" } }) }));
vi.mock("next/link", () => ({ default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a> }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
beforeEach(() => { perms = ["assets:read", "assets:write", "events:read", "cases:read", "cases:write", "audit:read"]; });

const asset = { id: "a1", type: "host", key: "ws-01", display_name: "ws-01", criticality: "HIGH", owner: "", tags: [], attributes: {}, event_count: 5,
  first_seen: "2026-03-01T09:00:00Z", last_seen: "2026-03-01T10:00:00Z", created_at: "2026-03-01T09:00:00Z" };

describe("assets", () => {
  it("filters map to the list request and discovery posts the chosen window", async () => {
    const m = mockFetch({
      "GET /api/v1/assets": () => [asset],
      "POST /api/v1/assets/discover": () => ({ created: 3, updated: 1 }),
    });
    renderWithQuery(<AssetsList />);
    await screen.findByText("ws-01");
    await userEvent.selectOptions(screen.getByLabelText("Type filter"), "host");
    await userEvent.selectOptions(screen.getByLabelText("Criticality filter"), "HIGH");
    await waitFor(() => expect(m.fn.mock.calls.map((c) => String(c[0]))).toContain("/api/v1/assets?type=host&criticality=HIGH&limit=200"));
    await userEvent.selectOptions(screen.getByLabelText("Discovery window"), "14");
    await userEvent.click(screen.getByRole("button", { name: "Discover from telemetry" }));
    expect(await screen.findByRole("status")).toHaveTextContent("3 new, 1 updated");
    expect(m.bodiesFor("POST /api/v1/assets/discover")).toEqual([{ days: 14 }]);
  });

  it("read-only roles cannot discover or create", async () => {
    perms = ["assets:read"];
    mockFetch({ "GET /api/v1/assets": () => [asset] });
    renderWithQuery(<AssetsList />);
    await screen.findByText("ws-01");
    expect(screen.getByRole("button", { name: "Discover from telemetry" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "New asset" })).toBeDisabled();
  });

  it("asset page turns related entities into Events pivots and lists linked cases", async () => {
    mockFetch({
      "GET /api/v1/assets/a1": () => asset,
      "GET /api/v1/assets/a1/events": () => ({ total: 0, hits: [] }),
      "GET /api/v1/assets/a1/related": () => ({ users: [{ key: "alice", count: 4 }], destinations: [{ key: "203.0.113.45", count: 9 }] }),
      "GET /api/v1/assets/a1/cases": () => [{ id: "c1", number: 1, title: "Phish", status: "INVESTIGATING", severity: "HIGH" }],
    });
    renderWithQuery(<AssetView id="a1" />);
    const user = await screen.findByRole("link", { name: "alice" });
    expect(user).toHaveAttribute("href", `/events?f=${encodeURIComponent("user.name|eq|alice")}`);
    expect(screen.getByRole("link", { name: "203.0.113.45" })).toHaveAttribute("href", `/events?f=${encodeURIComponent("network.dst_ip|eq|203.0.113.45")}`);
    expect(await screen.findByRole("link", { name: "CASE-0001" })).toHaveAttribute("href", "/cases/c1");
  });

  it("saves only the edited attributes", async () => {
    const m = mockFetch({
      "GET /api/v1/assets/a1": () => asset, "GET /api/v1/assets/a1/events": () => ({ total: 0, hits: [] }),
      "GET /api/v1/assets/a1/related": () => ({}), "GET /api/v1/assets/a1/cases": () => [],
      "PATCH /api/v1/assets/a1": () => asset,
    });
    renderWithQuery(<AssetView id="a1" />);
    const owner = await screen.findByLabelText("Owner");
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    await userEvent.type(owner, "Finance");
    await userEvent.click(save);
    await waitFor(() => expect(m.bodiesFor("PATCH /api/v1/assets/a1")).toEqual([{ owner: "Finance" }]));
  });
});

describe("audit trail", () => {
  it("maps filters to the query string and expands details as text", async () => {
    const row = { id: "r1", created_at: "2026-03-01T10:00:00Z", action: "case.create", outcome: "success", actor: "me@x", resource_type: "case", resource_id: "abcdef12-x", ip: "10.0.0.1", request_id: "rq1", details: { note: "<b>x</b>" } };
    const m = mockFetch({ "GET /api/v1/audit": () => [row] });
    renderWithQuery(<AuditView />);
    await screen.findByText("case.create");
    await userEvent.type(screen.getByLabelText("Action prefix"), "case.");
    await userEvent.selectOptions(screen.getByLabelText("Outcome"), "denied");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(m.fn.mock.calls.map((c) => String(c[0]))).toContain("/api/v1/audit?action=case.&outcome=denied&limit=50&offset=0"));
    await userEvent.click(screen.getAllByRole("button", { name: "Details" })[0]);
    expect(await screen.findByText(/<b>x<\/b>/)).toBeInTheDocument();
    expect(document.querySelector("pre b")).toBeNull();
  });

  it("paging advances the offset", async () => {
    const rows = Array.from({ length: 50 }, (_, i) => ({ id: `r${i}`, created_at: "2026-03-01T10:00:00Z", action: "x", outcome: "success", actor: "a", ip: null, details: {} }));
    const m = mockFetch({ "GET /api/v1/audit": () => rows });
    renderWithQuery(<AuditView />);
    await screen.findAllByText("x");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(m.fn.mock.calls.map((c) => String(c[0]))).toContain("/api/v1/audit?limit=50&offset=50"));
  });
});

describe("cases list", () => {
  const c = (o: object) => ({ id: "c1", case_id: "CASE-0001", number: 1, title: "Phish", severity: "HIGH", priority: "P2", status: "OPEN", assignee: null, evidence_count: 3, ioc_count: 2, asset_count: 1,
    updated_at: "2026-03-01T10:00:00Z", allowed_transitions: [], ...o });

  it("renders rows and maps filters to the request", async () => {
    const m = mockFetch({ "GET /api/v1/cases": () => [c({ assignee: { id: "u1", email: "me@x", full_name: "" } })] });
    renderWithQuery(<CasesList />);
    const row = (await screen.findByText("Phish")).closest("tr")!;
    expect(within(row).getByText("CASE-0001")).toBeInTheDocument();
    expect(within(row).getByText("me@x")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Status filter"), "INVESTIGATING");
    await userEvent.selectOptions(screen.getByLabelText("Severity filter"), "HIGH");
    await userEvent.click(screen.getByLabelText("Assigned to me"));
    await waitFor(() => expect(m.fn.mock.calls.map((x) => String(x[0]))).toContain("/api/v1/cases?status=INVESTIGATING&severity=HIGH&mine=true&limit=100"));
  });

  it("viewers see a read-only hint and a disabled New case button", async () => {
    perms = ["cases:read"];
    mockFetch({ "GET /api/v1/cases": () => [] });
    renderWithQuery(<CasesList />);
    await screen.findByText("No cases match.");
    expect(screen.getByRole("button", { name: "New case" })).toBeDisabled();
    expect(screen.getByText(/Read-only/)).toBeInTheDocument();
  });

  it("creates a case with the chosen fields and self-assignment", async () => {
    const m = mockFetch({ "GET /api/v1/cases": () => [], "POST /api/v1/cases": () => c({ id: "c9" }), "GET /api/v1/users": () => ({ __status: 403, body: { error: { message: "no" } } }) });
    renderWithQuery(<CasesList />);
    await userEvent.click(screen.getByRole("button", { name: "New case" }));
    await userEvent.type(screen.getByLabelText("Title"), "Ransomware precursor");
    await userEvent.selectOptions(screen.getByLabelText("Severity / priority"), "CRITICAL");
    await userEvent.selectOptions(screen.getByLabelText("Priority"), "P1");
    await userEvent.selectOptions(screen.getByLabelText("Assignee"), "u1");
    await userEvent.click(screen.getByRole("button", { name: "Create case" }));
    await waitFor(() => expect(m.bodiesFor("POST /api/v1/cases")).toEqual([{ title: "Ransomware precursor", description: "", severity: "CRITICAL", priority: "P1", assignee_id: "u1" }]));
  });
});
