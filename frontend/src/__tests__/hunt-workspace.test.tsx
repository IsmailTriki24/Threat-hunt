import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HuntWorkspace } from "@/components/hunt-workspace";
import { mockFetch, renderWithQuery } from "./helpers";

let perms = ["hunts:read", "hunts:write"];
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => perms.includes(p) }) }));

const ID1 = "a".repeat(32), ID2 = "b".repeat(32);
const hunt = { id: "h1", title: "PS hunt", hypothesis: "H", status: "ACTIVE", time_start: "2026-03-01T00:00:00Z", time_end: "2026-03-02T00:00:00Z",
  data_sources: [], conclusion: "", created_by: null, created_at: "2026-03-01T10:00:00Z", updated_at: "2026-03-01T10:00:00Z", finding_count: 0, query_count: 0 };
const ev = (id: string, host: string) => ({ id, timestamp: "2026-03-01T10:00:00Z", source: "sysmon", event_type: "process_creation", severity: 70,
  host: { hostname: host }, user: { name: "alice" }, process: { name: "powershell.exe", command_line: "powershell -enc AAA" } });
const result = { total: 2, total_relation: "eq", took_ms: 3, hits: [ev(ID1, "WS-01"), ev(ID2, "WS-02")], time_range: { start: "2026-03-01T00:00:00Z", end: "2026-03-02T00:00:00Z" },
  aggregations: { by_host: { buckets: [{ key: "ws-01", count: 1 }] }, timeline: { buckets: [] } } };

function routes(extra: Record<string, () => unknown> = {}) {
  return mockFetch({
    "GET /api/v1/hunts/h1": () => hunt,
    "GET /api/v1/events/fields": () => [{ name: "host.hostname", kind: "keyword", sortable: true, aggregatable: true }],
    "GET /api/v1/saved-queries": () => [],
    "GET /api/v1/query-history": () => [],
    "GET /api/v1/hunts/h1/findings": () => [],
    "GET /api/v1/hunts/h1/notes": () => [{ id: "n1", hunt_id: "h1", body: "<b>note</b>", author_id: null, created_at: "2026-03-01T10:00:00Z" }],
    "POST /api/v1/queries/parse": () => ({ q: null, filters: [] }),
    "POST /api/v1/hunts/h1/run": () => result,
    ...extra,
  });
}

async function runQuery(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByDisplayValue("PS hunt");
  await user.type(screen.getByLabelText("Hunt query"), "process.name:powershell.exe");
  await user.click(screen.getByRole("button", { name: /^Run/ }));
  await screen.findAllByText("WS-01");
}

it("run → results: posts the language text with the hunt window defaulted, renders rows, notes as plain text", async () => {
  perms = ["hunts:read", "hunts:write"];
  const m = routes();
  renderWithQuery(<HuntWorkspace id="h1" />);
  const user = userEvent.setup();
  await runQuery(user);
  const body = m.bodiesFor("POST /api/v1/hunts/h1/run")[0] as { query: Record<string, unknown> };
  expect(body.query.text).toBe("process.name:powershell.exe");
  expect(body.query.time_range).toEqual({ start: "2026-03-01T00:00:00Z", end: "2026-03-02T00:00:00Z" });
  expect(screen.getByText(/2 events/)).toBeInTheDocument();
  expect(screen.getByText("<b>note</b>")).toBeInTheDocument();
  expect(document.querySelector("li b")).toBeNull();
});

it("add finding sends the selected row ids and severity, then refreshes", async () => {
  perms = ["hunts:read", "hunts:write"];
  const m = routes({ "POST /api/v1/hunts/h1/findings": () => ({ id: "f1" }) });
  renderWithQuery(<HuntWorkspace id="h1" />);
  const user = userEvent.setup();
  await runQuery(user);
  expect(screen.getByRole("button", { name: "Add finding" })).toBeDisabled();
  await user.click(screen.getByLabelText(`Select event ${ID1.slice(0, 8)}`));
  await user.click(screen.getByLabelText(`Select event ${ID2.slice(0, 8)}`));
  await user.click(screen.getByRole("button", { name: "Add finding" }));
  const form = screen.getByRole("form", { name: "Add finding" });
  await user.type(within(form).getByLabelText("Finding title"), "Encoded PowerShell");
  await user.selectOptions(within(form).getByLabelText("Finding severity"), "HIGH");
  await user.type(within(form).getByLabelText("Finding description"), "Seen on two hosts");
  await user.click(within(form).getByRole("button", { name: /Save finding \(2 events\)/ }));
  await waitFor(() => expect(m.bodiesFor("POST /api/v1/hunts/h1/findings")).toHaveLength(1));
  expect(m.bodiesFor("POST /api/v1/hunts/h1/findings")[0]).toEqual({
    title: "Encoded PowerShell", description: "Seen on two hosts", severity: "HIGH", event_ids: [ID1, ID2],
  });
});

it("export downloads the server response as a file using the current query without aggregations", async () => {
  perms = ["hunts:read", "hunts:write"];
  const create = vi.fn(() => "blob:csv");
  Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() });
  let downloaded = "";
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { downloaded = this.download; });
  const m = routes({ "POST /api/v1/events/export": () => new Blob(["timestamp\n"], { type: "text/csv" }) });
  renderWithQuery(<HuntWorkspace id="h1" />);
  const user = userEvent.setup();
  await runQuery(user);
  await user.click(screen.getByRole("button", { name: "Export CSV" }));
  await waitFor(() => expect(downloaded).toBe("hunt-h1.csv"));
  const sent = m.bodiesFor("POST /api/v1/events/export")[0] as { query: Record<string, unknown>; format: string; max_rows: number };
  expect(sent.format).toBe("csv");
  expect(sent.max_rows).toBe(5000);
  expect(sent.query.text).toBe("process.name:powershell.exe");
  expect(sent.query).not.toHaveProperty("aggregations");
  expect(screen.getByText(/max 5,000 rows/)).toBeInTheDocument();
  click.mockRestore();
});

it("aggregation clicks pivot into the query text; viewers cannot edit or add findings/notes", async () => {
  perms = ["hunts:read"];
  routes();
  renderWithQuery(<HuntWorkspace id="h1" />);
  const user = userEvent.setup();
  await screen.findByDisplayValue("PS hunt");
  expect(screen.getByLabelText("Hunt title")).toHaveAttribute("readonly");
  expect(screen.getByRole("button", { name: "Save query" })).toBeDisabled();
  expect(screen.queryByLabelText("New note")).toBeNull();
  await user.click(screen.getByRole("button", { name: /^Run/ }));
  await user.click(await screen.findByTitle("Filter host.hostname = ws-01"));
  expect(screen.getByLabelText("Hunt query")).toHaveValue("host.hostname:ws-01");
});

it("a 422 from run shows the parser message; unknown hunt shows not found", async () => {
  perms = ["hunts:read"];
  routes({ "POST /api/v1/hunts/h1/run": () => ({ __status: 422, body: { error: { code: "validation_error", message: "Invalid request", details: [{ msg: "Value error, query text: unknown field 'x'" }] } } }) });
  renderWithQuery(<HuntWorkspace id="h1" />);
  await screen.findByDisplayValue("PS hunt");
  await userEvent.click(screen.getByRole("button", { name: /^Run/ }));
  expect(await screen.findByText(/Run failed|unknown field/)).toBeInTheDocument();
});

it("unknown hunt id → not found", async () => {
  mockFetch({ "GET /api/v1/hunts/zzz": () => ({ __status: 404, body: { error: { code: "not_found", message: "Hunt not found" } } }) });
  renderWithQuery(<HuntWorkspace id="zzz" />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Hunt not found");
});

it("promotes a finding to a case and adds selected rows to a case (cases:write only)", async () => {
  perms = ["hunts:read", "hunts:write", "cases:write"];
  const finding = { id: "f1", hunt_id: "h1", title: "PS from Word", description: "d", severity: "HIGH", evidence: [], created_by: null, created_at: "2026-03-01T10:00:00Z" };
  const m = routes({
    "GET /api/v1/hunts/h1/findings": () => [finding],
    "POST /api/v1/cases": () => ({ id: "c1", case_id: "CASE-0001" }),
    "GET /api/v1/cases": () => [],
  });
  renderWithQuery(<HuntWorkspace id="h1" />);
  const user = userEvent.setup();
  await runQuery(user);
  await user.click(screen.getByRole("button", { name: "Promote finding PS from Word to case" }));
  await waitFor(() => expect(m.bodiesFor("POST /api/v1/cases")).toEqual([{ title: "PS from Word", description: "d", severity: "HIGH", finding_id: "f1" }]));
  expect(screen.getByRole("button", { name: "Add to case…" })).toBeDisabled(); // nothing selected yet
  await user.click(screen.getByLabelText(`Select event ${ID1.slice(0, 8)}`));
  expect(screen.getByRole("button", { name: "Add to case…" })).toBeEnabled();
  await user.click(screen.getByRole("button", { name: "Add to case…" }));
  expect(await screen.findByRole("dialog", { name: "Add to case" })).toHaveTextContent("1 event selected");
});

it("without cases:write the case actions are disabled/hidden", async () => {
  perms = ["hunts:read", "hunts:write"];
  routes({ "GET /api/v1/hunts/h1/findings": () => [{ id: "f1", hunt_id: "h1", title: "T", description: "", severity: "LOW", evidence: [], created_by: null, created_at: "2026-03-01T10:00:00Z" }] });
  renderWithQuery(<HuntWorkspace id="h1" />);
  await runQuery(userEvent.setup());
  expect(screen.queryByRole("button", { name: /Promote finding/ })).toBeNull();
  expect(screen.getByRole("button", { name: "Add to case…" })).toBeDisabled();
});
