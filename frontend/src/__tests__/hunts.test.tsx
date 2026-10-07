import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HuntsList, NewHuntForm, parseSources } from "@/components/hunts-list";
import { mockFetch, renderWithQuery, status } from "./helpers";

let perms: string[] = [];
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => perms.includes(p) }) }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("next/link", () => ({ default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a> }));

const hunt = (o: object) => ({ id: "1", title: "PS persistence", hypothesis: "PowerShell used for persistence", status: "ACTIVE", time_start: null, time_end: null,
  data_sources: [], conclusion: "", created_by: null, created_at: "2026-03-01T10:00:00Z", updated_at: "2026-03-01T11:00:00Z", finding_count: 2, query_count: 3, ...o });

it("lists hunts with counts and filters by status", async () => {
  perms = ["hunts:read"];
  mockFetch({ "GET /api/v1/hunts": () => [hunt({}), hunt({ id: "2", title: "Old", status: "ARCHIVED", finding_count: 0, query_count: 0 })] });
  renderWithQuery(<HuntsList />);
  expect(await screen.findByRole("link", { name: "PS persistence" })).toHaveAttribute("href", "/hunts/1");
  expect(screen.getByRole("link", { name: "Old" })).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Status filter"), "ARCHIVED");
  expect(screen.queryByRole("link", { name: "PS persistence" })).toBeNull();
});

it("read-only roles see a hint and cannot create or delete (UI hints; server enforces)", async () => {
  perms = ["hunts:read"];
  mockFetch({ "GET /api/v1/hunts": () => [hunt({})] });
  renderWithQuery(<HuntsList />);
  await screen.findByRole("link", { name: "PS persistence" });
  expect(screen.getByRole("button", { name: "New hunt" })).toBeDisabled();
  expect(screen.getByText(/Read-only/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
});

it("writers can create; only delete-permission roles see Delete", async () => {
  perms = ["hunts:read", "hunts:write"];
  mockFetch({ "GET /api/v1/hunts": () => [hunt({})] });
  const { unmount } = renderWithQuery(<HuntsList />);
  await screen.findByRole("link", { name: "PS persistence" });
  expect(screen.getByRole("button", { name: "New hunt" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
  unmount();
  perms = ["hunts:read", "hunts:write", "hunts:delete"];
  renderWithQuery(<HuntsList />);
  expect(await screen.findByRole("button", { name: "Delete" })).toBeInTheDocument();
});

it("create form validates, then posts the hunt body", async () => {
  const onCreated = vi.fn();
  const m = mockFetch({ "POST /api/v1/hunts": () => hunt({ id: "new" }) });
  renderWithQuery(<NewHuntForm onCreated={onCreated} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Create hunt" }));
  expect(screen.getByRole("alert")).toHaveTextContent("Title is required");
  await user.type(screen.getByLabelText("Title"), "  Suspicious PowerShell ");
  await user.type(screen.getByLabelText("Hypothesis"), "PS execution and persistence");
  await user.selectOptions(screen.getByLabelText("Status"), "ACTIVE");
  await user.type(screen.getByLabelText("Data sources"), "Sysmon, windows");
  await user.type(screen.getByLabelText("Window start"), "2026-03-01T10:00");
  await user.click(screen.getByRole("button", { name: "Create hunt" }));
  expect(screen.getByRole("alert")).toHaveTextContent(/both window start and end/);
  await user.type(screen.getByLabelText("Window end"), "2026-03-02T10:00");
  await user.click(screen.getByRole("button", { name: "Create hunt" }));
  await waitFor(() => expect(onCreated).toHaveBeenCalledWith("new"));
  expect(m.bodiesFor("POST /api/v1/hunts")[0]).toEqual({
    title: "Suspicious PowerShell", hypothesis: "PS execution and persistence", status: "ACTIVE", data_sources: ["sysmon", "windows"],
    time_start: "2026-03-01T10:00:00.000Z", time_end: "2026-03-02T10:00:00.000Z",
  });
});

it("surfaces API errors on create and parses source lists", async () => {
  mockFetch({ "POST /api/v1/hunts": () => status(403, { error: { code: "forbidden", message: "Insufficient permissions" } }) });
  renderWithQuery(<NewHuntForm onCreated={() => {}} />);
  await userEvent.type(screen.getByLabelText("Title"), "x");
  await userEvent.click(screen.getByRole("button", { name: "Create hunt" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("do not have permission");
  expect(parseSources(" A, b  c,, ")).toEqual(["a", "b", "c"]);
});
