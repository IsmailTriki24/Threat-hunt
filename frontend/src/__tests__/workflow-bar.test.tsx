import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { WorkflowBar } from "@/components/workflow-bar";
import type { CaseOut } from "@/lib/api-types";
import { mockFetch, renderWithQuery, status } from "./helpers";

const kase = (o: Partial<CaseOut>): CaseOut => ({
  id: "c1", case_id: "CASE-0001", number: 1, title: "T", description: "", severity: "HIGH", priority: "P2", status: "INVESTIGATING",
  resolution: "", assignee: null, hunt_id: null, created_by: null, created_at: "2026-03-01T10:00:00Z", updated_at: "2026-03-01T10:00:00Z",
  closed_at: null, evidence_count: 0, ioc_count: 0, asset_count: 0, allowed_transitions: ["OPEN", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"], ...o,
});

it("offers only the transitions the server allows", () => {
  mockFetch({});
  renderWithQuery(<WorkflowBar c={kase({ allowed_transitions: ["CONTAINED", "RESOLVED"] })} canWrite />);
  const bar = screen.getByLabelText("Case workflow");
  expect(within(bar).getAllByRole("button").map((b) => b.textContent)).toEqual(["CONTAINED", "RESOLVED"]);
  expect(within(bar).queryByRole("button", { name: "CLOSED" })).toBeNull();
});

it("non-terminal transitions are sent immediately without a comment", async () => {
  const m = mockFetch({ "POST /api/v1/cases/c1/transition": () => kase({ status: "CONTAINED" }) });
  renderWithQuery(<WorkflowBar c={kase({})} canWrite />);
  await userEvent.click(screen.getByRole("button", { name: "CONTAINED" }));
  await waitFor(() => expect(m.bodiesFor("POST /api/v1/cases/c1/transition")).toEqual([{ status: "CONTAINED", comment: "" }]));
});

it("terminal transitions require a resolution before confirming", async () => {
  const m = mockFetch({ "POST /api/v1/cases/c1/transition": () => kase({ status: "RESOLVED" }) });
  renderWithQuery(<WorkflowBar c={kase({})} canWrite />);
  await userEvent.click(screen.getByRole("button", { name: "RESOLVED" }));
  const dialog = screen.getByRole("dialog");
  const confirm = within(dialog).getByRole("button", { name: "Confirm" });
  expect(confirm).toBeDisabled();
  expect(m.calls).toHaveLength(0);
  await userEvent.type(within(dialog).getByLabelText(/resolution/i), "reimaged host");
  expect(confirm).toBeEnabled();
  await userEvent.click(confirm);
  await waitFor(() => expect(m.bodiesFor("POST /api/v1/cases/c1/transition")).toEqual([{ status: "RESOLVED", comment: "reimaged host" }]));
});

it("reopening a closed case asks for a reason and surfaces server 409 messages", async () => {
  mockFetch({ "POST /api/v1/cases/c1/transition": () => status(409, { error: { code: "invalid_transition", message: "Cannot move from CLOSED to OPEN (allowed: INVESTIGATING)" } }) });
  renderWithQuery(<WorkflowBar c={kase({ status: "CLOSED", allowed_transitions: ["INVESTIGATING"] })} canWrite />);
  await userEvent.click(screen.getByRole("button", { name: /Reopen as INVESTIGATING/ }));
  const dialog = screen.getByRole("dialog", { name: "Reopen case" });
  await userEvent.type(within(dialog).getByLabelText(/reason/i), "new evidence");
  await userEvent.click(within(dialog).getByRole("button", { name: "Confirm" }));
  expect(await within(dialog).findByRole("alert")).toHaveTextContent("Cannot move from CLOSED to OPEN");
});

it("disables transitions for read-only roles", () => {
  mockFetch({});
  renderWithQuery(<WorkflowBar c={kase({})} canWrite={false} />);
  for (const b of within(screen.getByLabelText("Case workflow")).getAllByRole("button")) expect(b).toBeDisabled();
});
