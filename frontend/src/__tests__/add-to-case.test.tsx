import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AddToCaseDialog } from "@/components/add-to-case-dialog";
import { EventDrawer } from "@/components/event-drawer";
import { mockFetch, renderWithQuery } from "./helpers";

vi.mock("next/link", () => ({ default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a> }));

const ID = "a".repeat(32);
const kase = (id: string, status: string, title: string) => ({ id, case_id: `CASE-000${id}`, number: Number(id), title, status, severity: "HIGH", priority: "P2", assignee: null, allowed_transitions: [] });

const detail = { event: { id: ID, timestamp: "2026-03-01T10:00:00Z", source: "sysmon", event_type: "process_creation" }, pivots: [] };

it("the event drawer offers “Add to case…” only when the caller can, and passes the event id", async () => {
  mockFetch({ [`GET /api/v1/events/${ID}`]: () => detail });
  const onAdd = vi.fn();
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { rerender } = render(<QueryClientProvider client={qc}><EventDrawer id={ID} onClose={vi.fn()} onPivot={vi.fn()} /></QueryClientProvider>);
  await screen.findByText("Event detail");
  expect(screen.queryByRole("button", { name: /Add to case/ })).toBeNull();
  rerender(<QueryClientProvider client={qc}><EventDrawer id={ID} onClose={vi.fn()} onPivot={vi.fn()} onAddToCase={onAdd} /></QueryClientProvider>);
  await userEvent.click(screen.getByRole("button", { name: /Add to case/ }));
  expect(onAdd).toHaveBeenCalledWith(ID);
});

it("the drawer can render a stored snapshot without fetching live telemetry", () => {
  const m = mockFetch({});
  renderWithQuery(<EventDrawer id={ID} snapshot={detail.event} onClose={vi.fn()} onPivot={vi.fn()} />);
  expect(screen.getByText("process_creation")).toBeInTheDocument();
  expect(m.calls).toHaveLength(0);
});

it("adds events as evidence to the chosen open case (closed cases are not offered)", async () => {
  const m = mockFetch({
    "GET /api/v1/cases": () => [kase("1", "INVESTIGATING", "Phish"), kase("2", "CLOSED", "Old one")],
    "POST /api/v1/cases/1/evidence": () => [],
    "GET /api/v1/cases/1": () => kase("1", "INVESTIGATING", "Phish"),
  });
  renderWithQuery(<AddToCaseDialog eventIds={[ID, "b".repeat(32)]} onClose={vi.fn()} />);
  const select = await screen.findByLabelText("Case");
  await waitFor(() => expect(screen.getByRole("option", { name: /Phish/ })).toBeInTheDocument());
  expect(screen.queryByRole("option", { name: /Old one/ })).toBeNull();
  expect(screen.getByRole("button", { name: "Add evidence" })).toBeDisabled();
  await userEvent.selectOptions(select, "1");
  await userEvent.type(screen.getByLabelText("Comment"), "seen on WS-01");
  await userEvent.click(screen.getByRole("button", { name: "Add evidence" }));
  expect(await screen.findByText(/Added 2 events/)).toBeInTheDocument();
  expect(m.bodiesFor("POST /api/v1/cases/1/evidence")).toEqual([{ event_ids: [ID, "b".repeat(32)], comment: "seen on WS-01" }]);
  expect(screen.getByRole("link", { name: "Open case" })).toHaveAttribute("href", "/cases/1");
});

it("can create a new case seeded with the events", async () => {
  const m = mockFetch({ "GET /api/v1/cases": () => [], "POST /api/v1/cases": () => kase("7", "OPEN", "New investigation") });
  renderWithQuery(<AddToCaseDialog eventIds={[ID]} onClose={vi.fn()} />);
  await userEvent.click(screen.getByLabelText("New case"));
  await userEvent.type(screen.getByLabelText("New case title"), "New investigation");
  await userEvent.click(screen.getByRole("button", { name: "Create case" }));
  await screen.findByText(/Added 1 event to/);
  expect(m.bodiesFor("POST /api/v1/cases")).toEqual([{ title: "New investigation", event_ids: [ID] }]);
});

it("shows the server error (e.g. closed case / unknown event) instead of failing silently", async () => {
  mockFetch({
    "GET /api/v1/cases": () => [kase("1", "INVESTIGATING", "Phish")],
    "POST /api/v1/cases/1/evidence": () => ({ __status: 400, body: { error: { code: "bad_request", message: "Unknown event ids: aaaa" } } }),
  });
  renderWithQuery(<AddToCaseDialog eventIds={[ID]} onClose={vi.fn()} />);
  await waitFor(() => expect(screen.getByRole("option", { name: /Phish/ })).toBeInTheDocument());
  await userEvent.selectOptions(screen.getByLabelText("Case"), "1");
  await userEvent.click(screen.getByRole("button", { name: "Add evidence" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Unknown event ids");
});
