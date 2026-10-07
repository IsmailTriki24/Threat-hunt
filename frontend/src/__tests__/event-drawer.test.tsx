import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EventDrawer } from "@/components/event-drawer";

const detail = {
  event: { id: "a".repeat(32), timestamp: "2026-03-01T10:00:00Z", source: "sysmon", event_type: "process_creation", severity: 80,
    host: { hostname: "WS-01" }, process: { name: "powershell.exe", command_line: "<b>x</b>" }, raw: { Hashes: "SHA256=ab" } },
  pivots: [{ label: "Host", field: "host.hostname", value: "WS-01", entity: "host" }],
};

function setup() {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(detail), { status: 200 })));
  const onPivot = vi.fn();
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}><EventDrawer id={"a".repeat(32)} onClose={vi.fn()} onPivot={onPivot} /></QueryClientProvider>);
  return onPivot;
}

it("pivot adds an eq filter", async () => {
  const onPivot = setup();
  await userEvent.click(await screen.findByRole("button", { name: /Host: WS-01/ }));
  expect(onPivot).toHaveBeenCalledWith({ field: "host.hostname", op: "eq", value: "WS-01" });
});

it("renders values as text and toggles raw JSON", async () => {
  setup();
  expect(await screen.findByText("<b>x</b>")).toBeInTheDocument();
  expect(document.querySelector("dd b")).toBeNull();
  expect(screen.queryByText(/SHA256=ab/)).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: /show raw event/i }));
  expect(screen.getByText(/SHA256=ab/)).toBeInTheDocument();
});
