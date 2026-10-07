import { fireEvent, render, screen, within } from "@testing-library/react";
import { TimelineList } from "@/components/timeline-view";
import type { Timeline, TimelineEntry } from "@/lib/api-types";

const e = (o: Partial<TimelineEntry>): TimelineEntry => ({
  id: "x", timestamp: "2026-03-01T10:00:00Z", end_timestamp: null, count: 1, event_type: "process_creation", title: "title", severity: 0,
  host: "WS-01", user: "mharper", process: null, pid: null, destination: null, parent_event_id: null, process_event_id: null,
  event_ids: [o.id ?? "x"], periodicity: null, ...o,
});

const tl = (entries: TimelineEntry[], truncated = false): Timeline => ({ entries, total_events: 99, truncated });

it("renders a collapsed group with count, first→last time and an observational beacon note", () => {
  render(<TimelineList onOpen={() => {}} timeline={tl([e({
    id: "b", event_type: "network_connection", title: "powershell.exe → 203.0.113.45:443  ×240", count: 240,
    end_timestamp: "2026-03-01T14:00:00Z", destination: "203.0.113.45:443", periodicity: { median_interval_s: 60, jitter_pct: 4.2 },
  })])} />);
  expect(screen.getByText("240 events")).toBeInTheDocument();
  expect(screen.getByText(/2026-03-01 10:00:00 → 14:00:00/)).toBeInTheDocument();
  expect(screen.getByText("every ~60s, jitter 4%")).toBeInTheDocument();
  expect(screen.getByText(/beacon-like/)).toHaveTextContent(/verify before concluding/);
  expect(screen.queryByText(/malicious|C2 detected/i)).toBeNull();
});

it("shows periodicity but no beacon wording when jitter is high or the group is small", () => {
  render(<TimelineList onOpen={() => {}} timeline={tl([
    e({ id: "a", count: 30, periodicity: { median_interval_s: 61, jitter_pct: 55 } }),
    e({ id: "b", count: 6, periodicity: { median_interval_s: 60, jitter_pct: 2 } }),
  ])} />);
  expect(screen.getAllByText(/every ~/)).toHaveLength(2);
  expect(screen.queryByText(/beacon-like/)).toBeNull();
});

it("indents by lineage and the 'spawned by parent' link highlights the parent entry", () => {
  const scroll = vi.fn();
  Element.prototype.scrollIntoView = scroll;
  render(<TimelineList onOpen={() => {}} timeline={tl([
    e({ id: "w", title: "WINWORD.EXE started" }),
    e({ id: "p", title: "powershell.exe started by WINWORD.EXE", parent_event_id: "w" }),
  ])} />);
  const [word, ps] = screen.getAllByTestId("timeline-entry");
  expect(word.style.marginLeft).toBe("0px");
  expect(ps.style.marginLeft).toBe("16px");
  expect(word.className).not.toContain("border-accent");
  fireEvent.click(within(ps).getByRole("button", { name: /spawned by parent/ }));
  expect(word.className).toContain("border-accent");
  expect(scroll).toHaveBeenCalled();
});

it("clicking a title opens the first underlying event; truncation is flagged; values render as text", () => {
  const onOpen = vi.fn();
  render(<TimelineList onOpen={onOpen} timeline={tl([e({ id: "g", title: "<img src=x onerror=alert(1)>", event_ids: ["g", "g2"], count: 2 })], true)} />);
  expect(document.querySelector("img")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: /<img src=x/ }));
  expect(onOpen).toHaveBeenCalledWith("g");
  expect(screen.getByRole("alert")).toHaveTextContent(/truncated/i);
});

it("empty timeline message", () => {
  render(<TimelineList onOpen={() => {}} timeline={tl([])} />);
  expect(screen.getByText(/No events in this scope/)).toBeInTheDocument();
});
