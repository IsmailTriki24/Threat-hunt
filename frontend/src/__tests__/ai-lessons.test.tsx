import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Lessons } from "@/components/ai-lessons";
import type { AiLesson } from "@/lib/ai";
import { mockFetch, renderWithQuery, status } from "./helpers";

const L = (o: Partial<AiLesson>): AiLesson => ({
  id: "l1", cue: "searching LogRhythm for a bare file extension", lesson: "Scope a bare extension such as .php to one host first.", evidence: "q11 matched 500 events",
  confidence: "high", origin: "auto", status: "active", times_shown: 3, run_id: "r1", created_at: "2026-10-22T14:00:00Z", ...o,
});

describe("Experience library", () => {
  it("lists what was learned, with where it came from and whether the agent sees it", async () => {
    mockFetch({ "GET /api/v1/ai/lessons": () => [L({}), L({ id: "l2", origin: "analyst", status: "disabled", cue: "asking Trend about a host", lesson: "Use the short host name for Trend queries." })] });
    renderWithQuery(<Lessons />);
    expect(await screen.findByText(/Scope a bare extension/)).toBeInTheDocument();
    expect(screen.getByText(/1 active of 2/)).toBeInTheDocument();
    expect(screen.getByText("analyst")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Switch on" })).toBeInTheDocument(); // the disabled one
    expect(screen.getAllByText(/Why: q11 matched 500 events/)).toHaveLength(2);
  });

  it("switches a lesson off, deletes one and adds one", async () => {
    const api = mockFetch({
      "GET /api/v1/ai/lessons": () => [L({})],
      "PATCH /api/v1/ai/lessons/l1": () => L({ status: "disabled" }),
      "DELETE /api/v1/ai/lessons/l1": () => status(204, null),
      "POST /api/v1/ai/lessons": () => L({ id: "l3", origin: "analyst" }),
    });
    renderWithQuery(<Lessons />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Switch off" }));
    await waitFor(() => expect(api.bodiesFor("PATCH /api/v1/ai/lessons/l1")).toEqual([{ status: "disabled" }]));
    await user.click(screen.getByRole("button", { name: /Delete lesson/ }));
    await waitFor(() => expect(api.calls.some((c) => c.key === "DELETE /api/v1/ai/lessons/l1")).toBe(true));

    const add = screen.getByRole("button", { name: "Add lesson" });
    expect(add).toBeDisabled(); // too short to be a lesson
    await user.type(screen.getByLabelText("When it applies"), "asking Trend about a host");
    await user.type(screen.getByLabelText("Lesson"), "Trend answers per short host name, not the fully qualified one.");
    await user.click(add);
    await waitFor(() => expect(api.bodiesFor("POST /api/v1/ai/lessons")).toEqual([{ cue: "asking Trend about a host", lesson: "Trend answers per short host name, not the fully qualified one." }]));
  });
});
