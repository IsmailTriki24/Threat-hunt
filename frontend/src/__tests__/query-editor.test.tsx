import { useState } from "react";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryEditor } from "@/components/query-editor";
import { errorMessage } from "@/lib/api";
import { mockFetch, renderWithQuery, status } from "./helpers";

it("debounces validation: one parse call after typing stops, then shows parsed chips", async () => {
  const m = mockFetch({
    "POST /api/v1/queries/parse": () => ({ q: "enc", filters: [{ field: "process.name", op: "eq", value: "powershell.exe", negate: true }] }),
  });
  const Wrapper = () => { const [v, setV] = useState(""); return <QueryEditor value={v} onChange={setV} onRun={() => {}} delayMs={50} />; };
  renderWithQuery(<Wrapper />);
  await userEvent.type(screen.getByLabelText("Hunt query"), "-process.name:powershell.exe enc");
  expect(await screen.findByText(/NOT process\.name is powershell\.exe/)).toBeInTheDocument();
  expect(screen.getByText(/text: enc/)).toBeInTheDocument();
  expect(m.bodiesFor("POST /api/v1/queries/parse")).toEqual([{ text: "-process.name:powershell.exe enc" }]); // not one call per keystroke
});

it("shows the server's parse error inline", async () => {
  mockFetch({ "POST /api/v1/queries/parse": () => status(400, { error: { code: "bad_request", message: "Query error: unknown field 'nope.field'" } }) });
  renderWithQuery(<QueryEditor value="nope.field:1" onChange={() => {}} onRun={() => {}} delayMs={10} />);
  expect(await screen.findByRole("alert")).toHaveTextContent("unknown field 'nope.field'");
});

it("does not call the API for empty text and shows the syntax hint", () => {
  const m = mockFetch({});
  renderWithQuery(<QueryEditor value="  " onChange={() => {}} onRun={() => {}} delayMs={10} />);
  expect(screen.getByText(/field:value/)).toBeInTheDocument();
  expect(m.fn).not.toHaveBeenCalled();
});

it("Ctrl+Enter and Cmd+Enter run; plain Enter does not", async () => {
  mockFetch({});
  const onRun = vi.fn();
  renderWithQuery(<QueryEditor value="" onChange={() => {}} onRun={onRun} />);
  const ta = screen.getByLabelText("Hunt query");
  await userEvent.type(ta, "{Enter}");
  expect(onRun).not.toHaveBeenCalled();
  await userEvent.type(ta, "{Control>}{Enter}{/Control}");
  await userEvent.type(ta, "{Meta>}{Enter}{/Meta}");
  expect(onRun).toHaveBeenCalledTimes(2);
});

it("422 details are surfaced instead of the generic message", async () => {
  expect(errorMessage({ code: "validation_error", message: "Invalid request", details: [
    { loc: ["body", "query"], msg: "Value error, query text: unknown field 'x'", type: "value_error" }] }, 422)).toBe("query text: unknown field 'x'");
  expect(errorMessage({ code: "x", message: "plain" }, 400)).toBe("plain");
  expect(errorMessage(undefined, 500)).toBe("Request failed (500)");
  await waitFor(() => {});
});
