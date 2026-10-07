import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FilterBuilder, FilterChips } from "@/components/filter-builder";
import type { FieldInfo } from "@/lib/api-types";

const fields: FieldInfo[] = [
  { name: "host.hostname", kind: "keyword", sortable: true, aggregatable: true },
  { name: "network.dst_port", kind: "integer", sortable: false, aggregatable: true },
];

it("offers operators by field kind and emits a typed filter", async () => {
  const onAdd = vi.fn();
  render(<FilterBuilder fields={fields} onAdd={onAdd} />);
  const user = userEvent.setup();
  expect(screen.getByRole("button", { name: "Add filter" })).toBeDisabled();
  await user.selectOptions(screen.getByLabelText("Field"), "network.dst_port");
  expect(screen.getByRole("option", { name: "≥" })).toBeInTheDocument();
  expect(screen.queryByRole("option", { name: "starts with" })).toBeNull();
  await user.selectOptions(screen.getByLabelText("Operator"), "gte");
  await user.type(screen.getByLabelText("Value"), "400");
  await user.click(screen.getByRole("button", { name: "Add filter" }));
  expect(onAdd).toHaveBeenCalledWith({ field: "network.dst_port", op: "gte", value: "400" });
});

it("supports negation and value-less operators", async () => {
  const onAdd = vi.fn();
  render(<FilterBuilder fields={fields} onAdd={onAdd} />);
  const user = userEvent.setup();
  await user.selectOptions(screen.getByLabelText("Field"), "host.hostname");
  await user.selectOptions(screen.getByLabelText("Operator"), "neq");
  await user.type(screen.getByLabelText("Value"), "ws-01");
  await user.click(screen.getByRole("button", { name: "Add filter" }));
  expect(onAdd).toHaveBeenLastCalledWith({ field: "host.hostname", op: "neq", value: "ws-01" });
  await user.selectOptions(screen.getByLabelText("Operator"), "exists");
  expect(screen.queryByLabelText("Value")).toBeNull();
  await user.click(screen.getByRole("button", { name: "Add filter" }));
  expect(onAdd).toHaveBeenLastCalledWith({ field: "host.hostname", op: "exists" });
});

it("renders values as text and removes chips", async () => {
  const onRemove = vi.fn();
  render(<FilterChips filters={[{ field: "user.name", op: "eq", value: "<img src=x onerror=alert(1)>" }]} onRemove={onRemove} />);
  expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(document.querySelector("img")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: /remove filter/i }));
  expect(onRemove).toHaveBeenCalledWith(0);
});
