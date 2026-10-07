import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DataSourcesView } from "@/components/data-sources-view";
import { mockFetch, renderWithQuery } from "./helpers";

let perms: string[] = [];
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => perms.includes(p) }) }));
beforeEach(() => { perms = ["datasources:read", "datasources:manage"]; });

const connectors = [
  { type: "sysmon", display_name: "Sysmon", supports_collect: false, config_schema: { properties: {}, type: "object" } },
  {
    type: "generic_rest", display_name: "Generic REST API", supports_collect: true,
    config_schema: { required: ["url"], properties: { url: { type: "string", format: "uri", title: "Url" }, timeout_s: { type: "number", default: 15, title: "Timeout S" },
      mapping: { $ref: "#/$defs/M", title: "Mapping" } } },
  },
];
const ds = (o: object = {}) => ({ id: "d1", name: "Sysmon push", connector_type: "sysmon", config: {}, has_secrets: false, secret_keys: [], enabled: true, supports_collect: false,
  health_status: "ok", health_detail: "fine", health_checked_at: null, last_ingest_at: "2026-03-01T10:00:00Z", events_total: 42, created_at: "2026-03-01T09:00:00Z", ingest_key: null, ...o });

it("lists sources with health, mode and counts; read-only roles cannot manage", async () => {
  perms = ["datasources:read"];
  mockFetch({ "GET /api/v1/data-sources": () => [ds({ has_secrets: true })], "GET /api/v1/data-sources/connectors": () => connectors });
  renderWithQuery(<DataSourcesView />);
  expect(await screen.findByText("Sysmon push")).toBeInTheDocument();
  expect(screen.getByText("42")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "New data source" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Test" })).toBeDisabled();
  expect(screen.getByLabelText("Enable Sysmon push")).toBeDisabled();
});

it("generates the config form from the connector JSON schema and validates it", async () => {
  const m = mockFetch({ "GET /api/v1/data-sources": () => [], "GET /api/v1/data-sources/connectors": () => connectors });
  renderWithQuery(<DataSourcesView />);
  await waitFor(() => expect(screen.getByRole("button", { name: "New data source" })).toBeEnabled());
  await userEvent.click(screen.getByRole("button", { name: "New data source" }));
  await userEvent.selectOptions(screen.getByLabelText("Connector"), "generic_rest");
  expect(screen.getByLabelText(/^Url/)).toBeInTheDocument();
  expect(screen.getByLabelText("Timeout S")).toHaveAttribute("placeholder", "15");
  expect(screen.getByLabelText("Mapping").tagName).toBe("TEXTAREA");
  await userEvent.click(screen.getByRole("button", { name: "Create data source" }));
  expect(screen.getByRole("alert")).toHaveTextContent("Name is required");
  expect(screen.getByRole("alert")).toHaveTextContent("Url is required");
  expect(m.calls.filter((c) => c.key.startsWith("POST"))).toHaveLength(0);
});

it("secrets are write-only password inputs sent with the create request", async () => {
  const m = mockFetch({
    "GET /api/v1/data-sources": () => [], "GET /api/v1/data-sources/connectors": () => connectors,
    "POST /api/v1/data-sources": () => ds({ id: "d9", name: "SIEM", connector_type: "generic_rest", ingest_key: "hk_secretvalue" }),
  });
  renderWithQuery(<DataSourcesView />);
  await waitFor(() => expect(screen.getByRole("button", { name: "New data source" })).toBeEnabled());
  await userEvent.click(screen.getByRole("button", { name: "New data source" }));
  await userEvent.selectOptions(screen.getByLabelText("Connector"), "generic_rest");
  await userEvent.type(screen.getByLabelText("Name"), "SIEM");
  await userEvent.type(screen.getByLabelText(/^Url/), "https://siem.example.com/api");
  await userEvent.click(screen.getByRole("button", { name: "Add secret" }));
  expect(screen.getByLabelText("Secret value 1")).toHaveAttribute("type", "password");
  await userEvent.type(screen.getByLabelText("Secret value 1"), "Bearer tok");
  await userEvent.click(screen.getByRole("button", { name: "Create data source" }));
  await waitFor(() => expect(m.bodiesFor("POST /api/v1/data-sources")).toHaveLength(1));
  expect(m.bodiesFor("POST /api/v1/data-sources")[0]).toEqual({
    name: "SIEM", connector_type: "generic_rest", config: { url: "https://siem.example.com/api" }, secrets: { authorization: "Bearer tok" }, enabled: true,
  });
});

it("shows the ingest key exactly once and never again after the dialog is closed", async () => {
  mockFetch({
    "GET /api/v1/data-sources": () => [ds({ id: "d9", name: "SIEM" })], "GET /api/v1/data-sources/connectors": () => connectors,
    "POST /api/v1/data-sources": () => ds({ id: "d9", name: "SIEM", ingest_key: "hk_secretvalue" }),
  });
  renderWithQuery(<DataSourcesView />);
  await waitFor(() => expect(screen.getByRole("button", { name: "New data source" })).toBeEnabled());
  await userEvent.click(screen.getByRole("button", { name: "New data source" }));
  await userEvent.type(screen.getByLabelText("Name"), "SIEM");
  await userEvent.click(screen.getByRole("button", { name: "Create data source" }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByTestId("ingest-key")).toHaveTextContent("hk_secretvalue");
  expect(dialog).toHaveTextContent("/api/v1/ingest/d9");
  await userEvent.click(within(dialog).getByRole("button", { name: "Close dialog" }));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(document.body.textContent).not.toContain("hk_secretvalue");
  // the refreshed list (key is null server-side) does not resurrect it either
  expect(await screen.findByText("SIEM")).toBeInTheDocument();
  expect(document.body.textContent).not.toContain("hk_secretvalue");
});

it("rotating a key requires confirmation and reveals the new key once", async () => {
  vi.stubGlobal("confirm", vi.fn(() => true));
  mockFetch({
    "GET /api/v1/data-sources": () => [ds()], "GET /api/v1/data-sources/connectors": () => connectors,
    "POST /api/v1/data-sources/d1/rotate-key": () => ds({ ingest_key: "hk_rotated" }),
  });
  renderWithQuery(<DataSourcesView />);
  await userEvent.click(await screen.findByRole("button", { name: "Rotate key" }));
  expect(await screen.findByTestId("ingest-key")).toHaveTextContent("hk_rotated");
  await userEvent.click(screen.getByRole("button", { name: "Close dialog" }));
  expect(document.body.textContent).not.toContain("hk_rotated");
});

it("collect-now only exists for pull-capable sources", async () => {
  mockFetch({ "GET /api/v1/data-sources": () => [ds(), ds({ id: "d2", name: "REST", connector_type: "generic_rest", supports_collect: true })], "GET /api/v1/data-sources/connectors": () => connectors });
  renderWithQuery(<DataSourcesView />);
  await screen.findByText("REST");
  expect(screen.getAllByRole("button", { name: "Collect now" })).toHaveLength(1);
});
