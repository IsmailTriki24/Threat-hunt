import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DataSourcesView, SecretDialog, defaultSecretName } from "@/components/data-sources-view";
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
  mockFetch({
    "GET /api/v1/data-sources": () => [ds()], "GET /api/v1/data-sources/connectors": () => connectors,
    "POST /api/v1/data-sources/d1/rotate-key": () => ds({ ingest_key: "hk_rotated" }),
  });
  renderWithQuery(<DataSourcesView />);
  await userEvent.click(await screen.findByRole("button", { name: /More actions for Sysmon push/ }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Rotate ingest key" }));
  const confirmDialog = await screen.findByRole("dialog", { name: /Rotate the ingest key/ });
  expect(confirmDialog).toHaveTextContent(/old key stops working immediately/);
  await userEvent.click(within(confirmDialog).getByRole("button", { name: "Rotate key" }));
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

it("shows the indicator sweep status of SIEM sources, and a dash for sources that are not swept", async () => {
  const cursor = new Date(Date.now() - 9 * 60000).toISOString();
  mockFetch({
    "GET /api/v1/data-sources": () => [
      ds({ id: "l1", name: "LR DC", connector_type: "logrhythm", supports_collect: true, sweep: { status: "partial", detail: "40 indicator(s) of the current window still to search", cursor, last_run_at: cursor, last_ok_at: cursor, iocs_total: 1200, ioas_total: 30, pending: 40, hits_total: 3, windows_done: 5, fast: { status: "ok", detail: "", cursor: new Date(Date.now() - 2 * 60000).toISOString(), last_run_at: cursor, iocs_total: 150, ioas_total: 5, pending: 0, hits_total: 1 } } }),
      ds({ id: "t1", name: "TM EP", connector_type: "trend_vision_one", supports_collect: true, sweep: { status: "error", detail: "Trend returned 500", cursor, last_run_at: cursor, last_ok_at: null, iocs_total: 10, pending: 10, hits_total: 0, windows_done: 0 } }),
      ds({ id: "n1", name: "TM new", connector_type: "trend_vision_one", supports_collect: true, sweep: { status: "pending", detail: "", cursor: null, last_run_at: null, last_ok_at: null, iocs_total: 0, pending: 0, hits_total: 0, windows_done: 0 } }),
      ds({ id: "p1", name: "Push", sweep: null }),
    ],
    "GET /api/v1/data-sources/connectors": () => connectors,
  });
  renderWithQuery(<DataSourcesView />);
  const lr = (await screen.findByText("LR DC")).closest("tr") as HTMLElement;
  expect(within(lr).getByText("partial")).toBeInTheDocument();
  expect(within(lr).getByText(/9 min behind · 1,200 IOCs · 30 behaviours · 40 left · 3 hits/)).toBeInTheDocument();
  expect(within(lr).getByText(/fast lane: 150 hot \+ 5 behaviours · 2 min behind/)).toBeInTheDocument();
  const tm = screen.getByText("TM EP").closest("tr") as HTMLElement;
  expect(within(tm).getByText("error")).toBeInTheDocument();
  expect(within(tm).getByText("Trend returned 500")).toBeInTheDocument();
  expect(within(screen.getByText("TM new").closest("tr") as HTMLElement).getByText("starting")).toBeInTheDocument();
  expect(within(screen.getByText("Push").closest("tr") as HTMLElement).getByText("—")).toBeInTheDocument();
});

it("a LogRhythm source is given its console account as username, then password, never the old API token", async () => {
  const lr = (keys: string[]) => ds({ id: "lr1", name: "LogRhythm SIEM", connector_type: "logrhythm", secret_keys: keys, has_secrets: keys.length > 0, supports_collect: true });
  expect(defaultSecretName(lr([]))).toBe("username");
  expect(defaultSecretName(lr(["username"]))).toBe("password");
  expect(defaultSecretName(lr(["username", "password"]))).toBe("password");
  expect(defaultSecretName(lr(["token"]))).toBe("username");
  const m = mockFetch({ "PUT /api/v1/data-sources/lr1/secrets/username": () => ({}) });
  renderWithQuery(<SecretDialog source={lr([])} onClose={() => {}} onSaved={() => {}} />);
  expect(screen.getByLabelText("Credential name")).toHaveValue("username");
  expect(screen.getByText(/dedicated read-only account/)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Credential value"), "svc-account");
  await userEvent.click(screen.getByRole("button", { name: "Save credential" }));
  await waitFor(() => expect(m.calls.filter((c) => c.key.startsWith("PUT"))).toHaveLength(1));
});
