import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TenantsView, slugify } from "@/components/tenants-view";
import { ToastProvider } from "@/components/ui/toast";
import { mockFetch, renderWithQuery, status } from "./helpers";

let perms: string[] = [];
const switchTenant = vi.fn(async () => {});
const push = vi.fn();
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ can: (p: string) => perms.includes(p), session: { tenant: null }, switchTenant }) }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push, replace: vi.fn() }), usePathname: () => "/tenants" }));
beforeEach(() => { perms = ["tenants:manage", "audit:platform"]; switchTenant.mockClear(); push.mockClear(); });

const tenant = (o: object = {}) => ({ id: "t1", slug: "wifak-bank", name: "Wifak Bank", is_active: true, retention_days: 90, created_at: "2026-10-01T00:00:00Z",
  member_count: 3, admin_count: 1, data_source_count: 2, data_sources_down: 0, ...o });
const member = (o: object = {}) => ({ user_id: "u1", email: "admin@wifak.example", full_name: "Wifak Admin", role: "TENANT_ADMIN", is_active: true, last_login_at: null, ...o });

it("is closed to anyone who is not the platform administrator and asks the server for nothing", () => {
  perms = ["users:manage", "datasources:read"];
  const m = mockFetch({});
  renderWithQuery(<TenantsView />);
  expect(screen.getByText("Platform administrators only")).toBeInTheDocument();
  expect(m.fn).not.toHaveBeenCalled();
});

it("lists every tenant with its members and assigned log sources, and flags a tenant with no admin or a source that is down", async () => {
  mockFetch({ "GET /api/v1/tenants": () => [tenant(), tenant({ id: "t2", slug: "other", name: "Other Bank", admin_count: 0, data_source_count: 1, data_sources_down: 1, is_active: false })] });
  renderWithQuery(<TenantsView />);
  expect(await screen.findByText("Wifak Bank")).toBeInTheDocument();
  const other = screen.getByText("Other Bank").closest("tr")!;
  expect(within(other).getByText("No admin")).toBeInTheDocument();
  expect(within(other).getByText("1 down")).toBeInTheDocument();
  expect(within(other).getByText("Disabled")).toBeInTheDocument();
  expect(within(other).getByRole("button", { name: "Open" })).toBeDisabled(); // cannot act inside a disabled tenant
});

it("opens a tenant by switching into it, then goes to its data sources", async () => {
  mockFetch({ "GET /api/v1/tenants": () => [tenant()] });
  renderWithQuery(<TenantsView />);
  await userEvent.click(await screen.findByRole("button", { name: "Open" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith("/data-sources"));
  expect(switchTenant).toHaveBeenCalledWith("t1");
});

it("derives the slug from the name until it is edited, and creates the tenant with its first admin", async () => {
  expect(slugify("  Wifak Bank (Tunisia)! ")).toBe("wifak-bank-tunisia");
  const m = mockFetch({ "GET /api/v1/tenants": () => [], "POST /api/v1/tenants": () => ({ ...tenant(), id: "new" }) });
  renderWithQuery(<TenantsView />);
  await userEvent.click(await screen.findByRole("button", { name: "New tenant" }));
  await userEvent.type(screen.getByLabelText("Name"), "Atlas Bank");
  expect(screen.getByLabelText(/^Slug/)).toHaveValue("atlas-bank");
  await userEvent.type(screen.getByLabelText(/^Administrator email/), "root@atlas.example");
  await userEvent.type(screen.getByLabelText(/^Administrator password/), "A-long-enough-pass1");
  await userEvent.click(screen.getByRole("button", { name: "Create tenant" }));
  await waitFor(() => expect(m.bodiesFor("POST /api/v1/tenants")).toEqual([{ name: "Atlas Bank", slug: "atlas-bank", retention_days: 90, admin_email: "root@atlas.example", admin_password: "A-long-enough-pass1" }]));
});

it("shows the server's reason when a tenant cannot be created", async () => {
  mockFetch({ "GET /api/v1/tenants": () => [], "POST /api/v1/tenants": () => status(409, { error: { code: "conflict", message: "Tenant slug already exists" } }) });
  renderWithQuery(<TenantsView />);
  await userEvent.click(await screen.findByRole("button", { name: "New tenant" }));
  await userEvent.type(screen.getByLabelText("Name"), "Dup Bank");
  await userEvent.type(screen.getByLabelText(/^Administrator email/), "a@dup.example");
  await userEvent.type(screen.getByLabelText(/^Administrator password/), "A-long-enough-pass1");
  await userEvent.click(screen.getByRole("button", { name: "Create tenant" }));
  expect(await screen.findByRole("alert")).toBeInTheDocument();
});

it("manages members: change a role, deactivate, add one (password optional) and reset a password", async () => {
  const m = mockFetch({
    "GET /api/v1/tenants": () => [tenant()],
    "GET /api/v1/tenants/t1/members": () => [member(), member({ user_id: "u2", email: "hunter@wifak.example", role: "THREAT_HUNTER" })],
    "PATCH /api/v1/tenants/t1/members/u2": () => member({ user_id: "u2" }),
    "POST /api/v1/tenants/t1/members": () => member({ user_id: "u3" }),
  });
  renderWithQuery(<TenantsView />);
  await userEvent.click(await screen.findByRole("button", { name: /Members/ }));
  await userEvent.selectOptions(await screen.findByLabelText("Role for hunter@wifak.example"), "VIEWER");
  await waitFor(() => expect(m.bodiesFor("PATCH /api/v1/tenants/t1/members/u2")).toContainEqual({ role: "VIEWER" }));
  const row = screen.getByText("hunter@wifak.example").closest("tr")!;
  await userEvent.click(within(row).getByRole("button", { name: "Deactivate" }));
  await waitFor(() => expect(m.bodiesFor("PATCH /api/v1/tenants/t1/members/u2")).toContainEqual({ is_active: false }));

  const form = screen.getByRole("form", { name: "Add member" });
  await userEvent.type(within(form).getByLabelText("Email"), "shared@bank.example");
  await userEvent.click(within(form).getByRole("button", { name: "Add member" }));
  await waitFor(() => expect(m.bodiesFor("POST /api/v1/tenants/t1/members")).toEqual([{ email: "shared@bank.example", full_name: "", role: "SOC_ANALYST" }])); // no password key: attach an existing account

  await userEvent.click(within(row).getByRole("button", { name: /Reset password/ }));
  const dialog = await screen.findByRole("dialog", { name: "Reset password" });
  const save = within(dialog).getByRole("button", { name: "Reset password" });
  expect(save).toBeDisabled(); // 12 characters minimum
  await userEvent.type(within(dialog).getByLabelText(/^New password/), "Rotated-Passw0rd-1");
  await userEvent.click(save);
  await waitFor(() => expect(m.bodiesFor("PATCH /api/v1/tenants/t1/members/u2")).toContainEqual({ new_password: "Rotated-Passw0rd-1" }));
});

it("explains why a change was refused instead of silently reverting (last admin)", async () => {
  mockFetch({
    "GET /api/v1/tenants": () => [tenant()],
    "GET /api/v1/tenants/t1/members": () => [member()],
    "PATCH /api/v1/tenants/t1/members/u1": () => status(409, { error: { code: "conflict", message: "A tenant must keep at least one active tenant admin" } }),
  });
  renderWithQuery(<ToastProvider><TenantsView /></ToastProvider>);
  await userEvent.click(await screen.findByRole("button", { name: /Members/ }));
  await userEvent.click(await screen.findByRole("button", { name: "Deactivate" }));
  await waitFor(() => expect(screen.getByText("Change not applied")).toBeInTheDocument());
});

it("confirms before disabling a tenant", async () => {
  const m = mockFetch({ "GET /api/v1/tenants": () => [tenant()], "PATCH /api/v1/tenants/t1": () => tenant({ is_active: false }) });
  renderWithQuery(<TenantsView />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable" }));
  expect(m.bodiesFor("PATCH /api/v1/tenants/t1")).toEqual([]); // nothing sent until confirmed
  await userEvent.click(screen.getByRole("button", { name: "Disable tenant" }));
  await waitFor(() => expect(m.bodiesFor("PATCH /api/v1/tenants/t1")).toEqual([{ is_active: false }]));
});
