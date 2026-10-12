import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Shell } from "@/components/shell";
import { mockFetch, renderWithQuery } from "./helpers";

let path = "/cases";
let perms: string[] = [];
const push = vi.fn(), replace = vi.fn(), logout = vi.fn(async () => undefined), switchTenant = vi.fn(async () => undefined);
let tenants = [{ id: "t1", slug: "acme", name: "Acme Bank" }];
vi.mock("next/navigation", () => ({ usePathname: () => path, useRouter: () => ({ push, replace }) }));
vi.mock("next/link", () => ({ default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => <a href={href} {...rest}>{children}</a> }));
vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    status: "authed", logout, switchTenant, can: (p: string) => perms.includes(p),
    session: { user_id: "u1", email: "ana.lyst@acme.example", full_name: "Ana Lyst", role: "SOC_ANALYST", permissions: perms, tenant: tenants[0], available_tenants: tenants },
  }),
}));

beforeEach(() => {
  path = "/cases"; perms = ["detections:read", "intel:write"]; tenants = [{ id: "t1", slug: "acme", name: "Acme Bank" }];
  push.mockReset(); replace.mockReset(); logout.mockClear(); switchTenant.mockClear(); localStorage.clear();
  mockFetch({ "GET /api/v1/detections/overview": () => ({ rules_by_status: {}, open_alerts: 7, alerts_by_severity: {}, coverage: [] }) });
});

const nav = () => screen.getAllByRole("navigation", { name: "Primary" })[0];

it("groups navigation by task, marks the current page, and shows breadcrumbs", () => {
  renderWithQuery(<Shell><p>content</p></Shell>);
  const n = within(nav());
  expect(["Investigate", "Intelligence", "Detect & respond", "Manage"].every((g) => n.getByText(g))).toBe(true);
  expect(n.getByRole("link", { name: "Cases" })).toHaveAttribute("aria-current", "page");
  expect(n.getByRole("link", { name: "Events" })).not.toHaveAttribute("aria-current");
  const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
  expect(crumbs).toHaveTextContent("Investigate");
  expect(within(crumbs).getByText("Cases")).toHaveAttribute("aria-current", "page");
  expect(screen.getByText("content")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
});

it("a detail page keeps its parent highlighted and links back in the breadcrumb", () => {
  path = "/hunts/abc";
  renderWithQuery(<Shell><p>x</p></Shell>);
  expect(within(nav()).getByRole("link", { name: "Hunts" })).toHaveAttribute("aria-current", "page");
  const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
  expect(within(crumbs).getByRole("link", { name: "Hunts" })).toHaveAttribute("href", "/hunts");
});

it("collapses to icons with accessible names, and remembers the choice", async () => {
  const { unmount } = renderWithQuery(<Shell><p>x</p></Shell>);
  await userEvent.click(screen.getByRole("button", { name: "Collapse navigation" }));
  expect(screen.getByRole("button", { name: "Expand navigation" })).toHaveAttribute("aria-pressed", "true");
  expect(within(nav()).getByRole("link", { name: "Threat Map" })).toBeInTheDocument(); // sr-only label keeps the name when only the icon is visible
  expect(localStorage.getItem("thp.sidebar.collapsed")).toBe("1");
  unmount();
  renderWithQuery(<Shell><p>x</p></Shell>);
  expect(await screen.findByRole("button", { name: "Expand navigation" })).toBeInTheDocument();
});

it("the mobile menu opens as a labelled dialog and closes on Escape or after navigating", async () => {
  renderWithQuery(<Shell><p>x</p></Shell>);
  await userEvent.click(screen.getByRole("button", { name: "Open navigation" }));
  const dialog = screen.getByRole("dialog", { name: "Navigation" });
  expect(within(dialog).getByRole("link", { name: "Overview" })).toBeInTheDocument();
  await userEvent.keyboard("{Escape}");
  expect(screen.queryByRole("dialog", { name: "Navigation" })).toBeNull();
});

describe("global search", () => {
  const box = () => screen.getByRole("textbox", { name: "Search events and indicators" });

  it("an IP offers an events search and a threat-intel lookup; Enter runs the events search", async () => {
    renderWithQuery(<Shell><p>x</p></Shell>);
    await userEvent.type(box(), "185.220.101.5");
    const list = screen.getByRole("listbox", { name: "Search actions" });
    expect(within(list).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "Events where “185.220.101.5” is the destination", "Events where “185.220.101.5” is the source", "Events where “185.220.101.5” is the sign-in source",
      "Events where “185.220.101.5” is the host address", "Look up ip in threat intelligence",
    ]);
    await userEvent.keyboard("{Enter}");
    const href = push.mock.calls[0][0] as string;
    const u = new URL(href, "http://x");
    expect(u.pathname).toBe("/events");
    expect(u.searchParams.get("lang")).toBe("1");
    expect(u.searchParams.get("q")).toBe("network.dst_ip:185.220.101.5"); // Enter runs the primary role; the others are one click away
  });

  it("the intel lookup option goes to the lookup form, prefilled", async () => {
    renderWithQuery(<Shell><p>x</p></Shell>);
    await userEvent.type(box(), "evil.example");
    await userEvent.click(screen.getByRole("option", { name: /Look up domain/ }));
    expect(push).toHaveBeenCalledWith("/threat-intel?lookup=evil.example");
  });

  it("the intel lookup option is hidden without intel:write", async () => {
    perms = ["detections:read"];
    renderWithQuery(<Shell><p>x</p></Shell>);
    await userEvent.type(box(), "evil.example");
    expect(screen.getAllByRole("option")).toHaveLength(2); // connection destination + DNS query, no intel lookup
    expect(screen.queryByRole("option", { name: /Look up/ })).toBeNull();
  });

  it("hashes search the right field, free text becomes a plain query, and Ctrl+K focuses the box", async () => {
    renderWithQuery(<Shell><p>x</p></Shell>);
    await userEvent.type(box(), "a".repeat(64) + "{Enter}");
    expect(new URL(push.mock.calls[0][0] as string, "http://x").searchParams.get("q")).toBe(`process.hash.sha256:${"a".repeat(64)}`);
    await userEvent.clear(box());
    await userEvent.type(box(), "powershell -enc{Enter}");
    const u = new URL(push.mock.calls[1][0] as string, "http://x");
    expect(u.searchParams.get("q")).toBe("powershell -enc"); expect(u.searchParams.get("lang")).toBeNull();
    (document.activeElement as HTMLElement).blur();
    await userEvent.keyboard("{Control>}k{/Control}");
    expect(box()).toHaveFocus();
  });

  it("offers nothing for an empty box", async () => {
    renderWithQuery(<Shell><p>x</p></Shell>);
    await userEvent.click(box());
    expect(screen.queryByRole("listbox")).toBeNull();
  });
});

it("the alerts bell shows the real open-alert count and links to Detections; hidden without permission", async () => {
  renderWithQuery(<Shell><p>x</p></Shell>);
  const bell = await screen.findByRole("link", { name: "Alerts: 7 open" });
  expect(bell).toHaveAttribute("href", "/detections");
  expect(bell).toHaveTextContent("7");
});

it("the alerts bell degrades honestly when the count cannot be loaded", async () => {
  mockFetch({ "GET /api/v1/detections/overview": () => ({ __status: 500, body: { error: { code: "x", message: "boom" } } }) });
  renderWithQuery(<Shell><p>x</p></Shell>);
  expect(await screen.findByRole("link", { name: "Alerts (unavailable)" })).toBeInTheDocument();
});

it("the user menu shows identity, switches tenant when there are several, and signs out", async () => {
  tenants = [{ id: "t1", slug: "acme", name: "Acme Bank" }, { id: "t2", slug: "glx", name: "Globex Bank" }];
  renderWithQuery(<Shell><p>x</p></Shell>);
  await userEvent.click(screen.getByRole("button", { name: /ana\.lyst@acme\.example/ }));
  const menu = screen.getByRole("menu");
  expect(menu).toHaveTextContent("SOC_ANALYST");
  await userEvent.selectOptions(within(menu).getByLabelText("Tenant"), "t2");
  expect(switchTenant).toHaveBeenCalledWith("t2");
  await userEvent.click(screen.getByRole("button", { name: /ana\.lyst@acme\.example/ }));
  await userEvent.click(screen.getByRole("menuitem", { name: /Sign out/ }));
  await waitFor(() => expect(replace).toHaveBeenCalledWith("/login"));
  expect(logout).toHaveBeenCalled();
});
