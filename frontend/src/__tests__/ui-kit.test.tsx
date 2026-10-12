import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { HealthBadge, LevelBadge, StatusBadge } from "@/components/badges";
import { useConfirm } from "@/components/ui/confirm";
import { BarList } from "@/components/ui/bar-list";
import { CopyValue } from "@/components/ui/copy-value";
import { EmptyState } from "@/components/ui/empty-state";
import { KpiCard } from "@/components/ui/kpi-card";
import { ActionMenu } from "@/components/ui/menu";
import { Drawer, Modal } from "@/components/ui/overlay";
import { SeverityBadge, toLevel } from "@/components/ui/severity";
import { Tabs } from "@/components/ui/tabs";
import { ToastProvider, useToast } from "@/components/ui/toast";

describe("severity vocabulary", () => {
  it("maps numbers and strings onto one scale", () => {
    expect([0, 19, 20, 40, 60, 80, 100].map(toLevel)).toEqual(["info", "info", "low", "medium", "high", "critical", "critical"]);
    expect(["CRITICAL", "High", "medium", "low", "ok", "degraded", "warning", "weird", null].map(toLevel)).toEqual(["critical", "high", "medium", "low", "ok", "medium", "medium", "info", "info"]);
  });

  it("never relies on colour alone: every level has a text label and its own icon shape", () => {
    const shapes = new Set<string>();
    for (const l of ["critical", "high", "medium", "low", "info", "ok"]) {
      const { container, unmount } = render(<SeverityBadge level={l} />);
      expect(container.textContent?.trim().length).toBeGreaterThan(1);
      const svg = container.querySelector("svg");
      expect(svg).toHaveAttribute("aria-hidden", "true");
      shapes.add(svg!.innerHTML);
      unmount();
    }
    expect(shapes.size).toBe(6); // six levels, six different glyphs
  });

  it("compact badges keep an accessible name", () => {
    render(<SeverityBadge level="high" compact />);
    expect(screen.getByText("High")).toHaveClass("sr-only");
  });

  it("case, status and health badges share it", () => {
    render(<><LevelBadge level="CRITICAL" /><StatusBadge status="FALSE_POSITIVE" /><HealthBadge status="down" /></>);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("FALSE POSITIVE")).toBeInTheDocument();
    expect(screen.getByText("down")).toBeInTheDocument();
  });
});

describe("Tabs", () => {
  function Harness() {
    const [v, setV] = useState<"a" | "b" | "c">("a");
    return <><Tabs label="Sections" value={v} onChange={setV} tabs={[{ key: "a", label: "Alpha", count: 3 }, { key: "b", label: "Beta" }, { key: "c", label: "Gamma", disabled: true }]} /><p data-testid="v">{v}</p></>;
  }
  it("exposes selection, counts and arrow-key navigation (skipping disabled tabs)", async () => {
    render(<Harness />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs[0]).toHaveAccessibleName("Alpha (3)");
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(tabs[0]).toHaveAttribute("tabindex", "0");
    expect(tabs[1]).toHaveAttribute("tabindex", "-1");
    tabs[0].focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(screen.getByTestId("v")).toHaveTextContent("b");
    await userEvent.keyboard("{ArrowRight}"); // Gamma is disabled: wraps back to Alpha
    expect(screen.getByTestId("v")).toHaveTextContent("a");
    await userEvent.keyboard("{ArrowLeft}");
    expect(screen.getByTestId("v")).toHaveTextContent("b");
    expect(screen.getByRole("tab", { name: "Gamma" })).toBeDisabled();
  });
});

describe("Modal / Drawer / confirmation", () => {
  it("modal: labelled dialog, focus moves in, Escape closes, focus returns to the opener, scroll is locked then restored", async () => {
    function Host() {
      const [open, setOpen] = useState(false);
      return <><button onClick={() => setOpen(true)}>Open</button>{open && <Modal title="Edit thing" onClose={() => setOpen(false)}><input aria-label="Field" /><button>Inner</button></Modal>}</>;
    }
    render(<Host />);
    const opener = screen.getByRole("button", { name: "Open" });
    await userEvent.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Edit thing" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.body.style.overflow).toBe("hidden");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(document.body.style.overflow).not.toBe("hidden");
  });

  it("modal traps Tab and Shift+Tab inside the dialog", async () => {
    render(<Modal title="Trap" onClose={() => undefined}><input aria-label="One" /><input aria-label="Two" /></Modal>);
    const dialog = screen.getByRole("dialog");
    const inside = () => dialog.contains(document.activeElement);
    for (let i = 0; i < 6; i++) { await userEvent.tab(); expect(inside()).toBe(true); }
    for (let i = 0; i < 6; i++) { await userEvent.tab({ shift: true }); expect(inside()).toBe(true); }
  });

  it("clicking the backdrop closes; clicking inside does not", async () => {
    const onClose = vi.fn();
    render(<Modal title="T" onClose={onClose}><p>body</p></Modal>);
    await userEvent.click(screen.getByText("body"));
    expect(onClose).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("presentation"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("drawer closes on Escape and names itself", async () => {
    const onClose = vi.fn();
    render(<Drawer title="Bulletin" subtitle="Threat" onClose={onClose}><p>x</p></Drawer>);
    expect(screen.getByRole("dialog", { name: "Bulletin" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });

  function Confirmer({ run }: { run: () => void }) {
    const { confirm, node } = useConfirm();
    return <><button onClick={() => confirm({ title: "Delete it?", message: "Gone for good.", confirmLabel: "Delete", run })}>Remove</button>{node}</>;
  }
  it("destructive actions run only after explicit confirmation, and Cancel/Escape run nothing", async () => {
    const run = vi.fn();
    render(<Confirmer run={run} />);
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    let dialog = screen.getByRole("dialog", { name: "Delete it?" });
    expect(dialog).toHaveTextContent("Gone for good.");
    expect(within(dialog).getByRole("button", { name: "Delete" })).toHaveFocus(); // the labelled action is focused, never an ambiguous "OK"
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(run).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    await userEvent.keyboard("{Escape}");
    expect(run).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    expect(run).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("ActionMenu", () => {
  it("opens on click, moves with arrow keys, skips disabled items, closes on Escape and restores focus", async () => {
    const a = vi.fn(), c = vi.fn();
    render(<ActionMenu label="More actions for X" items={[{ label: "First", onSelect: a }, { label: "Disabled", onSelect: vi.fn(), disabled: true }, { label: "Third", onSelect: c, danger: true }]} />);
    const trigger = screen.getByRole("button", { name: "More actions for X" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    const items = screen.getAllByRole("menuitem");
    expect(items[0]).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(items[2]).toHaveFocus(); // the disabled item is skipped
    await userEvent.keyboard("{ArrowUp}");
    expect(items[0]).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
    expect(trigger).toHaveFocus();
    await userEvent.click(trigger);
    await userEvent.click(screen.getByRole("menuitem", { name: "Third" }));
    expect(c).toHaveBeenCalledTimes(1); expect(a).not.toHaveBeenCalled();
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

describe("toasts", () => {
  function Fire() {
    const t = useToast();
    return <><button onClick={() => t.success("Saved", "details")}>ok</button><button onClick={() => t.error("Failed", "why")}>bad</button></>;
  }
  it("success is polite and auto-dismisses; errors are assertive and stay until dismissed", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<ToastProvider><Fire /></ToastProvider>);
      await userEvent.click(screen.getByRole("button", { name: "ok" }));
      expect(screen.getByRole("status")).toHaveTextContent("Saved");
      await userEvent.click(screen.getByRole("button", { name: "bad" }));
      expect(screen.getByRole("alert")).toHaveTextContent("Failed");
      act(() => { vi.advanceTimersByTime(6000); });
      expect(screen.queryByText("Saved")).toBeNull();
      expect(screen.getByRole("alert")).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
      expect(screen.queryByRole("alert")).toBeNull();
    } finally { vi.useRealTimers(); }
  });

  it("useToast is a harmless no-op outside a provider", async () => {
    render(<Fire />);
    await userEvent.click(screen.getByRole("button", { name: "ok" }));
    expect(screen.queryByRole("status")).toBeNull();
  });
});

describe("small components", () => {
  it("CopyValue copies the full value, truncates the display, and confirms", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const long = "a".repeat(80);
    render(<CopyValue value={long} max={20} />);
    expect(screen.getByTitle(long).textContent!.length).toBeLessThanOrEqual(20);
    await userEvent.click(screen.getByRole("button", { name: /^Copy a+/ }));
    expect(writeText).toHaveBeenCalledWith(long);
    expect(await screen.findByText("Copied")).toBeInTheDocument();
  });

  it("KpiCard distinguishes loading, unavailable and a real zero; links are plain links", () => {
    const { rerender } = render(<KpiCard label="Open alerts" value={0} loading />);
    expect(screen.getByRole("group", { name: "Open alerts" })).not.toHaveTextContent("0");
    rerender(<KpiCard label="Open alerts" value={0} unavailable />);
    expect(screen.getByRole("group", { name: "Open alerts" })).toHaveTextContent("—");
    rerender(<KpiCard label="Open alerts" value={0} />);
    expect(screen.getByRole("group", { name: "Open alerts" })).toHaveTextContent("0");
    rerender(<KpiCard label="Open alerts" value={4} href="/detections" hint="2 high" />);
    const link = screen.getByRole("link", { name: /Open alerts/ });
    expect(link).toHaveAttribute("href", "/detections");
    expect(link).toHaveTextContent("2 high");
  });

  it("EmptyState says what and why; BarList prints every value and scales bars", () => {
    const { rerender } = render(<EmptyState title="Nothing here" action={<button>Fix it</button>}>Because reasons.</EmptyState>);
    expect(screen.getByText("Nothing here")).toBeInTheDocument(); expect(screen.getByText("Because reasons.")).toBeInTheDocument(); expect(screen.getByRole("button", { name: "Fix it" })).toBeInTheDocument();
    rerender(<BarList rows={[{ key: "a", label: "A", value: 100, href: "/x" }, { key: "b", label: "B", value: 25 }]} />);
    expect(screen.getByText("100")).toBeInTheDocument(); expect(screen.getByText("25")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "A" })).toHaveAttribute("href", "/x");
    const widths = [...document.querySelectorAll<HTMLElement>("li .h-full")].map((e) => e.style.width);
    expect(widths).toEqual(["100%", "25%"]);
    rerender(<BarList rows={[]} empty="No hosts." />);
    expect(screen.getByText("No hosts.")).toBeInTheDocument();
  });
});
