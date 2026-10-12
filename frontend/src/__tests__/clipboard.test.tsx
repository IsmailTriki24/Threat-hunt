import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CopyButton } from "@/components/badges";
import { CopyValue } from "@/components/ui/copy-value";
import { copyText } from "@/lib/clipboard";

const setClipboard = (c: unknown) => Object.defineProperty(navigator, "clipboard", { value: c, configurable: true });
const setExec = (fn: unknown) => Object.defineProperty(document, "execCommand", { value: fn, configurable: true });

afterEach(() => { setClipboard(undefined); setExec(undefined); });

describe("copyText", () => {
  it("uses the async Clipboard API when it exists (HTTPS / localhost)", async () => {
    const writeText = vi.fn(async () => undefined);
    setClipboard({ writeText });
    expect(await copyText("1.2.3.4")).toBe(true);
    expect(writeText).toHaveBeenCalledWith("1.2.3.4");
  });

  it("falls back to execCommand over plain HTTP, where navigator.clipboard is undefined", async () => {
    setClipboard(undefined);
    let copied = "";
    setExec(vi.fn(() => { copied = (document.activeElement as HTMLTextAreaElement).value; return true; }));
    expect(await copyText("185.220.101.5")).toBe(true);
    expect(copied).toBe("185.220.101.5");
    expect(document.querySelector("textarea")).toBeNull(); // the helper element never lingers
  });

  it("falls back when the Clipboard API rejects (permission denied)", async () => {
    setClipboard({ writeText: vi.fn(async () => { throw new Error("denied"); }) });
    setExec(vi.fn(() => true));
    expect(await copyText("x")).toBe(true);
  });

  it("reports failure honestly when nothing works", async () => {
    setClipboard(undefined);
    setExec(vi.fn(() => false));
    expect(await copyText("x")).toBe(false);
    setExec(vi.fn(() => { throw new Error("blocked"); }));
    expect(await copyText("x")).toBe(false);
    expect(document.querySelector("textarea")).toBeNull();
  });

  it("restores focus to the button that triggered the copy", async () => {
    setClipboard(undefined); setExec(vi.fn(() => true));
    render(<button>Trigger</button>);
    const b = screen.getByRole("button", { name: "Trigger" });
    b.focus();
    await copyText("x");
    expect(b).toHaveFocus();
  });
});

describe("copy buttons", () => {
  it("CopyButton works over HTTP and only says Copied when it did", async () => {
    setClipboard(undefined);
    const exec = vi.fn(() => true);
    setExec(exec);
    render(<CopyButton text="10.0.0.1" label="Copy IOC" />);
    await userEvent.click(screen.getByRole("button", { name: /^Copy IOC/ }));
    expect(exec).toHaveBeenCalledWith("copy");
    expect(await screen.findByText("Copied")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Copied to clipboard"); // announced, since the button's own name does not change
  });

  it("CopyButton says so when the copy fails", async () => {
    setClipboard(undefined); setExec(vi.fn(() => false));
    render(<CopyButton text="10.0.0.1" />);
    await userEvent.click(screen.getByRole("button", { name: /^Copy/ }));
    expect(await screen.findByText("Copy failed")).toBeInTheDocument();
    expect(screen.queryByText("Copied")).toBeNull();
  });

  it("CopyValue copies the full value over HTTP and announces the result", async () => {
    setClipboard(undefined);
    let copied = "";
    setExec(vi.fn(() => { copied = (document.activeElement as HTMLTextAreaElement).value; return true; }));
    const long = "d".repeat(70);
    render(<CopyValue value={long} max={16} />);
    await userEvent.click(screen.getByRole("button", { name: /^Copy d+/ }));
    expect(copied).toBe(long);
    expect(await screen.findByText("Copied")).toBeInTheDocument();
  });

  it("CopyValue announces a failure", async () => {
    setClipboard(undefined); setExec(vi.fn(() => false));
    render(<CopyValue value="abc" />);
    await userEvent.click(screen.getByRole("button", { name: /^Copy abc/ }));
    expect(await screen.findByText("Copy failed")).toBeInTheDocument();
  });
});
