"use client";
import { MoreHorizontal } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

export interface MenuItem { label: ReactNode; onSelect: () => void; danger?: boolean; disabled?: boolean; title?: string }

/** Overflow ("kebab") menu for secondary row actions. Arrow keys move, Escape closes and returns focus, outside click closes. */
export function ActionMenu({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    // position:fixed so the popover is never clipped by a scrolling table container
    const r = trigger.current?.getBoundingClientRect();
    if (r) setPos({ top: r.bottom + 4, right: Math.max(8, window.innerWidth - r.right) });
    const close = () => setOpen(false);
    window.addEventListener("scroll", close, true); window.addEventListener("resize", close);
    box.current?.querySelector<HTMLElement>('[role="menuitem"]:not([disabled])')?.focus();
    const click = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", click);
    return () => { document.removeEventListener("mousedown", click); window.removeEventListener("scroll", close, true); window.removeEventListener("resize", close); };
  }, [open]);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") { setOpen(false); trigger.current?.focus(); return; }
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const els = [...(box.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? [])];
    const i = els.indexOf(document.activeElement as HTMLElement);
    els[(i + (e.key === "ArrowDown" ? 1 : -1) + els.length) % els.length]?.focus();
  };
  return (
    <div ref={box} className="relative inline-block" onKeyDown={onKey}>
      <button ref={trigger} type="button" className="btn btn-ghost px-1.5" aria-haspopup="menu" aria-expanded={open} aria-label={label} onClick={() => setOpen((o) => !o)}>
        <MoreHorizontal aria-hidden className="h-4 w-4" />
      </button>
      {open && (
        <div role="menu" aria-label={label} style={pos ? { top: pos.top, right: pos.right } : { visibility: "hidden" }} className="fixed z-50 min-w-[11rem] overflow-hidden rounded-lg border border-line bg-panel py-1 shadow-pop animate-pop-in">
          {items.map((it, i) => (
            <button key={i} role="menuitem" type="button" disabled={it.disabled} title={it.title}
              className={`block w-full px-3 py-1.5 text-left text-sm transition-colors duration-fast hover:bg-subtle focus-visible:bg-subtle focus-visible:outline-none disabled:opacity-50 ${it.danger ? "text-sev-critical" : "text-ink"}`}
              onClick={() => { setOpen(false); trigger.current?.focus(); it.onSelect(); }}>{it.label}</button>
          ))}
        </div>
      )}
    </div>
  );
}
