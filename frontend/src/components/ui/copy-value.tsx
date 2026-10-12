"use client";
import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";

/** An indicator (IP, hash, domain...) in monospace with a one-click copy. Long values truncate but the full value is in the title and the copy. */
export function CopyValue({ value, display, className = "", max = 48 }: { value: string; display?: string; className?: string; max?: number }) {
  const [done, setDone] = useState(false);
  const t = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(t.current), []);
  const shown = display ?? value;
  return (
    <span className={`group/cv inline-flex max-w-full items-center gap-1 ${className}`}>
      <span className="truncate font-mono text-[0.92em]" title={value}>{shown.length > max ? `${shown.slice(0, max - 1)}…` : shown}</span>
      <button type="button" aria-label={`Copy ${value.slice(0, 40)}`} title="Copy"
        onClick={() => { void navigator.clipboard?.writeText(value); setDone(true); window.clearTimeout(t.current); t.current = window.setTimeout(() => setDone(false), 1400); }}
        className="inline-grid h-5 w-5 shrink-0 place-items-center rounded text-muted opacity-0 transition duration-fast hover:bg-subtle hover:text-ink focus-visible:opacity-100 group-hover/cv:opacity-100">
        {done ? <Check aria-hidden className="h-3 w-3 text-sev-ok" /> : <Copy aria-hidden className="h-3 w-3" />}
      </button>
      <span role="status" className="sr-only">{done ? "Copied" : ""}</span>
    </span>
  );
}
