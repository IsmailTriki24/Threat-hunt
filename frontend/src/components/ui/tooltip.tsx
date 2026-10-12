"use client";
import { useId, type ReactNode } from "react";

/** CSS tooltip that appears on hover and keyboard focus and is announced via aria-describedby. */
export function Tooltip({ text, children, side = "bottom" }: { text: string; children: ReactNode; side?: "bottom" | "right" | "top" }) {
  const id = useId();
  const pos = side === "right" ? "left-full top-1/2 ml-2 -translate-y-1/2" : side === "top" ? "bottom-full left-1/2 mb-1.5 -translate-x-1/2" : "top-full left-1/2 mt-1.5 -translate-x-1/2";
  return (
    <span className="group/tt relative inline-flex" aria-describedby={id}>
      {children}
      <span id={id} role="tooltip" className={`pointer-events-none absolute z-50 whitespace-nowrap rounded bg-ink px-2 py-1 text-xs text-white opacity-0 shadow-pop transition-opacity duration-fast group-hover/tt:opacity-100 group-focus-within/tt:opacity-100 ${pos}`}>{text}</span>
    </span>
  );
}
