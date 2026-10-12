"use client";
import type { ReactNode } from "react";

export interface TabDef<T extends string> { key: T; label: ReactNode; count?: number | string | null; disabled?: boolean }

/** Accessible tab strip (roving arrow keys). The panel is rendered by the caller so each page keeps its own data flow. */
export function Tabs<T extends string>({ tabs, value, onChange, label, className = "" }: { tabs: Array<TabDef<T>>; value: T; onChange: (k: T) => void; label: string; className?: string }) {
  const move = (dir: 1 | -1) => {
    const enabled = tabs.filter((t) => !t.disabled);
    const i = enabled.findIndex((t) => t.key === value);
    onChange(enabled[(i + dir + enabled.length) % enabled.length].key);
  };
  return (
    <div role="tablist" aria-label={label} className={`flex flex-wrap gap-x-1 border-b border-line ${className}`}
      onKeyDown={(e) => { if (e.key === "ArrowRight") { e.preventDefault(); move(1); } if (e.key === "ArrowLeft") { e.preventDefault(); move(-1); } }}>
      {tabs.map((t) => (
        <button key={t.key} role="tab" type="button" aria-selected={t.key === value} tabIndex={t.key === value ? 0 : -1} disabled={t.disabled} className="tab disabled:opacity-40"
          onClick={() => onChange(t.key)}>
          {t.label}
          {t.count !== undefined && t.count !== null && <>{" "}<span className="font-normal text-muted tabular-nums">({t.count})</span></>}
        </button>
      ))}
    </div>
  );
}
