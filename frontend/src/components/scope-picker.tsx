"use client";
import { useMemo, useState } from "react";

export interface ScopeOption { id: number; name: string; sources?: number }

/** A compact multi-select with a type-to-narrow box, for the LogRhythm entities and log source types a browse can be narrowed to. */
export function ScopePicker({ label, options, selected, onChange }: {
  label: string; options: ScopeOption[]; selected: number[]; onChange: (ids: number[]) => void;
}) {
  const [needle, setNeedle] = useState("");
  const shown = useMemo(() => {
    const n = needle.trim().toLowerCase();
    return n ? options.filter((o) => o.name.toLowerCase().includes(n)) : options;
  }, [options, needle]);
  const toggle = (id: number) => onChange(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);
  return (
    <details className="relative text-sm">
      <summary className="btn btn-sm cursor-pointer select-none">
        {label}{selected.length ? ` · ${selected.length} selected` : " · all"}
      </summary>
      <div className="panel absolute z-20 mt-1 w-80 max-w-[90vw] space-y-2 p-2 shadow-lg">
        <input className="input w-full" value={needle} onChange={(e) => setNeedle(e.target.value)} placeholder={`Find ${label.toLowerCase()}…`} aria-label={`Find ${label}`} maxLength={64} />
        <ul className="max-h-64 space-y-0.5 overflow-auto" aria-label={label}>
          {shown.map((o) => (
            <li key={o.id}>
              <label className="flex items-center gap-1.5 text-ink-2">
                <input type="checkbox" checked={selected.includes(o.id)} onChange={() => toggle(o.id)} />
                <span className="truncate">{o.name}</span>
                {o.sources !== undefined && <span className="ml-auto text-xs text-muted tabular-nums">{o.sources}</span>}
              </label>
            </li>
          ))}
          {shown.length === 0 && <li className="text-xs text-muted">Nothing matches.</li>}
        </ul>
        {selected.length > 0 && <button type="button" className="btn btn-sm" onClick={() => onChange([])}>Clear</button>}
      </div>
    </details>
  );
}
