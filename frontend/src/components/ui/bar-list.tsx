import Link from "next/link";
import type { ReactNode } from "react";

export interface BarRow { key: string; label: ReactNode; value: number; href?: string; mono?: boolean; tone?: string }

/** Ranked list with proportional bars. Values are always printed, so the bar is a visual aid, not the only encoding. */
export function BarList({ rows, empty, color = "bg-accent-brand" }: { rows: BarRow[]; empty?: ReactNode; color?: string }) {
  if (!rows.length) return <p className="py-4 text-center text-sm text-muted">{empty ?? "No data."}</p>;
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <li key={r.key}>
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className={`min-w-0 truncate ${r.mono ? "font-mono text-[13px]" : ""}`}>{r.href ? <Link href={r.href} className="hover:text-accent hover:underline">{r.label}</Link> : r.label}</span>
            <span className="shrink-0 tabular-nums text-ink-2">{r.value.toLocaleString("en-US")}</span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line/70"><div className={`h-full rounded-full ${r.tone ?? color} animate-grow-x origin-left`} style={{ width: `${Math.max(2, (r.value / max) * 100)}%` }} /></div>
        </li>
      ))}
    </ul>
  );
}
