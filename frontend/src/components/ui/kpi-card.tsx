import Link from "next/link";
import { ArrowUpRight, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Skeleton } from "./skeleton";

/** A single headline number with its context. `href` makes the whole card a drill-down; `loading`/`unavailable` are explicit states, never a silent 0. */
export function KpiCard({ label, value, hint, icon: Icon, tone, href, loading, unavailable, compact }: {
  label: string; value: ReactNode; hint?: ReactNode; icon?: LucideIcon; tone?: "critical" | "high" | "medium" | "ok" | "accent"; href?: string; loading?: boolean; unavailable?: boolean;
  /** Denser variant for pages where another element (a map, a table) must stay the focus. */
  compact?: boolean;
}) {
  const toneCls = { critical: "text-sev-critical", high: "text-sev-high", medium: "text-sev-medium", ok: "text-sev-ok", accent: "text-accent" }[tone ?? "accent"] ?? "";
  const body = (
    <>
      <div className="flex items-center gap-2">
        {Icon && <span className={`grid ${compact ? "h-6 w-6" : "h-7 w-7"} place-items-center rounded-md bg-accent-soft text-accent`}><Icon aria-hidden className="h-4 w-4" /></span>}
        <span className="text-xs font-medium text-muted">{label}</span>
        {href && <ArrowUpRight aria-hidden className="ml-auto h-3.5 w-3.5 text-muted opacity-0 transition-opacity duration-fast group-hover:opacity-100" />}
      </div>
      <div className={`${compact ? "mt-1 text-2xl" : "mt-2 text-2xl sm:text-3xl"} font-semibold tabular-nums tracking-tight ${tone && !loading && !unavailable ? toneCls : "text-ink"}`}>
        {loading ? <Skeleton className="h-8 w-20" /> : unavailable ? <span className="text-muted" title="Unavailable">—</span> : value}
      </div>
      {hint && <div className={`mt-0.5 text-xs text-muted ${compact ? "truncate" : ""}`} title={compact && typeof hint === "string" ? hint : undefined}>{hint}</div>}
    </>
  );
  const cls = `group panel block ${compact ? "px-3.5 py-3" : "p-3 sm:p-4"} text-left transition duration-base`;
  return href
    ? <Link href={href} className={`${cls} hover:border-accent/40 hover:shadow-card`}>{body}</Link>
    : <div role="group" aria-label={label} className={cls}>{body}</div>;
}
