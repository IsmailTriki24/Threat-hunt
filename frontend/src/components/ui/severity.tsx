import { CircleAlert, CircleCheck, CircleDot, Info, ShieldAlert, TriangleAlert, type LucideIcon } from "lucide-react";

/** One severity vocabulary for the whole product. Colour is never the only signal: every level also has its own icon shape and a text label. */
export type Level = "critical" | "high" | "medium" | "low" | "info" | "ok";

const LEVELS: Record<Level, { label: string; icon: LucideIcon; cls: string; dot: string }> = {
  critical: { label: "Critical", icon: ShieldAlert, cls: "bg-sev-critical-bg text-sev-critical border-sev-critical/30", dot: "bg-sev-critical" },
  high: { label: "High", icon: TriangleAlert, cls: "bg-sev-high-bg text-sev-high border-sev-high/30", dot: "bg-sev-high" },
  medium: { label: "Medium", icon: CircleAlert, cls: "bg-sev-medium-bg text-sev-medium border-sev-medium/30", dot: "bg-sev-medium" },
  low: { label: "Low", icon: CircleDot, cls: "bg-sev-low-bg text-sev-low border-sev-low/30", dot: "bg-sev-low" },
  info: { label: "Info", icon: Info, cls: "bg-sev-info-bg text-sev-info border-sev-info/25", dot: "bg-sev-info" },
  ok: { label: "OK", icon: CircleCheck, cls: "bg-sev-ok-bg text-sev-ok border-sev-ok/30", dot: "bg-sev-ok" },
};

export function toLevel(v: string | number | null | undefined): Level {
  if (typeof v === "number") return v >= 80 ? "critical" : v >= 60 ? "high" : v >= 40 ? "medium" : v >= 20 ? "low" : "info";
  const s = String(v ?? "").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "ok") return s;
  if (s === "warning" || s === "degraded") return "medium";
  return "info";
}

export const LEVEL_HEX: Record<Level, string> = { critical: "#B42318", high: "#B93808", medium: "#925404", low: "#175CD3", info: "#475467", ok: "#056E42" };

export function SeverityBadge({ level, label, compact }: { level: string | number; label?: string; compact?: boolean }) {
  const l = toLevel(level);
  const { icon: Icon, cls, label: text } = LEVELS[l];
  return (
    <span className={`badge ${cls}`} data-level={l}>
      <Icon aria-hidden className="h-3 w-3 shrink-0" strokeWidth={2.4} />
      {compact ? <span className="sr-only">{label ?? text}</span> : label ?? text}
    </span>
  );
}

export function SeverityDot({ level }: { level: string | number }) {
  const l = toLevel(level);
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${LEVELS[l].dot}`} role="img" aria-label={LEVELS[l].label} />;
}
