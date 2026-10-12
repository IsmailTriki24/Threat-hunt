import { Ban, CircleCheck, CircleDot, Lock, Minus, Search, ShieldHalf, type LucideIcon } from "lucide-react";
import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ApiError } from "@/lib/api";
import { SeverityBadge } from "./ui/severity";
export { Modal } from "./ui/overlay";

const STATUS: Record<string, { cls: string; icon: LucideIcon }> = {
  OPEN: { cls: "border-accent/40 bg-accent-soft text-accent", icon: CircleDot },
  INVESTIGATING: { cls: "border-sev-medium/30 bg-sev-medium-bg text-sev-medium", icon: Search },
  CONTAINED: { cls: "border-sev-high/30 bg-sev-high-bg text-sev-high", icon: ShieldHalf },
  RESOLVED: { cls: "border-sev-ok/30 bg-sev-ok-bg text-sev-ok", icon: CircleCheck },
  FALSE_POSITIVE: { cls: "border-line-strong bg-subtle text-muted", icon: Ban },
  CLOSED: { cls: "border-line-strong bg-subtle text-muted", icon: Lock },
};

/** Case/alert severity (CRITICAL..INFO). Icon + label + colour. */
export function LevelBadge({ level }: { level: string }) {
  return <SeverityBadge level={level} label={level} />;
}
export function StatusBadge({ status }: { status: string }) {
  const { cls, icon: Icon } = STATUS[status] ?? { cls: "border-line-strong bg-subtle text-muted", icon: Minus };
  return <span className={`badge ${cls}`}><Icon aria-hidden className="h-3 w-3" strokeWidth={2.4} />{status.replace("_", " ")}</span>;
}
export function HealthBadge({ status }: { status: string }) {
  const level = status === "ok" ? "ok" : status === "down" ? "critical" : status === "degraded" ? "medium" : "info";
  return <SeverityBadge level={level} label={status} />;
}

export const errText = (e: unknown, fallback: string): string => (e instanceof ApiError ? e.friendly : fallback);

export function ErrorLine({ error, fallback }: { error: unknown; fallback: string }) {
  if (!error) return null;
  return <p role="alert" className="text-xs text-sev-critical">{errText(error, fallback)}</p>;
}

/** Button that copies text. Shows a brief confirmation and announces it. Accessible name keeps the existing "<label> <text>" form. */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const t = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(t.current), []);
  return (
    <button className="btn btn-sm" aria-label={`${label} ${text.slice(0, 24)}`}
      onClick={() => { void navigator.clipboard?.writeText(text); setDone(true); window.clearTimeout(t.current); t.current = window.setTimeout(() => setDone(false), 1400); }}>
      {done ? <Check aria-hidden className="h-3 w-3 text-sev-ok" /> : <Copy aria-hidden className="h-3 w-3" />}{done ? "Copied" : label}
    </button>
  );
}
