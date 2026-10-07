import type { ReactNode } from "react";
import { ApiError } from "@/lib/api";

const SEV: Record<string, string> = {
  CRITICAL: "bg-red-900/70 text-red-200", HIGH: "bg-red-900/50 text-red-300", MEDIUM: "bg-orange-900/50 text-orange-300",
  LOW: "bg-yellow-900/40 text-yellow-300", INFO: "text-muted border border-line",
};
const STATUS: Record<string, string> = {
  OPEN: "text-accent border border-accent", INVESTIGATING: "text-yellow-300 border border-yellow-700",
  CONTAINED: "text-orange-300 border border-orange-700", RESOLVED: "text-green-400 border border-green-700",
  FALSE_POSITIVE: "text-muted border border-line", CLOSED: "text-muted border border-line",
};

export function LevelBadge({ level }: { level: string }) {
  return <span className={`px-1.5 rounded-sm text-xs ${SEV[level] ?? "text-muted"}`}>{level}</span>;
}
export function StatusBadge({ status }: { status: string }) {
  return <span className={`px-1.5 rounded-sm text-xs whitespace-nowrap ${STATUS[status] ?? "text-muted border border-line"}`}>{status.replace("_", " ")}</span>;
}
export function HealthBadge({ status }: { status: string }) {
  const cls = status === "ok" ? "text-green-400" : status === "down" ? "text-red-400" : status === "degraded" ? "text-yellow-400" : "text-muted";
  return <span className={cls}>● {status}</span>;
}

export const errText = (e: unknown, fallback: string): string => (e instanceof ApiError ? e.friendly : fallback);

export function ErrorLine({ error, fallback }: { error: unknown; fallback: string }) {
  if (!error) return null;
  return <p role="alert" className="text-red-400 text-xs">{errText(error, fallback)}</p>;
}

/** Minimal modal. Content is rendered by the caller; closing is the caller's state change. */
export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div className="fixed inset-0 z-20 bg-black/60 flex items-start justify-center pt-24" role="presentation">
      <div role="dialog" aria-modal="true" aria-label={title} className={`panel p-3 ${wide ? "w-[44rem]" : "w-[30rem]"} max-w-full space-y-2`}>
        <div className="flex items-center">
          <h2 className="font-semibold">{title}</h2>
          <button className="btn ml-auto py-0" onClick={onClose} aria-label="Close dialog">Close</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  return <button className="btn py-0 text-xs" onClick={() => void navigator.clipboard?.writeText(text)} aria-label={`${label} ${text.slice(0, 24)}`}>{label}</button>;
}
