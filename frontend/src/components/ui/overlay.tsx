"use client";
import { X } from "lucide-react";
import { useEffect, useId, useRef, type ReactNode } from "react";

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/** Shared behaviour for modal-like surfaces: Escape closes, focus moves in and is trapped, scroll is locked, focus returns to the opener. */
function useOverlay(onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    const first = el?.querySelector<HTMLElement>("[data-autofocus]") ?? el?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? el)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.stopPropagation(); close.current(); return; }
      if (e.key !== "Tab" || !el) return;
      const f = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((n) => n.offsetParent !== null || n === document.activeElement);
      if (!f.length) { e.preventDefault(); return; }
      const a = document.activeElement;
      if (e.shiftKey && (a === f[0] || a === el)) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && a === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    };
    document.addEventListener("keydown", onKey, true);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.removeEventListener("keydown", onKey, true); document.body.style.overflow = overflow; prev?.focus?.(); };
  }, []);
  return ref;
}

export function Modal({ title, description, onClose, children, wide, footer }: { title: string; description?: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean; footer?: ReactNode }) {
  const ref = useOverlay(onClose);
  const id = useId();
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-ink/40 p-4 pt-[10vh] animate-fade-in" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={id} className={`w-full ${wide ? "max-w-3xl" : "max-w-lg"} rounded-xl border border-line bg-panel shadow-pop animate-pop-in focus:outline-none`}>
        <div className="flex items-start gap-3 border-b border-line px-5 py-3">
          <div className="min-w-0 flex-1"><h2 id={id} className="text-base font-semibold text-ink">{title}</h2>{description && <p className="mt-0.5 text-sm text-muted">{description}</p>}</div>
          <button type="button" className="btn btn-ghost -mr-2 px-1.5" onClick={onClose} aria-label="Close dialog"><X aria-hidden className="h-4 w-4" /></button>
        </div>
        <div className="space-y-3 px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line bg-subtle/60 px-5 py-3 rounded-b-xl">{footer}</div>}
      </div>
    </div>
  );
}

/** Right-hand detail drawer. Keeps the page behind it visible and in context. */
export function Drawer({ title, subtitle, onClose, children, width = "max-w-xl" }: { title: ReactNode; subtitle?: ReactNode; onClose: () => void; children: ReactNode; width?: string }) {
  const ref = useOverlay(onClose);
  const id = useId();
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-ink/30 animate-fade-in" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={id} className={`flex h-full w-full ${width} flex-col border-l border-line bg-panel shadow-drawer animate-slide-in focus:outline-none`}>
        <div className="flex items-start gap-3 border-b border-line px-5 py-3">
          <div className="min-w-0 flex-1"><h2 id={id} className="truncate text-base font-semibold text-ink">{title}</h2>{subtitle && <div className="text-xs text-muted">{subtitle}</div>}</div>
          <button type="button" className="btn btn-ghost -mr-2 px-1.5" onClick={onClose} aria-label="Close panel"><X aria-hidden className="h-4 w-4" /></button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

/** Confirmation for anything destructive or hard to undo. The primary button names the action; the dialog never closes on a failed request. */
export function ConfirmDialog({ title, message, confirmLabel, danger, busy, error, onConfirm, onClose }: {
  title: string; message: ReactNode; confirmLabel: string; danger?: boolean; busy?: boolean; error?: ReactNode; onConfirm: () => void; onClose: () => void;
}) {
  return (
    <Modal title={title} onClose={onClose}
      footer={<><button type="button" className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button type="button" data-autofocus className={`btn ${danger ? "btn-danger" : "btn-primary"}`} disabled={busy} onClick={onConfirm}>{busy ? "Working…" : confirmLabel}</button></>}>
      <div className="text-sm text-ink-2">{message}</div>
      {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
    </Modal>
  );
}
