"use client";
import { CircleAlert, CircleCheck, Info, X } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

type Kind = "success" | "error" | "info";
interface Toast { id: number; kind: Kind; title: string; detail?: string }
interface Api { toast: (kind: Kind, title: string, detail?: string) => void; success: (t: string, d?: string) => void; error: (t: string, d?: string) => void }

const Ctx = createContext<Api | null>(null);
const STYLE: Record<Kind, { icon: typeof Info; cls: string }> = {
  success: { icon: CircleCheck, cls: "text-sev-ok" }, error: { icon: CircleAlert, cls: "text-sev-critical" }, info: { icon: Info, cls: "text-accent" },
};

/** Transient confirmations and errors. Announced politely (errors assertively) for screen readers; success auto-dismisses, errors stay until closed. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const next = useRef(1);
  const dismiss = useCallback((id: number) => setItems((l) => l.filter((t) => t.id !== id)), []);
  const toast = useCallback((kind: Kind, title: string, detail?: string) => {
    const id = next.current++;
    setItems((l) => [...l.slice(-3), { id, kind, title, detail }]);
    if (kind !== "error") window.setTimeout(() => dismiss(id), 4500);
  }, [dismiss]);
  const api = useMemo<Api>(() => ({ toast, success: (t, d) => toast("success", t, d), error: (t, d) => toast("error", t, d) }), [toast]);
  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2">
        {items.map((t) => {
          const { icon: Icon, cls } = STYLE[t.kind];
          return (
            <div key={t.id} role={t.kind === "error" ? "alert" : "status"} className="pointer-events-auto flex items-start gap-2 rounded-lg border border-line bg-panel p-3 shadow-pop animate-slide-in">
              <Icon aria-hidden className={`mt-0.5 h-4 w-4 shrink-0 ${cls}`} />
              <div className="min-w-0 flex-1"><p className="text-sm font-medium text-ink">{t.title}</p>{t.detail && <p className="mt-0.5 break-words text-xs text-muted">{t.detail}</p>}</div>
              <button type="button" aria-label="Dismiss notification" className="rounded p-0.5 text-muted hover:bg-subtle hover:text-ink" onClick={() => dismiss(t.id)}><X aria-hidden className="h-3.5 w-3.5" /></button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}

/** Safe outside a provider (unit tests of leaf components): becomes a no-op rather than throwing. */
export function useToast(): Api {
  return useContext(Ctx) ?? { toast: () => undefined, success: () => undefined, error: () => undefined };
}
