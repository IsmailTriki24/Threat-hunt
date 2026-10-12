import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import type { ReactNode } from "react";

/** Say what is empty, why that might be, and the next step. */
export function EmptyState({ title, children, icon: Icon = Inbox, action, compact }: { title: ReactNode; children?: ReactNode; icon?: LucideIcon; action?: ReactNode; compact?: boolean }) {
  return (
    <div className={`flex flex-col items-center justify-center text-center ${compact ? "py-6" : "py-12"}`}>
      <span className="mb-3 grid h-10 w-10 place-items-center rounded-full bg-accent-soft text-accent"><Icon aria-hidden className="h-5 w-5" /></span>
      <p className="text-sm font-semibold text-ink">{title}</p>
      {children && <p className="mt-1 max-w-md text-sm text-muted">{children}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}
