import type { ReactNode } from "react";

/** Every page starts with this: title, one line of purpose, and the page's primary actions on the right. */
export function PageHeader({ title, description, actions, meta, flush }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; meta?: ReactNode; /** No bottom margin: use inside a flex/grid parent that already provides the gap. */ flush?: boolean }) {
  return (
    <header className={`${flush ? "" : "mb-4"} flex flex-wrap items-start gap-x-4 gap-y-2`}>
      <div className="min-w-0 flex-1">
        <h1 className="flex flex-wrap items-center gap-2 text-2xl font-semibold tracking-tight text-ink">{title}{meta}</h1>
        {description && <p className="mt-0.5 max-w-3xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Section({ title, description, actions, children, className = "" }: { title?: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="flex items-center gap-2 border-b border-line px-4 py-2.5">
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-ink">{title}</h2>
            {description && <p className="text-xs text-muted">{description}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
