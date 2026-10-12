export const Skeleton = ({ className = "" }: { className?: string }) => <span aria-hidden className={`skeleton inline-block ${className}`} />;

export function SkeletonRows({ rows = 5, className = "" }: { rows?: number; className?: string }) {
  return (
    <div role="status" aria-label="Loading" className={`space-y-2 ${className}`}>
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className={`block h-5 ${i % 3 === 2 ? "w-2/3" : "w-full"}`} />)}
    </div>
  );
}

/** Standard loading placeholder: skeleton lines for sighted users, a polite "Loading…" for assistive tech. */
export function Loading({ rows = 4, className = "" }: { rows?: number; className?: string }) {
  return (
    <div role="status" className={`space-y-2 py-2 ${className}`}>
      {Array.from({ length: rows }, (_, i) => <Skeleton key={i} className={`block h-4 ${i % 3 === 2 ? "w-2/3" : "w-full"}`} />)}
      <span className="sr-only">Loading…</span>
    </div>
  );
}
