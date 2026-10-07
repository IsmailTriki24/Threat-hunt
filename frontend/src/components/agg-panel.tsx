"use client";
import type { Bucket, Filter } from "@/lib/api-types";

const PANELS: Array<{ agg: string; title: string; field: string }> = [
  { agg: "by_host", title: "Hosts", field: "host.hostname" },
  { agg: "by_user", title: "Users", field: "user.name" },
  { agg: "by_process", title: "Processes", field: "process.name" },
  { agg: "by_type", title: "Event types", field: "event_type" },
  { agg: "by_dst_ip", title: "Destination IPs", field: "network.dst_ip" },
];

export function AggPanel({ aggs, onFilter }: {
  aggs: Record<string, { buckets: Bucket[] }>; onFilter: (f: Filter) => void;
}) {
  return (
    <aside className="space-y-3 w-56 shrink-0" aria-label="Aggregations">
      {PANELS.map((p) => {
        const buckets = aggs[p.agg]?.buckets ?? [];
        return (
          <section key={p.agg}>
            <h3 className="text-xs text-muted uppercase mb-0.5">{p.title}</h3>
            {buckets.length === 0 ? <p className="text-xs text-muted">—</p> : (
              <ul>
                {buckets.map((b) => (
                  <li key={String(b.key)}>
                    <button className="w-full flex justify-between gap-2 hover:text-accent text-left"
                      title={`Filter ${p.field} = ${String(b.key)}`} onClick={() => onFilter({ field: p.field, op: "eq", value: String(b.key) })}>
                      <span className="truncate font-mono text-xs">{String(b.key)}</span>
                      <span className="text-muted tabular-nums">{b.count}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        );
      })}
    </aside>
  );
}
