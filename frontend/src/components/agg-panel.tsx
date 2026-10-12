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
    <aside className="panel hidden w-64 shrink-0 divide-y divide-line self-start xl:block" aria-label="Aggregations">
      {PANELS.map((p) => {
        const buckets = aggs[p.agg]?.buckets ?? [];
        return (
          <section key={p.agg} className="px-3 py-2.5">
            <h2 className="eyebrow mb-1">{p.title}</h2>
            {buckets.length === 0 ? <p className="text-xs text-muted">No values</p> : (
              <ul className="-mx-1">
                {buckets.map((b) => (
                  <li key={String(b.key)}>
                    <button className="flex w-full items-center justify-between gap-2 rounded px-1 py-1 text-left hover:bg-accent-soft hover:text-accent"
                      title={`Filter ${p.field} = ${String(b.key)}`} onClick={() => onFilter({ field: p.field, op: "eq", value: String(b.key) })}>
                      <span className="truncate font-mono text-xs">{String(b.key)}</span>
                      <span className="text-xs tabular-nums text-muted">{b.count.toLocaleString("en-US")}</span>
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
