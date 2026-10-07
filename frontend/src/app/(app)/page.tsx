"use client";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { CASE_STATUSES } from "@/lib/api-types";
import { StatusBadge } from "@/components/badges";
import { OVERVIEW_AGGS, defaultState, toRequestBody } from "@/lib/query";

function Status({ s }: { s: string }) {
  const cls = s === "ok" ? "text-green-400" : s === "degraded" ? "text-yellow-400" : "text-red-400";
  return <span className={cls}>{s}</span>;
}

export default function Overview() {
  const { can, session } = useAuth();
  const cases = useQuery({ queryKey: ["cases", "overview"], queryFn: () => api.listCases("?limit=200"), enabled: can("cases:read") });
  const byStatus = (s: string) => (cases.data ?? []).filter((c) => c.status === s).length;
  const mine = (cases.data ?? []).filter((c) => c.assignee?.id === session?.user_id && c.status !== "CLOSED");
  const ready = useQuery({ queryKey: ["ready"], queryFn: api.ready, refetchInterval: 30_000 });
  const stats = useQuery({ queryKey: ["overview"], queryFn: () => api.search({ ...toRequestBody(defaultState(), OVERVIEW_AGGS), limit: 1 }) });
  const link = (field: string, value: string) => `/events?f=${encodeURIComponent(`${field}|eq|${value}`)}`;

  return (
    <section className="space-y-3 max-w-4xl">
      <h1 className="text-base font-semibold">Overview</h1>
      <div className="grid md:grid-cols-3 gap-3">
        <div className="panel p-3">
          <h2 className="text-xs text-muted uppercase mb-1">Platform health</h2>
          {ready.isLoading && <p className="text-muted">Checking…</p>}
          {ready.error && <p className="text-red-400">Health endpoint unreachable</p>}
          {ready.data && <ul>{Object.entries(ready.data.components).map(([k, v]) => <li key={k} className="flex justify-between"><span>{k}</span><Status s={v.status} /></li>)}</ul>}
        </div>
        <div className="panel p-3">
          <h2 className="text-xs text-muted uppercase mb-1">Events, last 24h</h2>
          {stats.isLoading && <p className="text-muted">Loading…</p>}
          {stats.error && <p className="text-red-400">Unavailable</p>}
          {stats.data && <p className="text-2xl tabular-nums">{stats.data.total_relation === "gte" ? "≥ " : ""}{stats.data.total.toLocaleString()}</p>}
        </div>
        <div className="panel p-3">
          <h2 className="text-xs text-muted uppercase mb-1">By event type</h2>
          <ul>{stats.data?.aggregations.by_type?.buckets.map((b) => (
            <li key={String(b.key)} className="flex justify-between"><Link className="hover:text-accent" href={link("event_type", String(b.key))}>{String(b.key)}</Link><span className="text-muted tabular-nums">{b.count}</span></li>))}</ul>
        </div>
      </div>
      <div className="panel p-3">
        <h2 className="text-xs text-muted uppercase mb-1">Top hosts (24h)</h2>
        {stats.data?.aggregations.by_host?.buckets.length === 0 && <p className="text-muted">No events in the last 24 hours.</p>}
        <ul>{stats.data?.aggregations.by_host?.buckets.map((b) => (
          <li key={String(b.key)} className="flex justify-between max-w-sm"><Link className="hover:text-accent font-mono" href={link("host.hostname", String(b.key))}>{String(b.key)}</Link><span className="text-muted tabular-nums">{b.count}</span></li>))}</ul>
      </div>
      {can("cases:read") && (
        <div className="grid md:grid-cols-2 gap-3">
          <div className="panel p-3" aria-label="Open cases by status">
            <h2 className="text-xs text-muted uppercase mb-1">Cases by status</h2>
            {cases.isLoading && <p className="text-muted">Loading…</p>}
            {cases.data && <ul>{CASE_STATUSES.map((s) => (
              <li key={s} className="flex justify-between max-w-xs"><Link className="hover:text-accent" href={`/cases?status=${s}`}>{s.replace("_", " ")}</Link><span className="tabular-nums text-muted">{byStatus(s)}</span></li>
            ))}</ul>}
          </div>
          <div className="panel p-3" aria-label="My cases">
            <h2 className="text-xs text-muted uppercase mb-1">Assigned to me</h2>
            {cases.data && mine.length === 0 && <p className="text-muted">Nothing assigned to you.</p>}
            <ul>{mine.map((c) => (
              <li key={c.id} className="flex gap-2 items-center"><span className="font-mono text-xs text-muted">{c.case_id}</span><Link className="hover:text-accent truncate" href={`/cases/${c.id}`}>{c.title}</Link><span className="ml-auto"><StatusBadge status={c.status} /></span></li>
            ))}</ul>
          </div>
        </div>
      )}
    </section>
  );
}
