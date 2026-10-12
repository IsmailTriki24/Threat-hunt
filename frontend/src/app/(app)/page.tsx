"use client";
import { useQuery } from "@tanstack/react-query";
import { Activity, Briefcase, Radar, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { StatusBadge } from "@/components/badges";
import { BarList } from "@/components/ui/bar-list";
import { EmptyState } from "@/components/ui/empty-state";
import { KpiCard } from "@/components/ui/kpi-card";
import { PageHeader, Section } from "@/components/ui/page-header";
import { SeverityBadge } from "@/components/ui/severity";
import { SkeletonRows } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { CASE_STATUSES } from "@/lib/api-types";
import { OVERVIEW_AGGS, defaultState, toRequestBody } from "@/lib/query";

const ACTIVE = new Set(["OPEN", "INVESTIGATING", "CONTAINED"]);

export default function Overview() {
  const { can, session } = useAuth();
  const cases = useQuery({ queryKey: ["cases", "overview"], queryFn: () => api.listCases("?limit=200"), enabled: can("cases:read") });
  const ready = useQuery({ queryKey: ["ready"], queryFn: api.ready, refetchInterval: 30_000 });
  const stats = useQuery({ queryKey: ["overview"], queryFn: () => api.search({ ...toRequestBody(defaultState(), OVERVIEW_AGGS), limit: 1 }) });
  const det = useQuery({ queryKey: ["det-overview"], queryFn: () => api.detOverview(), enabled: can("detections:read") });
  const ioc = useQuery({ queryKey: ["ioc-overview"], queryFn: () => api.iocOverview(), enabled: can("iochunt:read") });

  const link = (field: string, value: string) => `/events?f=${encodeURIComponent(`${field}|eq|${value}`)}`;
  const all = cases.data ?? [];
  const byStatus = (s: string) => all.filter((c) => c.status === s).length;
  const active = all.filter((c) => ACTIVE.has(c.status)).length;
  const mine = all.filter((c) => c.assignee?.id === session?.user_id && c.status !== "CLOSED");
  const events = stats.data;
  const bad = Object.entries(ready.data?.components ?? {}).filter(([, v]) => v.status !== "ok");

  return (
    <div className="space-y-5">
      <PageHeader title="Overview" description={`What needs attention in ${session?.tenant?.name ?? "your tenant"} right now. Figures cover the last 24 hours unless stated.`} />

      <div className="grid grid-cols-2 gap-3 md:gap-4 xl:grid-cols-4">
        <KpiCard label="Events, last 24 h" icon={Activity} href="/events" loading={stats.isLoading} unavailable={stats.isError}
          value={events ? `${events.total.toLocaleString("en-US")}${events.total_relation === "gte" ? "+" : ""}` : "—"}
          hint={events?.total_relation === "gte" ? "Search result limit reached; open Events for the full picture" : "Searchable in Events"} />
        {can("cases:read") && <KpiCard label="Active cases" icon={Briefcase} href="/cases" loading={cases.isLoading} unavailable={cases.isError} value={active}
          hint={`${byStatus("OPEN")} open · ${byStatus("INVESTIGATING")} investigating · ${byStatus("CONTAINED")} contained`} />}
        {can("detections:read") && <KpiCard label="Open alerts" icon={ShieldAlert} href="/detections" loading={det.isLoading} unavailable={det.isError} value={det.data?.open_alerts ?? 0}
          tone={det.data?.open_alerts ? "high" : "ok"}
          hint={det.data ? (Object.entries(det.data.alerts_by_severity).filter(([, n]) => n).map(([s, n]) => `${n} ${s.toLowerCase()}`).join(" · ") || "No open alerts") : undefined} />}
        {can("iochunt:read") && <KpiCard label="IOCs seen in your telemetry" icon={Radar} href="/ioc-hunting" loading={ioc.isLoading} unavailable={ioc.isError} value={ioc.data?.seen_in_environment ?? 0}
          tone={ioc.data?.seen_in_environment ? "critical" : "ok"} hint={ioc.data ? `${ioc.data.threats_by_status?.NEW ?? 0} threats awaiting review · ${ioc.data.feeds_failing} feed${ioc.data.feeds_failing === 1 ? "" : "s"} failing` : undefined} />}
      </div>

      {bad.length > 0 && (
        <div role="alert" className="flex flex-wrap items-center gap-2 rounded-lg border border-sev-high/30 bg-sev-high-bg px-4 py-2.5 text-sm text-sev-high">
          <SeverityBadge level="high" label="Degraded" />
          <span>{bad.map(([k, v]) => `${k}: ${v.status}`).join(" · ")}. Collection or search may be incomplete.</span>
        </div>
      )}
      {ready.isError && <div role="alert" className="rounded-lg border border-sev-critical/30 bg-sev-critical-bg px-4 py-2.5 text-sm text-sev-critical">The health endpoint is unreachable.</div>}

      <div className="grid gap-4 lg:grid-cols-3">
        {can("cases:read") && (
          <Section title="Assigned to me" description="Your unfinished cases" className="lg:col-span-2" actions={<Link href="/cases" className="link text-xs">All cases</Link>}>
            {cases.isLoading ? <SkeletonRows rows={4} /> : mine.length === 0 ? (
              <EmptyState compact icon={Briefcase} title="Nothing is assigned to you">Cases you own appear here. Open <Link className="link" href="/cases">Cases</Link> to pick one up.</EmptyState>
            ) : (
              <ul className="-my-2 divide-y divide-line">
                {mine.slice(0, 8).map((c) => (
                  <li key={c.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
                    <span className="w-20 shrink-0 font-mono text-xs text-muted">{c.case_id}</span>
                    <Link className="order-last min-w-0 basis-full truncate font-medium hover:text-accent sm:order-none sm:basis-0 sm:flex-1" href={`/cases/${c.id}`}>{c.title}</Link>
                    <SeverityBadge level={c.severity} label={c.severity} /><StatusBadge status={c.status} />
                  </li>
                ))}
              </ul>
            )}
          </Section>
        )}
        <Section title="Platform health" description="Refreshed every 30 s">
          {ready.isLoading ? <SkeletonRows rows={4} /> : (
            <ul className="space-y-2">
              {Object.entries(ready.data?.components ?? {}).map(([k, v]) => (
                <li key={k} className="flex items-center justify-between text-sm"><span className="capitalize">{k}</span><SeverityBadge level={v.status === "ok" ? "ok" : v.status === "degraded" ? "medium" : "critical"} label={v.status} /></li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Section title="Top hosts" description="By event count, last 24 h">
          {stats.isLoading ? <SkeletonRows /> : <BarList empty="No events in the last 24 hours." rows={(events?.aggregations.by_host?.buckets ?? []).slice(0, 8).map((b) => ({ key: String(b.key), label: String(b.key), mono: true, value: b.count, href: link("host.hostname", String(b.key)) }))} />}
        </Section>
        <Section title="Events by type" description="Last 24 h">
          {stats.isLoading ? <SkeletonRows /> : <BarList empty="No events in the last 24 hours." rows={(events?.aggregations.by_type?.buckets ?? []).map((b) => ({ key: String(b.key), label: String(b.key).replace(/_/g, " "), value: b.count, href: link("event_type", String(b.key)) }))} />}
        </Section>
        {can("cases:read") && (
          <Section title="Cases by status" description="All time, most recent 200">
            {cases.isLoading ? <SkeletonRows /> : <BarList rows={CASE_STATUSES.map((s) => ({ key: s, label: s.replace("_", " "), value: byStatus(s), href: `/cases?status=${s}` }))} />}
          </Section>
        )}
      </div>
    </div>
  );
}
