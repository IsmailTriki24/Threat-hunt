"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { SiemSearchCard } from "./siem-search-card";
import { api } from "@/lib/api";
import {
  ago, defang, flagEmoji, ipRoleLinks, windowFor, fmtInt, fmtTs, LAYER_COLOR, timelineMax,
  type Correlation, type CountryRow, type Layer, type MapFilters, type MapMarker, type Severity,
} from "@/lib/threat-map";
import { SeverityBadge as Badge, SeverityDot as Dot } from "./ui/severity";
import { AddToCaseDialog } from "./add-to-case-dialog";
import { CopyButton, ErrorLine } from "./badges";
import { IntelOpenButton } from "./intel-action";

export function SeverityDot({ severity }: { severity: Severity | string }) { return <Dot level={severity} />; }
export function SeverityTag({ severity }: { severity: string }) { return <Badge level={severity} />; }
const Chip = ({ children, tone }: { children: React.ReactNode; tone?: string }) => (
  <span className={`badge ${tone ?? "border-line-strong bg-subtle text-ink-2"}`}>{children}</span>
);
const Section = ({ title, children, count }: { title: string; children: React.ReactNode; count?: number }) => (
  <section className="border-t border-line px-4 py-3">
    <h3 className="eyebrow mb-1.5">{title}{count !== undefined && <span className="ml-1 font-normal">({count})</span>}</h3>
    {children}
  </section>
);
const KV = ({ k, v }: { k: string; v: React.ReactNode }) => (
  <div className="flex justify-between gap-3 py-px text-xs"><span className="text-muted shrink-0">{k}</span><span className="text-right break-words min-w-0">{v}</span></div>
);

// ---- investigation panel ---------------------------------------------------------------------------------
export function InvestigationPanel({ ip, filters, rangeQs, onClose }: { ip: string; filters: MapFilters; rangeQs: string; onClose: () => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["tm-indicator", ip, rangeQs], queryFn: () => api.threatMapIndicator(ip, rangeQs), staleTime: 15_000 });
  const [caseOpen, setCaseOpen] = useState(false);
  // The panel also asks the whole LogRhythm SIEM about this address (the connector only collects a slice), over the map's time range.
  const siem = useQuery({
    queryKey: ["tm-siem", ip, filters.range, filters.start, filters.end], queryFn: () => api.siemLookup("ip", ip, windowFor(filters)),
    enabled: q.isSuccess && q.data.class === "public", staleTime: Infinity, retry: false, refetchOnWindowFocus: false,
  });
  const siemImported = siem.data?.imported ?? 0;
  useEffect(() => { if (siemImported > 0) { void qc.invalidateQueries({ queryKey: ["tm-indicator", ip] }); void qc.invalidateQueries({ queryKey: ["tm-data"] }); } }, [siemImported, siem.dataUpdatedAt, qc, ip]);
  const [note, setNote] = useState("");
  const d = q.data;
  const roles = ipRoleLinks(ip, filters.range, filters.start, filters.end, d?.observed ?? null);
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["tm-indicator", ip] }); void qc.invalidateQueries({ queryKey: ["tm-data"] }); };

  const hunt = useMutation({
    mutationFn: () => api.validateIocs({ ioc_ids: (d?.intel ?? []).filter((i) => i.status === "NEW" || i.status === "VALIDATED").map((i) => i.id), lookback_days: 7, name: `Threat map: ${ip}` }),
    onSuccess: (h) => { setNote(`Hunt started (${h.id.slice(0, 8)}). Follow it in IOC Hunting.`); refresh(); },
  });
  const queue = useMutation({
    mutationFn: () => api.addIoc({ type: "ip", value: ip, confidence: 60, description: "Added from the threat map" }),
    onSuccess: () => { setNote("Added to the IOC queue. Validate it from here or from IOC Hunting."); refresh(); },
  });

  return (
    <aside aria-label="Indicator investigation" className="panel flex h-full min-h-0 flex-col overflow-hidden shadow-card">
      <header className="flex items-start gap-2 px-4 py-3">
        <div className="min-w-0 flex-1">
          <div className="font-mono text-base break-all" data-testid="panel-ip">{ip}</div>
          <div className="flex flex-wrap gap-1 pt-1">
            {d && <Chip>{d.class === "public" ? "public IP" : `${d.class} address`}</Chip>}
            {d?.correlated && <Chip tone="border-sev-critical/30 bg-sev-critical-bg text-sev-critical">correlated</Chip>}
            {d && d.intel.length > 0 && <Chip tone="border-sev-medium/30 bg-sev-medium-bg text-sev-medium">reported by intelligence</Chip>}
            {d?.observed && <Chip tone="border-accent/30 bg-accent-soft text-accent">seen in your telemetry</Chip>}
          </div>
        </div>
        <button className="btn btn-ghost px-1.5" aria-label="Close investigation panel" onClick={onClose}><X aria-hidden className="h-4 w-4" /></button>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {q.isLoading && <div className="px-4 py-4 text-muted" role="status"><span className="animate-pulse">Loading indicator…</span></div>}
        {q.isError && <div className="px-4 py-3"><ErrorLine error={q.error} fallback="Could not load this indicator" /> <button className="btn btn-sm" onClick={() => void q.refetch()}>Retry</button></div>}
        {d && (
          <>
            <div className="flex flex-wrap gap-1.5 px-4 pb-3" role="group" aria-label="Actions">
              <CopyButton text={d.ip} label="Copy IOC" />
              <CopyButton text={defang(d.ip)} label="Copy defanged" />
              {d.actions.investigate && <Link className="btn btn-sm" href={roles[0].href}>Investigate this IP</Link>}
              {d.actions.hunt && d.intel.length > 0 && <button className="btn btn-primary btn-sm" disabled={hunt.isPending} onClick={() => hunt.mutate()}>{hunt.isPending ? "Starting…" : "Launch threat hunt"}</button>}
              {d.actions.add_to_watchlist && d.intel.length === 0 && <button className="btn btn-sm" disabled={queue.isPending || queue.isSuccess} onClick={() => queue.mutate()}>Add to IOC queue</button>}
              {d.actions.intel_lookup && <IntelOpenButton type="ip" value={d.ip} label="Open intelligence record" />}
              {d.actions.add_to_case && d.events.length > 0 && <button className="btn btn-sm" onClick={() => setCaseOpen(true)}>Add to case</button>}
            </div>
            {note && <div role="status" className="mx-4 mb-3 rounded-md border border-sev-ok/30 bg-sev-ok-bg px-3 py-2 text-xs text-sev-ok">{note} <Link className="underline" href="/ioc-hunting">Open IOC Hunting</Link></div>}
            <div className="px-4"><ErrorLine error={hunt.error ?? queue.error} fallback="Action failed" /></div>

            <Section title="Location (approximate)">
              {d.geo ? (
                <>
                  <KV k="Country" v={<>{flagEmoji(d.geo.country)} {d.geo.country_name || d.geo.country}</>} />
                  {(d.geo.city || d.geo.region) && <KV k="City / region" v={[d.geo.city, d.geo.region].filter(Boolean).join(", ")} />}
                  {d.geo.asn && <KV k="ASN" v={`AS${d.geo.asn}`} />}
                  {d.geo.org && <KV k="Organisation" v={d.geo.org} />}
                </>
              ) : null}
              <p className="pt-1 text-[11px] text-muted">{d.geo_note}</p>
            </Section>

            <Section title="Threat intelligence" count={d.intel.length}>
              {d.intel.length === 0 ? <p className="text-xs text-muted">No feed or analyst record reports this address in your tenant.</p> : (
                <ul className="space-y-2">
                  {d.intel.map((i) => (
                    <li key={i.id} className="rounded border border-line/70 px-2 py-1">
                      <div className="flex flex-wrap items-center gap-1.5 text-xs">
                        <strong>{i.source}</strong><SeverityTag severity={i.severity} /><span className="text-muted">confidence {i.confidence}</span>
                        {i.stale && <Chip tone="border-sev-high/30 bg-sev-high-bg text-sev-high">stale</Chip>}<Chip>{i.status.toLowerCase()}</Chip>
                      </div>
                      {(i.threat || i.malware || i.threat_type) && <div className="text-xs">{[i.threat, i.malware, i.threat_type].filter(Boolean).join(" · ")}</div>}
                      {i.description && <div className="text-xs text-muted break-words">{i.description}</div>}
                      <div className="text-[11px] text-muted">first seen {fmtTs(i.first_seen)} · last seen {fmtTs(i.last_seen)}</div>
                      {i.reference && <a className="text-xs text-accent hover:underline break-all" href={i.reference} target="_blank" rel="noopener noreferrer">Source report ↗</a>}
                    </li>
                  ))}
                </ul>
              )}
              <p className="pt-1 text-[11px] text-muted">Reported by a third party. This is not evidence of an attack on your organisation.</p>
            </Section>

            {d.class === "public" && (
              <section className="border-t border-line px-4 py-3" aria-label="LogRhythm SIEM">
                <h3 className="eyebrow mb-1.5">LogRhythm SIEM · whole SIEM</h3>
                <SiemSearchCard query={siem} />
              </section>
            )}
            <Section title="Observed in your telemetry">
              {!d.observed ? <p className="text-xs text-muted">No events in the selected range name this address.</p> : (
                <>
                  <KV k="Events" v={fmtInt(d.observed.events)} />
                  <KV k="As source / destination / sign-in source" v={`${d.observed.as_source} / ${d.observed.as_destination} / ${d.observed.as_signin_source}`} />
                  <KV k="First / last seen" v={`${fmtTs(d.observed.first_seen)} → ${fmtTs(d.observed.last_seen)}`} />
                  <KV k="Highest event severity" v={<SeverityTag severity={d.observed.max_severity} />} />
                  {d.observed.ports.length > 0 && <KV k="Destination ports" v={d.observed.ports.join(", ")} />}
                  {d.actions.investigate && <div className="flex flex-wrap items-center gap-1.5 pt-2" role="group" aria-label="View related events">
                    <span className="text-xs text-muted">View events:</span>
                    {roles.filter((r) => r.count > 0).map((r) => <Link key={r.key} className="btn btn-sm" href={r.href}>{r.label} ({fmtInt(r.count)})</Link>)}
                  </div>}
                  <KV k="Log sources" v={d.observed.sources.join(", ")} />
                </>
              )}
              {d.correlated && <p className="pt-1 text-xs text-red-300">{d.correlation_reason}</p>}
            </Section>

            {d.events.length > 0 && (
              <Section title="Matched internal events" count={d.events_total}>
                <ul className="space-y-1">
                  {d.events.slice(0, 8).map((e) => (
                    <li key={e.id} className="text-xs">
                      <Link className="text-accent hover:underline" href={`/events?event=${e.id}`}>{fmtTs(e.timestamp)}</Link>{" "}
                      <span className="text-muted">{e.source}</span> <span className="break-words">{e.summary}</span>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
            {d.hunt_matches.length > 0 && (
              <Section title="IOC hunt matches" count={d.hunt_matches.length}>
                <ul className="space-y-1 text-xs">{d.hunt_matches.map((m) => <li key={m.event_id + m.ioc_value}><Chip>{m.ioc_type}</Chip> <span className="font-mono break-all">{m.ioc_value}</span> <span className="text-muted">on {m.matched_field || "event"}{m.host ? ` @ ${m.host}` : ""}</span></li>)}</ul>
              </Section>
            )}
            {d.related_iocs.length > 0 && (
              <Section title="Related indicators (same threat)" count={d.related_iocs.length}>
                <ul className="space-y-0.5 text-xs">{d.related_iocs.slice(0, 10).map((r) => <li key={r.id}><Chip>{r.type}</Chip> <span className="font-mono break-all">{r.value}</span> <span className="text-muted">{r.source}</span></li>)}</ul>
              </Section>
            )}
            {d.peers.length > 0 && (
              <Section title="Connected to" count={d.peers.length}>
                <ul className="space-y-0.5 font-mono text-xs">{d.peers.slice(0, 6).map((p, i) => <li key={i}>{p.src_ip} → {p.dst_ip}{p.ports[0] ? `:${p.ports[0]}` : ""} <span className="text-muted">×{p.events}</span></li>)}</ul>
              </Section>
            )}
            {(d.alerts.length > 0 || d.cases.length > 0) && (
              <Section title="Alerts and cases">
                <ul className="space-y-1 text-xs">
                  {d.alerts.map((a) => <li key={a.id}><SeverityTag severity={a.severity.toLowerCase()} /> <Link className="text-accent hover:underline" href={`/events?event=${a.event_id}`}>{a.rule}</Link> <span className="text-muted">{a.status.toLowerCase()}</span></li>)}
                  {d.cases.map((c) => <li key={c.id}><Link className="text-accent hover:underline" href={`/cases/${c.id}`}>{c.case_id}</Link> {c.title} <span className="text-muted">{c.status.toLowerCase()}</span></li>)}
                </ul>
              </Section>
            )}
          </>
        )}
      </div>
      {caseOpen && d && <AddToCaseDialog eventIds={d.events.slice(0, 50).map((e) => e.id)} onClose={() => setCaseOpen(false)} />}
    </aside>
  );
}

// ---- supporting panels ------------------------------------------------------------------------------------
const Card = ({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) => (
  <section className="panel flex min-h-0 flex-col">
    <header className="flex items-center justify-between border-b border-line px-4 py-2.5"><h2 className="text-sm font-semibold text-ink">{title}</h2>{action}</header>
    <div className="min-h-0 flex-1 overflow-auto px-4 py-3">{children}</div>
  </section>
);
const Empty = ({ children }: { children: React.ReactNode }) => <p className="py-3 text-center text-xs text-muted">{children}</p>;

export function TopCountries({ rows, layer, onPick, active }: { rows: CountryRow[]; layer: Layer; onPick: (iso: string) => void; active: string[] }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  const unit = { intelligence: "IPs", observed: "events", correlated: "correlated IPs" }[layer];
  return (
    <Card title={`Top countries · ${unit}`}>
      {rows.length === 0 ? <Empty>No located addresses.</Empty> : (
        <ul className="space-y-1">
          {rows.map((r) => (
            <li key={r.iso}>
              <button className={`group w-full text-left ${active.includes(r.iso) ? "text-accent" : ""}`} onClick={() => onPick(r.iso)} title={`Filter to ${r.name}`}>
                <div className="flex justify-between text-xs"><span>{flagEmoji(r.iso)} {r.name || r.iso}</span><span className="tabular-nums">{fmtInt(r.value)}</span></div>
                <div className="h-1 rounded bg-line"><div className="h-1 rounded" style={{ width: `${(r.value / max) * 100}%`, background: LAYER_COLOR[layer] }} /></div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function TopIps({ rows, layer, onPick, selected }: { rows: MapMarker[]; layer: Layer; onPick: (ip: string) => void; selected: string | null }) {
  return (
    <Card title={layer === "intelligence" ? "Most-reported IPs" : layer === "observed" ? "Most active IPs" : "Most correlated IPs"}>
      {rows.length === 0 ? <Empty>Nothing to rank.</Empty> : (
        <ul className="space-y-0.5">
          {rows.map((m) => (
            <li key={m.ip}>
              <button className={`flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-xs hover:bg-accent-soft ${selected === m.ip ? "bg-bg" : ""}`} onClick={() => onPick(m.ip)}>
                <SeverityDot severity={m.severity} />
                <span className="font-mono">{m.ip}</span>
                <span className="text-muted">{m.geo?.country ?? "—"}</span>
                <span className="ml-auto tabular-nums text-muted">{layer === "intelligence" ? `${m.intel?.iocs ?? 0} IOC` : `${fmtInt(m.observed?.events ?? m.weight)} ev`}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function RecentCorrelations({ rows, total, offset, setOffset, loading, onPick }: {
  rows: Correlation[]; total: number; offset: number; setOffset: (n: number) => void; loading: boolean; onPick: (ip: string) => void;
}) {
  const page = 8;
  return (
    <Card title="Recent correlated detections" action={total > page && (
      <span className="flex items-center gap-1 text-xs text-muted">
        <button className="btn btn-sm" disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - page))} aria-label="Newer correlations">‹</button>
        <span className="tabular-nums">{offset + 1}–{Math.min(total, offset + page)} of {total}</span>
        <button className="btn btn-sm" disabled={offset + page >= total || loading} onClick={() => setOffset(offset + page)} aria-label="Older correlations">›</button>
      </span>
    )}>
      {rows.length === 0 ? <Empty>No observed activity matches reported intelligence or an IOC hunt in this range.</Empty> : (
        <ul className="space-y-2">
          {rows.map((c) => (
            <li key={c.id} className="rounded border border-line/70 px-2 py-1">
              <button className="w-full text-left" onClick={() => onPick(c.ip)}>
                <div className="flex flex-wrap items-center gap-1.5 text-xs">
                  <SeverityTag severity={c.severity} /><span className="font-mono">{c.ip}</span><Chip>{c.ioc_type}</Chip>
                  {c.kind === "hunt_match" && <span className="font-mono text-muted break-all">{c.ioc_value}</span>}
                  <span className="ml-auto text-muted">{ago(c.last_seen)}</span>
                </div>
                <div className="text-xs text-muted break-words">{c.reason}</div>
                <div className="flex flex-wrap gap-x-3 text-[11px] text-muted"><span>{c.source}</span><span>confidence {c.confidence}</span><span>{fmtInt(c.events)} event{c.events === 1 ? "" : "s"}</span><span>{c.status.toLowerCase()}</span>{c.case && <span>{c.case.case_id}</span>}</div>
              </button>
              {c.case && <Link className="text-xs text-accent hover:underline" href={`/cases/${c.case.id}`}>Open {c.case.case_id}</Link>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function ActivityTimeline({ points, unit, layer }: { points: Array<{ t: string; count: number }>; unit: string; layer: Layer }) {
  const max = timelineMax(points);
  const W = 600, H = 70, bw = points.length ? W / points.length : W;
  const label = { intelligence: "indicators last reported", observed: "events with an IP address", correlated: "events involving a reported IP" }[layer];
  return (
    <Card title={`Threat activity · ${label} per ${unit}`}>
      {points.length === 0 || points.every((p) => p.count === 0) ? <Empty>No activity in this range.</Empty> : (
        <svg viewBox={`0 0 ${W} ${H + 12}`} className="h-24 w-full" role="img" aria-label="Threat activity timeline">
          {points.map((p, i) => {
            const h = (p.count / max) * H;
            return <rect key={p.t} x={i * bw + 0.5} y={H - h} width={Math.max(bw - 1, 1)} height={Math.max(h, p.count ? 1 : 0)} fill={LAYER_COLOR[layer]} opacity={0.85}><title>{`${fmtTs(p.t)} — ${fmtInt(p.count)}`}</title></rect>;
          })}
          <text x={0} y={H + 10} fontSize="9" fill="#8b949e">{fmtTs(points[0].t)}</text>
          <text x={W} y={H + 10} fontSize="9" fill="#8b949e" textAnchor="end">peak {fmtInt(max)}</text>
        </svg>
      )}
    </Card>
  );
}
