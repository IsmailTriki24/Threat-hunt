"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import { ASSET_TYPES, CRITICALITIES, type AssetType, type Criticality } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { assetListQuery, relatedPivotHref } from "@/lib/cases";
import { fmtTime } from "@/lib/query";
import { AddToCaseDialog } from "./add-to-case-dialog";
import { ErrorLine, LevelBadge, StatusBadge } from "./badges";
import { EventDrawer } from "./event-drawer";
import { ResultsTable } from "./results-table";

export function AssetsList() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [f, setF] = useState({ type: "", criticality: "", q: "" });
  const [days, setDays] = useState(7);
  const [showNew, setShowNew] = useState(false);
  const [nt, setNt] = useState<AssetType>("host");
  const [nk, setNk] = useState("");
  const [nc, setNc] = useState<Criticality>("MEDIUM");
  const qs = assetListQuery(f);
  const assets = useQuery({ queryKey: ["assets", qs], queryFn: () => api.listAssets(qs) });
  const canWrite = can("assets:write");
  const discover = useMutation({ mutationFn: () => api.discoverAssets(days), onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }) });
  const create = useMutation({
    mutationFn: () => api.createAsset({ type: nt, key: nk.trim(), criticality: nc }),
    onSuccess: () => { setNk(""); setShowNew(false); void qc.invalidateQueries({ queryKey: ["assets"] }); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (nk.trim()) create.mutate(); };

  return (
    <div className="space-y-2">
      <div className="flex gap-2 items-center flex-wrap">
        <input aria-label="Search assets" className="input" placeholder="Search…" value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} />
        <select aria-label="Type filter" className="input" value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })}>
          <option value="">All types</option>{ASSET_TYPES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <select aria-label="Criticality filter" className="input" value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value })}>
          <option value="">All criticalities</option>{CRITICALITIES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <span className="ml-auto flex items-center gap-1 text-xs">
          <select aria-label="Discovery window" className="input" value={days} onChange={(e) => setDays(Number(e.target.value))}>{[1, 7, 14, 30].map((d) => <option key={d} value={d}>last {d}d</option>)}</select>
          <button className="btn" disabled={!canWrite || discover.isPending} onClick={() => discover.mutate()}>Discover from telemetry</button>
          <button className="btn btn-primary" disabled={!canWrite} onClick={() => setShowNew((s) => !s)}>New asset</button>
        </span>
      </div>
      {discover.data && <p role="status" className="text-xs text-muted">Discovery finished: {discover.data.created} new, {discover.data.updated} updated.</p>}
      <ErrorLine error={discover.error} fallback="Discovery failed" />
      {!canWrite && <p className="text-xs text-muted">Read-only: your role cannot create or edit assets.</p>}
      {showNew && canWrite && (
        <form onSubmit={submit} className="panel p-2 flex gap-1 items-center" aria-label="New asset">
          <select aria-label="Asset type" className="input" value={nt} onChange={(e) => setNt(e.target.value as AssetType)}>{ASSET_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
          <input aria-label="Asset key" className="input w-64" placeholder="hostname / user / IP / domain" value={nk} onChange={(e) => setNk(e.target.value)} />
          <select aria-label="Asset criticality" className="input" value={nc} onChange={(e) => setNc(e.target.value as Criticality)}>{CRITICALITIES.map((t) => <option key={t}>{t}</option>)}</select>
          <button className="btn btn-primary" type="submit" disabled={!nk.trim() || create.isPending}>Create</button>
          <ErrorLine error={create.error} fallback="Failed to create asset" />
        </form>
      )}
      <ErrorLine error={assets.error} fallback="Failed to load assets" />
      {assets.data && (assets.data.length === 0 ? <p className="panel p-3 text-muted">No assets. Use “Discover from telemetry” to populate the inventory.</p> : (
        <table className="w-full">
          <thead><tr>{["Type", "Asset", "Criticality", "Owner", "Events", "First seen", "Last seen"].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {assets.data.map((a) => (
              <tr key={a.id} className="hover:bg-bg">
                <td className="td">{a.type}</td>
                <td className="td"><Link className="text-accent hover:underline" href={`/assets/${a.id}`}>{a.display_name}</Link></td>
                <td className="td"><LevelBadge level={a.criticality} /></td>
                <td className="td">{a.owner}</td>
                <td className="td tabular-nums">{a.event_count}</td>
                <td className="td font-mono whitespace-nowrap">{a.first_seen ? fmtTime(a.first_seen) : ""}</td>
                <td className="td font-mono whitespace-nowrap">{a.last_seen ? fmtTime(a.last_seen) : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}

export function AssetView({ id }: { id: string }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const asset = useQuery({ queryKey: ["asset", id], queryFn: () => api.getAsset(id), retry: false });
  const events = useQuery({ queryKey: ["asset-events", id], queryFn: () => api.assetEvents(id), enabled: asset.isSuccess && can("events:read") });
  const related = useQuery({ queryKey: ["asset-related", id], queryFn: () => api.assetRelated(id), enabled: asset.isSuccess && can("events:read") });
  const cases = useQuery({ queryKey: ["asset-cases", id], queryFn: () => api.assetCases(id), enabled: asset.isSuccess && can("cases:read") });
  const [open, setOpen] = useState<string | null>(null);
  const [caseEvent, setCaseEvent] = useState<string | null>(null);
  const [owner, setOwner] = useState<string | null>(null);
  const [tags, setTags] = useState<string | null>(null);
  const [crit, setCrit] = useState<Criticality | null>(null);
  const save = useMutation({
    mutationFn: () => api.updateAsset(id, {
      ...(crit ? { criticality: crit } : {}), ...(owner !== null ? { owner } : {}),
      ...(tags !== null ? { tags: tags.split(",").map((t) => t.trim()).filter(Boolean) } : {}),
    }),
    onSuccess: () => { setOwner(null); setTags(null); setCrit(null); void qc.invalidateQueries({ queryKey: ["asset", id] }); void qc.invalidateQueries({ queryKey: ["assets"] }); },
  });

  if (asset.isLoading) return <p className="text-muted">Loading…</p>;
  if (asset.error || !asset.data) return <ErrorLine error={asset.error} fallback="Asset not found" />;
  const a = asset.data;
  const canWrite = can("assets:write");
  const dirty = owner !== null || tags !== null || crit !== null;

  return (
    <div className="space-y-3">
      <h1 className="text-base font-semibold flex gap-2 items-center"><span className="text-muted">{a.type}</span>{a.display_name}<LevelBadge level={a.criticality} /></h1>
      <div className="grid md:grid-cols-3 gap-3">
        <section className="panel p-3 space-y-1" aria-label="Attributes">
          <h2 className="text-xs text-muted uppercase">Attributes</h2>
          <label className="block text-xs">Criticality
            <select className="input w-full" disabled={!canWrite} value={crit ?? a.criticality} onChange={(e) => setCrit(e.target.value as Criticality)}>{CRITICALITIES.map((c) => <option key={c}>{c}</option>)}</select>
          </label>
          <label className="block text-xs">Owner
            <input className="input w-full" disabled={!canWrite} value={owner ?? a.owner} onChange={(e) => setOwner(e.target.value)} />
          </label>
          <label className="block text-xs">Tags (comma separated)
            <input className="input w-full" disabled={!canWrite} value={tags ?? a.tags.join(", ")} onChange={(e) => setTags(e.target.value)} />
          </label>
          <button className="btn btn-primary" disabled={!canWrite || !dirty || save.isPending} onClick={() => save.mutate()}>Save</button>
          <ErrorLine error={save.error} fallback="Failed to save asset" />
          <dl className="grid grid-cols-[6rem_1fr] text-xs pt-1">
            <dt className="text-muted">Events</dt><dd className="tabular-nums">{a.event_count}</dd>
            <dt className="text-muted">First seen</dt><dd className="font-mono">{a.first_seen ? fmtTime(a.first_seen) : "—"}</dd>
            <dt className="text-muted">Last seen</dt><dd className="font-mono">{a.last_seen ? fmtTime(a.last_seen) : "—"}</dd>
          </dl>
        </section>
        <section className="panel p-3" aria-label="Related entities">
          <h2 className="text-xs text-muted uppercase mb-1">Related (derived from telemetry, 7d)</h2>
          <ErrorLine error={related.error} fallback="Failed to load relationships" />
          {related.data && Object.entries(related.data).map(([group, items]) => (
            <div key={group} className="mb-1">
              <h3 className="text-xs capitalize text-muted">{group}</h3>
              {items.length === 0 ? <p className="text-xs text-muted">none</p> : (
                <ul className="text-xs">{items.map((r) => {
                  const href = relatedPivotHref(group, r.key);
                  return <li key={String(r.key)} className="flex justify-between">{href ? <Link className="hover:text-accent font-mono" href={href}>{String(r.key)}</Link> : <span>{String(r.key)}</span>}<span className="text-muted tabular-nums">{r.count}</span></li>;
                })}</ul>
              )}
            </div>
          ))}
        </section>
        <section className="panel p-3" aria-label="Linked cases">
          <h2 className="text-xs text-muted uppercase mb-1">Cases</h2>
          {cases.data?.length === 0 && <p className="text-xs text-muted">Not linked to any case.</p>}
          <ul>{cases.data?.map((c) => (
            <li key={c.id} className="flex gap-2 text-xs"><Link className="text-accent hover:underline font-mono" href={`/cases/${c.id}`}>CASE-{String(c.number).padStart(4, "0")}</Link><span className="truncate">{c.title}</span><span className="ml-auto"><StatusBadge status={c.status} /></span></li>
          ))}</ul>
        </section>
      </div>
      <section aria-label="Recent events">
        <h2 className="text-xs text-muted uppercase mb-1">Recent events {events.data ? `(${events.data.total.toLocaleString()} in 7d)` : ""}</h2>
        <ErrorLine error={events.error} fallback="Failed to load events" />
        {events.data && (events.data.hits.length === 0 ? <p className="panel p-3 text-muted">No telemetry for this asset in the last 7 days.</p> : (
          <ResultsTable hits={events.data.hits} dense selected={open} onOpen={setOpen} sort={null} onSort={() => undefined} />
        ))}
      </section>
      {open && <EventDrawer id={open} onClose={() => setOpen(null)} onPivot={() => setOpen(null)} onAddToCase={can("cases:write") ? setCaseEvent : undefined} />}
      {caseEvent && <AddToCaseDialog eventIds={[caseEvent]} onClose={() => setCaseEvent(null)} />}
    </div>
  );
}
