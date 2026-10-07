"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { IntelCoverage, IntelDetail, IntelObservation } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { coverageLine, defangEntity, ENTITY_LABEL, MODEL_NOTE, sightingsHref, watchPayload } from "@/lib/intel";
import { fmtTime } from "@/lib/query";
import { CopyButton, ErrorLine } from "./badges";
import { EventDrawer } from "./event-drawer";
import { ScoreBar, Section, StatusPill, VerdictBadge } from "./intel-bits";

function Breakdown({ d }: { d: IntelDetail }) {
  return (
    <Section title="Score breakdown">
      <p className="text-xs text-muted">{MODEL_NOTE}</p>
      {d.score_breakdown.length === 0 ? <p className="text-muted">No provider has produced a signal yet.</p> : (
        <table className="w-full">
          <thead><tr>{["Provider", "Verdict", "Confidence", "Weight", "Contribution", "Summary"].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {d.score_breakdown.map((s) => (
              <tr key={s.provider}>
                <td className="td">{s.provider}</td><td className="td"><VerdictBadge verdict={s.verdict} /></td>
                <td className="td tabular-nums">{s.confidence}</td><td className="td tabular-nums">{s.weight}</td>
                <td className="td tabular-nums">+{s.contribution}</td><td className="td text-muted">{s.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Section>
  );
}

const dataLine = (o: IntelObservation): string =>
  Object.entries(o.data).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(" · ");

function Observations({ obs }: { obs: IntelObservation[] }) {
  return (
    <Section title="Provider observations">
      {obs.length === 0 && <p className="text-muted">No observations yet — run an enrichment.</p>}
      <div className="grid md:grid-cols-2 gap-2">
        {obs.map((o) => (
          <article key={o.provider} className="border border-line p-2 space-y-0.5" aria-label={`Observation ${o.provider}`}>
            <div className="flex items-center gap-2"><strong>{o.provider}</strong><StatusPill status={o.status} /><span className="ml-auto text-xs text-muted">{fmtTime(o.fetched_at)}</span></div>
            {o.status === "error" ? <p className="text-red-400 text-xs">Provider failed: {o.summary}. This does not mean the indicator is clean.</p> : (
              <p className="text-xs"><VerdictBadge verdict={o.verdict} /> confidence {o.confidence} — {o.summary}</p>
            )}
            {dataLine(o) && <p className="text-xs text-muted break-words">{dataLine(o)}</p>}
          </article>
        ))}
      </div>
    </Section>
  );
}

function WatchEditor({ d, canWrite }: { d: IntelDetail; canWrite: boolean }) {
  const qc = useQueryClient();
  const e = d.entity;
  const [verdict, setVerdict] = useState<string>(e.watch_verdict ?? "");
  const [confidence, setConfidence] = useState(e.watch_confidence || 80);
  const [notes, setNotes] = useState(e.notes);
  const [tags, setTags] = useState(e.tags.join(", "));
  const save = useMutation({
    mutationFn: () => api.updateEntity(e.id, watchPayload(verdict, confidence, notes, tags)),
    onSuccess: (r) => qc.setQueryData(["intel-entity", e.id], r),
  });
  return (
    <Section title="Watch-list & notes">
      <form className="space-y-1" onSubmit={(ev) => { ev.preventDefault(); save.mutate(); }} aria-label="Watch-list">
        <div className="flex items-center gap-2 flex-wrap">
          <select aria-label="Watch-list verdict" className="input" value={verdict} disabled={!canWrite} onChange={(x) => setVerdict(x.target.value)}>
            <option value="">not on watch-list</option><option>malicious</option><option>suspicious</option><option>benign</option>
          </select>
          <label className="text-xs">confidence <input aria-label="Watch-list confidence" className="input w-16" type="number" min={0} max={100} value={confidence} disabled={!canWrite || !verdict}
            onChange={(x) => setConfidence(Math.max(0, Math.min(100, Number(x.target.value) || 0)))} /></label>
          <input aria-label="Tags" className="input flex-1 min-w-40" placeholder="tags, comma separated" value={tags} disabled={!canWrite} onChange={(x) => setTags(x.target.value)} />
        </div>
        <textarea aria-label="Notes" className="input w-full" rows={2} maxLength={10000} placeholder="Analyst notes" value={notes} disabled={!canWrite} onChange={(x) => setNotes(x.target.value)} />
        <button className="btn btn-primary" type="submit" disabled={!canWrite || save.isPending}>Save</button>
        {!canWrite && <span className="text-xs text-muted ml-2">Read-only for your role</span>}
        <ErrorLine error={save.error} fallback="Save failed" />
      </form>
    </Section>
  );
}

function SightingsPanel({ id, value }: { id: string; value: string }) {
  const [open, setOpen] = useState<string | null>(null);
  const s = useQuery({ queryKey: ["intel-sightings", id], queryFn: () => api.sightings(id), retry: false });
  const fields = s.data ? Object.entries(s.data.by_field) : [];
  return (
    <Section title="Sightings in your telemetry (last 30 days)">
      <ErrorLine error={s.error} fallback="Failed to load sightings" />
      {s.data && (s.data.total === 0 ? <p className="text-muted">Never seen in this tenant&apos;s telemetry.</p> : (
        <div className="space-y-1">
          <p>{s.data.total} matching event{s.data.total === 1 ? "" : "s"} · first {s.data.first_seen ? fmtTime(s.data.first_seen) : "?"} · last {s.data.last_seen ? fmtTime(s.data.last_seen) : "?"}</p>
          <ul className="text-xs flex flex-wrap gap-2">
            {fields.map(([f, n]) => <li key={f}><Link className="text-accent hover:underline" href={sightingsHref(f, value)}>{f} ×{n} → Open in Events</Link></li>)}
          </ul>
          <p className="text-xs">Hosts: {s.data.hosts.map((h) => (
            <Link key={h.key} className="text-accent hover:underline mr-2" href={sightingsHref("host.hostname", h.key)}>{h.key} ({h.count})</Link>
          ))}</p>
          <ul className="text-xs">
            {s.data.recent.map((e) => (
              <li key={e.id}><button className="hover:text-accent text-left" onClick={() => setOpen(e.id)}>{fmtTime(e.timestamp)} · {e.host?.hostname ?? "?"} · {e.event_type}{e.process?.name ? ` · ${e.process.name}` : ""}</button></li>
            ))}
          </ul>
        </div>
      ))}
      {open && <EventDrawer id={open} onClose={() => setOpen(null)} onPivot={() => setOpen(null)} />}
    </Section>
  );
}

function Relations({ d, canWrite }: { d: IntelDetail; canWrite: boolean }) {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("uses");
  const found = useQuery({ queryKey: ["intel-rel-search", search], queryFn: () => api.listEntities(`?q=${encodeURIComponent(search.trim())}&limit=8`), enabled: search.trim().length >= 2 });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["intel-entity", d.entity.id] });
  const add = useMutation({ mutationFn: (dst: string) => api.addRelation(d.entity.id, dst, kind), onSuccess: () => { setSearch(""); refresh(); } });
  const del = useMutation({ mutationFn: (rid: string) => api.removeRelation(rid), onSuccess: refresh });
  return (
    <Section title="Relations">
      {d.relations.length === 0 && <p className="text-muted">No related malware, actors or campaigns.</p>}
      <ul>
        {d.relations.map((r) => (
          <li key={r.id} className="flex items-center gap-2">
            <span className="text-muted w-32">{r.direction === "out" ? `${r.kind} →` : `← ${r.kind}`}</span>
            <span className="text-xs border border-line px-1 rounded-sm">{ENTITY_LABEL[r.other.type] ?? r.other.type}</span>
            <Link className="text-accent hover:underline font-mono" href={`/threat-intel/${r.other.id}`}>{r.other.value}</Link>
            <span className="text-xs text-muted">via {r.source}</span>
            {canWrite && <button className="btn py-0 text-xs ml-auto" aria-label={`Remove relation to ${r.other.value}`} onClick={() => del.mutate(r.id)}>Remove</button>}
          </li>
        ))}
      </ul>
      {canWrite && (
        <div className="text-xs space-y-1">
          <div className="flex gap-1">
            <select aria-label="Relation kind" className="input" value={kind} onChange={(e) => setKind(e.target.value)}>{["uses", "indicates", "attributed-to", "part-of"].map((k) => <option key={k}>{k}</option>)}</select>
            <input aria-label="Search entity to relate" className="input w-64" placeholder="Find an entity to relate…" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {found.data && (
            <ul className="panel w-96">
              {found.data.filter((e) => e.id !== d.entity.id).map((e) => (
                <li key={e.id} className="px-2 py-0.5 flex items-center gap-2"><span className="flex-1 truncate font-mono">{e.type}: {e.value}</span><button className="btn py-0 text-xs" onClick={() => add.mutate(e.id)}>Relate</button></li>
              ))}
            </ul>
          )}
          <ErrorLine error={add.error ?? del.error} fallback="Relation change failed" />
        </div>
      )}
    </Section>
  );
}

export function EntityView({ id }: { id: string }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const router = useRouter();
  const [defanged, setDefanged] = useState(true);
  const [coverage, setCoverage] = useState<IntelCoverage | null>(null);
  const q = useQuery({ queryKey: ["intel-entity", id], queryFn: () => api.getEntity(id), retry: false });
  const enrich = useMutation({
    mutationFn: (refresh: boolean) => api.enrichEntity(id, refresh),
    onSuccess: (r) => { setCoverage(r.coverage); qc.setQueryData(["intel-entity", id], r); void qc.invalidateQueries({ queryKey: ["intel-sightings", id] }); },
  });
  const del = useMutation({ mutationFn: () => api.deleteEntity(id), onSuccess: () => router.push("/threat-intel") });

  if (q.isLoading) return <p className="text-muted">Loading entity…</p>;
  if (q.error || !q.data) return <p role="alert" className="panel p-3 text-red-400">{q.error instanceof ApiError && q.error.status === 404 ? "Entity not found." : q.error instanceof ApiError ? q.error.friendly : "Failed to load entity"}</p>;
  const d = q.data, e = d.entity;
  const canWrite = can("intel:write");
  const shown = defanged ? defangEntity(e.type, e.value) : e.value;
  const cov = coverage ?? d.coverage;

  return (
    <div className="space-y-2">
      <div className="panel p-3 flex items-center gap-3 flex-wrap">
        <span className="text-xs border border-line px-1 rounded-sm">{ENTITY_LABEL[e.type] ?? e.type}</span>
        <h1 className="font-mono text-base break-all">{shown}</h1>
        <CopyButton text={shown} />
        <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={defanged} onChange={(x) => setDefanged(x.target.checked)} /> defang</label>
        <span className="ml-auto flex items-center gap-3"><VerdictBadge verdict={e.verdict} /><ScoreBar score={e.score} wide /></span>
      </div>
      <div className="flex items-center gap-2 text-xs">
        <button className="btn" disabled={!canWrite || enrich.isPending} onClick={() => enrich.mutate(false)}>{enrich.isPending ? "Enriching…" : "Enrich"}</button>
        <button className="btn" disabled={!canWrite || enrich.isPending} onClick={() => enrich.mutate(true)} title="Ignore cached provider results">Force refresh</button>
        <span className="text-muted">Last enriched {e.last_enriched_at ? fmtTime(e.last_enriched_at) : "never"} · source {e.source}</span>
        <button className="btn ml-auto" disabled={!canWrite} onClick={() => { if (confirm(`Delete entity “${e.value}”?`)) del.mutate(); }}>Delete</button>
      </div>
      <ErrorLine error={enrich.error ?? del.error} fallback="Request failed" />
      {cov && <p className="text-xs text-muted" aria-label="Provider coverage">Coverage: {coverageLine(cov)}</p>}
      <div className="grid xl:grid-cols-2 gap-2">
        <Breakdown d={d} />
        <WatchEditor key={`${e.updated_at}`} d={d} canWrite={canWrite} />
      </div>
      <Observations obs={d.observations} />
      {can("events:read") && <SightingsPanel id={id} value={e.value} />}
      <Relations d={d} canWrite={canWrite} />
    </div>
  );
}
