"use client";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { MatrixTechnique } from "@/lib/api-types";
import { cellClass, filterMatrix, mapHref, matrixTotals, RISK_CLASS, summaryLine } from "@/lib/intel";
import { ConfidenceBadge, Section } from "./intel-bits";

const attackUrl = (id: string): string => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

function TechniqueCell({ t }: { t: MatrixTechnique }) {
  const [open, setOpen] = useState(false);
  return (
    <li>
      <div className={`border text-xs flex items-stretch ${cellClass(t)}`}>
        <Link href={`/mitre/techniques/${t.id}`} className="flex-1 px-1 py-0.5 hover:underline" title={t.mapping_count ? `${t.mapping_count} mapping(s), top confidence ${t.top_confidence}` : "No mappings"}>
          <span className="font-mono">{t.id}</span> {t.name}{t.mapping_count > 0 && <span className="ml-1 tabular-nums">({t.mapping_count})</span>}
        </Link>
        {t.subtechniques.length > 0 && (
          <button className="px-1 border-l border-line" aria-expanded={open} aria-label={`${open ? "Collapse" : "Expand"} sub-techniques of ${t.id}`} onClick={() => setOpen(!open)}>{open ? "▾" : "▸"}{t.subtechniques.length}</button>
        )}
      </div>
      {open && (
        <ul className="ml-3 mt-0.5 space-y-0.5">
          {t.subtechniques.map((s) => (
            <li key={s.id} className={`border text-xs px-1 py-0.5 ${cellClass(s)}`}>
              <Link href={`/mitre/techniques/${s.id}`} className="hover:underline"><span className="font-mono">{s.id}</span> {s.name}{s.mapping_count > 0 && <span className="ml-1 tabular-nums">({s.mapping_count})</span>}</Link>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function MatrixView() {
  const [query, setQuery] = useState("");
  const [mappedOnly, setMappedOnly] = useState(false);
  const m = useQuery({ queryKey: ["mitre-matrix"], queryFn: api.mitreMatrix, retry: false });
  if (m.isLoading) return <p className="text-muted">Loading matrix…</p>;
  if (m.error || !m.data) return <p role="alert" className="panel p-3 text-red-400">{m.error instanceof ApiError ? m.error.friendly : "Failed to load matrix"}</p>;
  const cols = filterMatrix(m.data, query, mappedOnly);
  const totals = matrixTotals(m.data);
  return (
    <div className="space-y-2">
      <h1 className="text-base font-semibold">MITRE ATT&amp;CK</h1>
      <div className="flex items-center gap-3 text-xs flex-wrap">
        <input aria-label="Filter techniques" className="input w-64" placeholder="Filter by id or name…" value={query} onChange={(e) => setQuery(e.target.value)} />
        <label className="flex items-center gap-1"><input type="checkbox" checked={mappedOnly} onChange={(e) => setMappedOnly(e.target.checked)} /> mapped only</label>
        <span className="text-muted">{totals.mapped} of {totals.techniques} techniques mapped in this tenant</span>
        <ul aria-label="Legend" className="ml-auto flex gap-2">
          {(["HIGH", "MEDIUM", "LOW"] as const).map((c) => <li key={c} className={`border px-1 ${cellClass({ mapping_count: 1, top_confidence: c })}`}>{c} confidence</li>)}
          <li className="border px-1 border-line text-muted">unmapped</li>
        </ul>
      </div>
      <p className="text-xs text-muted">Mappings are analyst-confirmed claims backed by reasoning and evidence. The reference set is a curated subset unless the full ATT&amp;CK bundle has been loaded.</p>
      <div className="flex gap-2 overflow-x-auto pb-2">
        {cols.map((c) => (
          <section key={c.tactic.id} aria-label={c.tactic.name} className="w-56 shrink-0">
            <h2 className="text-xs uppercase text-muted border-b border-line mb-1 pb-0.5">{c.tactic.name} <span className="tabular-nums">({c.techniques.length})</span></h2>
            <ul className="space-y-0.5">{c.techniques.map((t) => <TechniqueCell key={t.id} t={t} />)}</ul>
          </section>
        ))}
      </div>
    </div>
  );
}

export function TechniqueView({ id }: { id: string }) {
  const tech = useQuery({ queryKey: ["mitre-technique", id], queryFn: () => api.mitreTechnique(id), retry: false });
  const summary = useQuery({ queryKey: ["mitre-summary", id], queryFn: () => api.mitreSummary(id), retry: false });
  if (tech.isLoading) return <p className="text-muted">Loading technique…</p>;
  if (tech.error || !tech.data) return <p role="alert" className="panel p-3 text-red-400">{tech.error instanceof ApiError && tech.error.status === 404 ? "Technique not found." : "Failed to load technique"}</p>;
  const t = tech.data;
  const s = summary.data;
  return (
    <div className="space-y-2">
      <h1 className="text-base font-semibold"><span className="font-mono text-muted">{t.id}</span> {t.name}</h1>
      <p className="text-xs">Tactics: {t.tactics.join(", ")} · <a className="text-accent hover:underline" href={attackUrl(t.id)} target="_blank" rel="noopener noreferrer">View on attack.mitre.org ↗</a></p>
      <Section title="Description"><p className="whitespace-pre-wrap">{t.description || "No description."}</p></Section>
      {t.subtechniques && t.subtechniques.length > 0 && (
        <Section title="Sub-techniques"><ul>{t.subtechniques.map((x) => <li key={x.id}><Link className="text-accent hover:underline" href={`/mitre/techniques/${x.id}`}>{x.id} {x.name}</Link></li>)}</ul></Section>
      )}
      <Section title="Your evidence">
        {summary.error && <p role="alert" className="text-red-400 text-xs">{summary.error instanceof ApiError ? summary.error.friendly : "Failed to load summary"}</p>}
        {s && (
          <div className="space-y-1">
            <p className="text-sm" aria-label="Technique summary">{summaryLine(s).split(" · ").map((part, i, arr) => (
              <span key={part}>{part.startsWith("Risk:") ? <>Risk: <strong className={RISK_CLASS[s.risk]}>{s.risk}</strong></> : part}{i < arr.length - 1 ? " · " : ""}</span>
            ))}</p>
            {s.risk_reasons.length > 0 && <ul className="text-xs text-muted list-disc ml-4">{s.risk_reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
            {s.hosts.names.length > 0 && <p className="text-xs">Hosts: {s.hosts.names.join(", ")}</p>}
            {s.users.names.length > 0 && <p className="text-xs">Users: {s.users.names.join(", ")}</p>}
            <h3 className="text-xs text-muted uppercase pt-1">Mapped by ({s.mappings})</h3>
            {s.objects.length === 0 ? <p className="text-muted">Not mapped to any case or hunt yet.</p> : (
              <ul>{s.objects.map((o) => {
                const href = mapHref(o.object_type, o.object_id);
                return <li key={`${o.object_type}${o.object_id}`} className="flex items-center gap-2"><span className="text-xs border border-line px-1 rounded-sm">{o.object_type}</span>{href ? <Link className="text-accent hover:underline" href={href}>{o.title}</Link> : <span>{o.title}</span>}<ConfidenceBadge level={o.confidence} /></li>;
              })}</ul>
            )}
          </div>
        )}
      </Section>
    </div>
  );
}
