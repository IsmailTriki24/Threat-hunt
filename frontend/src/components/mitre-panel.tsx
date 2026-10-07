"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api";
import { CONFIDENCES, type Confidence, type MitreMapping, type MitreObjectType, type MitreSuggestion } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { acceptDraft, mappingPayload, validateDraft, type AcceptDraft } from "@/lib/intel";
import { ErrorLine, Modal } from "./badges";
import { EventDrawer } from "./event-drawer";
import { ConfidenceBadge, Section } from "./intel-bits";

export interface MapTarget { type: MitreObjectType; id: string; label: string }

/** Compact technique chips for list/overview pages (unique techniques, strongest first). */
export function TechniqueChips({ mappings, max = 6 }: { mappings: Array<Pick<MitreMapping, "technique_id" | "technique_name" | "confidence">>; max?: number }) {
  const rank: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const best = new Map<string, (typeof mappings)[number]>();
  for (const m of mappings) { const cur = best.get(m.technique_id); if (!cur || rank[m.confidence] > rank[cur.confidence]) best.set(m.technique_id, m); }
  const list = [...best.values()].sort((a, b) => rank[b.confidence] - rank[a.confidence] || a.technique_id.localeCompare(b.technique_id));
  if (!list.length) return null;
  return (
    <span className="inline-flex flex-wrap gap-1" aria-label="MITRE techniques">
      {list.slice(0, max).map((m) => (
        <Link key={m.technique_id} href={`/mitre/techniques/${m.technique_id}`} title={`${m.technique_name} (${m.confidence})`}
          className="font-mono text-xs border border-line px-1 rounded-sm hover:text-accent">{m.technique_id}</Link>
      ))}
      {list.length > max && <span className="text-xs text-muted">+{list.length - max}</span>}
    </span>
  );
}

export function ObjectTechniqueChips({ objectType, objectId }: { objectType: MitreObjectType; objectId: string }) {
  const { can } = useAuth();
  const q = useQuery({ queryKey: ["mitre-mappings", objectType, objectId], queryFn: () => api.mitreMappings(`?object_type=${objectType}&object_id=${objectId}`), enabled: can("mitre:read") });
  return q.data?.length ? <p className="text-xs flex items-center gap-2 flex-wrap"><span className="text-muted uppercase">ATT&amp;CK</span><TechniqueChips mappings={q.data} /></p> : null;
}
export const CaseTechniqueChips = ({ caseId }: { caseId: string }) => <ObjectTechniqueChips objectType="case" objectId={caseId} />;

function AcceptDialog({ s, targets, onClose, onDone }: { s: MitreSuggestion; targets: MapTarget[]; onClose: () => void; onDone: () => void }) {
  const [draft, setDraft] = useState<AcceptDraft>(() => acceptDraft(s));
  const [target, setTarget] = useState(targets[0]);
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: async () => {
      const problem = validateDraft(draft);
      if (problem) { setError(problem); throw new Error("invalid"); }
      setError(null);
      return api.createMapping(mappingPayload(s, draft, target.type, target.id));
    },
    onSuccess: onDone,
  });
  return (
    <Modal title={`Map ${s.technique_id} — ${s.name}`} onClose={onClose} wide>
      <form className="space-y-2" aria-label="Accept suggestion" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
        {targets.length > 1 && (
          <label className="block">Map to <select className="input ml-1" aria-label="Map to" value={`${target.type}:${target.id}`} onChange={(e) => setTarget(targets.find((t) => `${t.type}:${t.id}` === e.target.value) ?? targets[0])}>
            {targets.map((t) => <option key={`${t.type}:${t.id}`} value={`${t.type}:${t.id}`}>{t.label}</option>)}
          </select></label>
        )}
        <label className="block">Confidence <select className="input ml-1" aria-label="Confidence" value={draft.confidence} onChange={(e) => setDraft({ ...draft, confidence: e.target.value as Confidence })}>{CONFIDENCES.map((c) => <option key={c}>{c}</option>)}</select></label>
        <label className="block">Reasoning (editable — say why this applies)
          <textarea aria-label="Reasoning" className="input w-full mt-0.5" rows={5} maxLength={5000} value={draft.reasoning} onChange={(e) => setDraft({ ...draft, reasoning: e.target.value })} />
        </label>
        <p className="text-xs text-muted">Evidence: {draft.evidence.length} event{draft.evidence.length === 1 ? "" : "s"} will be cited. MEDIUM and HIGH require at least one.</p>
        {error && <p role="alert" className="text-red-400 text-xs">{error}</p>}
        <ErrorLine error={create.error instanceof Error && create.error.message === "invalid" ? null : create.error} fallback="Mapping failed" />
        <div className="flex gap-1"><button className="btn btn-primary" type="submit" disabled={create.isPending}>Accept mapping</button><button className="btn" type="button" onClick={onClose}>Cancel</button></div>
      </form>
    </Modal>
  );
}

/** Mapped techniques + rule-based suggestions for a case or hunt. */
export function MitrePanel({ source, targets, mutable }: { source: { case_id: string } | { hunt_id: string }; targets: MapTarget[]; mutable: boolean }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const main = targets[0];
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [accepting, setAccepting] = useState<MitreSuggestion | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const mapKey = ["mitre-mappings", main.type, main.id];
  const mappings = useQuery({ queryKey: mapKey, queryFn: () => api.mitreMappings(`?object_type=${main.type}&object_id=${main.id}`) });
  const findingMaps = useQuery({
    queryKey: ["mitre-mappings", "findings", main.id], enabled: targets.length > 1,
    queryFn: async () => (await Promise.all(targets.slice(1).map((t) => api.mitreMappings(`?object_type=${t.type}&object_id=${t.id}`)))).flat(),
  });
  const suggest = useMutation({ mutationFn: () => api.mitreSuggest(source), onSuccess: () => setDismissed(new Set()) });
  const del = useMutation({ mutationFn: (id: string) => api.deleteMapping(id), onSuccess: () => { void qc.invalidateQueries({ queryKey: ["mitre-mappings"] }); void qc.invalidateQueries({ queryKey: ["mitre-matrix"] }); } });
  const canMap = can("mitre:write") && mutable;
  const accepted = (t: string) => (mappings.data ?? []).some((m) => m.technique_id === t);
  const done = () => { setAccepting(null); void qc.invalidateQueries({ queryKey: ["mitre-mappings"] }); void qc.invalidateQueries({ queryKey: ["mitre-matrix"] }); suggest.mutate(); };
  const rows = [...(mappings.data ?? []), ...(findingMaps.data ?? [])];
  const visible = (suggest.data?.suggestions ?? []).filter((s) => !dismissed.has(s.technique_id));

  return (
    <div className="space-y-3">
      <Section title={`Mapped techniques (${rows.length})`}>
        <ErrorLine error={mappings.error ?? del.error} fallback="Failed to load mappings" />
        {rows.length === 0 ? <p className="text-muted">No techniques mapped yet. Mappings need reasoning and, above LOW confidence, evidence.</p> : (
          <ul className="space-y-1">
            {rows.map((m) => (
              <li key={m.id} className="border border-line p-2 space-y-0.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <Link className="font-mono text-accent hover:underline" href={`/mitre/techniques/${m.technique_id}`}>{m.technique_id}</Link>
                  <strong>{m.technique_name}</strong><span className="text-xs text-muted">{m.tactics.join(", ")}</span>
                  <ConfidenceBadge level={m.confidence} /><span className="text-xs border border-line px-1 rounded-sm">{m.source}</span>
                  {m.object_type === "finding" && <span className="text-xs text-muted">(finding)</span>}
                  <button className="btn py-0 text-xs ml-auto" aria-label={`Remove mapping ${m.technique_id}`} disabled={!canMap} onClick={() => del.mutate(m.id)}>Remove</button>
                </div>
                <p className="text-xs whitespace-pre-wrap">{m.reasoning}</p>
                <p className="text-xs text-muted">Evidence: {m.evidence_count} event{m.evidence_count === 1 ? "" : "s"}
                  {m.evidence_event_ids.slice(0, 5).map((id) => <button key={id} className="ml-2 text-accent hover:underline font-mono" onClick={() => setOpen(id)}>{id.slice(0, 8)}</button>)}</p>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Suggested techniques" actions={<button className="btn" disabled={!can("mitre:write") || suggest.isPending} onClick={() => suggest.mutate()}>{suggest.isPending ? "Analysing…" : "Suggest techniques"}</button>}>
        <p className="text-xs text-yellow-300">Suggestions are rule-based hints derived from event fields — verify them against the evidence before accepting. They are not verdicts.</p>
        <ErrorLine error={suggest.error} fallback="Suggestion failed" />
        {suggest.data && <p className="text-xs text-muted">Analysed {suggest.data.analyzed_events} events · {visible.length} suggestion{visible.length === 1 ? "" : "s"}</p>}
        <ul className="space-y-1">
          {visible.map((s) => (
            <li key={s.technique_id} className="border border-line p-2 space-y-0.5">
              <div className="flex items-center gap-2 flex-wrap">
                <Link className="font-mono text-accent hover:underline" href={`/mitre/techniques/${s.technique_id}`}>{s.technique_id}</Link><strong>{s.name}</strong>
                <ConfidenceBadge level={s.confidence} /><span className="text-xs text-muted">{s.event_count} event{s.event_count === 1 ? "" : "s"}</span>
                <span className="ml-auto flex gap-1">
                  {s.mapped || accepted(s.technique_id) ? <span className="text-xs text-green-400">mapped ✓</span> : (
                    <button className="btn py-0 text-xs" disabled={!canMap} aria-label={`Accept ${s.technique_id}`} onClick={() => setAccepting(s)} title={canMap ? "" : "Requires mitre:write and write access to this object"}>Accept…</button>
                  )}
                  <button className="btn py-0 text-xs" aria-label={`Dismiss ${s.technique_id}`} onClick={() => setDismissed(new Set([...dismissed, s.technique_id]))}>Dismiss</button>
                </span>
              </div>
              <ul className="text-xs list-disc ml-5">{s.reasoning.map((r, i) => <li key={i}>{r}</li>)}</ul>
              <p className="text-xs text-muted">{s.hosts.length > 0 && `Hosts: ${s.hosts.join(", ")}`}{s.users.length > 0 && ` · Users: ${s.users.join(", ")}`}
                {s.event_ids.slice(0, 3).map((id) => <button key={id} className="ml-2 text-accent hover:underline font-mono" onClick={() => setOpen(id)}>{id.slice(0, 8)}</button>)}</p>
            </li>
          ))}
        </ul>
      </Section>
      {accepting && <AcceptDialog s={accepting} targets={targets} onClose={() => setAccepting(null)} onDone={done} />}
      {open && <EventDrawer id={open} onClose={() => setOpen(null)} onPivot={() => setOpen(null)} />}
    </div>
  );
}
