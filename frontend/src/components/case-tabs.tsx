"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import { IOC_TYPES, type CaseOut, type IocType } from "@/lib/api-types";
import { defang, describeActivity, mergeJournal } from "@/lib/cases";
import { downloadBlob } from "@/lib/hunt-query";
import { fmtTime } from "@/lib/query";
import { ErrorLine, CopyButton, LevelBadge } from "./badges";
import { EventDrawer } from "./event-drawer";
import { TimelineList } from "./timeline-view";

const invalidate = (qc: ReturnType<typeof useQueryClient>, id: string, ...keys: string[]) => {
  for (const k of ["case", "cases", ...keys]) void qc.invalidateQueries({ queryKey: k === "cases" ? ["cases"] : [k, id] });
  void qc.invalidateQueries({ queryKey: ["case-activity", id] });
};

export function OverviewTab({ c }: { c: CaseOut }) {
  return (
    <div className="grid md:grid-cols-3 gap-3">
      <section className="panel p-3 md:col-span-2 space-y-2">
        <h2 className="text-xs text-muted uppercase">Description</h2>
        <p className="whitespace-pre-wrap">{c.description || <span className="text-muted">No description.</span>}</p>
        {c.resolution && (<><h2 className="text-xs text-muted uppercase">Resolution</h2><p className="whitespace-pre-wrap">{c.resolution}</p></>)}
        {c.hunt_id && <p className="text-xs"><Link className="text-accent hover:underline" href={`/hunts/${c.hunt_id}`}>Originating hunt →</Link></p>}
      </section>
      <section className="panel p-3">
        <h2 className="text-xs text-muted uppercase mb-1">Summary</h2>
        <dl className="grid grid-cols-[7rem_1fr]">
          <dt className="text-muted">Status</dt><dd>{c.status}</dd>
          <dt className="text-muted">Severity</dt><dd><LevelBadge level={c.severity} /></dd>
          <dt className="text-muted">Priority</dt><dd>{c.priority}</dd>
          <dt className="text-muted">Evidence</dt><dd className="tabular-nums">{c.evidence_count}</dd>
          <dt className="text-muted">IOCs</dt><dd className="tabular-nums">{c.ioc_count}</dd>
          <dt className="text-muted">Assets</dt><dd className="tabular-nums">{c.asset_count}</dd>
        </dl>
      </section>
    </div>
  );
}

export function TimelineTab({ caseId }: { caseId: string }) {
  const [collapse, setCollapse] = useState(true);
  const [merged, setMerged] = useState(true);
  const [open, setOpen] = useState<string | null>(null);
  const tl = useQuery({ queryKey: ["case-timeline", caseId, collapse], queryFn: () => api.caseTimeline(caseId, collapse) });
  const act = useQuery({ queryKey: ["case-activity", caseId], queryFn: () => api.caseActivity(caseId) });
  const evidence = useQuery({ queryKey: ["case-evidence", caseId], queryFn: () => api.caseEvidence(caseId) });
  const snapshotFor = (eid: string) => evidence.data?.find((e) => e.event_id === eid)?.snapshot;
  const items = mergeJournal(tl.data, act.data);
  const lineage = tl.data ? { ...tl.data, entries: tl.data.entries } : undefined;

  return (
    <div className="space-y-2">
      <div className="flex gap-3 text-xs items-center">
        <label className="flex items-center gap-1"><input type="checkbox" checked={collapse} onChange={(e) => setCollapse(e.target.checked)} /> Collapse repeated activity</label>
        <label className="flex items-center gap-1"><input type="checkbox" checked={merged} onChange={(e) => setMerged(e.target.checked)} /> Interleave case journal</label>
        <span className="text-muted ml-auto">Telemetry is rebuilt from live events where retained, otherwise from stored snapshots.</span>
      </div>
      {tl.isLoading && <p className="text-muted">Building timeline…</p>}
      <ErrorLine error={tl.error} fallback="Timeline failed" />
      {lineage && !merged && <TimelineList timeline={lineage} onOpen={setOpen} />}
      {lineage && merged && (
        <ol className="space-y-0.5" aria-label="Merged timeline">
          {items.map((it, i) => it.kind === "journal" && it.activity ? (
            <li key={`j-${it.activity.id}`} data-testid="journal-item" className="border-l-2 border-accent bg-bg px-2 py-1 text-xs">
              <span className="font-mono text-muted mr-2">{fmtTime(it.at)}</span>
              <span className="text-accent mr-2">journal · {it.activity.kind.replace(/_/g, " ")}</span>
              <span className="whitespace-pre-wrap">{describeActivity(it.activity)}</span>
              {it.activity.actor_email && <span className="text-muted"> — {it.activity.actor_email}</span>}
            </li>
          ) : it.entry ? (
            <li key={`t-${it.entry.id}-${i}`} data-testid="telemetry-item" className="panel px-2 py-1 text-xs">
              <span className="font-mono text-muted mr-2">{fmtTime(it.at)}</span>
              <button className="hover:text-accent text-left" onClick={() => setOpen(it.entry!.event_ids[0])}>{it.entry.title}</button>
              <span className="text-muted ml-2">{[it.entry.host, it.entry.user, it.entry.destination && `→ ${it.entry.destination}`].filter(Boolean).join(" · ")}</span>
            </li>
          ) : null)}
        </ol>
      )}
      {open && <EventDrawer id={open} snapshot={snapshotFor(open)} onClose={() => setOpen(null)} onPivot={() => setOpen(null)} />}
    </div>
  );
}

export function EvidenceTab({ caseId, mutable }: { caseId: string; mutable: boolean }) {
  const qc = useQueryClient();
  const [ids, setIds] = useState("");
  const [comment, setComment] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const ev = useQuery({ queryKey: ["case-evidence", caseId], queryFn: () => api.caseEvidence(caseId) });
  const add = useMutation({
    mutationFn: () => api.addCaseEvidence(caseId, ids.split(/[\s,]+/).filter(Boolean), comment),
    onSuccess: () => { setIds(""); setComment(""); void qc.invalidateQueries({ queryKey: ["case-evidence", caseId] }); invalidate(qc, caseId, "case-timeline", "case-iocs", "case-assets"); },
  });
  const remove = useMutation({
    mutationFn: (eid: string) => api.removeCaseEvidence(caseId, eid),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["case-evidence", caseId] }); invalidate(qc, caseId, "case-timeline"); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (ids.trim()) add.mutate(); };
  const open_ = ev.data?.find((e) => e.event_id === open);

  return (
    <div className="space-y-2">
      <form onSubmit={submit} className="flex gap-1 items-center text-xs" aria-label="Add evidence">
        <input aria-label="Event ids" className="input flex-1 font-mono" placeholder="Paste event ids (or use “Add to case…” in the event drawer)" value={ids} disabled={!mutable} onChange={(e) => setIds(e.target.value)} />
        <input aria-label="Evidence comment" className="input w-56" placeholder="Comment" value={comment} disabled={!mutable} onChange={(e) => setComment(e.target.value)} />
        <button className="btn" type="submit" disabled={!mutable || !ids.trim() || add.isPending}>Add evidence</button>
      </form>
      <ErrorLine error={add.error ?? remove.error} fallback="Evidence change failed" />
      {ev.isLoading && <p className="text-muted">Loading…</p>}
      {ev.data && (ev.data.length === 0 ? <p className="panel p-3 text-muted">No evidence attached yet.</p> : (
        <table className="w-full">
          <thead><tr>{["Time (UTC)", "Event", "Host", "Comment", ""].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {ev.data.map((e) => (
              <tr key={e.id} className="hover:bg-bg">
                <td className="td font-mono whitespace-nowrap">{fmtTime(e.snapshot.timestamp)}</td>
                <td className="td"><button className="hover:text-accent text-left" onClick={() => setOpen(e.event_id)}>{e.summary}</button></td>
                <td className="td">{e.snapshot.host?.hostname ?? ""}</td>
                <td className="td text-muted">{e.comment}</td>
                <td className="td"><button className="btn py-0 text-xs" disabled={!mutable} aria-label={`Remove evidence ${e.event_id.slice(0, 8)}`} onClick={() => remove.mutate(e.id)}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
      {open_ && <EventDrawer id={open_.event_id} snapshot={open_.snapshot} onClose={() => setOpen(null)} onPivot={() => setOpen(null)} />}
    </div>
  );
}

export function IocsTab({ caseId, mutable }: { caseId: string; mutable: boolean }) {
  const qc = useQueryClient();
  const [type, setType] = useState<IocType>("ip");
  const [value, setValue] = useState("");
  const [defanged, setDefanged] = useState(true);
  const iocs = useQuery({ queryKey: ["case-iocs", caseId], queryFn: () => api.caseIocs(caseId) });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["case-iocs", caseId] }); invalidate(qc, caseId); };
  const add = useMutation({ mutationFn: () => api.addCaseIoc(caseId, type, value.trim()), onSuccess: () => { setValue(""); refresh(); } });
  const remove = useMutation({ mutationFn: (id: string) => api.removeCaseIoc(caseId, id), onSuccess: refresh });
  const extract = useMutation({ mutationFn: () => api.extractCaseIocs(caseId), onSuccess: refresh });
  const submit = (e: FormEvent) => { e.preventDefault(); if (value.trim()) add.mutate(); };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs flex-wrap">
        <form onSubmit={submit} className="flex gap-1" aria-label="Add IOC">
          <select aria-label="IOC type" className="input" value={type} onChange={(e) => setType(e.target.value as IocType)} disabled={!mutable}>{IOC_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
          <input aria-label="IOC value" className="input w-80 font-mono" value={value} disabled={!mutable} onChange={(e) => setValue(e.target.value)} placeholder="indicator value" />
          <button className="btn" type="submit" disabled={!mutable || !value.trim() || add.isPending}>Add IOC</button>
        </form>
        <button className="btn" disabled={!mutable || extract.isPending} onClick={() => extract.mutate()}>Re-extract from evidence</button>
        <label className="ml-auto flex items-center gap-1"><input type="checkbox" checked={defanged} onChange={(e) => setDefanged(e.target.checked)} /> Defang display</label>
      </div>
      <ErrorLine error={add.error ?? remove.error ?? extract.error} fallback="IOC change failed" />
      {iocs.data && (iocs.data.length === 0 ? <p className="panel p-3 text-muted">No indicators yet. Attach evidence or add one manually.</p> : (
        <table className="w-full">
          <thead><tr>{["Type", "Value", "Source", "Seen", "Context", ""].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {iocs.data.map((i) => {
              const shown = defanged ? defang(i.type, i.value) : i.value;
              return (
                <tr key={i.id} className="hover:bg-bg">
                  <td className="td">{i.type}</td>
                  <td className="td font-mono break-all">{shown} <CopyButton text={shown} /></td>
                  <td className="td">{i.source}</td>
                  <td className="td tabular-nums">{i.occurrences}</td>
                  <td className="td text-muted">{i.context}</td>
                  <td className="td"><button className="btn py-0 text-xs" disabled={!mutable} aria-label={`Remove IOC ${i.value}`} onClick={() => remove.mutate(i.id)}>Remove</button></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ))}
    </div>
  );
}

export function AssetsTab({ caseId, mutable }: { caseId: string; mutable: boolean }) {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const linked = useQuery({ queryKey: ["case-assets", caseId], queryFn: () => api.caseAssets(caseId) });
  const found = useQuery({ queryKey: ["asset-search", search], queryFn: () => api.listAssets(`?q=${encodeURIComponent(search.trim())}&limit=10`), enabled: search.trim().length >= 2 });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["case-assets", caseId] }); invalidate(qc, caseId); };
  const link = useMutation({ mutationFn: (aid: string) => api.linkCaseAsset(caseId, aid), onSuccess: refresh });
  const unlink = useMutation({ mutationFn: (aid: string) => api.unlinkCaseAsset(caseId, aid), onSuccess: refresh });
  const linkedIds = new Set((linked.data ?? []).map((a) => a.id));

  return (
    <div className="space-y-2">
      <div className="text-xs">
        <input aria-label="Search assets to link" className="input w-72" placeholder="Search assets to link…" value={search} disabled={!mutable} onChange={(e) => setSearch(e.target.value)} />
        {found.data && (
          <ul className="panel mt-1 w-72">
            {found.data.length === 0 && <li className="px-2 py-1 text-muted">No assets match.</li>}
            {found.data.map((a) => (
              <li key={a.id} className="px-2 py-0.5 flex items-center gap-2">
                <span className="flex-1 truncate">{a.type}: {a.display_name}</span>
                <button className="btn py-0 text-xs" disabled={linkedIds.has(a.id) || link.isPending} onClick={() => link.mutate(a.id)}>{linkedIds.has(a.id) ? "Linked" : "Link"}</button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <ErrorLine error={link.error ?? unlink.error} fallback="Asset change failed" />
      {linked.data && (linked.data.length === 0 ? <p className="panel p-3 text-muted">No assets linked.</p> : (
        <table className="w-full">
          <thead><tr>{["Type", "Asset", "Criticality", "Last seen", ""].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {linked.data.map((a) => (
              <tr key={a.id} className="hover:bg-bg">
                <td className="td">{a.type}</td>
                <td className="td"><Link className="text-accent hover:underline" href={`/assets/${a.id}`}>{a.display_name}</Link></td>
                <td className="td"><LevelBadge level={a.criticality} /></td>
                <td className="td font-mono">{a.last_seen ? fmtTime(a.last_seen) : ""}</td>
                <td className="td"><button className="btn py-0 text-xs" disabled={!mutable} aria-label={`Unlink ${a.display_name}`} onClick={() => unlink.mutate(a.id)}>Unlink</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}

export function JournalTab({ caseId, canWrite }: { caseId: string; canWrite: boolean }) {
  const qc = useQueryClient();
  const [body, setBody] = useState("");
  const act = useQuery({ queryKey: ["case-activity", caseId], queryFn: () => api.caseActivity(caseId) });
  const add = useMutation({ mutationFn: () => api.addCaseNote(caseId, body.trim()), onSuccess: () => { setBody(""); void qc.invalidateQueries({ queryKey: ["case-activity", caseId] }); } });
  const submit = (e: FormEvent) => { e.preventDefault(); if (body.trim()) add.mutate(); };
  return (
    <div className="space-y-2 max-w-3xl">
      <form onSubmit={submit} className="space-y-1" aria-label="Add note">
        <textarea aria-label="Note" className="input w-full" rows={3} maxLength={20000} placeholder="Add a note (plain text)" value={body} disabled={!canWrite} onChange={(e) => setBody(e.target.value)} />
        <button className="btn btn-primary" type="submit" disabled={!canWrite || !body.trim() || add.isPending}>Add note</button>
        <ErrorLine error={add.error} fallback="Failed to add note" />
      </form>
      <ol className="space-y-1">
        {(act.data ?? []).map((a) => (
          <li key={a.id} className={`panel p-2 text-xs ${a.kind === "note" ? "" : "text-muted"}`}>
            <div className="flex gap-2"><span className="font-mono">{fmtTime(a.created_at)}</span><span>{a.actor_email ?? "system"}</span><span className="ml-auto uppercase">{a.kind.replace(/_/g, " ")}</span></div>
            <p className="whitespace-pre-wrap text-[#c9d1d9]">{describeActivity(a)}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function ReportsTab({ caseId, canWrite, caseNumber }: { caseId: string; canWrite: boolean; caseNumber: string }) {
  const qc = useQueryClient();
  const [version, setVersion] = useState<number | null>(null);
  const reports = useQuery({ queryKey: ["case-reports", caseId], queryFn: () => api.caseReports(caseId) });
  const gen = useMutation({
    mutationFn: () => api.generateReport(caseId),
    onSuccess: (r) => { setVersion(r.version); void qc.invalidateQueries({ queryKey: ["case-reports", caseId] }); void qc.invalidateQueries({ queryKey: ["case-activity", caseId] }); },
  });
  const current = reports.data?.find((r) => r.version === (version ?? reports.data?.[0]?.version));
  return (
    <div className="space-y-2">
      <div className="flex gap-2 items-center text-xs">
        <button className="btn btn-primary" disabled={!canWrite || gen.isPending} onClick={() => gen.mutate()}>Generate new version</button>
        {reports.data?.map((r) => (
          <button key={r.id} className={`btn py-0 ${current?.version === r.version ? "border-accent text-accent" : ""}`} onClick={() => setVersion(r.version)}>v{r.version}</button>
        ))}
        {current && (
          <span className="ml-auto flex gap-1">
            <CopyButton text={current.content} label="Copy markdown" />
            <button className="btn py-0 text-xs" onClick={() => downloadBlob(new Blob([current.content], { type: "text/markdown" }), `${caseNumber}-report-v${current.version}.md`)}>Download .md</button>
          </span>
        )}
      </div>
      <ErrorLine error={gen.error} fallback="Report generation failed" />
      {current ? (
        <div>
          <p className="text-xs text-muted mb-1">Version {current.version} · generated {fmtTime(current.created_at)}</p>
          <pre className="panel p-3 text-xs whitespace-pre-wrap break-words max-h-[60vh] overflow-y-auto">{current.content}</pre>
        </div>
      ) : <p className="panel p-3 text-muted">No reports yet. Generate one to snapshot the case as Markdown.</p>}
    </div>
  );
}

export function AuditTab({ caseId }: { caseId: string }) {
  const a = useQuery({ queryKey: ["case-audit", caseId], queryFn: () => api.caseAudit(caseId) });
  return (
    <div>
      <ErrorLine error={a.error} fallback="Failed to load audit trail" />
      {a.data && (a.data.length === 0 ? <p className="panel p-3 text-muted">No audit records.</p> : (
        <table className="w-full">
          <thead><tr>{["Time (UTC)", "Action", "Outcome", "Actor", "IP", "Details"].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {a.data.map((r) => (
              <tr key={r.id}>
                <td className="td font-mono whitespace-nowrap">{fmtTime(r.created_at)}</td><td className="td">{r.action}</td><td className="td">{r.outcome}</td>
                <td className="td">{r.actor}</td><td className="td font-mono">{r.ip}</td><td className="td font-mono text-xs text-muted">{JSON.stringify(r.details)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}
