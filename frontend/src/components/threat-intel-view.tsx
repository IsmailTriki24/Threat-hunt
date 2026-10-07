"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import { ENTITY_TYPES, type EntityType, type IntelProvider, type StixImportResult } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { buildProviderPayload, degradationMessage, parseStixText, providerFields, stixSummary } from "@/lib/intel";
import { fmtTime } from "@/lib/query";
import { ErrorLine, HealthBadge, Modal } from "./badges";
import { ScoreBar, StatusPill, VerdictBadge } from "./intel-bits";

type Tab = "entities" | "providers" | "import";

export function LookupBar() {
  const { can } = useAuth();
  const router = useRouter();
  const [value, setValue] = useState("");
  const [type, setType] = useState<EntityType | "">("");
  const [refresh, setRefresh] = useState(false);
  const look = useMutation({
    mutationFn: () => api.intelLookup({ value: value.trim(), ...(type ? { type } : {}), refresh }),
    onSuccess: (d) => router.push(`/threat-intel/${d.entity.id}`),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (value.trim()) look.mutate(); };
  const allowed = can("intel:write");
  return (
    <form onSubmit={submit} aria-label="Indicator lookup" className="panel p-2 flex items-center gap-2 flex-wrap">
      <input aria-label="Indicator" className="input flex-1 min-w-64 font-mono" placeholder="Paste an IP, domain, URL, hash or e-mail — type is auto-detected"
        value={value} onChange={(e) => setValue(e.target.value)} disabled={!allowed} />
      <select aria-label="Indicator type" className="input" value={type} onChange={(e) => setType(e.target.value as EntityType | "")} disabled={!allowed}>
        <option value="">auto-detect</option>{ENTITY_TYPES.map((t) => <option key={t}>{t}</option>)}
      </select>
      <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={refresh} onChange={(e) => setRefresh(e.target.checked)} disabled={!allowed} /> force refresh</label>
      <button className="btn btn-primary" type="submit" disabled={!allowed || !value.trim() || look.isPending} title={allowed ? "" : "Your role cannot run lookups"}>
        {look.isPending ? "Looking up…" : "Look up"}
      </button>
      <ErrorLine error={look.error} fallback="Lookup failed" />
    </form>
  );
}

function EntitiesTab() {
  const [type, setType] = useState("");
  const [verdict, setVerdict] = useState("");
  const [q, setQ] = useState("");
  const qs = `?${new URLSearchParams({ ...(type && { type }), ...(verdict && { verdict }), ...(q.trim() && { q: q.trim() }), limit: "200" })}`;
  const list = useQuery({ queryKey: ["intel-entities", qs], queryFn: () => api.listEntities(qs) });
  return (
    <div className="space-y-2">
      <div className="flex gap-2 text-xs">
        <select aria-label="Filter type" className="input" value={type} onChange={(e) => setType(e.target.value)}><option value="">all types</option>{ENTITY_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
        <select aria-label="Filter verdict" className="input" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
          <option value="">all verdicts</option>{["malicious", "suspicious", "benign", "unknown"].map((v) => <option key={v}>{v}</option>)}
        </select>
        <input aria-label="Search entities" className="input w-64" placeholder="Search value…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <ErrorLine error={list.error} fallback="Failed to load entities" />
      {list.data && (list.data.length === 0 ? <p className="panel p-3 text-muted">No entities yet. Look up an indicator above, or import a STIX bundle.</p> : (
        <table className="w-full">
          <thead><tr>{["Type", "Value", "Verdict", "Score", "Watch-list", "Tags", "Last enriched"].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {list.data.map((e) => (
              <tr key={e.id} className="hover:bg-bg">
                <td className="td">{e.type.replace("_", " ")}</td>
                <td className="td font-mono break-all"><Link className="text-accent hover:underline" href={`/threat-intel/${e.id}`}>{e.value}</Link></td>
                <td className="td"><VerdictBadge verdict={e.verdict} /></td>
                <td className="td"><ScoreBar score={e.score} /></td>
                <td className="td">{e.watch_verdict ? `${e.watch_verdict} (${e.watch_confidence})` : <span className="text-muted">—</span>}</td>
                <td className="td text-muted">{e.tags.join(", ")}</td>
                <td className="td font-mono whitespace-nowrap">{e.last_enriched_at ? fmtTime(e.last_enriched_at) : "never"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}

export function ProviderForm({ p, onClose }: { p: IntelProvider; onClose: () => void }) {
  const qc = useQueryClient();
  const fields = providerFields(p);
  const [enabled, setEnabled] = useState(true);
  const [values, setValues] = useState<Record<string, string | boolean>>({});
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [errors, setErrors] = useState<string[]>([]);
  const [testMsg, setTestMsg] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: async () => {
      const { body, errors: errs } = buildProviderPayload(p, enabled, values, secrets);
      if (errs.length) { setErrors(errs); throw new Error("invalid"); }
      setErrors([]);
      return api.configureProvider(p.key, body);
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["intel-providers"] }); onClose(); },
  });
  const test = useMutation({ mutationFn: () => api.testProvider(p.key), onSuccess: (r) => setTestMsg(`${r.ok ? "OK" : "Failed"}: ${r.detail}`) });
  return (
    <Modal title={`Configure ${p.display_name}`} onClose={onClose}>
      <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }} aria-label={`Configure ${p.display_name}`}>
        <p className="text-xs text-muted">Stored secrets and existing config are never shown back. Leave a secret blank to keep the current value; the config below replaces the stored config on save.</p>
        <label className="flex items-center gap-1"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
        {fields.map((f) => (
          <div key={f.name} className="grid grid-cols-[9rem_1fr] gap-2 items-center">
            <label htmlFor={`pf-${f.name}`}>{f.label}{f.required ? " *" : ""}</label>
            <input id={`pf-${f.name}`} className="input" placeholder={f.placeholder} value={String(values[f.name] ?? "")} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })} />
          </div>
        ))}
        {p.secret_keys.map((k) => (
          <div key={k} className="grid grid-cols-[9rem_1fr] gap-2 items-center">
            <label htmlFor={`ps-${k}`}>{k.replace("_", " ")}</label>
            <input id={`ps-${k}`} className="input" type="password" autoComplete="off" placeholder={p.configured ? "•••••••• (stored — leave blank to keep)" : "required"}
              value={secrets[k] ?? ""} onChange={(e) => setSecrets({ ...secrets, [k]: e.target.value })} />
          </div>
        ))}
        {errors.map((e) => <p key={e} role="alert" className="text-red-400 text-xs">{e}</p>)}
        <ErrorLine error={save.error instanceof Error && save.error.message === "invalid" ? null : save.error} fallback="Save failed" />
        {testMsg && <p role="status" className="text-xs">{testMsg}</p>}
        <ErrorLine error={test.error} fallback="Test failed" />
        <div className="flex gap-1">
          <button className="btn btn-primary" type="submit" disabled={save.isPending}>Save</button>
          <button className="btn" type="button" disabled={test.isPending} onClick={() => test.mutate()}>Test</button>
        </div>
      </form>
    </Modal>
  );
}

function ProvidersTab() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<IntelProvider | null>(null);
  const [pulled, setPulled] = useState<string | null>(null);
  const providers = useQuery({ queryKey: ["intel-providers"], queryFn: api.intelProviders });
  const pull = useMutation({ mutationFn: api.taxiiPull, onSuccess: (r) => { setPulled(stixSummary(r)); void qc.invalidateQueries({ queryKey: ["intel-providers"] }); void qc.invalidateQueries({ queryKey: ["intel-entities"] }); } });
  const manage = can("intel:manage");
  const banner = providers.data ? degradationMessage(providers.data) : null;
  return (
    <div className="space-y-2">
      {banner && <p role="status" className="panel p-2 text-yellow-300 text-xs">{banner}</p>}
      <ErrorLine error={providers.error} fallback="Failed to load providers" />
      {pulled && <p role="status" className="text-xs">TAXII pull: {pulled}</p>}
      <ErrorLine error={pull.error} fallback="TAXII pull failed" />
      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-2">
        {providers.data?.map((p) => (
          <section key={p.key} className="panel p-3 space-y-1" aria-label={p.display_name}>
            <div className="flex items-center gap-2">
              <h2 className="font-semibold">{p.display_name}</h2>
              <span className="text-xs border border-line px-1 rounded-sm">{p.offline ? "offline" : "online"}</span>
              <span className="ml-auto text-xs">{p.enabled ? <HealthBadge status="ok" /> : <span className="text-muted">● {p.configured ? "disabled" : "not configured"}</span>}</span>
            </div>
            <p className="text-xs text-muted">{p.description}</p>
            {p.supported_types.length > 0 && <p className="text-xs">Types: {p.supported_types.join(", ")}</p>}
            {!p.offline && <p className="text-xs"><StatusPill status={p.last_status} /> {p.last_detail}{p.last_checked_at ? ` · ${fmtTime(p.last_checked_at)}` : ""}</p>}
            {!p.offline && (
              <div className="flex gap-1 pt-1">
                <button className="btn" disabled={!manage} title={manage ? "" : "Requires intel:manage (tenant admin)"} onClick={() => setEditing(p)} aria-label={`Configure ${p.display_name}`}>Configure</button>
                {p.key === "taxii" && <button className="btn" disabled={!manage || !p.configured || pull.isPending} onClick={() => pull.mutate()}>Pull now</button>}
              </div>
            )}
          </section>
        ))}
      </div>
      {editing && <ProviderForm p={editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

function ImportTab() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const [result, setResult] = useState<StixImportResult | null>(null);
  const imp = useMutation({
    mutationFn: async () => {
      const { bundle, error } = parseStixText(text);
      if (error) { setParseError(error); throw new Error("invalid"); }
      setParseError(null);
      return api.importStix(bundle);
    },
    onSuccess: (r) => { setResult(r); void qc.invalidateQueries({ queryKey: ["intel-entities"] }); },
  });
  const onFile = async (f: File | undefined) => { if (f) setText(await f.text()); };
  return (
    <div className="space-y-2 max-w-3xl">
      <p className="text-xs text-muted">Import a STIX 2.x bundle into your tenant watch-list. Simple single-indicator patterns are imported; expired and compound patterns are skipped. Existing analyst verdicts are never overwritten.</p>
      <input aria-label="STIX bundle file" type="file" accept=".json,application/json" onChange={(e) => void onFile(e.target.files?.[0])} className="text-xs" />
      <textarea aria-label="STIX bundle JSON" className="input w-full font-mono h-48" placeholder='{"type":"bundle","objects":[…]}' value={text} onChange={(e) => setText(e.target.value)} />
      <button className="btn btn-primary" disabled={!can("intel:write") || !text.trim() || imp.isPending} onClick={() => imp.mutate()}>Import</button>
      {parseError && <p role="alert" className="text-red-400 text-xs">{parseError}</p>}
      <ErrorLine error={imp.error instanceof Error && imp.error.message === "invalid" ? null : imp.error} fallback="Import failed" />
      {result && <p role="status" className="panel p-2 text-xs">Import complete: {stixSummary(result)}</p>}
    </div>
  );
}

export function ThreatIntelView() {
  const [tab, setTab] = useState<Tab>("entities");
  return (
    <div className="space-y-2">
      <h1 className="text-base font-semibold">Threat Intelligence</h1>
      <LookupBar />
      <div role="tablist" className="flex gap-0.5 border-b border-line">
        {(["entities", "providers", "import"] as Tab[]).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`px-3 py-1 capitalize border-b-2 ${tab === t ? "border-accent text-accent" : "border-transparent text-muted hover:text-[#c9d1d9]"}`}>{t}</button>
        ))}
      </div>
      <div role="tabpanel">{tab === "entities" ? <EntitiesTab /> : tab === "providers" ? <ProvidersTab /> : <ImportTab />}</div>
    </div>
  );
}
