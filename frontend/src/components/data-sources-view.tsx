"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import type { ConnectorInfo, DataSource } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { buildConfig, fieldsFromSchema, ingestCurl } from "@/lib/cases";
import { fmtTime } from "@/lib/query";
import { CopyButton, ErrorLine, HealthBadge, Modal } from "./badges";

const DEFAULT_SECRET: Record<string, string> = { logrhythm: "token", trend_vision_one: "api_key", generic_rest: "authorization" };

/** Write-only credential editor: the value is never read back from the server and is cleared on close. */
export function SecretDialog({ source, onClose, onSaved }: { source: DataSource; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(source.secret_keys[0] ?? DEFAULT_SECRET[source.connector_type] ?? "authorization");
  const [value, setValue] = useState("");
  const save = useMutation({ mutationFn: () => api.setDataSourceSecret(source.id, name.trim(), value), onSuccess: () => { setValue(""); onSaved(); onClose(); } });
  const valid = /^[A-Za-z0-9_.-]{1,64}$/.test(name.trim()) && value.length > 0;
  return (
    <Modal title={`Set credential — ${source.name}`} onClose={onClose}>
      <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (valid) save.mutate(); }}>
        <p className="text-xs text-muted">Stored encrypted and never shown again. Other credentials on this source are kept. Use this to rotate a key too.</p>
        <label className="block text-xs">Name <input aria-label="Credential name" className="input w-full font-mono" value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="block text-xs">Value <input aria-label="Credential value" className="input w-full" type="password" autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} /></label>
        <ErrorLine error={save.error} fallback="Could not save the credential" />
        <button className="btn btn-primary" type="submit" disabled={!valid || save.isPending}>Save credential</button>
      </form>
    </Modal>
  );
}

/** The ingest key is shown exactly once: this dialog owns the only copy and drops it on close. */
export function OneTimeKeyDialog({ sourceId, ingestKey, onClose }: { sourceId: string; ingestKey: string; onClose: () => void }) {
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  return (
    <Modal title="Ingest key — copy it now" onClose={onClose} wide>
      <p className="text-xs text-yellow-300" role="alert">This key will not be shown again. Store it in your collector&apos;s secret store; rotate it if it leaks.</p>
      <div className="flex gap-1 items-center"><code data-testid="ingest-key" className="input flex-1 font-mono break-all">{ingestKey}</code><CopyButton text={ingestKey} /></div>
      <pre className="bg-bg border border-line p-2 text-xs overflow-x-auto">{ingestCurl(origin, sourceId)}</pre>
    </Modal>
  );
}

function CreateWizard({ connectors, onCreated, onCancel }: {
  connectors: ConnectorInfo[]; onCreated: (ds: DataSource) => void; onCancel: () => void;
}) {
  const [type, setType] = useState(connectors[0]?.type ?? "");
  const [name, setName] = useState("");
  const [values, setValues] = useState<Record<string, string | boolean>>({});
  const [secrets, setSecrets] = useState<Array<{ k: string; v: string }>>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const connector = connectors.find((c) => c.type === type);
  const fields = fieldsFromSchema(connector?.config_schema);
  const create = useMutation({ mutationFn: api.createDataSource, onSuccess: onCreated });

  function submit(e: FormEvent) {
    e.preventDefault();
    const { config, errors: errs } = buildConfig(fields, values);
    if (!name.trim()) errs.unshift("Name is required");
    setErrors(errs);
    if (errs.length) return;
    const sec: Record<string, string> = {};
    for (const s of secrets) if (s.k.trim() && s.v) sec[s.k.trim()] = s.v;
    create.mutate({ name: name.trim(), connector_type: type, config, secrets: sec, enabled: true });
  }

  return (
    <form onSubmit={submit} className="panel p-3 space-y-2 max-w-3xl" aria-label="New data source">
      <div className="grid grid-cols-[9rem_1fr] gap-2 items-start">
        <label htmlFor="ds-type">Connector</label>
        <select id="ds-type" className="input" value={type} onChange={(e) => { setType(e.target.value); setValues({}); }}>
          {connectors.map((c) => <option key={c.type} value={c.type}>{c.display_name} {c.supports_collect ? "(pull)" : "(push)"}</option>)}
        </select>
        <label htmlFor="ds-name">Name</label>
        <input id="ds-name" className="input" value={name} maxLength={120} onChange={(e) => setName(e.target.value)} />
        {fields.map((f) => (
          <div key={f.name} className="contents">
            <label htmlFor={`cfg-${f.name}`} title={f.description}>{f.label}{f.required ? " *" : ""}</label>
            {f.kind === "boolean" ? (
              <input id={`cfg-${f.name}`} type="checkbox" checked={Boolean(values[f.name] ?? f.defaultValue)} onChange={(e) => setValues({ ...values, [f.name]: e.target.checked })} />
            ) : f.kind === "enum" ? (
              <select id={`cfg-${f.name}`} className="input" value={String(values[f.name] ?? "")} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}>
                <option value="">default</option>{f.options?.map((o) => <option key={o}>{o}</option>)}
              </select>
            ) : f.kind === "json" ? (
              <textarea id={`cfg-${f.name}`} className="input font-mono text-xs" rows={3} placeholder="JSON" value={String(values[f.name] ?? "")} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })} />
            ) : (
              <input id={`cfg-${f.name}`} className="input" type={f.kind === "string" ? "text" : "number"} step={f.kind === "number" ? "any" : undefined}
                placeholder={f.placeholder} value={String(values[f.name] ?? "")} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })} />
            )}
          </div>
        ))}
        {connector?.supports_collect && (
          <>
            <span>Secrets</span>
            <div className="space-y-1">
              {secrets.map((s, i) => (
                <div key={i} className="flex gap-1">
                  <input aria-label={`Secret name ${i + 1}`} className="input w-40" placeholder="e.g. authorization" value={s.k} onChange={(e) => setSecrets(secrets.map((x, j) => (j === i ? { ...x, k: e.target.value } : x)))} />
                  <input aria-label={`Secret value ${i + 1}`} className="input flex-1" type="password" autoComplete="new-password" placeholder="write-only" value={s.v} onChange={(e) => setSecrets(secrets.map((x, j) => (j === i ? { ...x, v: e.target.value } : x)))} />
                </div>
              ))}
              <button type="button" className="btn text-xs py-0" onClick={() => setSecrets([...secrets, { k: "authorization", v: "" }])}>Add secret</button>
              <p className="text-xs text-muted">Secrets are encrypted at rest and never returned by the API.</p>
            </div>
          </>
        )}
      </div>
      {errors.length > 0 && <ul role="alert" className="text-red-400 text-xs">{errors.map((e) => <li key={e}>{e}</li>)}</ul>}
      <ErrorLine error={create.error} fallback="Failed to create data source" />
      <div className="flex gap-1">
        <button className="btn btn-primary" type="submit" disabled={create.isPending}>Create data source</button>
        <button className="btn" type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

export function DataSourcesView() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const manage = can("datasources:manage");
  const [showNew, setShowNew] = useState(false);
  const [reveal, setReveal] = useState<{ id: string; key: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [secretFor, setSecretFor] = useState<DataSource | null>(null);
  const sources = useQuery({ queryKey: ["data-sources"], queryFn: api.listDataSources });
  const connectors = useQuery({ queryKey: ["connectors"], queryFn: api.connectors });
  const refresh = () => qc.invalidateQueries({ queryKey: ["data-sources"] });

  const toggle = useMutation({ mutationFn: (d: DataSource) => api.updateDataSource(d.id, { enabled: !d.enabled }), onSuccess: refresh });
  const test = useMutation({ mutationFn: (d: DataSource) => api.testDataSource(d.id).then((r) => ({ d, r })), onSuccess: ({ d, r }) => { setNotice(`${d.name}: ${r.ok ? "OK" : "FAILED"} — ${r.detail}`); void refresh(); } });
  const collect = useMutation({ mutationFn: (d: DataSource) => api.collectDataSource(d.id).then((r) => ({ d, r })), onSuccess: ({ d, r }) => { setNotice(`${d.name}: collected ${r.accepted} new events`); void refresh(); } });
  const rotate = useMutation({ mutationFn: (d: DataSource) => api.rotateKey(d.id), onSuccess: (d) => { if (d.ingest_key) setReveal({ id: d.id, key: d.ingest_key }); void refresh(); } });
  const remove = useMutation({ mutationFn: (d: DataSource) => api.deleteDataSource(d.id), onSuccess: refresh });

  const hint = manage ? "" : "Requires datasources:manage";
  return (
    <div className="space-y-2">
      <div className="flex items-center">
        <p className="text-xs text-muted">Push sources send events to their ingest endpoint with a per-source key; pull sources are collected by the worker every 5 minutes.</p>
        <button className="btn btn-primary ml-auto" disabled={!manage || !connectors.data} title={hint} onClick={() => setShowNew((s) => !s)}>New data source</button>
      </div>
      {!manage && <p className="text-xs text-muted">Read-only: managing data sources requires the tenant admin role.</p>}
      {notice && <p role="status" className="panel p-2 text-xs">{notice}</p>}
      <ErrorLine error={test.error ?? collect.error ?? rotate.error ?? remove.error ?? toggle.error} fallback="Action failed" />
      {showNew && manage && connectors.data && (
        <CreateWizard connectors={connectors.data} onCancel={() => setShowNew(false)}
          onCreated={(ds) => { setShowNew(false); void refresh(); if (ds.ingest_key) setReveal({ id: ds.id, key: ds.ingest_key }); }} />
      )}
      {secretFor && <SecretDialog source={secretFor} onClose={() => setSecretFor(null)} onSaved={() => { setNotice(`Credential saved for ${secretFor.name}. Enable the source (or Test it) to use it.`); void refresh(); }} />}
      {reveal && <OneTimeKeyDialog sourceId={reveal.id} ingestKey={reveal.key} onClose={() => setReveal(null)} />}
      <ErrorLine error={sources.error} fallback="Failed to load data sources" />
      {sources.data && (sources.data.length === 0 ? <p className="panel p-3 text-muted">No data sources configured.</p> : (
        <table className="w-full">
          <thead><tr>{["Name", "Connector", "Mode", "Health", "Last ingest", "Events", "Enabled", "Actions"].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {sources.data.map((d) => (
              <tr key={d.id} className="hover:bg-bg">
                <td className="td">{d.name}{d.has_secrets && <span className="text-xs text-muted"> 🔒</span>}</td>
                <td className="td font-mono">{d.connector_type}</td>
                <td className="td">{d.supports_collect ? "pull" : "push"}</td>
                <td className="td" title={d.health_detail}><HealthBadge status={d.health_status} /></td>
                <td className="td font-mono whitespace-nowrap">{d.last_ingest_at ? fmtTime(d.last_ingest_at) : "never"}</td>
                <td className="td tabular-nums">{d.events_total.toLocaleString()}</td>
                <td className="td"><input type="checkbox" aria-label={`Enable ${d.name}`} checked={d.enabled} disabled={!manage || toggle.isPending} onChange={() => toggle.mutate(d)} /></td>
                <td className="td whitespace-nowrap">
                  <button className="btn py-0 text-xs" disabled={!manage} title={hint} onClick={() => test.mutate(d)}>Test</button>{" "}
                  {d.supports_collect && <button className="btn py-0 text-xs" disabled={!manage} onClick={() => collect.mutate(d)}>Collect now</button>}{" "}
                  {d.supports_collect && <button className="btn py-0 text-xs" disabled={!manage} title={hint} onClick={() => setSecretFor(d)}>Set credential</button>}{" "}
                  <button className="btn py-0 text-xs" disabled={!manage} onClick={() => { if (confirm(`Rotate the ingest key for “${d.name}”? The old key stops working immediately.`)) rotate.mutate(d); }}>Rotate key</button>{" "}
                  <button className="btn py-0 text-xs" disabled={!manage} onClick={() => { if (confirm(`Delete data source “${d.name}”? Ingested events are kept.`)) remove.mutate(d); }}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}
