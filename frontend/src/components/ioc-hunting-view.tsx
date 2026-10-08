"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { age, COVERAGE_CLASS, defangIoc, HUNT_STATUS_CLASS, IOC_TYPES, selectable, validationSummary, type FeedType, type IocFeed, type IocHunt, type IocItem } from "@/lib/ioc";
import { fmtTime } from "@/lib/query";
import { ErrorLine, Modal } from "./badges";

type Tab = "queue" | "hunts" | "feeds" | "allow";

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return <div className="panel px-3 py-2"><div className={`text-lg font-semibold ${tone ?? ""}`}>{value}</div><div className="text-xs text-muted">{label}</div></div>;
}

function Overview() {
  const ov = useQuery({ queryKey: ["ioc-overview"], queryFn: () => api.iocOverview(), refetchInterval: 15000 });
  const d = ov.data;
  if (!d) return <ErrorLine error={ov.error} fallback="Failed to load overview" />;
  return (
    <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
      <Stat label="awaiting review" value={d.iocs_by_status.NEW ?? 0} />
      <Stat label="already seen in your telemetry" value={d.seen_in_environment} tone={d.seen_in_environment ? "text-orange-300" : ""} />
      <Stat label="new in the last 24h" value={d.new_last_24h} />
      <Stat label="on the watch list" value={d.iocs_by_status.VALIDATED ?? 0} />
      <Stat label="open IOC cases" value={d.open_ioc_cases} />
      <Stat label="feeds failing" value={`${d.feeds_failing}/${d.feeds}`} tone={d.feeds_failing ? "text-red-400" : ""} />
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const tone = value >= 75 ? "bg-red-500" : value >= 45 ? "bg-orange-400" : "bg-slate-500";
  return <div className="flex items-center gap-1" title={`confidence ${value}`}><div className="w-14 h-1.5 bg-line rounded"><div className={`h-1.5 rounded ${tone}`} style={{ width: `${value}%` }} /></div><span className="text-xs tabular-nums">{value}</span></div>;
}

function ValidateDialog({ items, onClose, onDone }: { items: IocItem[]; onClose: () => void; onDone: (hunt: IocHunt) => void }) {
  const [name, setName] = useState("");
  const [days, setDays] = useState(7);
  const go = useMutation({ mutationFn: () => api.validateIocs({ ioc_ids: items.map((i) => i.id), lookback_days: days, ...(name.trim() ? { name: name.trim() } : {}) }), onSuccess: onDone });
  return (
    <Modal title="Validate and hunt" onClose={onClose} wide>
      <div className="space-y-2 text-xs">
        <p>{validationSummary(items)}.</p>
        <p className="text-muted">Validating adds them to the watch list and starts an automatic hunt across your data sources (ingested telemetry, Trend Vision One search, LogRhythm where configured). A case is opened with the result whether or not anything is found, and the indicators are re-checked every few hours.</p>
        <label className="block">Hunt name (optional) <input aria-label="Hunt name" className="input w-full" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Weekly ransomware C2 IOCs" /></label>
        <label className="block">Look back <input aria-label="Lookback days" type="number" min={1} max={30} className="input w-20" value={days} onChange={(e) => setDays(Math.max(1, Math.min(30, Number(e.target.value) || 7)))} /> days</label>
        <ErrorLine error={go.error} fallback="Could not start the hunt" />
        <button className="btn btn-primary" disabled={go.isPending} onClick={() => go.mutate()}>{go.isPending ? "Starting…" : `Validate ${items.length} and start hunt`}</button>
      </div>
    </Modal>
  );
}

function AddIocDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [type, setType] = useState("ip");
  const [value, setValue] = useState("");
  const [conf, setConf] = useState(70);
  const [desc, setDesc] = useState("");
  const add = useMutation({ mutationFn: () => api.addIoc({ type, value: value.trim(), confidence: conf, description: desc }), onSuccess: () => { onDone(); onClose(); } });
  return (
    <Modal title="Add an indicator" onClose={onClose}>
      <div className="space-y-2 text-xs">
        <div className="flex gap-2">
          <select aria-label="Indicator type" className="input" value={type} onChange={(e) => setType(e.target.value)}>{IOC_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
          <input aria-label="Indicator value" className="input flex-1 font-mono" placeholder="defanged values are fine: hxxp://bad[.]example" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
        <label className="block">Confidence <input aria-label="Confidence" type="number" min={0} max={100} className="input w-20" value={conf} onChange={(e) => setConf(Math.max(0, Math.min(100, Number(e.target.value) || 0)))} /></label>
        <input aria-label="Description" className="input w-full" placeholder="Why this matters (source, report, ticket)" value={desc} onChange={(e) => setDesc(e.target.value)} />
        <ErrorLine error={add.error} fallback="Could not add" />
        <button className="btn btn-primary" disabled={!value.trim() || add.isPending} onClick={() => add.mutate()}>Add to queue</button>
      </div>
    </Modal>
  );
}

function QueueTab({ onHunt }: { onHunt: () => void }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [status, setStatus] = useState("NEW");
  const [type, setType] = useState("");
  const [source, setSource] = useState("");
  const [minConf, setMinConf] = useState(0);
  const [seenOnly, setSeenOnly] = useState(false);
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<"validate" | "add" | null>(null);
  const qs = `?${new URLSearchParams({ ...(status && { status }), ...(type && { type }), ...(source && { source }), ...(minConf && { min_confidence: String(minConf) }), ...(seenOnly && { seen: "true" }), ...(q.trim() && { q: q.trim() }), limit: "200" })}`;
  const page = useQuery({ queryKey: ["iocs", qs], queryFn: () => api.iocs(qs) });
  const refresh = () => { setPicked(new Set()); void qc.invalidateQueries({ queryKey: ["iocs"] }); void qc.invalidateQueries({ queryKey: ["ioc-overview"] }); void qc.invalidateQueries({ queryKey: ["ioc-hunts"] }); };
  const reject = useMutation({ mutationFn: () => api.rejectIocs([...picked], "rejected in triage"), onSuccess: refresh });
  const items = useMemo(() => page.data?.items ?? [], [page.data]);
  const chosen = useMemo(() => items.filter((i) => picked.has(i.id)), [items, picked]);
  const validate = can("iochunt:validate");
  const toggle = (id: string) => setPicked((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2 text-xs items-center">
        <select aria-label="Status" className="input" value={status} onChange={(e) => setStatus(e.target.value)}>{["NEW", "VALIDATED", "REJECTED", "EXPIRED", ""].map((s) => <option key={s} value={s}>{s || "all"}</option>)}</select>
        <select aria-label="Type" className="input" value={type} onChange={(e) => setType(e.target.value)}><option value="">all types</option>{IOC_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
        <select aria-label="Source" className="input" value={source} onChange={(e) => setSource(e.target.value)}><option value="">all sources</option>{Object.keys(page.data?.facets.source ?? {}).map((s) => <option key={s}>{s}</option>)}</select>
        <label>min confidence <input aria-label="Minimum confidence" type="number" min={0} max={100} className="input w-16" value={minConf} onChange={(e) => setMinConf(Math.max(0, Math.min(100, Number(e.target.value) || 0)))} /></label>
        <label className="flex items-center gap-1"><input type="checkbox" checked={seenOnly} onChange={(e) => setSeenOnly(e.target.checked)} /> seen in my telemetry</label>
        <input aria-label="Search indicators" className="input w-56" placeholder="Search value, malware, description…" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="ml-auto flex gap-2">
          <button className="btn" disabled={!validate} onClick={() => setDialog("add")} title={validate ? "" : "Requires iochunt:validate"}>Add indicator</button>
          <button className="btn" disabled={!validate || picked.size === 0 || reject.isPending} onClick={() => reject.mutate()}>Reject{picked.size ? ` (${picked.size})` : ""}</button>
          <button className="btn btn-primary" disabled={!validate || chosen.length === 0} onClick={() => setDialog("validate")} title={validate ? "" : "Only tenant admins can validate indicators"}>Validate &amp; hunt{chosen.length ? ` (${chosen.length})` : ""}</button>
        </span>
      </div>
      <p className="text-xs text-muted">Sorted by relevance: indicators already present in your own telemetry first, then by confidence. Only recent indicators are kept; stale ones expire automatically.</p>
      <ErrorLine error={page.error ?? reject.error} fallback="Failed to load indicators" />
      {page.data && (items.length === 0 ? <p className="panel p-3 text-muted">Nothing to review. Add a feed under <b>Feeds</b>, or add an indicator manually.</p> : (
        <table className="w-full text-xs">
          <thead className="text-left text-muted"><tr><th /><th>Type</th><th>Indicator</th><th>Confidence</th><th>In my telemetry</th><th>Context</th><th>Source</th><th>Age</th><th>Status</th></tr></thead>
          <tbody>{items.map((i) => (
            <tr key={i.id} className="border-t border-line align-top">
              <td><input type="checkbox" aria-label={`Select ${i.value}`} disabled={!validate || !selectable(i)} checked={picked.has(i.id)} onChange={() => toggle(i.id)} /></td>
              <td>{i.type}</td>
              <td className="font-mono break-all max-w-md">{defangIoc(i.type, i.value)}{i.reference && <> <a className="underline text-muted" href={i.reference} target="_blank" rel="noreferrer noopener">ref</a></>}</td>
              <td><ConfidenceBar value={i.confidence} /></td>
              <td>{i.seen_count > 0 ? <span className="text-orange-300">{i.seen_count} event(s)</span> : <span className="text-muted">none</span>}</td>
              <td>{[i.malware, i.threat_type, ...i.techniques].filter(Boolean).join(" · ")}<div className="text-muted">{i.description.slice(0, 90)}</div></td>
              <td>{i.source}</td><td title={fmtTime(i.last_seen)}>{age(i.last_seen)}</td>
              <td>{i.status}{i.case_id && <> · <Link className="underline" href={`/cases/${i.case_id}`}>case</Link></>}</td>
            </tr>))}
          </tbody>
        </table>
      ))}
      {page.data && <p className="text-xs text-muted">{page.data.total} indicator(s) match.</p>}
      {dialog === "validate" && <ValidateDialog items={chosen} onClose={() => setDialog(null)} onDone={() => { setDialog(null); refresh(); onHunt(); }} />}
      {dialog === "add" && <AddIocDialog onClose={() => setDialog(null)} onDone={refresh} />}
    </div>
  );
}

function HuntRow({ h }: { h: IocHunt }) {
  const [open, setOpen] = useState(false);
  const { can } = useAuth();
  const qc = useQueryClient();
  const detail = useQuery({ queryKey: ["ioc-hunt", h.id], queryFn: () => api.iocHunt(h.id), enabled: open });
  const retry = useMutation({ mutationFn: () => api.retryIocHunt(h.id), onSuccess: () => { void qc.invalidateQueries({ queryKey: ["ioc-hunts"] }); } });
  return (
    <>
      <tr className="border-t border-line cursor-pointer hover:bg-white/5" onClick={() => setOpen((o) => !o)}>
        <td><span className={`px-1.5 rounded ${HUNT_STATUS_CLASS[h.status] ?? ""}`}>{h.status}</span></td>
        <td>{h.name}<div className="text-muted">{h.mode === "rehunt" ? "scheduled re-hunt" : `last ${h.lookback_days} day(s)`}</div></td>
        <td>{h.ioc_count}</td>
        <td className={h.match_count ? "text-orange-300" : ""}>{h.match_count}{h.new_match_count && h.mode === "rehunt" ? ` (+${h.new_match_count} new)` : ""}</td>
        <td>{h.case_id ? <Link className="underline" href={`/cases/${h.case_id}`} onClick={(e) => e.stopPropagation()}>CASE-{String(h.case_number).padStart(4, "0")}</Link> : "—"}{h.case_status && <span className="text-muted"> {h.case_status}</span>}</td>
        <td>{fmtTime(h.created_at)}</td>
      </tr>
      {open && (
        <tr><td colSpan={6} className="bg-bg p-2">
          <p className="text-xs mb-2">{h.hypothesis}</p>
          {h.error && <p role="alert" className="text-red-400 text-xs">{h.error}</p>}
          <table className="w-full text-xs mb-2"><thead className="text-left text-muted"><tr><th>Data source</th><th>Status</th><th>Searched</th><th>Matches</th><th>Notes</th></tr></thead>
            <tbody>{h.coverage.map((c, i) => <tr key={i}><td>{c.source}</td><td className={COVERAGE_CLASS[c.status]}>{c.status}</td><td>{c.iocs_searched}</td><td>{c.hits}</td><td className="text-muted">{c.detail}</td></tr>)}</tbody></table>
          {detail.data && detail.data.matches.length > 0 && (
            <table className="w-full text-xs"><thead className="text-left text-muted"><tr><th>Time</th><th>Indicator</th><th>Host</th><th>User</th><th>Event</th></tr></thead>
              <tbody>{detail.data.matches.slice(0, 50).map((m) => <tr key={m.id}><td>{fmtTime(m.event_timestamp)}</td><td className="font-mono">{defangIoc(m.ioc_type, m.ioc_value)}</td><td>{m.host}</td><td>{m.user}</td><td><Link className="underline" href={`/events?id=${m.event_id}`}>{m.summary.slice(0, 80)}</Link></td></tr>)}</tbody></table>
          )}
          {(h.status === "FAILED" || h.status === "PARTIAL") && <button className="btn mt-2" disabled={!can("iochunt:validate") || retry.isPending} onClick={() => retry.mutate()}>Retry hunt</button>}
          <ErrorLine error={retry.error} fallback="Retry failed" />
        </td></tr>
      )}
    </>
  );
}

function HuntsTab() {
  const hunts = useQuery({ queryKey: ["ioc-hunts"], queryFn: () => api.iocHunts(), refetchInterval: 8000 });
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted">Hunts start automatically within about a minute of validation. Click a row for the hypothesis, per-source coverage and matched events.</p>
      <ErrorLine error={hunts.error} fallback="Failed to load hunts" />
      {hunts.data && (hunts.data.length === 0 ? <p className="panel p-3 text-muted">No hunts yet. Validate indicators in the queue to start one.</p> : (
        <table className="w-full text-xs"><thead className="text-left text-muted"><tr><th>Status</th><th>Hunt</th><th>IOCs</th><th>Matches</th><th>Case</th><th>Started</th></tr></thead>
          <tbody>{hunts.data.map((h) => <HuntRow key={h.id} h={h} />)}</tbody></table>
      ))}
    </div>
  );
}

function FeedForm({ types, onDone }: { types: FeedType[]; onDone: () => void }) {
  const [type, setType] = useState(types[0]?.type ?? "");
  const t = types.find((x) => x.type === type);
  const [name, setName] = useState("");
  const [config, setConfig] = useState("{}");
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [maxAge, setMaxAge] = useState(14);
  const [minConf, setMinConf] = useState(0);
  const [maxItems, setMaxItems] = useState(2000);
  const [err, setErr] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => {
      let cfg: Record<string, unknown>;
      try { cfg = JSON.parse(config) as Record<string, unknown>; } catch { throw new Error("Configuration must be valid JSON"); }
      const sec = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v));
      return api.createIocFeed({ name: name.trim() || t?.name, feed_type: type, config: cfg, secrets: sec, max_age_days: maxAge, min_confidence: minConf, max_items: maxItems });
    },
    onSuccess: onDone, onError: (e) => setErr(e instanceof Error ? e.message : "Failed"),
  });
  return (
    <div className="panel p-3 space-y-2 text-xs">
      <div className="flex gap-2 flex-wrap">
        <select aria-label="Feed type" className="input" value={type} onChange={(e) => { setType(e.target.value); setSecrets({}); }}>{types.map((x) => <option key={x.type} value={x.type}>{x.name}</option>)}</select>
        <input aria-label="Feed name" className="input w-64" placeholder={t?.name} value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      {t && <p className="text-muted">{t.description}</p>}
      {t?.secret_names.map((s) => <label key={s} className="block">{s}{t.needs_secret ? " (required)" : ""} <input aria-label={`Secret ${s}`} type="password" autoComplete="new-password" className="input w-80" value={secrets[s] ?? ""} onChange={(e) => setSecrets({ ...secrets, [s]: e.target.value })} /></label>)}
      <label className="block">Configuration (JSON) <textarea aria-label="Feed configuration" className="input w-full font-mono h-16" value={config} onChange={(e) => setConfig(e.target.value)} /></label>
      <div className="flex gap-3 flex-wrap">
        <label>Only indicators from the last <input aria-label="Max age days" type="number" min={1} max={90} className="input w-16" value={maxAge} onChange={(e) => setMaxAge(Math.max(1, Math.min(90, Number(e.target.value) || 14)))} /> days</label>
        <label>min confidence <input aria-label="Feed min confidence" type="number" min={0} max={100} className="input w-16" value={minConf} onChange={(e) => setMinConf(Math.max(0, Math.min(100, Number(e.target.value) || 0)))} /></label>
        <label>keep at most <input aria-label="Max items" type="number" min={1} max={20000} className="input w-20" value={maxItems} onChange={(e) => setMaxItems(Math.max(1, Math.min(20000, Number(e.target.value) || 2000)))} /> per refresh</label>
      </div>
      {err && <p role="alert" className="text-red-400">{err}</p>}
      <ErrorLine error={create.error} fallback="Could not add the feed" />
      <button className="btn btn-primary" disabled={create.isPending} onClick={() => { setErr(null); create.mutate(); }}>Add feed</button>
    </div>
  );
}

function FeedsTab() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const manage = can("iochunt:manage");
  const [adding, setAdding] = useState(false);
  const [credFor, setCredFor] = useState<IocFeed | null>(null);
  const [credName, setCredName] = useState("");
  const [credVal, setCredVal] = useState("");
  const feeds = useQuery({ queryKey: ["ioc-feeds"], queryFn: () => api.iocFeeds() });
  const types = useQuery({ queryKey: ["ioc-feed-types"], queryFn: () => api.iocFeedTypes() });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["ioc-feeds"] }); void qc.invalidateQueries({ queryKey: ["iocs"] }); void qc.invalidateQueries({ queryKey: ["ioc-overview"] }); };
  const run = useMutation({ mutationFn: (f: IocFeed) => api.runIocFeed(f.id), onSuccess: refresh });
  const toggle = useMutation({ mutationFn: (f: IocFeed) => api.updateIocFeed(f.id, { enabled: !f.enabled }), onSuccess: refresh });
  const remove = useMutation({ mutationFn: (f: IocFeed) => api.deleteIocFeed(f.id), onSuccess: refresh });
  const saveCred = useMutation({ mutationFn: () => api.setIocFeedSecret(credFor!.id, credName.trim(), credVal), onSuccess: () => { setCredFor(null); setCredVal(""); refresh(); } });
  return (
    <div className="space-y-2">
      <div className="flex items-center"><p className="text-xs text-muted">Feeds refresh on a schedule and import only recent indicators; imported indicators keep their provenance.</p>
        <button className="btn btn-primary ml-auto" disabled={!manage || !types.data} title={manage ? "" : "Requires iochunt:manage"} onClick={() => setAdding((a) => !a)}>Add feed</button></div>
      {adding && types.data && <FeedForm types={types.data} onDone={() => { setAdding(false); refresh(); }} />}
      <ErrorLine error={feeds.error ?? run.error ?? toggle.error ?? remove.error} fallback="Feed action failed" />
      {feeds.data && (feeds.data.length === 0 ? <p className="panel p-3 text-muted">No feeds yet. A good start with no accounts: <b>abuse.ch URLhaus (recent URLs)</b> and <b>Feodo Tracker</b>; add your <b>Trend Vision One Suspicious Object List</b> with the same API key as your Trend data source.</p> : (
        <table className="w-full text-xs"><thead className="text-left text-muted"><tr><th>Feed</th><th>Health</th><th>Last run</th><th>Last result</th><th>Indicators</th><th>Enabled</th><th /></tr></thead>
          <tbody>{feeds.data.map((f) => (
            <tr key={f.id} className="border-t border-line">
              <td>{f.name}{f.has_secrets && " 🔒"}<div className="text-muted">{f.feed_type} · ≤{f.max_age_days}d · every {f.interval_minutes}m</div></td>
              <td className={f.last_status === "ok" ? "text-green-300" : f.last_status === "error" ? "text-red-400" : "text-muted"}>{f.last_status || "not run yet"}</td>
              <td>{f.last_run_at ? fmtTime(f.last_run_at) : "—"}</td><td className="text-muted max-w-sm">{f.last_detail}</td><td>{f.ioc_count}</td>
              <td><input type="checkbox" aria-label={`Enable ${f.name}`} disabled={!manage} checked={f.enabled} onChange={() => toggle.mutate(f)} /></td>
              <td className="space-x-1 whitespace-nowrap">
                <button className="btn py-0" disabled={!manage || run.isPending} onClick={() => run.mutate(f)}>Run now</button>
                <button className="btn py-0" disabled={!manage} onClick={() => { setCredFor(f); setCredName(f.secret_keys[0] ?? types.data?.find((t) => t.type === f.feed_type)?.secret_names[0] ?? "api_key"); }}>Set credential</button>
                <button className="btn py-0" disabled={!manage} onClick={() => { if (confirm(`Delete feed “${f.name}”? Imported indicators are kept.`)) remove.mutate(f); }}>Delete</button>
              </td>
            </tr>))}
          </tbody></table>
      ))}
      {credFor && (
        <Modal title={`Set credential — ${credFor.name}`} onClose={() => setCredFor(null)}>
          <form className="space-y-2 text-xs" onSubmit={(e) => { e.preventDefault(); if (credName.trim() && credVal) saveCred.mutate(); }}>
            <p className="text-muted">Stored encrypted and never shown again.</p>
            <input aria-label="Credential name" className="input w-full font-mono" value={credName} onChange={(e) => setCredName(e.target.value)} />
            <input aria-label="Credential value" type="password" autoComplete="new-password" className="input w-full" value={credVal} onChange={(e) => setCredVal(e.target.value)} />
            <ErrorLine error={saveCred.error} fallback="Could not save" />
            <button className="btn btn-primary" type="submit" disabled={!credName.trim() || !credVal || saveCred.isPending}>Save credential</button>
          </form>
        </Modal>
      )}
    </div>
  );
}

function AllowTab() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const manage = can("iochunt:manage");
  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const list = useQuery({ queryKey: ["ioc-allow"], queryFn: () => api.iocAllowlist() });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["ioc-allow"] }); void qc.invalidateQueries({ queryKey: ["iocs"] }); };
  const add = useMutation({ mutationFn: () => api.addIocAllow({ type, value: value.trim(), reason }), onSuccess: () => { setValue(""); setReason(""); refresh(); } });
  const del = useMutation({ mutationFn: (id: string) => api.deleteIocAllow(id), onSuccess: refresh });
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted">Values that must never be imported or hunted: your own domains, partners, scanners. A domain entry also covers its subdomains and URLs on it.</p>
      <div className="flex gap-2 text-xs">
        <select aria-label="Allow type" className="input" value={type} onChange={(e) => setType(e.target.value)}>{IOC_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
        <input aria-label="Allow value" className="input w-64 font-mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder="partner.example" />
        <input aria-label="Allow reason" className="input flex-1" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why" />
        <button className="btn btn-primary" disabled={!manage || !value.trim() || add.isPending} onClick={() => add.mutate()}>Add</button>
      </div>
      <ErrorLine error={add.error ?? del.error ?? list.error} fallback="Allow-list action failed" />
      {list.data && (list.data.length === 0 ? <p className="panel p-3 text-muted">Nothing allow-listed.</p> : (
        <table className="w-full text-xs"><tbody>{list.data.map((a) => <tr key={a.id} className="border-t border-line"><td>{a.type}</td><td className="font-mono">{a.value}</td><td className="text-muted">{a.reason}</td><td className="text-right"><button className="btn py-0" disabled={!manage} onClick={() => del.mutate(a.id)}>Remove</button></td></tr>)}</tbody></table>
      ))}
    </div>
  );
}

export function IocHuntingView() {
  const [tab, setTab] = useState<Tab>("queue");
  const tabs: [Tab, string][] = [["queue", "Triage queue"], ["hunts", "Hunts"], ["feeds", "Feeds"], ["allow", "Allow-list"]];
  return (
    <section className="space-y-3">
      <h1 className="text-base font-semibold">IOC Hunting</h1>
      <p className="text-xs text-muted">Feeds bring in recent indicators → a tenant admin validates the relevant ones → the platform hunts all data sources automatically and opens a case with the result, whether or not anything is found.</p>
      <Overview />
      <div role="tablist" className="flex gap-2">{tabs.map(([k, label]) => <button key={k} role="tab" aria-selected={tab === k} className={`btn ${tab === k ? "btn-primary" : ""}`} onClick={() => setTab(k)}>{label}</button>)}</div>
      {tab === "queue" && <QueueTab onHunt={() => setTab("hunts")} />}
      {tab === "hunts" && <HuntsTab />}
      {tab === "feeds" && <FeedsTab />}
      {tab === "allow" && <AllowTab />}
    </section>
  );
}
