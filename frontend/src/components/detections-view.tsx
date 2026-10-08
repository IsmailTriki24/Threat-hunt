"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import {
  activationBlocker, NEXT_STATES, parseEvent, SAMPLE_EVENT, STATUS_CLASS, type Alert, type Rule, type RuleStatus,
} from "@/lib/detections";
import { fmtTime } from "@/lib/query";
import { ErrorLine } from "./badges";

const SIGMA_TEMPLATE = `title: Encoded PowerShell
description: PowerShell started with an encoded command
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc'
  condition: sel
level: high
tags:
  - attack.execution
  - attack.t1059.001
`;

function StatusPill({ status }: { status: RuleStatus }) {
  return <span className={`px-1.5 rounded text-xs ${STATUS_CLASS[status]}`}>{status}</span>;
}

function RuleDetail({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [content, setContent] = useState(rule.content);
  const [evText, setEvText] = useState(SAMPLE_EVENT);
  const [name, setName] = useState("");
  const [expect, setExpect] = useState(true);
  const [localErr, setLocalErr] = useState<string | null>(null);
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["det-rules"] }); void qc.invalidateQueries({ queryKey: ["det-tests", rule.id] }); };
  const tests = useQuery({ queryKey: ["det-tests", rule.id], queryFn: () => api.ruleTests(rule.id) });
  const write = can("detections:write");
  const manage = can("detections:manage");
  const save = useMutation({ mutationFn: () => api.updateRule(rule.id, { content }), onSuccess: refresh });
  const move = useMutation({ mutationFn: (to: RuleStatus) => api.transitionRule(rule.id, to), onSuccess: refresh });
  const addTest = useMutation({
    mutationFn: () => {
      const p = parseEvent(evText);
      if (!p.event) throw new Error(p.error);
      return api.addRuleTest(rule.id, { name: name.trim(), event: p.event, expect_match: expect });
    },
    onSuccess: () => { setName(""); refresh(); },
  });
  const delTest = useMutation({ mutationFn: (id: string) => api.deleteRuleTest(rule.id, id), onSuccess: refresh });
  const run = useMutation({ mutationFn: () => api.runRuleTests(rule.id), onSuccess: refresh });
  const back = useMutation({ mutationFn: () => api.backtestRule(rule.id) });
  const del = useMutation({ mutationFn: () => api.deleteRule(rule.id), onSuccess: () => { refresh(); onClose(); } });
  const blocker = activationBlocker(rule);
  const dirty = content !== rule.content;
  return (
    <section className="panel p-3 space-y-3" aria-label="Rule detail">
      <div className="flex items-center gap-2">
        <h2 className="font-semibold">{rule.title}</h2><StatusPill status={rule.status} />
        <span className="text-xs text-muted">v{rule.version} · {rule.severity} · {rule.format}</span>
        <button className="btn ml-auto" onClick={onClose}>Close</button>
      </div>
      {rule.techniques.length > 0 && <p className="text-xs">ATT&amp;CK: {rule.techniques.map((t) => <Link key={t} className="underline mr-2" href={`/mitre?technique=${t}`}>{t}</Link>)}</p>}
      {rule.unsupported.length > 0 && <p role="alert" className="text-orange-300 text-xs">Not executable: {rule.unsupported.join("; ")}</p>}
      {rule.warnings.length > 0 && <p className="text-xs text-muted">Notes: {rule.warnings.join("; ")}</p>}
      {rule.last_run_status === "error" && <p role="alert" className="text-red-400 text-xs">Last scheduled run failed: {rule.last_run_error}</p>}
      <textarea aria-label="Rule source" className="input w-full font-mono text-xs h-56" value={content} onChange={(e) => setContent(e.target.value)} disabled={!write} spellCheck={false} />
      <div className="flex gap-2 flex-wrap items-center">
        <button className="btn btn-primary" disabled={!write || !dirty || save.isPending} onClick={() => save.mutate()}>Save new version</button>
        {dirty && <span className="text-xs text-muted">Saving creates version {rule.version + 1} and returns the rule to DRAFT.</span>}
        {NEXT_STATES[rule.status].map((to) => {
          const prod = to === "ACTIVE" || to === "DISABLED" || rule.status === "ACTIVE" || rule.status === "DISABLED";
          const off = !write || (prod && !manage) || (to === "ACTIVE" && blocker !== null) || (to === "TESTING" && !rule.executable);
          return <button key={to} className="btn" disabled={off || move.isPending} onClick={() => move.mutate(to)}
            title={to === "ACTIVE" && blocker ? blocker : prod && !manage ? "Requires detections:manage" : ""}>Move to {to}</button>;
        })}
        {manage && <button className="btn" disabled={del.isPending} onClick={() => { if (confirm("Delete this rule and its alerts?")) del.mutate(); }}>Delete</button>}
      </div>
      <ErrorLine error={save.error ?? move.error ?? del.error} fallback="Action failed" />

      <div className="space-y-2">
        <h3 className="font-semibold text-xs">Unit tests ({rule.test_count}) {rule.tests_passed === true && <span className="text-green-300">· passing</span>}{rule.tests_passed === false && <span className="text-red-400">· failing</span>}</h3>
        {tests.data?.map((c) => {
          const r = run.data?.results.find((x) => x.case_id === c.id);
          return <div key={c.id} className="flex items-center gap-2 text-xs">
            <span>{c.name}</span><span className="text-muted">must {c.expect_match ? "match" : "not match"}</span>
            {r && <span className={r.passed ? "text-green-300" : "text-red-400"}>{r.passed ? "pass" : `FAIL (${r.matched ? "matched" : "did not match"})`}{r.explanation.length > 0 && ` · selections: ${r.explanation.join(", ")}`}</span>}
            <button className="btn py-0 ml-auto" disabled={!write} onClick={() => delTest.mutate(c.id)} aria-label={`Delete test ${c.name}`}>Remove</button>
          </div>;
        })}
        <div className="flex gap-2 items-start">
          <textarea aria-label="Sample event JSON" className="input font-mono text-xs h-32 flex-1" value={evText} onChange={(e) => setEvText(e.target.value)} spellCheck={false} disabled={!write} />
          <div className="space-y-1 text-xs">
            <input aria-label="Test name" className="input w-48" placeholder="Test name" value={name} onChange={(e) => setName(e.target.value)} disabled={!write} />
            <label className="flex items-center gap-1"><input type="checkbox" checked={expect} onChange={(e) => setExpect(e.target.checked)} /> must match</label>
            <button className="btn" disabled={!write || !name.trim() || addTest.isPending} onClick={() => { setLocalErr(parseEvent(evText).error ?? null); addTest.mutate(); }}>Add test</button>
            <button className="btn block" disabled={!write || !rule.executable || run.isPending} onClick={() => run.mutate()}>Run tests</button>
          </div>
        </div>
        {localErr && <p role="alert" className="text-red-400 text-xs">{localErr}</p>}
        <ErrorLine error={addTest.error ?? run.error} fallback="Test action failed" />
      </div>

      <div className="space-y-1">
        <h3 className="font-semibold text-xs">Backtest</h3>
        <p className="text-xs text-muted">Counts matches in the last 24 hours of telemetry. A backtest never raises alerts.</p>
        <button className="btn" disabled={!write || !rule.executable || back.isPending} onClick={() => back.mutate()}>{back.isPending ? "Running…" : "Run backtest"}</button>
        {back.data && <p className="text-xs">{back.data.total} matching event(s) in {back.data.run.took_ms} ms{back.data.total > back.data.hits.length ? ` (showing ${back.data.hits.length})` : ""}.</p>}
        <ErrorLine error={back.error} fallback="Backtest failed" />
      </div>
    </section>
  );
}

function RulesTab() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [text, setText] = useState(SIGMA_TEMPLATE);
  const [fmt, setFmt] = useState("sigma");
  const rules = useQuery({ queryKey: ["det-rules"], queryFn: () => api.listRules() });
  const create = useMutation({
    mutationFn: () => api.createRule({ format: fmt, content: text }),
    onSuccess: (r) => { void qc.invalidateQueries({ queryKey: ["det-rules"] }); setAdding(false); setSelected(r.id); },
  });
  const sel = rules.data?.find((r) => r.id === selected);
  return (
    <div className="space-y-3">
      <div className="flex gap-2 items-center">
        <button className="btn btn-primary" disabled={!can("detections:write")} onClick={() => setAdding((a) => !a)}>New rule</button>
        <span className="text-xs text-muted">Rules are stored as DRAFT. A rule runs only after its tests pass and a manager activates it.</span>
      </div>
      {adding && (
        <div className="panel p-3 space-y-2">
          <select aria-label="Rule format" className="input" value={fmt} onChange={(e) => { setFmt(e.target.value); setText(e.target.value === "sigma" ? SIGMA_TEMPLATE : "# title: My query\n# level: medium\nprocess.name:powershell.exe"); }}>
            <option value="sigma">Sigma</option><option value="hunt_query">Hunt query</option>
          </select>
          <textarea aria-label="New rule source" className="input w-full font-mono text-xs h-48" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
          <button className="btn btn-primary" disabled={create.isPending} onClick={() => create.mutate()}>Create draft</button>
          <ErrorLine error={create.error} fallback="Could not create rule" />
        </div>
      )}
      <ErrorLine error={rules.error} fallback="Failed to load rules" />
      {rules.data && (rules.data.length === 0 ? <p className="panel p-3 text-muted">No detection rules yet.</p> : (
        <table className="w-full text-xs">
          <thead className="text-left text-muted"><tr><th>Rule</th><th>Status</th><th>Severity</th><th>ATT&amp;CK</th><th>Tests</th><th>Open alerts</th><th>Updated</th></tr></thead>
          <tbody>{rules.data.map((r) => (
            <tr key={r.id} className="border-t border-line cursor-pointer hover:bg-white/5" onClick={() => setSelected(r.id)}>
              <td><button className="underline text-left" onClick={() => setSelected(r.id)}>{r.title}</button></td>
              <td><StatusPill status={r.status} /></td><td>{r.severity}</td><td>{r.techniques.join(", ")}</td>
              <td>{r.test_count}{r.tests_passed === true ? " ✓" : r.tests_passed === false ? " ✗" : ""}</td><td>{r.open_alerts}</td><td>{fmtTime(r.updated_at)}</td>
            </tr>))}
          </tbody>
        </table>
      ))}
      {sel && <RuleDetail key={`${sel.id}-${sel.version}`} rule={sel} onClose={() => setSelected(null)} />}
    </div>
  );
}

function AlertsTab() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [status, setStatus] = useState("OPEN");
  const alerts = useQuery({ queryKey: ["det-alerts", status], queryFn: () => api.listAlerts(status ? `?status=${status}` : "") });
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["det-alerts"] }); void qc.invalidateQueries({ queryKey: ["det-overview"] }); };
  const upd = useMutation({ mutationFn: (v: { a: Alert; s: Alert["status"] }) => api.updateAlert(v.a.id, v.s), onSuccess: refresh });
  const toCase = useMutation({ mutationFn: (a: Alert) => api.alertToCase(a.id), onSuccess: refresh });
  return (
    <div className="space-y-2">
      <select aria-label="Alert status" className="input text-xs" value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">all</option><option>OPEN</option><option>ACKNOWLEDGED</option><option>CLOSED</option>
      </select>
      <ErrorLine error={alerts.error ?? upd.error ?? toCase.error} fallback="Alert action failed" />
      {alerts.data && (alerts.data.length === 0 ? <p className="panel p-3 text-muted">No alerts.</p> : (
        <table className="w-full text-xs">
          <thead className="text-left text-muted"><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Status</th><th>Event</th><th /></tr></thead>
          <tbody>{alerts.data.map((a) => (
            <tr key={a.id} className="border-t border-line">
              <td>{fmtTime(a.event_timestamp)}</td><td>{a.rule_title} <span className="text-muted">v{a.rule_version}</span></td><td>{a.severity}</td><td>{a.status}</td>
              <td className="font-mono"><Link className="underline" href={`/events?id=${a.event_id}`}>{a.event_id.slice(0, 8)}</Link></td>
              <td className="space-x-1 text-right">
                {a.status === "OPEN" && <button className="btn py-0" disabled={!can("detections:write")} onClick={() => upd.mutate({ a, s: "ACKNOWLEDGED" })}>Acknowledge</button>}
                {a.status !== "CLOSED" && <button className="btn py-0" disabled={!can("detections:write")} onClick={() => upd.mutate({ a, s: "CLOSED" })}>Close</button>}
                {a.case_id ? <Link className="underline" href={`/cases/${a.case_id}`}>Case</Link>
                  : <button className="btn py-0" disabled={!can("cases:write") || !can("detections:write")} onClick={() => toCase.mutate(a)}>Open case</button>}
              </td>
            </tr>))}
          </tbody>
        </table>
      ))}
    </div>
  );
}

export function DetectionsView() {
  const [tab, setTab] = useState<"rules" | "alerts">("rules");
  const ov = useQuery({ queryKey: ["det-overview"], queryFn: () => api.detOverview() });
  return (
    <section className="space-y-3">
      <div className="flex items-center gap-3">
        <h1 className="text-base font-semibold">Detections</h1>
        {ov.data && <span className="text-xs text-muted">{ov.data.rules_by_status.ACTIVE ?? 0} active · {ov.data.open_alerts} open alert(s) · {ov.data.coverage.length} technique(s) covered</span>}
      </div>
      <div role="tablist" className="flex gap-2">
        {(["rules", "alerts"] as const).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} className={`btn ${tab === t ? "btn-primary" : ""}`} onClick={() => setTab(t)}>{t === "rules" ? "Rules" : "Alerts"}</button>
        ))}
      </div>
      {tab === "rules" ? <RulesTab /> : <AlertsTab />}
    </section>
  );
}
