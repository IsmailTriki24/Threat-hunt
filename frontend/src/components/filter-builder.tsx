"use client";
import { Plus, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import type { FieldInfo, Filter, Op } from "@/lib/api-types";
import { OP_LABEL, operatorsFor } from "@/lib/query";

export function FilterBuilder({ fields, onAdd }: { fields: FieldInfo[]; onAdd: (f: Filter) => void }) {
  const [field, setField] = useState("");
  const [op, setOp] = useState<Op>("eq");
  const [value, setValue] = useState("");
  const spec = fields.find((f) => f.name === field);
  const ops = spec ? operatorsFor(spec.kind) : [];
  const noValue = op === "exists" || op === "not_exists";

  function pickField(name: string) {
    setField(name);
    const s = fields.find((f) => f.name === name);
    setOp(s ? operatorsFor(s.kind)[0] : "eq");
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!spec || (!noValue && value.trim() === "")) return;
    onAdd(noValue ? { field, op } : { field, op, value: value.trim() });
    setValue("");
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-center gap-1.5" aria-label="Add filter">
      <select aria-label="Field" className="input" value={field} onChange={(e) => pickField(e.target.value)}>
        <option value="">field…</option>
        {fields.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
      </select>
      <select aria-label="Operator" className="input" value={op} onChange={(e) => setOp(e.target.value as Op)} disabled={!spec}>
        {ops.map((o) => <option key={o} value={o}>{OP_LABEL[o]}</option>)}
      </select>
      {!noValue && (
        <input aria-label="Value" className="input w-44" value={value} onChange={(e) => setValue(e.target.value)} placeholder="value" maxLength={128} disabled={!spec} />
      )}
      <button type="submit" className="btn" disabled={!spec}><Plus aria-hidden className="h-3.5 w-3.5" />Add filter</button>
    </form>
  );
}

export function FilterChips({ filters, onRemove }: { filters: Filter[]; onRemove: (i: number) => void }) {
  if (!filters.length) return null;
  return (
    <ul className="flex flex-wrap gap-1.5" aria-label="Active filters">
      {filters.map((f, i) => (
        <li key={`${f.field}-${f.op}-${String(f.value)}-${i}`}
          className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs ${f.op === "neq" || f.op === "not_exists" ? "border-sev-critical/40 bg-sev-critical-bg text-sev-critical" : "border-accent/30 bg-accent-soft text-ink"}`}>
          <span className="text-muted">{f.field}</span>
          <span>{OP_LABEL[f.op]}</span>
          {f.value !== undefined && f.value !== null && <span className="font-mono">{String(f.value)}</span>}
          <button aria-label={`Remove filter ${f.field}`} className="rounded text-muted hover:text-ink" onClick={() => onRemove(i)}><X aria-hidden className="h-3 w-3" /></button>
        </li>
      ))}
    </ul>
  );
}
