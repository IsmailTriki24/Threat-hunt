"use client";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Filter } from "@/lib/api-types";
import { OP_LABEL } from "@/lib/query";

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

const HINT = 'field:value  -field:value  field:(a|b)  field>=N  value*  *value*  has:field  "free text" AND/OR/NOT';

function chip(f: Filter): string {
  const v = Array.isArray(f.value) ? `(${f.value.join("|")})` : String(f.value ?? "");
  const op = f.op === "exists" ? "exists" : OP_LABEL[f.op];
  return `${f.negate ? "NOT " : ""}${f.field} ${op}${f.op === "exists" ? "" : ` ${v}`}`;
}

/** Hunt-query-language editor: monospace, Ctrl/Cmd+Enter runs, debounced live validation against the server parser. */
export function QueryEditor({ value, onChange, onRun, readOnly = false, delayMs = 350, rows = 3 }: {
  value: string; onChange: (v: string) => void; onRun: () => void; readOnly?: boolean; delayMs?: number; rows?: number;
}) {
  const debounced = useDebounced(value.trim(), delayMs);
  const parsed = useQuery({
    queryKey: ["parse-query", debounced],
    queryFn: () => api.parseQuery(debounced),
    enabled: debounced.length > 0,
    retry: false,
    staleTime: 60_000,
  });
  const pending = value.trim() !== debounced;
  const err = parsed.error instanceof ApiError ? parsed.error.message.replace(/^Query error: /, "") : parsed.error ? "Validation failed" : null;

  return (
    <div className="space-y-1">
      <textarea aria-label="Hunt query" className="input w-full font-mono text-xs" rows={rows} value={value} readOnly={readOnly}
        spellCheck={false} maxLength={2000} placeholder='process.parent.name:WINWORD.EXE process.name:powershell.exe'
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); onRun(); } }} />
      <div className="text-xs min-h-4" aria-live="polite">
        {value.trim() === "" ? <span className="text-muted">{HINT}</span>
          : pending || parsed.isFetching ? <span className="text-muted">Validating…</span>
          : err ? <span role="alert" className="text-red-400">{err}</span>
          : parsed.data ? (
            <span className="flex flex-wrap gap-1 items-center" aria-label="Parsed query">
              <span className="text-muted">Parsed:</span>
              {parsed.data.filters.map((f, i) => <span key={i} className="border border-line px-1 rounded-sm font-mono">{chip(f)}</span>)}
              {parsed.data.q && <span className="border border-line px-1 rounded-sm font-mono">text: {parsed.data.q}</span>}
              {!parsed.data.filters.length && !parsed.data.q && <span className="text-muted">empty</span>}
            </span>
          ) : null}
      </div>
    </div>
  );
}
