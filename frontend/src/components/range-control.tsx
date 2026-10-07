"use client";
import { RELATIVE_RANGES, type RangeSpec } from "@/lib/query";

const toLocalInput = (iso: string) => iso.slice(0, 16);

/** Relative presets plus a custom UTC window. Shared by Events, hunt workspace and the timeline builder. */
export function RangeControl({ value, onChange }: { value: RangeSpec; onChange: (r: RangeSpec) => void }) {
  const key = value.kind === "rel" ? value.value : "custom";
  return (
    <span className="inline-flex items-center gap-1">
      <select aria-label="Time range" className="input" value={key}
        onChange={(e) => {
          if (e.target.value !== "custom") onChange({ kind: "rel", value: e.target.value });
          else {
            const end = new Date();
            onChange({ kind: "abs", start: new Date(end.getTime() - 3_600_000).toISOString(), end: end.toISOString() });
          }
        }}>
        {Object.keys(RELATIVE_RANGES).map((r) => <option key={r} value={r}>Last {r}</option>)}
        <option value="custom">Custom</option>
      </select>
      {value.kind === "abs" && (
        <span className="inline-flex items-center gap-1 text-xs">
          <label>From <input aria-label="Range start" type="datetime-local" className="input" value={toLocalInput(value.start)}
            onChange={(e) => e.target.value && onChange({ ...value, start: new Date(e.target.value + "Z").toISOString() })} /></label>
          <label>To <input aria-label="Range end" type="datetime-local" className="input" value={toLocalInput(value.end)}
            onChange={(e) => e.target.value && onChange({ ...value, end: new Date(e.target.value + "Z").toISOString() })} /></label>
          <span className="text-muted">UTC</span>
        </span>
      )}
    </span>
  );
}
