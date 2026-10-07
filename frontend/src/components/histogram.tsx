"use client";
import { useState } from "react";
import type { Bucket } from "@/lib/api-types";

interface Props { buckets: Bucket[]; rangeEnd: string; onSelect: (start: string, end: string) => void }

/** Plain-SVG timeline. Click a bar or drag across bars to narrow the time range. */
export function Histogram({ buckets, rangeEnd, onSelect }: Props) {
  const [drag, setDrag] = useState<{ from: number; to: number } | null>(null);
  if (!buckets.length) return null;
  const starts = buckets.map((b) => Date.parse(String(b.key)));
  const step = starts.length > 1 ? starts[1] - starts[0] : 60_000;
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const W = 1000, H = 60, bw = W / buckets.length;

  function finish(to: number) {
    if (!drag) return;
    const lo = Math.min(drag.from, to), hi = Math.max(drag.from, to);
    const end = Math.min(starts[hi] + step, Date.parse(rangeEnd));
    onSelect(new Date(starts[lo]).toISOString(), new Date(end).toISOString());
    setDrag(null);
  }

  return (
    <svg viewBox={`0 0 ${W} ${H + 12}`} className="w-full h-20 select-none" role="img" aria-label="Event timeline"
      onMouseLeave={() => setDrag(null)}>
      {buckets.map((b, i) => {
        const h = (b.count / max) * H;
        const sel = drag && i >= Math.min(drag.from, drag.to) && i <= Math.max(drag.from, drag.to);
        return (
          <g key={String(b.key)} onMouseDown={() => setDrag({ from: i, to: i })}
            onMouseEnter={() => drag && setDrag({ ...drag, to: i })} onMouseUp={() => finish(i)} className="cursor-crosshair">
            <rect x={i * bw} y={0} width={bw} height={H} fill="transparent" />
            <rect x={i * bw + 0.5} y={H - h} width={Math.max(bw - 1, 1)} height={h} fill={sel ? "#d29922" : "#58a6ff"}>
              <title>{`${String(b.key)} — ${b.count}`}</title>
            </rect>
          </g>
        );
      })}
      <text x={0} y={H + 10} fontSize="9" fill="#8b949e">{new Date(starts[0]).toISOString().slice(0, 16).replace("T", " ")}</text>
      <text x={W} y={H + 10} fontSize="9" fill="#8b949e" textAnchor="end">{rangeEnd.slice(0, 16).replace("T", " ")}</text>
    </svg>
  );
}
