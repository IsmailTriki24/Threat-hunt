"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import type { RangeSpec } from "@/lib/query";
import { resolveRange } from "@/lib/query";
import type { TimelineScope } from "@/lib/api-types";
import { appendPivot } from "@/lib/hunt-query";
import { EventDrawer } from "./event-drawer";
import { QueryEditor } from "./query-editor";
import { RangeControl } from "./range-control";
import { TimelinePanel, type TimelineSource } from "./timeline-view";

const ID = /^[a-f0-9]{32}$/;

/** Standalone timeline builder: from a hunt-language query + time range, or around an event (?event=<id>). */
export function InvestigationView() {
  const sp = useSearchParams();
  const router = useRouter();
  const ev = sp.get("event");
  const [text, setText] = useState("");
  const [range, setRange] = useState<RangeSpec>({ kind: "rel", value: "6h" });
  const [source, setSource] = useState<TimelineSource | null>(
    ev && ID.test(ev) ? { kind: "around", eventId: ev, scope: (sp.get("scope") as TimelineScope) || "host", windowMinutes: 30 } : null);
  const [open, setOpen] = useState<string | null>(null);

  const build = () => setSource({ kind: "query", query: { text: text.trim() || undefined, time_range: resolveRange(range), filters: [], sort: [], offset: 0, limit: 50, aggregations: [] } });

  return (
    <div className="space-y-2">
      <QueryEditor value={text} onChange={setText} onRun={build} />
      <div className="flex gap-1 items-center">
        <RangeControl value={range} onChange={setRange} />
        <button className="btn btn-primary" onClick={build}>Build timeline</button>
        {source?.kind === "around" && <button className="btn" onClick={() => { setSource(null); router.replace("/investigations"); }}>Clear event scope</button>}
        <span className="text-xs text-muted ml-2">Tip: scope with host.hostname:… and user.name:… to follow one actor.</span>
      </div>
      <TimelinePanel source={source} onOpen={setOpen} />
      {open && (
        <EventDrawer id={open} onClose={() => setOpen(null)} onPivot={(f) => { setText((t) => appendPivot(t, f.field, String(f.value))); setOpen(null); }}
          onTimeline={(eventId, scope, windowMinutes) => { setSource({ kind: "around", eventId, scope, windowMinutes }); setOpen(null); }} />
      )}
    </div>
  );
}
