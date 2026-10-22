"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import { fmtTime } from "@/lib/query";
import { ErrorLine } from "./badges";

/** The experience library: what the agent has learned about searching this tenant's SIEMs. Active lessons are shown to it at the start of
 *  every hunt; an analyst can write one, switch one off, or delete it. */
export function Lessons() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["ai-lessons"], queryFn: () => api.aiLessons() });
  const [cue, setCue] = useState("");
  const [lesson, setLesson] = useState("");
  const done = () => { void qc.invalidateQueries({ queryKey: ["ai-lessons"] }); };
  const add = useMutation({ mutationFn: () => api.aiAddLesson({ cue: cue.trim(), lesson: lesson.trim() }), onSuccess: () => { setCue(""); setLesson(""); done(); } });
  const toggle = useMutation({ mutationFn: (x: { id: string; status: "active" | "disabled" }) => api.aiSetLesson(x.id, x.status), onSuccess: done });
  const del = useMutation({ mutationFn: (id: string) => api.aiDeleteLesson(id), onSuccess: done });
  const rows = list.data ?? [];
  const active = rows.filter((x) => x.status === "active").length;
  const valid = cue.trim().length >= 8 && lesson.trim().length >= 20;
  return (
    <details className="panel p-4" aria-label="Experience library">
      <summary className="cursor-pointer text-xs font-semibold">Experience library <span className="font-normal text-muted">· {active} active of {rows.length}</span></summary>
      <div className="mt-2 space-y-3">
        <p className="text-xs text-muted">Lessons about <em>how to search</em>, written from finished hunts or by you. The agent sees the active ones at the start of each hunt as guidance, never as facts about your environment. Switch off or delete any that are wrong.</p>
        {rows.length === 0 && !list.isLoading && <p className="text-xs text-muted">Nothing learned yet. Lessons appear after a hunt with enough searches to learn from.</p>}
        <ul className="space-y-2">
          {rows.map((x) => (
            <li key={x.id} className={`rounded-md border border-line p-2 text-xs ${x.status === "disabled" ? "opacity-60" : ""}`}>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-medium">When {x.cue.replace(/\.$/, "")}</span>
                <span className="badge">{x.origin === "analyst" ? "analyst" : "learned"}</span>
                <span className="badge">{x.confidence}</span>
                <span className="text-muted">shown {x.times_shown}× · {fmtTime(x.created_at)}</span>
                <span className="ml-auto flex gap-1">
                  <button type="button" className="btn" disabled={toggle.isPending} onClick={() => toggle.mutate({ id: x.id, status: x.status === "active" ? "disabled" : "active" })}>{x.status === "active" ? "Switch off" : "Switch on"}</button>
                  <button type="button" className="btn" disabled={del.isPending} aria-label={`Delete lesson: ${x.cue}`} onClick={() => del.mutate(x.id)}>Delete</button>
                </span>
              </div>
              <p className="mt-1">{x.lesson}</p>
              {x.evidence && <p className="mt-0.5 text-muted">Why: {x.evidence}</p>}
            </li>
          ))}
        </ul>
        <div className="space-y-1.5 border-t border-line pt-2">
          <input aria-label="When it applies" className="input w-full" placeholder="When it applies, e.g. asking Trend about a host" value={cue} onChange={(e) => setCue(e.target.value)} maxLength={200} />
          <textarea aria-label="Lesson" className="input h-16 w-full resize-none" placeholder="What to do, e.g. Trend answers per short host name; do not use the fully qualified name." value={lesson} onChange={(e) => setLesson(e.target.value)} maxLength={400} />
          <button type="button" className="btn" disabled={!valid || add.isPending} onClick={() => add.mutate()}>{add.isPending ? "Adding…" : "Add lesson"}</button>
        </div>
        <ErrorLine error={list.error ?? add.error ?? toggle.error ?? del.error} fallback="Could not update the library" />
      </div>
    </details>
  );
}
