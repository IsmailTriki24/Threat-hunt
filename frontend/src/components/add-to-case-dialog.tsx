"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import type { CaseOut } from "@/lib/api-types";
import { ErrorLine, Modal } from "./badges";

/** Attach events to an existing open case, or create a new case seeded with them. */
export function AddToCaseDialog({ eventIds, onClose }: { eventIds: string[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [mode, setMode] = useState<"existing" | "new">("existing");
  const [caseId, setCaseId] = useState("");
  const [title, setTitle] = useState("");
  const [comment, setComment] = useState("");
  const [done, setDone] = useState<CaseOut | null>(null);
  const cases = useQuery({ queryKey: ["cases", "picker"], queryFn: () => api.listCases("?limit=200") });
  const open = (cases.data ?? []).filter((c) => c.status !== "CLOSED");

  const add = useMutation({
    mutationFn: async () => {
      if (mode === "new") return api.createCase({ title: title.trim(), event_ids: eventIds });
      await api.addCaseEvidence(caseId, eventIds, comment);
      return api.getCase(caseId);
    },
    onSuccess: (c) => { setDone(c); void qc.invalidateQueries({ queryKey: ["cases"] }); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); add.mutate(); };
  const valid = mode === "new" ? title.trim().length > 0 : !!caseId;

  return (
    <Modal title="Add to case" onClose={onClose}>
      {done ? (
        <div className="space-y-2">
          <p>Added {eventIds.length} event{eventIds.length === 1 ? "" : "s"} to <span className="font-mono">{done.case_id}</span> — {done.title}.</p>
          <Link className="btn btn-primary inline-block" href={`/cases/${done.id}`}>Open case</Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-2" aria-label="Add to case">
          <p className="text-xs text-muted">{eventIds.length} event{eventIds.length === 1 ? "" : "s"} selected. IOCs and assets are extracted automatically.</p>
          <div className="flex gap-3 text-xs">
            <label><input type="radio" name="mode" checked={mode === "existing"} onChange={() => setMode("existing")} /> Existing case</label>
            <label><input type="radio" name="mode" checked={mode === "new"} onChange={() => setMode("new")} /> New case</label>
          </div>
          {mode === "existing" ? (
            <>
              <select aria-label="Case" className="input w-full" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                <option value="">— choose an open case —</option>
                {open.map((c) => <option key={c.id} value={c.id}>{c.case_id} · {c.status} · {c.title}</option>)}
              </select>
              {cases.isLoading && <p className="text-xs text-muted">Loading cases…</p>}
              <input aria-label="Comment" className="input w-full" placeholder="Comment (optional)" maxLength={2000} value={comment} onChange={(e) => setComment(e.target.value)} />
            </>
          ) : (
            <input aria-label="New case title" className="input w-full" placeholder="Case title" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
          )}
          <ErrorLine error={add.error} fallback="Failed to add events to the case" />
          <button className="btn btn-primary" type="submit" disabled={!valid || add.isPending}>{mode === "new" ? "Create case" : "Add evidence"}</button>
        </form>
      )}
    </Modal>
  );
}
