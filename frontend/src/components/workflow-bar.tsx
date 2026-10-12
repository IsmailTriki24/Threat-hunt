"use client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import type { CaseOut } from "@/lib/api-types";
import { transitionNeedsComment } from "@/lib/cases";
import { ErrorLine, Modal, StatusBadge } from "./badges";

/** Shows the current status and exactly the transitions the server says are allowed. */
export function WorkflowBar({ c, canWrite }: { c: CaseOut; canWrite: boolean }) {
  const qc = useQueryClient();
  const [pending, setPending] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const move = useMutation({
    mutationFn: ({ to, text }: { to: string; text: string }) => api.transitionCase(c.id, to, text),
    onSuccess: () => {
      setPending(null); setComment("");
      void qc.invalidateQueries({ queryKey: ["case", c.id] });
      void qc.invalidateQueries({ queryKey: ["cases"] });
      void qc.invalidateQueries({ queryKey: ["case-activity", c.id] });
    },
  });
  const click = (to: string) => {
    move.reset();
    if (transitionNeedsComment(c.status, to)) setPending(to); else move.mutate({ to, text: "" });
  };
  const reopen = c.status === "CLOSED";

  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3" aria-label="Case workflow">
      <span className="text-sm text-muted">Status</span>
      <StatusBadge status={c.status} />
      <span aria-hidden className="text-muted">→</span>
      {c.allowed_transitions.length === 0 && <span className="text-sm text-muted">no transitions available</span>}
      {c.allowed_transitions.map((t) => (
        <button key={t} className="btn btn-sm" disabled={!canWrite || move.isPending} onClick={() => click(t)}
          title={canWrite ? "" : "Your role cannot change case status"}>
          {reopen ? `Reopen as ${t.replace("_", " ")}` : t.replace("_", " ")}
        </button>
      ))}
      {!pending && <ErrorLine error={move.error} fallback="Transition failed" />}
      {pending && (
        <Modal title={reopen ? "Reopen case" : `Move to ${pending.replace("_", " ")}`} onClose={() => { setPending(null); setComment(""); move.reset(); }}>
          <label htmlFor="resolution" className="text-sm font-medium text-ink-2">{reopen ? "Reason for reopening" : "Resolution / comment (required)"}</label>
          <textarea id="resolution" className="input w-full" rows={4} maxLength={10000} value={comment} onChange={(e) => setComment(e.target.value)} autoFocus data-autofocus />
          <ErrorLine error={move.error} fallback="Transition failed" />
          <div className="flex justify-end gap-2"><button className="btn" onClick={() => { setPending(null); setComment(""); move.reset(); }}>Cancel</button>
          <button className="btn btn-primary" disabled={!comment.trim() || move.isPending} onClick={() => move.mutate({ to: pending, text: comment.trim() })}>Confirm</button></div>
        </Modal>
      )}
    </div>
  );
}
