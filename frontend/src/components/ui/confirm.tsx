"use client";
import { useCallback, useState, type ReactNode } from "react";
import { ConfirmDialog } from "./overlay";

interface Ask { title: string; message: ReactNode; confirmLabel: string; danger?: boolean; run: () => void }

/** Replaces `window.confirm`: `confirm({...})` opens an accessible dialog, `node` renders it. The action runs only on explicit confirmation. */
export function useConfirm() {
  const [req, setReq] = useState<Ask | null>(null);
  const confirm = useCallback((a: Ask) => setReq(a), []);
  const node = req ? (
    <ConfirmDialog title={req.title} message={req.message} confirmLabel={req.confirmLabel} danger={req.danger ?? true}
      onConfirm={() => { const run = req.run; setReq(null); run(); }} onClose={() => setReq(null)} />
  ) : null;
  return { confirm, node };
}
