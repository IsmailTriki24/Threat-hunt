"use client";
import Link from "next/link";
import { use } from "react";
import { CaseWorkspace } from "@/components/case-workspace";

export default function CasePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <p className="text-xs mb-1"><Link href="/cases" className="text-muted hover:text-accent">← Cases</Link></p>
      <CaseWorkspace id={id} />
    </section>
  );
}
