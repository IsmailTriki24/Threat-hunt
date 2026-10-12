"use client";
import { BackLink } from "@/components/ui/back-link";
import { use } from "react";
import { CaseWorkspace } from "@/components/case-workspace";

export default function CasePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <BackLink href="/cases">Cases</BackLink>
      <CaseWorkspace id={id} />
    </section>
  );
}
