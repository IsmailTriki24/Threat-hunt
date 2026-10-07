"use client";
import Link from "next/link";
import { use } from "react";
import { EntityView } from "@/components/entity-view";

export default function EntityPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <p className="text-xs mb-1"><Link href="/threat-intel" className="text-muted hover:text-accent">← Threat Intelligence</Link></p>
      <EntityView id={id} />
    </section>
  );
}
