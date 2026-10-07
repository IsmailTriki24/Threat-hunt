"use client";
import Link from "next/link";
import { use } from "react";
import { TechniqueView } from "@/components/mitre-views";

export default function TechniquePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <p className="text-xs mb-1"><Link href="/mitre" className="text-muted hover:text-accent">← MITRE ATT&amp;CK</Link></p>
      <TechniqueView id={decodeURIComponent(id)} />
    </section>
  );
}
