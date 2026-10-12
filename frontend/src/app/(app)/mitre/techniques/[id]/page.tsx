"use client";
import { BackLink } from "@/components/ui/back-link";
import { use } from "react";
import { TechniqueView } from "@/components/mitre-views";

export default function TechniquePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <BackLink href="/mitre">MITRE ATT&amp;CK</BackLink>
      <TechniqueView id={decodeURIComponent(id)} />
    </section>
  );
}
