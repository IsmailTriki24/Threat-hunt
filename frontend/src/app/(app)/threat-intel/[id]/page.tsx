"use client";
import { BackLink } from "@/components/ui/back-link";
import { use } from "react";
import { EntityView } from "@/components/entity-view";

export default function EntityPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <BackLink href="/threat-intel">Threat Intelligence</BackLink>
      <EntityView id={id} />
    </section>
  );
}
