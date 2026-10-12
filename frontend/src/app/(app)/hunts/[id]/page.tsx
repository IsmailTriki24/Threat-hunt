"use client";
import { BackLink } from "@/components/ui/back-link";
import { use } from "react";
import { HuntWorkspace } from "@/components/hunt-workspace";

export default function HuntPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <BackLink href="/hunts">Hunts</BackLink>
      <HuntWorkspace id={id} />
    </section>
  );
}
