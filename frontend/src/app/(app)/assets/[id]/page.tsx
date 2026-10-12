"use client";
import { BackLink } from "@/components/ui/back-link";
import { use } from "react";
import { AssetView } from "@/components/assets-view";

export default function AssetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <BackLink href="/assets">Assets</BackLink>
      <AssetView id={id} />
    </section>
  );
}
