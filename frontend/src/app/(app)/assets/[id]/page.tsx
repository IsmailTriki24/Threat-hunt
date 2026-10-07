"use client";
import Link from "next/link";
import { use } from "react";
import { AssetView } from "@/components/assets-view";

export default function AssetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <p className="text-xs mb-1"><Link href="/assets" className="text-muted hover:text-accent">← Assets</Link></p>
      <AssetView id={id} />
    </section>
  );
}
