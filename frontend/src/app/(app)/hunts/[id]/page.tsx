"use client";
import Link from "next/link";
import { use } from "react";
import { HuntWorkspace } from "@/components/hunt-workspace";

export default function HuntPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <section>
      <p className="text-xs mb-1"><Link href="/hunts" className="text-muted hover:text-accent">← Hunts</Link></p>
      <HuntWorkspace id={id} />
    </section>
  );
}
