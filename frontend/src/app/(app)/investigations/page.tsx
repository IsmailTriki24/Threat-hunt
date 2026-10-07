import { Suspense } from "react";
import { InvestigationView } from "@/components/investigation-view";

export default function InvestigationsPage() {
  return (
    <section>
      <h1 className="text-base font-semibold mb-2">Investigations</h1>
      <Suspense fallback={<p className="text-muted">Loading…</p>}><InvestigationView /></Suspense>
    </section>
  );
}
