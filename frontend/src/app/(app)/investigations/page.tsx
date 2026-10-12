import { PageHeader } from "@/components/ui/page-header";
import { Suspense } from "react";
import { InvestigationView } from "@/components/investigation-view";
import { Loading } from "@/components/ui/skeleton";

export default function InvestigationsPage() {
  return (
    <section>
      <PageHeader title="Investigations" description="Reconstruct what happened around a host, user or event as a single timeline." />
      <Suspense fallback={<Loading />}><InvestigationView /></Suspense>
    </section>
  );
}
