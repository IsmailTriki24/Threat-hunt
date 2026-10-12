import { PageHeader } from "@/components/ui/page-header";
import { CasesList } from "@/components/cases-list";

export default function Page() {
  return (
    <section>
      <PageHeader title="Cases" description="Incidents with their evidence, indicators, affected assets and reports." />
      <CasesList />
    </section>
  );
}
