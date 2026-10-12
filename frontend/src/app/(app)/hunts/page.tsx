import { PageHeader } from "@/components/ui/page-header";
import { HuntsList } from "@/components/hunts-list";

export default function HuntsPage() {
  return (
    <section>
      <PageHeader title="Hunts" description="Hypothesis-driven investigations with saved queries, findings and notes." />
      <HuntsList />
    </section>
  );
}
