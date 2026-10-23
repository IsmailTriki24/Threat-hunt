import { PageHeader } from "@/components/ui/page-header";
import { TenantsView } from "@/components/tenants-view";

export default function Page() {
  return (
    <section>
      <PageHeader title="Tenants" description="Organisations on the platform, their administrators and the log sources assigned to them." />
      <TenantsView />
    </section>
  );
}
