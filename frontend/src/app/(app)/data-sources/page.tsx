import { PageHeader } from "@/components/ui/page-header";
import { DataSourcesView } from "@/components/data-sources-view";

export default function Page() {
  return (
    <section>
      <PageHeader title="Data Sources" description="Connectors that bring telemetry in. Credentials are write-only and stored encrypted." />
      <DataSourcesView />
    </section>
  );
}
