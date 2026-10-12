import { PageHeader } from "@/components/ui/page-header";
import { AssetsList } from "@/components/assets-view";

export default function Page() {
  return (
    <section>
      <PageHeader title="Assets" description="Hosts, users and other entities discovered in telemetry or added by analysts." />
      <AssetsList />
    </section>
  );
}
