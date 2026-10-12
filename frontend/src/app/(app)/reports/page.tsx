import { PageHeader } from "@/components/ui/page-header";
import { ReportsIndex } from "@/components/reports-view";

export default function Page() {
  return (
    <section>
      <PageHeader title="Reports" description="Case reports across the tenant. Open a case to author or version its report." />
      <ReportsIndex />
    </section>
  );
}
