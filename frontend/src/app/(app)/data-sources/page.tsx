import { DataSourcesView } from "@/components/data-sources-view";

export default function Page() {
  return (
    <section className="space-y-2">
      <h1 className="text-base font-semibold">Data Sources</h1>
      <DataSourcesView />
    </section>
  );
}
