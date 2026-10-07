import { AssetsList } from "@/components/assets-view";

export default function Page() {
  return (
    <section className="space-y-2">
      <h1 className="text-base font-semibold">Assets</h1>
      <AssetsList />
    </section>
  );
}
