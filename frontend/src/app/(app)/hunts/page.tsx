import { HuntsList } from "@/components/hunts-list";

export default function HuntsPage() {
  return (
    <section>
      <h1 className="text-base font-semibold mb-2">Hunts</h1>
      <HuntsList />
    </section>
  );
}
