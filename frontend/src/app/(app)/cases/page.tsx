import { CasesList } from "@/components/cases-list";

export default function Page() {
  return (
    <section className="space-y-2">
      <h1 className="text-base font-semibold">Cases</h1>
      <CasesList />
    </section>
  );
}
