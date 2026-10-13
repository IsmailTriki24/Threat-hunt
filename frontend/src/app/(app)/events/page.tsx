import { Suspense } from "react";
import { SiemSearchView } from "@/components/siem-search-view";
import { Loading } from "@/components/ui/skeleton";

export default function EventsPage() {
  return (
    <section>
      <Suspense fallback={<Loading />}><SiemSearchView /></Suspense>
    </section>
  );
}
