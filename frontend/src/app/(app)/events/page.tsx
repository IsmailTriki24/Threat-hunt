import { Suspense } from "react";
import { EventsView } from "@/components/events-view";
import { Loading } from "@/components/ui/skeleton";

export default function EventsPage() {
  return (
    <section>
      <Suspense fallback={<Loading />}><EventsView /></Suspense>
    </section>
  );
}
