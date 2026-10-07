import { Suspense } from "react";
import { EventsView } from "@/components/events-view";

export default function EventsPage() {
  return (
    <section>
      <h1 className="text-base font-semibold mb-2">Events</h1>
      <Suspense fallback={<p className="text-muted">Loading…</p>}><EventsView /></Suspense>
    </section>
  );
}
