import { Suspense } from "react";
import { ThreatMapView } from "@/components/threat-map-view";

export default function Page() {
  return <Suspense fallback={<div className="text-muted">Loading…</div>}><ThreatMapView /></Suspense>;
}
