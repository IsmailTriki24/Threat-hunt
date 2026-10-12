import { Suspense } from "react";
import { ThreatIntelView } from "@/components/threat-intel-view";

export default function Page() {
  return <Suspense fallback={null}><ThreatIntelView /></Suspense>;
}
