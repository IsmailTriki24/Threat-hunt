"use client";
import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import type { EntityType } from "@/lib/api-types";
import { ErrorLine } from "./badges";

/** Looks the indicator up (creating the entity if needed) and opens its page. Needs intel:write — callers gate on it. */
export function IntelOpenButton({ type, value, label = "Intel" }: { type: EntityType | string; value: string; label?: string }) {
  const router = useRouter();
  const look = useMutation({
    mutationFn: () => api.intelLookup({ value, type: type as EntityType }),
    onSuccess: (d) => router.push(`/threat-intel/${d.entity.id}`),
  });
  return (
    <span className="inline-flex items-center gap-1">
      <button className="btn py-0 text-xs" disabled={look.isPending} onClick={() => look.mutate()} aria-label={`Look up ${value} in threat intelligence`} title="Threat-intelligence lookup">{look.isPending ? "…" : label}</button>
      <ErrorLine error={look.error} fallback="Lookup failed" />
    </span>
  );
}
