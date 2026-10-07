"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { useAuth } from "@/lib/auth";

export const NAV = [
  { href: "/", label: "Overview" },
  { href: "/hunts", label: "Hunts" },
  { href: "/investigations", label: "Investigations" },
  { href: "/cases", label: "Cases" },
  { href: "/events", label: "Events" },
  { href: "/threat-intel", label: "Threat Intelligence" },
  { href: "/detections", label: "Detections" },
  { href: "/mitre", label: "MITRE ATT&CK" },
  { href: "/assets", label: "Assets" },
  { href: "/data-sources", label: "Data Sources" },
  { href: "/reports", label: "Reports" },
  { href: "/settings", label: "Settings" },
];
const LIVE = new Set(["/", "/events", "/settings"]);

export function Shell({ children }: { children: ReactNode }) {
  const { status, session, logout, switchTenant } = useAuth();
  const router = useRouter();
  const path = usePathname();

  useEffect(() => { if (status === "anon") router.replace("/login"); }, [status, router]);
  if (status !== "authed" || !session) return <div className="p-4 text-muted">Loading…</div>;

  return (
    <div className="flex min-h-screen">
      <nav aria-label="Primary" className="w-44 shrink-0 border-r border-line bg-panel py-2">
        {NAV.map((n) => {
          const active = n.href === "/" ? path === "/" : path.startsWith(n.href);
          return (
            <Link key={n.href} href={n.href}
              className={`block px-3 py-1 ${active ? "bg-bg text-accent border-l-2 border-accent" : "border-l-2 border-transparent hover:bg-bg"} ${LIVE.has(n.href) ? "" : "text-muted"}`}>
              {n.label}
            </Link>
          );
        })}
      </nav>
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-9 border-b border-line bg-panel px-3 flex items-center gap-3 text-xs">
          <span className="text-muted">Tenant</span>
          {session.available_tenants.length > 1 ? (
            <select aria-label="Tenant" className="input py-0" value={session.tenant?.id ?? ""}
              onChange={(e) => void switchTenant(e.target.value)}>
              {!session.tenant && <option value="">— select —</option>}
              {session.available_tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          ) : <span>{session.tenant?.name ?? "—"}</span>}
          <span className="ml-auto text-muted">{session.email}</span>
          <span className="border border-line px-1.5 rounded-sm">{session.role}</span>
          <button className="btn py-0" onClick={() => void logout().then(() => router.replace("/login"))}>Sign out</button>
        </header>
        <main className="flex-1 min-w-0 p-3">{children}</main>
      </div>
    </div>
  );
}
