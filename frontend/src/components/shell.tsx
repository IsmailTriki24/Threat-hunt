"use client";
import { useIsFetching, useIsMutating, useQuery } from "@tanstack/react-query";
import { Bell, ChevronDown, ChevronRight, Loader2, LogOut, Menu, PanelLeftClose, PanelLeftOpen, Search, ShieldCheck, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { targets } from "@/lib/global-search";
import { breadcrumbs, isActive, NAV, NAV_GROUPS } from "@/lib/nav";
import { Tooltip } from "./ui/tooltip";

export { NAV };
const COLLAPSE_KEY = "thp.sidebar.collapsed";

function Brand({ collapsed }: { collapsed?: boolean }) {
  return (
    <Link href="/" className="flex h-[var(--header-h)] items-center gap-2.5 border-b border-line px-4">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent-brand text-white shadow-sm"><ShieldCheck aria-hidden className="h-[18px] w-[18px]" /></span>
      {!collapsed && <span className="min-w-0 leading-tight"><span className="block truncate text-sm font-semibold text-ink">Threat Hunting</span><span className="block truncate text-[11px] text-muted">Investigation platform</span></span>}
    </Link>
  );
}

function NavList({ path, collapsed, onNavigate }: { path: string; collapsed: boolean; onNavigate?: () => void }) {
  // A SIEM search keeps running (and its result is kept) while another module is open: say so on its entry.
  const siemBusy = useIsFetching({ queryKey: ["siem-query"] }) + useIsMutating({ mutationKey: ["siem-more"] }) > 0;
  return (
    <nav aria-label="Primary" className="min-h-0 flex-1 overflow-y-auto px-2 py-3">
      {NAV_GROUPS.map((g, gi) => (
        <div key={g.label} className={gi ? "mt-4" : ""}>
          {collapsed ? (gi ? <hr className="mx-2 mb-2 border-line" /> : null) : <div className="eyebrow px-2.5 pb-1">{g.label}</div>}
          <ul className="space-y-0.5">
            {g.items.map((n) => {
              const active = isActive(n.href, path);
              const Icon = n.icon;
              const link = (
                <Link href={n.href} aria-current={active ? "page" : undefined} onClick={onNavigate} title={collapsed ? undefined : n.hint}
                  className={`group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors duration-fast ${collapsed ? "justify-center" : ""} ${active ? "bg-accent-soft text-accent" : "text-ink-2 hover:bg-subtle hover:text-ink"}`}>
                  {active && <span aria-hidden className="absolute -left-2 top-1.5 bottom-1.5 w-[3px] rounded-r bg-accent-brand" />}
                  <Icon aria-hidden className={`h-[18px] w-[18px] shrink-0 ${active ? "text-accent" : "text-muted group-hover:text-ink-2"}`} strokeWidth={active ? 2.2 : 1.9} />
                  {collapsed ? <span className="sr-only">{n.label}</span> : <span className="truncate">{n.label}</span>}
                  {n.href === "/events" && siemBusy && <Loader2 role="status" aria-label="A SIEM search is running" className="ml-auto h-3.5 w-3.5 shrink-0 animate-spin text-accent" />}
                </Link>
              );
              return <li key={n.href}>{collapsed ? <Tooltip text={n.label} side="right">{link}</Tooltip> : link}</li>;
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function GlobalSearch() {
  const router = useRouter();
  const { can } = useAuth();
  const [v, setV] = useState("");
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const opts = targets(v, can("intel:write"));
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); ref.current?.focus(); setOpen(true); } };
    const click = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    window.addEventListener("keydown", k); document.addEventListener("mousedown", click);
    return () => { window.removeEventListener("keydown", k); document.removeEventListener("mousedown", click); };
  }, []);
  const go = (href: string) => { setOpen(false); router.push(href); };
  return (
    <div ref={box} className="relative w-full max-w-md" role="search" aria-label="Global search">
      <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
      <input ref={ref} aria-label="Search events and indicators" className="input w-full pl-8 pr-14" placeholder="Search IP, hash, domain, host, user…" value={v} maxLength={300}
        onChange={(e) => { setV(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)}
        onKeyDown={(e) => { if (e.key === "Enter" && opts[0]) { e.preventDefault(); go(opts[0].href); } if (e.key === "Escape") setOpen(false); }} />
      <span aria-hidden className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 items-center gap-0.5 md:flex"><kbd className="kbd">Ctrl</kbd><kbd className="kbd">K</kbd></span>
      {open && opts.length > 0 && (
        <ul role="listbox" aria-label="Search actions" className="absolute left-0 right-0 top-full z-40 mt-1 overflow-hidden rounded-lg border border-line bg-panel py-1 shadow-pop animate-pop-in">
          {opts.map((o) => (
            <li key={o.href} role="presentation">
              <button type="button" role="option" aria-selected={false} className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-accent-soft" onClick={() => go(o.href)}>
                <Search aria-hidden className="h-3.5 w-3.5 text-muted" />{o.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AlertsBell() {
  const { can } = useAuth();
  const ok = can("detections:read");
  const ov = useQuery({ queryKey: ["det-overview-bell"], queryFn: () => api.detOverview(), enabled: ok, refetchInterval: 60_000, staleTime: 30_000 });
  if (!ok) return null;
  const n = ov.data?.open_alerts ?? 0;
  return (
    <Tooltip text={ov.isError ? "Alerts unavailable" : `${n} open alert${n === 1 ? "" : "s"}`}>
      <Link href="/detections" aria-label={ov.isError ? "Alerts (unavailable)" : `Alerts: ${n} open`} className="btn btn-ghost relative px-2">
        <Bell aria-hidden className="h-[18px] w-[18px]" />
        {n > 0 && <span aria-hidden className="absolute -right-0.5 -top-0.5 min-w-[16px] rounded-full bg-sev-critical px-1 text-center text-[10px] font-semibold leading-4 text-white">{n > 99 ? "99+" : n}</span>}
      </Link>
    </Tooltip>
  );
}

function UserMenu() {
  const { session, logout, switchTenant } = useAuth();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const click = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", click); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", click); document.removeEventListener("keydown", esc); };
  }, []);
  if (!session) return null;
  const initials = (session.full_name || session.email).split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join("");
  return (
    <div ref={box} className="relative">
      <button type="button" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)} className="btn btn-ghost gap-2 px-1.5">
        <span aria-hidden className="grid h-7 w-7 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-accent">{initials}</span>
        <span className="hidden text-left leading-tight lg:block"><span className="block max-w-[11rem] truncate text-xs font-medium text-ink">{session.email}</span><span className="block text-[11px] text-muted">{session.role.replace("_", " ").toLowerCase()}</span></span>
        <ChevronDown aria-hidden className="h-3.5 w-3.5 text-muted" />
      </button>
      {open && (
        <div role="menu" className="absolute right-0 top-full z-40 mt-1 w-72 overflow-hidden rounded-lg border border-line bg-panel shadow-pop animate-pop-in">
          <div className="border-b border-line px-3 py-2.5"><p className="truncate text-sm font-medium">{session.email}</p><p className="text-xs text-muted">{session.role}</p></div>
          <div className="border-b border-line px-3 py-2.5">
            <label className="eyebrow block pb-1" htmlFor="tenant-select">Tenant</label>
            {session.available_tenants.length > 1 ? (
              <select id="tenant-select" aria-label="Tenant" className="input w-full" value={session.tenant?.id ?? ""} onChange={(e) => { setOpen(false); void switchTenant(e.target.value); }}>
                {!session.tenant && <option value="">— select —</option>}
                {session.available_tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            ) : <p className="text-sm">{session.tenant?.name ?? "—"}</p>}
          </div>
          <button role="menuitem" type="button" className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm hover:bg-subtle" onClick={() => void logout().then(() => router.replace("/login"))}>
            <LogOut aria-hidden className="h-4 w-4 text-muted" />Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { status, session } = useAuth();
  const router = useRouter();
  const path = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);

  useEffect(() => { if (status === "anon") router.replace("/login"); }, [status, router]);
  useEffect(() => { try { setCollapsed(localStorage.getItem(COLLAPSE_KEY) === "1"); } catch { /* storage blocked: default expanded */ } }, []);
  useEffect(() => { setMobile(false); }, [path]);
  const toggle = useCallback(() => setCollapsed((c) => { try { localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1"); } catch { /* ignore */ } return !c; }), []);
  useEffect(() => {
    if (!mobile) return;
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setMobile(false); };
    document.addEventListener("keydown", esc); return () => document.removeEventListener("keydown", esc);
  }, [mobile]);

  if (status !== "authed" || !session) return <div className="grid min-h-screen place-items-center text-muted" role="status">Loading…</div>;
  const crumbs = breadcrumbs(path);

  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[70] focus:rounded focus:bg-panel focus:px-3 focus:py-2 focus:shadow-pop">Skip to content</a>
      {/* desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden flex-col border-r border-line bg-panel transition-[width] duration-slow ease-out lg:flex" style={{ width: collapsed ? "var(--sidebar-w-collapsed)" : "var(--sidebar-w)" }}>
        <Brand collapsed={collapsed} />
        <NavList path={path} collapsed={collapsed} />
        <div className="border-t border-line p-2">
          <button type="button" onClick={toggle} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"} aria-pressed={collapsed} className={`btn btn-ghost w-full ${collapsed ? "px-0" : "justify-start"}`}>
            {collapsed ? <PanelLeftOpen aria-hidden className="h-[18px] w-[18px]" /> : <><PanelLeftClose aria-hidden className="h-[18px] w-[18px]" /><span className="text-muted">Collapse</span></>}
          </button>
        </div>
      </aside>
      {/* mobile / tablet navigation */}
      {mobile && (
        <div className="fixed inset-0 z-50 lg:hidden" role="presentation">
          <div className="absolute inset-0 bg-ink/40 animate-fade-in" onClick={() => setMobile(false)} />
          <div role="dialog" aria-modal="true" aria-label="Navigation" className="absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col bg-panel shadow-drawer animate-slide-in">
            <div className="flex items-center"><div className="flex-1"><Brand /></div><button type="button" className="btn btn-ghost mr-2 px-1.5" onClick={() => setMobile(false)} aria-label="Close navigation"><X aria-hidden className="h-4 w-4" /></button></div>
            <NavList path={path} collapsed={false} onNavigate={() => setMobile(false)} />
          </div>
        </div>
      )}
      <div className={`flex min-h-screen min-w-0 flex-col transition-[padding] duration-slow ease-out ${collapsed ? "lg:pl-[var(--sidebar-w-collapsed)]" : "lg:pl-[var(--sidebar-w)]"}`}>
        <header className="sticky top-0 z-20 flex h-[var(--header-h)] items-center gap-3 border-b border-line bg-panel/95 px-4 backdrop-blur">
          <button type="button" className="btn btn-ghost px-1.5 lg:hidden" onClick={() => setMobile(true)} aria-label="Open navigation"><Menu aria-hidden className="h-5 w-5" /></button>
          <nav aria-label="Breadcrumb" className="hidden min-w-0 shrink-0 items-center gap-1 text-sm md:flex">
            {crumbs.map((c, i) => (
              <span key={i} className="flex items-center gap-1">
                {i > 0 && <ChevronRight aria-hidden className="h-3.5 w-3.5 text-muted" />}
                {c.href ? <Link href={c.href} className="text-muted hover:text-ink">{c.label}</Link> : <span className={i === crumbs.length - 1 ? "font-medium text-ink" : "text-muted"} aria-current={i === crumbs.length - 1 ? "page" : undefined}>{c.label}</span>}
              </span>
            ))}
          </nav>
          <div className="flex min-w-0 flex-1 justify-center px-2"><GlobalSearch /></div>
          <div className="flex shrink-0 items-center gap-1">
            <span className="mr-1 hidden max-w-[10rem] truncate rounded-full border border-line bg-subtle px-2.5 py-0.5 text-xs text-ink-2 xl:inline" title="Active tenant">{session.tenant?.name ?? "No tenant"}</span>
            <AlertsBell />
            <UserMenu />
          </div>
        </header>
        <main id="main" tabIndex={-1} className="mx-auto w-full max-w-[1680px] min-w-0 flex-1 px-4 py-5 focus:outline-none md:px-6">{children}</main>
      </div>
    </div>
  );
}
