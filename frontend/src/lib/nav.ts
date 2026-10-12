import {
  Bot, Boxes, Briefcase, Crosshair, Database, FileText, Globe, Grid3x3, LayoutDashboard, Radar, ScrollText, Search, Settings, ShieldCheck, Telescope,
  type LucideIcon,
} from "lucide-react";

export interface NavItem { href: string; label: string; icon: LucideIcon; hint: string }
export interface NavGroup { label: string; items: NavItem[] }

/** The single source of truth for navigation, breadcrumbs and page titles. Grouped by what an analyst is doing, not by how the code is organised. */
export const NAV_GROUPS: NavGroup[] = [
  { label: "Investigate", items: [
    { href: "/", label: "Overview", icon: LayoutDashboard, hint: "Platform health and what needs attention" },
    { href: "/threat-map", label: "Threat Map", icon: Globe, hint: "Reported intelligence vs. observed activity by location" },
    { href: "/events", label: "Events", icon: Search, hint: "Search all telemetry" },
    { href: "/hunts", label: "Hunts", icon: Crosshair, hint: "Hypotheses, queries and findings" },
    { href: "/investigations", label: "Investigations", icon: Telescope, hint: "Timeline of related activity" },
    { href: "/cases", label: "Cases", icon: Briefcase, hint: "Incidents, evidence and reports" },
  ] },
  { label: "Intelligence", items: [
    { href: "/threat-intel", label: "Threat Intelligence", icon: Radar, hint: "Indicator look-ups, watch-list, STIX/TAXII" },
    { href: "/ioc-hunting", label: "IOC Hunting", icon: ScrollText, hint: "Feeds, threat bulletins and automatic hunts" },
    { href: "/mitre", label: "MITRE ATT&CK", icon: Grid3x3, hint: "Technique coverage and mappings" },
  ] },
  { label: "Detect & respond", items: [
    { href: "/detections", label: "Detections", icon: ShieldCheck, hint: "Rules, tests and alerts" },
    { href: "/ai-hunting", label: "AI Hunting", icon: Bot, hint: "Agent-assisted investigations" },
  ] },
  { label: "Manage", items: [
    { href: "/assets", label: "Assets", icon: Boxes, hint: "Hosts, users and relationships" },
    { href: "/data-sources", label: "Data Sources", icon: Database, hint: "Connectors and ingestion" },
    { href: "/reports", label: "Reports", icon: FileText, hint: "Case reports" },
    { href: "/settings", label: "Settings", icon: Settings, hint: "Users, tenants and preferences" },
  ] },
];

export const NAV: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

export const isActive = (href: string, path: string): boolean => (href === "/" ? path === "/" : path === href || path.startsWith(href + "/"));

export interface Crumb { label: string; href?: string }
/** Section › Page (› Detail). The detail crumb is generic because the real title is rendered by the page itself. */
export function breadcrumbs(path: string): Crumb[] {
  const group = NAV_GROUPS.find((g) => g.items.some((i) => isActive(i.href, path)));
  const item = NAV.find((i) => isActive(i.href, path) && i.href !== "/") ?? NAV[0];
  if (!group) return [{ label: "Overview" }];
  const out: Crumb[] = [{ label: group.label }];
  if (item.href === path || (item.href === "/" && path === "/")) out.push({ label: item.label });
  else {
    out.push({ label: item.label, href: item.href });
    out.push({ label: path.includes("/techniques/") ? "Technique" : "Details" });
  }
  return out;
}
