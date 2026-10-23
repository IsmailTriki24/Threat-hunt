"use client";
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { KeyRound, Plus, UserPlus, Users } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import type { MemberOut, TenantSummary } from "@/lib/api-types";
import { useAuth } from "@/lib/auth";
import { AuditView } from "./audit-view";
import { errText, ErrorLine } from "./badges";
import { EmptyState } from "./ui/empty-state";
import { ConfirmDialog, Drawer, Modal } from "./ui/overlay";
import { Section } from "./ui/page-header";
import { SeverityBadge } from "./ui/severity";
import { SkeletonRows } from "./ui/skeleton";
import { Tabs } from "./ui/tabs";
import { useToast } from "./ui/toast";

export const ROLES = ["TENANT_ADMIN", "SOC_ANALYST", "THREAT_HUNTER", "INCIDENT_RESPONDER", "VIEWER"];
const ROLE_NOTE: Record<string, string> = {
  TENANT_ADMIN: "Manages the tenant's users, feeds and IOC validation", SOC_ANALYST: "Hunts, investigates and works cases", THREAT_HUNTER: "Hunts and authors detections",
  INCIDENT_RESPONDER: "Works and closes cases", VIEWER: "Read-only access",
};
export const slugify = (name: string): string => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);

export function TenantsView() {
  const { can } = useAuth();
  const [tab, setTab] = useState<"tenants" | "audit">("tenants");
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: api.tenants, enabled: can("tenants:manage") });
  if (!can("tenants:manage")) return <EmptyState title="Platform administrators only">Tenants are created and managed by the platform administrator.</EmptyState>;
  const names = Object.fromEntries((tenants.data ?? []).map((t) => [t.id, t.name]));
  return (
    <div className="space-y-4">
      <Tabs<"tenants" | "audit"> label="Tenant sections" value={tab} onChange={setTab}
        tabs={[{ key: "tenants", label: "Tenants", count: tenants.data?.length ?? null }, ...(can("audit:platform") ? [{ key: "audit" as const, label: "Platform audit" }] : [])]} />
      {tab === "audit" && <AuditView platform tenantNames={names} />}
      {tab === "tenants" && <TenantList tenants={tenants} />}
    </div>
  );
}

function TenantList({ tenants }: { tenants: UseQueryResult<TenantSummary[]> }) {
  const router = useRouter();
  const { session, switchTenant } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const [membersOf, setMembersOf] = useState<string | null>(null);
  const [toggling, setToggling] = useState<TenantSummary | null>(null);
  const toggle = useMutation({
    mutationFn: (t: TenantSummary) => api.updateTenant(t.id, { is_active: !t.is_active }),
    onSuccess: (_, t) => { toast.success(t.is_active ? "Tenant disabled" : "Tenant enabled", t.name); setToggling(null); void qc.invalidateQueries({ queryKey: ["tenants"] }); },
  });
  const open = useMutation({ mutationFn: async (id: string) => { await switchTenant(id); }, onSuccess: () => router.push("/data-sources"), onError: (e) => toast.error("Could not open the tenant", errText(e, "Failed")) });
  const selected = tenants.data?.find((t) => t.id === membersOf) ?? null;

  return (
    <Section title="Tenants" description="Open a tenant to assign or change its log sources; they act as that tenant and every action is audited."
      actions={<button className="btn btn-primary" onClick={() => setCreating(true)}><Plus aria-hidden className="h-4 w-4" />New tenant</button>}>
      <ErrorLine error={tenants.error} fallback="Failed to load tenants" />
      {tenants.isLoading && <SkeletonRows rows={3} />}
      {tenants.data && tenants.data.length === 0 && <EmptyState compact title="No tenants yet">Create the first tenant and its administrator.</EmptyState>}
      {tenants.data && tenants.data.length > 0 && (
        <div className="-m-4 overflow-x-auto">
          <table>
            <thead><tr><th>Tenant</th><th>Status</th><th>Members</th><th>Log sources</th><th>Retention</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {tenants.data.map((t) => (
                <tr key={t.id}>
                  <td><div className="font-medium">{t.name}</div><div className="font-mono text-xs text-muted">{t.slug}</div></td>
                  <td>{t.is_active ? <SeverityBadge level="ok" label="Active" /> : <SeverityBadge level="info" label="Disabled" />}</td>
                  <td>{t.member_count}{t.admin_count === 0 && <span className="ml-2"><SeverityBadge level="high" label="No admin" /></span>}</td>
                  <td>{t.data_source_count}{t.data_sources_down > 0 && <span className="ml-2"><SeverityBadge level="high" label={`${t.data_sources_down} down`} /></span>}</td>
                  <td className="text-muted">{t.retention_days} days</td>
                  <td>
                    <div className="flex justify-end gap-1">
                      <button className="btn btn-sm" onClick={() => setMembersOf(t.id)}><Users aria-hidden className="h-3.5 w-3.5" />Members</button>
                      <button className="btn btn-sm" disabled={!t.is_active || open.isPending} onClick={() => open.mutate(t.id)} title={session?.tenant?.id === t.id ? "Already open" : "Act as this tenant and manage its log sources"}>Open</button>
                      <button className="btn btn-sm" onClick={() => setToggling(t)}>{t.is_active ? "Disable" : "Enable"}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {creating && <NewTenantModal onClose={() => setCreating(false)} />}
      {selected && <MembersDrawer tenant={selected} onClose={() => setMembersOf(null)} />}
      {toggling && (
        <ConfirmDialog title={`${toggling.is_active ? "Disable" : "Enable"} ${toggling.name}?`} danger={toggling.is_active} confirmLabel={toggling.is_active ? "Disable tenant" : "Enable tenant"}
          message={toggling.is_active ? "Every member is signed out immediately and ingestion into this tenant stops. Nothing is deleted." : "Members can sign in again."}
          busy={toggle.isPending} error={toggle.error ? errText(toggle.error, "Failed") : undefined} onConfirm={() => toggle.mutate(toggling)} onClose={() => { setToggling(null); toggle.reset(); }} />
      )}
    </Section>
  );
}

function NewTenantModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [f, setF] = useState({ name: "", slug: "", retention: "90", email: "", password: "" });
  const [slugEdited, setSlugEdited] = useState(false);
  const create = useMutation({
    mutationFn: () => api.createTenant({ name: f.name.trim(), slug: f.slug, retention_days: Number(f.retention), admin_email: f.email.trim(), admin_password: f.password }),
    onSuccess: () => { toast.success("Tenant created", f.name); void qc.invalidateQueries({ queryKey: ["tenants"] }); onClose(); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (!create.isPending) create.mutate(); };
  return (
    <Modal title="New tenant" description="Creates the organisation and its first tenant administrator. Log sources are assigned afterwards." onClose={onClose}
      footer={<><button type="button" className="btn" onClick={onClose}>Cancel</button><button form="new-tenant" className="btn btn-primary" disabled={create.isPending}>{create.isPending ? "Creating…" : "Create tenant"}</button></>}>
      <form id="new-tenant" onSubmit={submit} className="space-y-3" aria-label="New tenant">
        <label className="block text-sm font-medium text-ink-2">Name<input className="input mt-1 w-full" required maxLength={200} autoFocus value={f.name} onChange={(e) => setF({ ...f, name: e.target.value, slug: slugEdited ? f.slug : slugify(e.target.value) })} /></label>
        <label className="block text-sm font-medium text-ink-2">Slug<input className="input mt-1 w-full font-mono" required pattern="[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]" value={f.slug} onChange={(e) => { setSlugEdited(true); setF({ ...f, slug: e.target.value }); }} />
          <span className="mt-1 block text-xs font-normal text-muted">Lower-case letters, digits and dashes. Cannot be changed later.</span></label>
        <label className="block text-sm font-medium text-ink-2">Telemetry retention (days)<input className="input mt-1 w-full" type="number" min={1} max={3650} required value={f.retention} onChange={(e) => setF({ ...f, retention: e.target.value })} /></label>
        <label className="block text-sm font-medium text-ink-2">Administrator email<input className="input mt-1 w-full" type="email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
        <label className="block text-sm font-medium text-ink-2">Administrator password<input className="input mt-1 w-full" type="password" required minLength={12} autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
          <span className="mt-1 block text-xs font-normal text-muted">At least 12 characters. Share it through a secure channel.</span></label>
        {create.error && <p role="alert" className="text-sm text-sev-critical">{errText(create.error, "Failed to create the tenant")}</p>}
      </form>
    </Modal>
  );
}

function MembersDrawer({ tenant, onClose }: { tenant: TenantSummary; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const key = ["tenant-members", tenant.id];
  const members = useQuery({ queryKey: key, queryFn: () => api.tenantMembers(tenant.id) });
  const refresh = () => { void qc.invalidateQueries({ queryKey: key }); void qc.invalidateQueries({ queryKey: ["tenants"] }); };
  const [form, setForm] = useState({ email: "", full_name: "", password: "", role: "SOC_ANALYST" });
  const [resetting, setResetting] = useState<MemberOut | null>(null);
  const add = useMutation({
    mutationFn: () => api.addTenantMember(tenant.id, { email: form.email.trim(), full_name: form.full_name, role: form.role, ...(form.password ? { password: form.password } : {}) }),
    onSuccess: (m) => { toast.success("Member added", m.email); setForm({ email: "", full_name: "", password: "", role: "SOC_ANALYST" }); refresh(); },
  });
  const update = useMutation({
    mutationFn: (v: { id: string; role?: string; is_active?: boolean }) => api.updateTenantMember(tenant.id, v.id, { role: v.role, is_active: v.is_active }),
    onSuccess: refresh,
    onError: (e) => toast.error("Change not applied", errText(e, "Failed")),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (!add.isPending) add.mutate(); };
  return (
    <Drawer title={`${tenant.name} · members`} subtitle={tenant.slug} onClose={onClose} width="max-w-2xl">
      <div className="space-y-5 p-5">
        <ErrorLine error={members.error} fallback="Failed to load members" />
        {members.isLoading && <SkeletonRows rows={3} />}
        {members.data && (
          <div className="overflow-x-auto">
            <table>
              <thead><tr><th>Member</th><th>Role</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {members.data.map((m) => (
                  <tr key={m.user_id}>
                    <td><div>{m.email}</div>{m.full_name && <div className="text-xs text-muted">{m.full_name}</div>}</td>
                    <td><select className="input" aria-label={`Role for ${m.email}`} value={m.role} disabled={update.isPending} onChange={(e) => update.mutate({ id: m.user_id, role: e.target.value })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></td>
                    <td>{m.is_active ? <SeverityBadge level="ok" label="Active" /> : <SeverityBadge level="info" label="Inactive" />}</td>
                    <td><div className="flex justify-end gap-1">
                      <button className="btn btn-sm" onClick={() => setResetting(m)}><KeyRound aria-hidden className="h-3.5 w-3.5" />Reset password</button>
                      <button className="btn btn-sm" disabled={update.isPending} onClick={() => update.mutate({ id: m.user_id, is_active: !m.is_active })}>{m.is_active ? "Deactivate" : "Activate"}</button>
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {members.data.length === 0 && <EmptyState compact title="No members">Add the first administrator below.</EmptyState>}
          </div>
        )}
        <form onSubmit={submit} aria-label="Add member" className="panel space-y-3 p-4">
          <div><h3 className="text-sm font-semibold">Add member</h3><p className="text-xs text-muted">Leave the password empty to attach a person who already has an account on another tenant.</p></div>
          <label className="block text-sm font-medium text-ink-2">Email<input className="input mt-1 w-full" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
          <label className="block text-sm font-medium text-ink-2">Full name<input className="input mt-1 w-full" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></label>
          <label className="block text-sm font-medium text-ink-2">Password<input className="input mt-1 w-full" type="password" minLength={12} autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          <label className="block text-sm font-medium text-ink-2">Role<select className="input mt-1 w-full" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
            <span className="mt-1 block text-xs font-normal text-muted">{ROLE_NOTE[form.role]}</span></label>
          {add.error && <p role="alert" className="text-sm text-sev-critical">{errText(add.error, "Failed to add the member")}</p>}
          <button className="btn btn-primary w-full" disabled={add.isPending}><UserPlus aria-hidden className="h-4 w-4" />{add.isPending ? "Adding…" : "Add member"}</button>
        </form>
      </div>
      {resetting && <ResetPassword tenantId={tenant.id} member={resetting} onClose={() => setResetting(null)} />}
    </Drawer>
  );
}

function ResetPassword({ tenantId, member, onClose }: { tenantId: string; member: MemberOut; onClose: () => void }) {
  const toast = useToast();
  const [pw, setPw] = useState("");
  const reset = useMutation({ mutationFn: () => api.updateTenantMember(tenantId, member.user_id, { new_password: pw }), onSuccess: () => { toast.success("Password reset", `${member.email} is signed out everywhere`); onClose(); } });
  const submit = (e: FormEvent) => { e.preventDefault(); if (!reset.isPending) reset.mutate(); };
  return (
    <Modal title="Reset password" description={`${member.email} is signed out on every device and must use the new password.`} onClose={onClose}
      footer={<><button type="button" className="btn" onClick={onClose}>Cancel</button><button form="reset-pw" className="btn btn-primary" disabled={reset.isPending || pw.length < 12}>{reset.isPending ? "Saving…" : "Reset password"}</button></>}>
      <form id="reset-pw" onSubmit={submit} aria-label="Reset password">
        <label className="block text-sm font-medium text-ink-2">New password<input className="input mt-1 w-full" type="password" required minLength={12} autoFocus autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
          <span className="mt-1 block text-xs font-normal text-muted">At least 12 characters.</span></label>
        {reset.error && <p role="alert" className="mt-2 text-sm text-sev-critical">{errText(reset.error, "Failed")}</p>}
      </form>
    </Modal>
  );
}
