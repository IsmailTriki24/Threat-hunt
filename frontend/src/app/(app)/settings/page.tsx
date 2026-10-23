"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { AuditView } from "@/components/audit-view";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader, Section } from "@/components/ui/page-header";
import { SeverityBadge } from "@/components/ui/severity";
import { SkeletonRows } from "@/components/ui/skeleton";
import { Tabs } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/toast";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";

const ROLES = ["TENANT_ADMIN", "SOC_ANALYST", "THREAT_HUNTER", "INCIDENT_RESPONDER", "VIEWER"];
const ROLE_NOTE: Record<string, string> = {
  TENANT_ADMIN: "Manages users and feeds, and validates IOCs", SOC_ANALYST: "Hunts, investigates and works cases", THREAT_HUNTER: "Hunts and authors detections",
  INCIDENT_RESPONDER: "Works and closes cases", VIEWER: "Read-only access",
};
const err = (e: unknown, fallback: string) => (e instanceof ApiError ? e.friendly : fallback);

export default function Settings() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const tenant = useQuery({ queryKey: ["tenant"], queryFn: api.currentTenant });
  const users = useQuery({ queryKey: ["users"], queryFn: api.listUsers, enabled: can("users:read") });
  const [form, setForm] = useState({ email: "", full_name: "", password: "", role: "SOC_ANALYST" });
  const create = useMutation({
    mutationFn: () => api.createUser(form),
    onSuccess: () => { toast.success("User created", form.email); setForm({ email: "", full_name: "", password: "", role: "SOC_ANALYST" }); void qc.invalidateQueries({ queryKey: ["users"] }); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (!create.isPending) create.mutate(); };
  const [tab, setTab] = useState<"general" | "audit">("general");

  return (
    <section className="space-y-4">
      <PageHeader title="Settings" description="Tenant details, people and the audit trail." />
      <Tabs<"general" | "audit"> label="Settings sections" value={tab} onChange={setTab}
        tabs={[{ key: "general", label: "General" }, ...(can("audit:read") ? [{ key: "audit" as const, label: "Audit trail" }] : [])]} />
      {tab === "audit" && can("audit:read") && <AuditView />}
      {tab === "general" && (
        <div className="grid gap-4 xl:grid-cols-3">
          <div className="space-y-4 xl:col-span-2">
            <Section title="Current tenant" description="Retention applies to ingested telemetry only.">
              {tenant.isLoading && <SkeletonRows rows={3} />}
              {tenant.error && <p role="alert" className="text-sm text-sev-critical">{err(tenant.error, "Failed to load")}</p>}
              {tenant.data && (
                <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
                  <dt className="text-muted">Name</dt><dd className="font-medium">{tenant.data.name}</dd>
                  <dt className="text-muted">Slug</dt><dd className="font-mono">{tenant.data.slug}</dd>
                  <dt className="text-muted">Retention</dt><dd>{tenant.data.retention_days} days</dd>
                </dl>
              )}
            </Section>
            <Section title="Users" description="People with access to this tenant.">
              {!can("users:read") && <EmptyState compact title="Your role cannot view users" />}
              {users.isLoading && can("users:read") && <SkeletonRows rows={4} />}
              {users.error && <p role="alert" className="text-sm text-sev-critical">{err(users.error, "Failed to load")}</p>}
              {users.data && (
                <div className="-m-4 overflow-x-auto">
                  <table><thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Last login</th></tr></thead>
                    <tbody>{users.data.map((u) => (
                      <tr key={u.user_id}><td>{u.email}</td><td>{u.full_name || <span className="text-muted">—</span>}</td><td><span className="badge border-line-strong bg-subtle text-ink-2" title={ROLE_NOTE[u.role]}>{u.role}</span></td>
                        <td>{u.is_active ? <SeverityBadge level="ok" label="Active" /> : <SeverityBadge level="info" label="Inactive" />}</td><td className="text-muted">{u.last_login_at ?? "never"}</td></tr>))}
                    </tbody></table>
                </div>
              )}
            </Section>
          </div>
          {can("users:manage") && (
            <form onSubmit={submit} aria-label="Create user" className="panel h-fit space-y-3 p-4">
              <div><h2 className="text-sm font-semibold">Create user</h2><p className="text-xs text-muted">The user signs in with this email and password.</p></div>
              <label className="block text-sm font-medium text-ink-2">Email<input className="input mt-1 w-full" type="email" required placeholder="analyst@example.com" aria-label="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
              <label className="block text-sm font-medium text-ink-2">Full name<input className="input mt-1 w-full" aria-label="Full name" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></label>
              <label className="block text-sm font-medium text-ink-2">Password<input className="input mt-1 w-full" type="password" required minLength={12} aria-label="Password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                <span className="mt-1 block text-xs font-normal text-muted">At least 12 characters.</span></label>
              <label className="block text-sm font-medium text-ink-2">Role<select className="input mt-1 w-full" aria-label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
                <span className="mt-1 block text-xs font-normal text-muted">{ROLE_NOTE[form.role]}</span></label>
              {create.error && <p role="alert" className="text-sm text-sev-critical">{err(create.error, "Failed")}</p>}
              <button className="btn btn-primary w-full" disabled={create.isPending}><UserPlus aria-hidden className="h-4 w-4" />{create.isPending ? "Creating…" : "Create user"}</button>
            </form>
          )}
        </div>
      )}
    </section>
  );
}
