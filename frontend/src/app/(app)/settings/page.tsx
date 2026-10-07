"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { AuditView } from "@/components/audit-view";
import { useAuth } from "@/lib/auth";

const ROLES = ["TENANT_ADMIN", "SOC_ANALYST", "THREAT_HUNTER", "INCIDENT_RESPONDER", "VIEWER"];

export default function Settings() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const tenant = useQuery({ queryKey: ["tenant"], queryFn: api.currentTenant });
  const users = useQuery({ queryKey: ["users"], queryFn: api.listUsers, enabled: can("users:read") });
  const [form, setForm] = useState({ email: "", full_name: "", password: "", role: "SOC_ANALYST" });
  const create = useMutation({
    mutationFn: () => api.createUser(form),
    onSuccess: () => { setForm({ email: "", full_name: "", password: "", role: "SOC_ANALYST" }); void qc.invalidateQueries({ queryKey: ["users"] }); },
  });
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  const [tab, setTab] = useState<"general" | "audit">("general");

  return (
    <section className="space-y-3 max-w-4xl">
      <h1 className="text-base font-semibold">Settings</h1>
      <div role="tablist" className="flex gap-0.5 border-b border-line">
        {([["general", "General"], ...(can("audit:read") ? [["audit", "Audit trail"]] : [])] as Array<["general" | "audit", string]>).map(([t, label]) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`px-3 py-1 border-b-2 ${tab === t ? "border-accent text-accent" : "border-transparent text-muted hover:text-[#c9d1d9]"}`}>{label}</button>
        ))}
      </div>
      {tab === "audit" && can("audit:read") && <div className="max-w-none"><AuditView /></div>}
      {tab === "general" && <>
      <div className="panel p-3">
        <h2 className="text-xs text-muted uppercase mb-1">Current tenant</h2>
        {tenant.error && <p className="text-red-400">{tenant.error instanceof ApiError ? tenant.error.friendly : "Failed to load"}</p>}
        {tenant.data && <dl className="grid grid-cols-[10rem_1fr]">
          <dt className="text-muted">Name</dt><dd>{tenant.data.name}</dd>
          <dt className="text-muted">Slug</dt><dd className="font-mono">{tenant.data.slug}</dd>
          <dt className="text-muted">Retention</dt><dd>{tenant.data.retention_days} days</dd>
        </dl>}
      </div>
      <div className="panel p-3">
        <h2 className="text-xs text-muted uppercase mb-1">Users</h2>
        {!can("users:read") && <p className="text-muted">Your role cannot view users.</p>}
        {users.error && <p className="text-red-400">{users.error instanceof ApiError ? users.error.friendly : "Failed to load"}</p>}
        {users.data && <table className="w-full"><thead><tr><th className="th">Email</th><th className="th">Name</th><th className="th">Role</th><th className="th">Active</th><th className="th">Last login</th></tr></thead>
          <tbody>{users.data.map((u) => <tr key={u.user_id}><td className="td">{u.email}</td><td className="td">{u.full_name}</td><td className="td">{u.role}</td><td className="td">{u.is_active ? "yes" : "no"}</td><td className="td">{u.last_login_at ?? "never"}</td></tr>)}</tbody></table>}
      </div>
      {can("users:manage") && (
        <form onSubmit={submit} className="panel p-3 grid grid-cols-2 gap-2 max-w-xl" aria-label="Create user">
          <h2 className="col-span-2 text-xs text-muted uppercase">Create user</h2>
          <input className="input" type="email" required placeholder="email" aria-label="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <input className="input" placeholder="full name" aria-label="Full name" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          <input className="input" type="password" required minLength={12} placeholder="password (min 12)" aria-label="Password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <select className="input" aria-label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
          {create.error && <p role="alert" className="col-span-2 text-red-400">{create.error instanceof ApiError ? create.error.friendly : "Failed"}</p>}
          <button className="btn btn-primary col-span-2" disabled={create.isPending}>Create</button>
        </form>
      )}
      </>}
    </section>
  );
}
