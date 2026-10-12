"use client";
import { CircleAlert, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export function LoginForm() {
  const { login } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      await login(email, password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof ApiError ? (err.status === 401 ? "Invalid credentials" : err.friendly) : "Unable to reach the server");
    } finally { setBusy(false); }
  }

  return (
    <form onSubmit={submit} className="panel w-full max-w-sm space-y-4 p-6 shadow-card" aria-label="Sign in">
      <div className="flex items-center gap-3">
        <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-brand text-white shadow-sm"><ShieldCheck aria-hidden className="h-5 w-5" /></span>
        <div><h1 className="text-lg font-semibold leading-tight">Threat Hunting Platform</h1><p className="text-xs text-muted">Sign in to your investigation workspace</p></div>
      </div>
      <label className="block text-sm font-medium text-ink-2">Email
        <input className="input mt-1 w-full py-2" type="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      <label className="block text-sm font-medium text-ink-2">Password
        <input className="input mt-1 w-full py-2" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      {error && <p role="alert" className="flex items-start gap-1.5 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"><CircleAlert aria-hidden className="mt-0.5 h-4 w-4 shrink-0" />{error}</p>}
      <button className="btn btn-primary w-full py-2" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  );
}
