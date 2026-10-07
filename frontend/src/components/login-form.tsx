"use client";
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
    <form onSubmit={submit} className="panel w-80 p-4 space-y-3" aria-label="Sign in">
      <h1 className="text-base font-semibold">Threat Hunting Platform</h1>
      <label className="block text-xs text-muted">Email
        <input className="input w-full mt-1" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      <label className="block text-xs text-muted">Password
        <input className="input w-full mt-1" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      {error && <p role="alert" className="text-xs text-red-400">{error}</p>}
      <button className="btn btn-primary w-full" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  );
}
