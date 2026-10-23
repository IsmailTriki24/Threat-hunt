"use client";
import { CircleAlert, Eye, EyeOff, Loader2 } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { SceneMode } from "./login-scene";

/** `onStatus` lets the scene behind the form react: it quickens while signing in and stalls when the sign-in is refused. */
export function LoginForm({ onStatus }: { onStatus?: (mode: SceneMode) => void }) {
  const { login } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [caps, setCaps] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(false);
  const settle = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(settle.current), []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null); onStatus?.("busy");
    try {
      await login(email, password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof ApiError ? (err.status === 401 ? "Invalid credentials" : err.friendly) : "Unable to reach the server");
      setShake(true); onStatus?.("denied");
      settle.current = setTimeout(() => onStatus?.("idle"), 1400);
    } finally { setBusy(false); }
  }

  return (
    <div data-scene-avoid className="w-full max-w-[400px] animate-rise-in">
      <form onSubmit={submit} onAnimationEnd={() => setShake(false)} aria-label="Sign in"
        className={`space-y-5 rounded-xl bg-panel p-7 shadow-[0_28px_90px_-16px_rgb(6_3_36/.75),0_0_0_1px_rgb(255_255_255/.07)] sm:p-8 ${shake ? "animate-shake" : ""}`}>
        <div>
          <h1 className="font-display text-[28px] font-semibold leading-[34px] tracking-tight text-ink">Sign in</h1>
          <p className="mt-1 text-sm text-muted">Pick up your investigations where you left them.</p>
        </div>
        <div>
          <label htmlFor="login-email" className="block text-sm font-medium text-ink-2">Email</label>
          <input id="login-email" className="input mt-1.5 w-full py-2.5 text-base" type="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div>
          <label htmlFor="login-password" className="block text-sm font-medium text-ink-2">Password</label>
          <div className="relative mt-1.5">
            <input id="login-password" className="input w-full py-2.5 pr-11 text-base" type={show ? "text" : "password"} autoComplete="current-password" required value={password}
              onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => setCaps(e.getModifierState?.("CapsLock") ?? false)} onKeyUp={(e) => setCaps(e.getModifierState?.("CapsLock") ?? false)} onBlur={() => setCaps(false)} />
            <button type="button" aria-pressed={show} aria-label={show ? "Hide password" : "Show password"} onClick={() => setShow((s) => !s)}
              className="absolute inset-y-0 right-0 grid w-10 place-items-center rounded-r text-muted transition-colors duration-fast hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-brand/40">
              {show ? <EyeOff aria-hidden className="h-4 w-4" /> : <Eye aria-hidden className="h-4 w-4" />}
            </button>
          </div>
          {caps && <p role="status" className="mt-1.5 text-xs text-sev-medium">Caps Lock is on.</p>}
        </div>
        {error && <p role="alert" className="flex items-start gap-1.5 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"><CircleAlert aria-hidden className="mt-0.5 h-4 w-4 shrink-0" />{error}</p>}
        <button className="btn btn-primary w-full py-2.5 text-base" disabled={busy}>
          {busy && <Loader2 aria-hidden className="h-4 w-4 animate-spin" />}{busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="text-xs text-muted">No account yet? Ask your platform administrator to add you to your organisation.</p>
      </form>
    </div>
  );
}
