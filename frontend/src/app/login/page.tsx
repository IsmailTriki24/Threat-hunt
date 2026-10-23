"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import "@fontsource-variable/bricolage-grotesque/opsz.css";
import { LoginForm } from "@/components/login-form";
import { LoginScene, type SceneMode } from "@/components/login-scene";
import { useAuth } from "@/lib/auth";

/** The product's three-host trace: two lilac hosts and the amber target. Also the mark in the corner of the sign-in page. */
function Mark() {
  return (
    <svg viewBox="0 0 28 28" aria-hidden="true" className="h-7 w-7 shrink-0">
      <path d="M5 21 13 11l10-4" fill="none" stroke="#c9c3fa" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="5" cy="21" r="2.6" fill="#7568e9" /><circle cx="13" cy="11" r="2.6" fill="#c9c3fa" /><circle cx="23" cy="7" r="3.3" fill="#ffb547" />
    </svg>
  );
}

const LINES = ["Follow the attacker,", "not the alerts."];

export default function LoginPage() {
  const { status } = useAuth();
  const router = useRouter();
  const [mode, setMode] = useState<SceneMode>("idle");
  useEffect(() => { if (status === "authed") router.replace("/"); }, [status, router]);
  return (
    <main className="login-stage relative isolate min-h-screen overflow-hidden text-[#f3f1ff]">
      <LoginScene mode={mode} />
      <div className="relative z-10 mx-auto flex min-h-screen w-full max-w-[1400px] flex-col px-6 py-6 sm:px-10 lg:px-14 lg:py-9">
        <div className="flex items-center gap-2.5"><Mark /><span className="text-[15px] font-semibold tracking-tight">Threat Hunting Platform</span></div>
        <div className="grid flex-1 items-end gap-10 pb-2 pt-10 lg:grid-cols-[minmax(0,1fr)_400px] lg:items-center lg:gap-16 lg:py-12">
          <div className="hidden lg:block lg:self-end lg:pb-6">
            <p className="font-display text-[clamp(2.3rem,4.1vw,4.5rem)] font-semibold leading-[1.02] tracking-[-0.025em]">
              {LINES.map((line, i) => <span key={line} className="block overflow-hidden pb-[0.08em]"><span className="block animate-reveal" style={{ animationDelay: `${0.25 + i * 0.12}s` }}>{line}</span></span>)}
            </p>
            <p className="mt-5 max-w-[38ch] text-[15px] leading-[1.6] text-[#c9c3fa]">Search your SIEMs where the logs already live, and keep every step of the investigation.</p>
          </div>
          <div className="flex justify-center lg:justify-end"><LoginForm onStatus={setMode} /></div>
        </div>
      </div>
    </main>
  );
}
