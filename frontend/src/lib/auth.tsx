"use client";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, refreshSession, setAccessToken, setSessionLostHandler } from "./api";
import type { SessionInfo, TokenResponse } from "./api-types";

interface AuthState {
  status: "loading" | "anon" | "authed";
  session: SessionInfo | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  switchTenant: (tenantId: string) => Promise<void>;
  can: (permission: string) => boolean;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthState["status"]>("loading");
  const [session, setSession] = useState<SessionInfo | null>(null);
  const qc = useQueryClient();

  const apply = useCallback((tr: TokenResponse | null) => {
    setSession(tr?.session ?? null);
    setStatus(tr ? "authed" : "anon");
  }, []);

  useEffect(() => {
    setSessionLostHandler(() => { setAccessToken(null); setSession(null); setStatus("anon"); qc.clear(); });
    let cancelled = false;
    refreshSession().then((tr) => { if (!cancelled) apply(tr); });
    return () => { cancelled = true; setSessionLostHandler(null); };
  }, [apply, qc]);

  const value = useMemo<AuthState>(() => ({
    status, session,
    login: async (email, password) => { apply(await api.login(email, password)); },
    logout: async () => { try { await api.logout(); } finally { qc.clear(); apply(null); } },
    switchTenant: async (id) => { const tr = await api.switchTenant(id); qc.clear(); apply(tr); },
    can: (p) => session?.permissions.includes(p) ?? false,
  }), [status, session, apply, qc]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
