"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { AuthProvider } from "@/lib/auth";
import { ApiError } from "@/lib/api";

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(() => new QueryClient({
    defaultOptions: { queries: {
      staleTime: 15_000, refetchOnWindowFocus: false,
      retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2,
    } },
  }));
  return <QueryClientProvider client={client}><AuthProvider>{children}</AuthProvider></QueryClientProvider>;
}
