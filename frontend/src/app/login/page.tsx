"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { LoginForm } from "@/components/login-form";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { status } = useAuth();
  const router = useRouter();
  useEffect(() => { if (status === "authed") router.replace("/"); }, [status, router]);
  return <main className="grid min-h-screen place-items-center bg-bg p-4"><LoginForm /></main>;
}
