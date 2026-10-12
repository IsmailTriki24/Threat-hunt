import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

/** Consistent "return to list" link at the top of every detail page. */
export function BackLink({ href, children }: { href: string; children: ReactNode }) {
  return <Link href={href} className="mb-3 inline-flex items-center gap-1 text-sm text-muted transition-colors duration-fast hover:text-ink"><ArrowLeft aria-hidden className="h-3.5 w-3.5" />{children}</Link>;
}
