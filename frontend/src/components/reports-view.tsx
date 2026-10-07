"use client";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fmtTime } from "@/lib/query";
import { ErrorLine, StatusBadge } from "./badges";

export function ReportsIndex() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const cases = useQuery({ queryKey: ["cases", "reports"], queryFn: () => api.listCases("?limit=200") });
  const reports = useQueries({
    queries: (cases.data ?? []).map((c) => ({ queryKey: ["case-reports", c.id], queryFn: () => api.caseReports(c.id) })),
  });
  const gen = useMutation({ mutationFn: (id: string) => api.generateReport(id), onSuccess: (_r, id) => qc.invalidateQueries({ queryKey: ["case-reports", id] }) });

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted">Reports are immutable, versioned Markdown snapshots of a case. Open a case’s Reports tab to read or download them.</p>
      <ErrorLine error={cases.error ?? gen.error} fallback="Failed to load reports" />
      {cases.data && (cases.data.length === 0 ? <p className="panel p-3 text-muted">No cases yet.</p> : (
        <table className="w-full">
          <thead><tr>{["Case", "Title", "Status", "Latest report", "Generated", ""].map((h) => <th key={h} className="th" scope="col">{h}</th>)}</tr></thead>
          <tbody>
            {cases.data.map((c, i) => {
              const latest = reports[i]?.data?.[0];
              return (
                <tr key={c.id} className="hover:bg-bg">
                  <td className="td font-mono">{c.case_id}</td>
                  <td className="td"><Link className="text-accent hover:underline" href={`/cases/${c.id}`}>{c.title}</Link></td>
                  <td className="td"><StatusBadge status={c.status} /></td>
                  <td className="td">{reports[i]?.isLoading ? "…" : latest ? `v${latest.version}` : <span className="text-muted">none</span>}</td>
                  <td className="td font-mono">{latest ? fmtTime(latest.created_at) : ""}</td>
                  <td className="td whitespace-nowrap">
                    {latest && <Link className="btn py-0 text-xs" href={`/cases/${c.id}`}>Open</Link>}{" "}
                    <button className="btn py-0 text-xs" disabled={!can("cases:write") || gen.isPending} onClick={() => gen.mutate(c.id)}>Generate</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ))}
    </div>
  );
}
