import type { ReactNode } from "react";

/** A deliberately small Markdown renderer for reports: headings, paragraphs, lists (with task boxes), quotes, rules, fenced code,
 * tables, and **bold** / _italic_ / `code` / [links](https://…). It builds React elements only - raw HTML is never interpreted, and a
 * link is rendered only for http(s) URLs - so report text (which may contain model or web output) cannot inject markup or scripts. */

const SAFE_URL = /^https?:\/\/[^\s<>"']{3,}$/i;

function inline(text: string, key: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /``\s*(.+?)\s*``|`([^`]+)`|\*\*(.+?)\*\*|\[([^\]]+)\]\(([^)\s]+)\)|(?<![\w*])_([^_]+)_(?![\w])|\\([|\\`*_])/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const k = `${key}-${i++}`;
    if (m[1] !== undefined || m[2] !== undefined) out.push(<code key={k} className="rounded bg-bg/80 px-1 font-mono text-[0.92em] text-sky-200">{m[1] ?? m[2]}</code>);
    else if (m[3] !== undefined) out.push(<strong key={k} className="font-semibold text-slate-100">{inline(m[3], k)}</strong>);
    else if (m[4] !== undefined) {
      out.push(SAFE_URL.test(m[5])
        ? <a key={k} href={m[5]} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline underline-offset-2">{m[4]}</a>
        : <span key={k}>{m[4]} ({m[5]})</span>);
    } else if (m[6] !== undefined) out.push(<em key={k} className="text-slate-300">{m[6]}</em>);
    else if (m[7] !== undefined) out.push(m[7]);
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const splitRow = (line: string): string[] =>
  line.trim().replace(/^\|/, "").replace(/\|$/, "").split(/(?<!\\)\|/).map((c) => c.trim());
const isSep = (line: string) => /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(line);

export function Markdown({ source }: { source: string }) {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let n = 0;
  const key = () => `b${n++}`;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    const fence = /^\s*```/.exec(line);
    if (fence) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      blocks.push(<pre key={key()} className="my-2 overflow-x-auto rounded border border-line bg-bg/80 p-2 font-mono text-xs text-slate-200">{buf.join("\n")}</pre>);
      continue;
    }
    const h = /^(#{1,4})\s+(.+)$/.exec(line);
    if (h) {
      const lvl = h[1].length;
      const cls = ["", "mb-3 mt-1 text-xl font-semibold text-slate-50", "mb-2 mt-6 border-b border-line pb-1 text-base font-semibold text-slate-100", "mb-1 mt-4 text-sm font-semibold text-slate-100", "mb-1 mt-3 text-sm font-medium text-slate-200"][lvl];
      const Tag = (`h${lvl}`) as "h1" | "h2" | "h3" | "h4";
      blocks.push(<Tag key={key()} className={cls}>{inline(h[2], `h${n}`)}</Tag>);
      i++;
      continue;
    }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { blocks.push(<hr key={key()} className="my-4 border-line" />); i++; continue; }
    if (/^\s*>/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) buf.push(lines[i++].replace(/^\s*>\s?/, ""));
      blocks.push(<blockquote key={key()} className="my-3 rounded-md border-l-4 border-ai bg-violet-500/10 px-3 py-2 text-sm text-slate-100">{inline(buf.join(" "), `q${n}`)}</blockquote>);
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && isSep(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(splitRow(lines[i++]));
      blocks.push(
        <div key={key()} className="my-2 overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead><tr>{head.map((c, j) => <th key={j} className="border-b border-line px-2 py-1 text-left font-medium text-muted">{inline(c, `th${n}-${j}`)}</th>)}</tr></thead>
            <tbody>{rows.map((r, ri) => <tr key={ri}>{r.map((c, j) => <td key={j} className="border-b border-line/60 px-2 py-1 align-top">{inline(c, `td${n}-${ri}-${j}`)}</td>)}</tr>)}</tbody>
          </table>
        </div>,
      );
      continue;
    }
    const li = /^\s*(?:[-*]|\d+\.)\s+/;
    if (li.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items: string[] = [];
      while (i < lines.length && li.test(lines[i])) items.push(lines[i++].replace(li, ""));
      const body = items.map((t, j) => {
        const task = /^\[( |x)\]\s+(.*)$/i.exec(t);
        return (
          <li key={j} className="my-0.5">
            {task ? <><span className={`mr-1.5 ${task[1].toLowerCase() === "x" ? "text-emerald-400" : "text-muted"}`} aria-label={task[1].toLowerCase() === "x" ? "done" : "not done"}>{task[1].toLowerCase() === "x" ? "✓" : "○"}</span>{inline(task[2], `li${n}-${j}`)}</> : inline(t, `li${n}-${j}`)}
          </li>
        );
      });
      const L = ordered ? "ol" : "ul";
      blocks.push(<L key={key()} className={`my-2 space-y-0.5 pl-5 text-sm ${ordered ? "list-decimal" : items.some((t) => /^\[( |x)\]/i.test(t)) ? "list-none pl-1" : "list-disc"}`}>{body}</L>);
      continue;
    }
    const buf: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|\s*>|\s*```|\s*(?:[-*]|\d+\.)\s+)/.test(lines[i]) && !(lines[i].includes("|") && isSep(lines[i + 1] ?? ""))) buf.push(lines[i++]);
    blocks.push(<p key={key()} className="my-2 text-sm leading-6 text-slate-300">{inline(buf.join(" "), `p${n}`)}</p>);
  }
  return <div className="markdown">{blocks}</div>;
}
