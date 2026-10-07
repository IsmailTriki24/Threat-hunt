export function Placeholder({ title, milestone, summary }: { title: string; milestone: string; summary: string }) {
  return (
    <section className="max-w-xl">
      <h1 className="text-base font-semibold mb-2">{title}</h1>
      <div className="panel p-3 text-muted">
        <p>Not implemented yet. Planned for <span className="text-[#c9d1d9]">{milestone}</span>.</p>
        <p className="mt-1">{summary}</p>
      </div>
    </section>
  );
}
