import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/verdict-badge";
import { listShowcaseSummaries } from "@/lib/showcase";
import { sortReportsForDemo } from "@/lib/format";

export default async function ShowcaseGalleryPage() {
  const summaries = await listShowcaseSummaries();
  const reports = sortReportsForDemo(summaries.flatMap((item) => (item.report ? [item.report] : [])));

  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm font-semibold uppercase tracking-normal text-slate-500">Frozen showcase data</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-normal text-slate-950">Showcase Gallery</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">
          These reports are replayable product demos generated from dashboard/state/showcase. No live Agent execution is required.
        </p>
      </div>
      {reports.length === 0 ? (
        <div className="panel p-8">
          <h2 className="text-lg font-semibold text-slate-950">No frozen showcase reports found</h2>
          <p className="mt-2 text-sm text-slate-600">Run python tools/demo/build_showcase_reports.py after freezing a showcase run.</p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {reports.map((report) => {
            const frida = report.pipeline.find((stage) => stage.key === "frida");
            const code = report.pipeline.find((stage) => stage.key === "codetracer");
            return (
              <Link key={report.id} href={`/showcases/${report.id}`} className="panel block border border-slate-200 p-5 transition hover:-translate-y-0.5 hover:border-slate-400 hover:shadow-md">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge value={report.verdict} tone="verdict" />
                  <Badge value={report.riskLevel} tone="risk" />
                  <Badge value={report.dataSource} />
                </div>
                <h2 className="mt-4 text-xl font-semibold text-slate-950">{report.title}</h2>
                <p className="mt-2 min-h-12 text-sm leading-6 text-slate-600">{report.executiveSummary || report.description}</p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Badge value={`Frida: ${frida?.status ?? "unknown"}`} />
                  <Badge value={`CodeTracer: ${code?.status ?? "unknown"}`} />
                </div>
                <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4 text-sm font-semibold text-slate-900">
                  <span>View Report</span>
                  <span aria-hidden="true">→</span>
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </AppShell>
  );
}
