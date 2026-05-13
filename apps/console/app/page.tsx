import Link from "next/link";
import { AlertTriangle, CheckCircle2, Files, GitBranch, RadioTower, Share2, ShieldAlert, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { MetricCard } from "@/components/metric-card";
import { Badge } from "@/components/verdict-badge";
import { listShowcaseSummaries } from "@/lib/showcase";
import { countBy, sortReportsForDemo } from "@/lib/format";

export default async function OverviewPage() {
  const summaries = await listShowcaseSummaries();
  const reports = sortReportsForDemo(summaries.flatMap((item) => (item.report ? [item.report] : [])));
  const blocked = countBy(reports, (report) => report.verdict === "block");
  const confirms = countBy(reports, (report) => report.verdict === "require_confirmation");
  const allowed = countBy(reports, (report) => report.verdict === "allow");
  const fridaAvailable = countBy(reports, (report) => ["ok", "available"].includes(report.pipeline.find((stage) => stage.key === "frida")?.status || ""));
  const codetracerAvailable = countBy(reports, (report) => ["ok", "available"].includes(report.pipeline.find((stage) => stage.key === "codetracer")?.status || ""));
  const deepTrace = countBy(reports, (report) => (report.traceBackbone?.traceDepth || report.metrics.traceQuality) === "deep");
  const openInference = countBy(reports, (report) => Boolean(report.traceBackbone?.exportAvailable || report.metrics.exportAvailable));

  return (
    <AppShell>
      <section className="report-header p-8">
        <p className="text-sm font-semibold uppercase tracking-normal text-slate-300">Transpect Agent Runtime Security</p>
        <div className="mt-4 grid gap-6 lg:grid-cols-[1.5fr_1fr]">
          <div>
            <h1 className="text-4xl font-semibold tracking-normal">Agent Security Overview</h1>
            <p className="mt-4 max-w-3xl text-base leading-7 text-slate-200">
              Correlate Agent runtime behavior, defense decisions, OS-level evidence, and diagnostic traces in replayable security reports.
            </p>
          </div>
          <div className="rounded-md border border-white/15 bg-white/10 p-4">
            <p className="text-sm font-semibold text-white">Recommended Demo Order</p>
            <ol className="mt-3 space-y-2 text-sm text-slate-200">
              {reports.slice(0, 4).map((report, index) => (
                <li key={report.id} className="flex items-center gap-2">
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-white/15 text-xs">{index + 1}</span>
                  <Link href={`/showcases/${report.id}`} className="hover:underline">
                    {report.title}
                  </Link>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </section>

      <section className="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total Showcases" value={reports.length} icon={Files} />
        <MetricCard label="Blocked" value={blocked} caption="High-confidence interventions" icon={ShieldAlert} />
        <MetricCard label="Requires Confirmation" value={confirms} caption="User verification required" icon={AlertTriangle} />
        <MetricCard label="Allowed" value={allowed} caption="Normal workflow examples" icon={CheckCircle2} />
        <MetricCard label="Frida Evidence Available" value={`${fridaAvailable}/${reports.length}`} caption="Frozen reports with OS-level evidence" icon={RadioTower} />
        <MetricCard label="CodeTracer Available" value={`${codetracerAvailable}/${reports.length}`} caption="Reports with diagnosis bundles" icon={ShieldCheck} />
        <MetricCard label="Deep Trace Ready" value={`${deepTrace}/${reports.length}`} caption="Canonical trace quality reached deep" icon={GitBranch} />
        <MetricCard label="OpenInference Export" value={`${openInference}/${reports.length}`} caption="Reports with standard span exports" icon={Share2} />
      </section>

      <section className="mt-8">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-xl font-semibold text-slate-950">Showcase Reports</h2>
          <Link href="/showcases" className="action-button-light">
            View All Reports
          </Link>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {reports.map((report) => (
            <Link key={report.id} href={`/showcases/${report.id}`} className="panel block border border-slate-200 p-5 transition hover:-translate-y-0.5 hover:border-slate-400 hover:shadow-md">
              <div className="flex flex-wrap items-center gap-2">
                <Badge value={report.verdict} tone="verdict" />
                <Badge value={report.riskLevel} tone="risk" />
                <Badge value={report.dataSource} />
              </div>
              <h3 className="mt-4 text-lg font-semibold text-slate-950">{report.title}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-600">{report.executiveSummary || report.description}</p>
              <div className="mt-4 grid grid-cols-4 gap-3 text-sm">
                <div>
                  <p className="text-xs text-slate-500">Runtime</p>
                  <p className="font-semibold text-slate-950">{report.metrics.runtimeEvents}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Frida</p>
                  <p className="font-semibold text-slate-950">{report.metrics.fridaEvents}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Artifacts</p>
                  <p className="font-semibold text-slate-950">{report.metrics.artifacts}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Trace</p>
                  <p className="font-semibold text-slate-950">{report.traceBackbone?.traceDepth || report.metrics.traceQuality || "fallback"}</p>
                </div>
              </div>
              <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                <span className="font-semibold text-slate-950">{report.traceBackbone?.spanCount ?? report.metrics.canonicalSpans ?? 0}</span> canonical spans
                <span className="px-2 text-slate-300">·</span>
                {report.traceBackbone?.exportAvailable || report.metrics.exportAvailable ? "OpenInference export ready" : "Export unavailable"}
              </div>
              <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4 text-sm font-semibold text-slate-900">
                <span>Open Security Report</span>
                <span aria-hidden="true">→</span>
              </div>
            </Link>
          ))}
        </div>
      </section>
    </AppShell>
  );
}
