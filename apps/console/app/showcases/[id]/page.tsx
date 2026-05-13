import { notFound } from "next/navigation";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/verdict-badge";
import { MetricCard } from "@/components/metric-card";
import { PipelineStrip } from "@/components/pipeline-strip";
import { RiskChainTimeline } from "@/components/risk-chain-timeline";
import { EvidenceTabs } from "@/components/evidence-tabs";
import { FindingsList } from "@/components/findings-list";
import { RecommendationList } from "@/components/recommendation-list";
import { ArtifactTable } from "@/components/artifact-table";
import { ReportActions } from "@/components/report-actions";
import { TraceBackboneCard } from "@/components/trace-backbone-card";
import { readReportModel } from "@/lib/showcase";

type Props = {
  params: Promise<{ id: string }>;
};

export default async function ShowcaseReportPage({ params }: Props) {
  const { id } = await params;
  const report = await readReportModel(id);
  if (!report) {
    notFound();
  }

  return (
    <AppShell>
      <section className="report-header p-10">
        <div className="grid gap-6 lg:grid-cols-[1fr_auto]">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge value={report.verdict} tone="verdict" />
              <Badge value={report.riskLevel} tone="risk" />
              <Badge value={report.dataSource} />
            </div>
            <h1 className="mt-6 text-4xl font-semibold tracking-normal">{report.title}</h1>
            <p className="mt-4 max-w-4xl text-base leading-7 text-slate-200">{report.executiveSummary || report.description}</p>
          </div>
          <ReportActions showcaseId={report.id} />
        </div>
        <div className="mt-5 rounded-md border border-white/15 bg-white/10 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs font-semibold uppercase tracking-normal text-slate-300">Security conclusion</p>
            <span className="mono rounded bg-white/10 px-2 py-1 text-xs text-slate-200" title={report.sourceRunId}>
              Source Run: {report.sourceRunId}
            </span>
          </div>
          <p className="mt-2 text-sm leading-6 text-white">{report.securityConclusion || report.reason || "No conclusion recorded in the report model."}</p>
        </div>
      </section>

      <section className="mt-6 grid gap-4 md:grid-cols-4">
        <MetricCard label="Runtime Events" value={report.metrics.runtimeEvents} />
        <MetricCard label="Canonical Spans" value={report.traceBackbone?.spanCount ?? report.metrics.canonicalSpans ?? 0} caption={report.traceBackbone?.traceDepth ? `Trace quality: ${report.traceBackbone.traceDepth}` : "Canonical trace fallback"} />
        <MetricCard label="Frida Events" value={report.metrics.fridaEvents} />
        <MetricCard label="OpenInference" value={report.traceBackbone?.exportAvailable || report.metrics.exportAvailable ? "Ready" : "N/A"} caption="Standard span export artifact" />
      </section>

      <div className="mt-6 space-y-6">
        <TraceBackboneCard report={report} />
        <PipelineStrip stages={report.pipeline} />
        <RiskChainTimeline nodes={report.riskChain} />
        <EvidenceTabs report={report} />
        <div className="grid gap-6 lg:grid-cols-2">
          <FindingsList findings={report.findings} />
          <RecommendationList recommendations={report.recommendations} />
        </div>
        <ArtifactTable showcaseId={report.id} artifacts={report.artifacts} />
      </div>

      <div className="mt-6 flex justify-end">
        <Link href="/showcases" className="action-button-light">
          Back to Gallery
        </Link>
      </div>
    </AppShell>
  );
}
