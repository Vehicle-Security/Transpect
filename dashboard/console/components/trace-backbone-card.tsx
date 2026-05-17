import { GitBranch, Layers3, Radar, Share2 } from "lucide-react";
import type { ReportModel } from "@/lib/report-model";
import { Badge } from "./verdict-badge";

const coverageLabels: Record<string, string> = {
  lifecycle: "Lifecycle",
  assistant: "Assistant",
  openclawTool: "OpenClaw Tools",
  pluginHooks: "Plugin Hooks",
  sessionTranscript: "Transcript",
  llm: "LLM",
  tool: "Tools",
  browser: "Browser",
  agentDefense: "Agent Defense",
  frida: "Frida",
  codetracer: "CodeTracer",
  finalJudgment: "Final Judgment"
};

function scoreLabel(value: number | undefined) {
  if (typeof value !== "number") return "Not scored";
  return `${Math.round(value * 100)}%`;
}

export function TraceBackboneCard({ report }: { report: ReportModel }) {
  const backbone = report.traceBackbone;
  const coverage = backbone?.quality?.coverage || report.metrics.coverage || {};
  const coverageEntries = Object.entries(coverage).filter(([key]) => key in coverageLabels);
  const availableCount = coverageEntries.filter(([, value]) => value).length;
  const totalCount = coverageEntries.length;
  const traceDepth = backbone?.traceDepth || report.metrics.traceQuality || "fallback";
  const exportReady = Boolean(backbone?.exportAvailable || report.metrics.exportAvailable);
  const missingSources = backbone?.missingSources || [];
  const warnings = backbone?.warnings || [];

  return (
    <section className="panel overflow-hidden">
      <div className="grid gap-0 lg:grid-cols-[1.1fr_1.4fr]">
        <div className="border-b border-slate-200 bg-slate-950 p-5 text-white lg:border-b-0 lg:border-r lg:border-slate-800">
          <div className="flex flex-wrap items-center gap-2">
            <Badge value={traceDepth === "deep" ? "deep_trace" : traceDepth} />
            <Badge value={exportReady ? "export_ready" : "export_unavailable"} />
          </div>
          <h2 className="mt-5 text-xl font-semibold">Agent Trace Backbone</h2>
          <p className="mt-2 text-sm leading-6 text-slate-300">
            Canonical span tree built from OpenClaw native streams, behavior-mediator events, Frida evidence, CodeTracer diagnosis, and final judgment.
          </p>
          <div className="mt-5 grid grid-cols-2 gap-3 text-sm">
            <div className="rounded-md border border-white/10 bg-white/10 p-3">
              <p className="text-xs uppercase text-slate-400">Quality Score</p>
              <p className="mt-1 text-2xl font-semibold">{scoreLabel(backbone?.quality?.score || report.metrics.traceQualityScore)}</p>
            </div>
            <div className="rounded-md border border-white/10 bg-white/10 p-3">
              <p className="text-xs uppercase text-slate-400">Coverage</p>
              <p className="mt-1 text-2xl font-semibold">
                {availableCount}/{totalCount || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="p-5">
          <div className="grid gap-3 md:grid-cols-4">
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
              <Layers3 className="h-4 w-4 text-slate-500" aria-hidden="true" />
              <p className="mt-3 text-xs text-slate-500">Canonical Spans</p>
              <p className="text-2xl font-semibold text-slate-950">{backbone?.spanCount ?? report.metrics.canonicalSpans ?? 0}</p>
            </div>
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
              <Radar className="h-4 w-4 text-slate-500" aria-hidden="true" />
              <p className="mt-3 text-xs text-slate-500">Evidence Spans</p>
              <p className="text-2xl font-semibold text-slate-950">{backbone?.evidenceSpanCount ?? report.metrics.evidenceSpanCount ?? 0}</p>
            </div>
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
              <GitBranch className="h-4 w-4 text-slate-500" aria-hidden="true" />
              <p className="mt-3 text-xs text-slate-500">Primary Spans</p>
              <p className="text-2xl font-semibold text-slate-950">{backbone?.primarySpanCount ?? report.metrics.primarySpanCount ?? 0}</p>
            </div>
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
              <Share2 className="h-4 w-4 text-slate-500" aria-hidden="true" />
              <p className="mt-3 text-xs text-slate-500">OpenInference</p>
              <p className="text-sm font-semibold text-slate-950">{exportReady ? "Export Ready" : "Unavailable"}</p>
            </div>
          </div>

          <div className="mt-5">
            <p className="text-xs font-semibold uppercase text-slate-500">Source Coverage</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {coverageEntries.length ? (
                coverageEntries.map(([key, value]) => (
                  <span key={key} className={`rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ${value ? "bg-emerald-50 text-emerald-700 ring-emerald-200" : "bg-slate-100 text-slate-600 ring-slate-200"}`}>
                    {coverageLabels[key]} {value ? "✓" : "–"}
                  </span>
                ))
              ) : (
                <span className="text-sm text-slate-500">Canonical trace coverage is not available for this frozen report.</span>
              )}
            </div>
          </div>

          {missingSources.length || warnings.length ? (
            <div className="mt-5 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
              {[...missingSources, ...warnings].slice(0, 3).join(" · ")}
            </div>
          ) : (
            <div className="mt-5 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm font-medium text-emerald-800">
              Deep trace coverage is complete for the required runtime, evidence, diagnosis, and judgment sources.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
