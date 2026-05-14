import { notFound } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, CheckCircle2, Scale, Shield } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { EvidenceStepCard } from "@/components/evidence-step-card";
import { OperationChainBoard } from "@/components/operation-chain-board";
import { buildDefenseWalkthrough } from "@/lib/defense-walkthrough";
import { labelize } from "@/lib/format";
import { readReportModel } from "@/lib/showcase";

type Props = {
  params: Promise<{ id: string }>;
};

export default async function DefenseWalkthroughPage({ params }: Props) {
  const { id } = await params;
  const report = await readReportModel(id);
  if (!report) {
    notFound();
  }
  const walkthrough = buildDefenseWalkthrough(report);

  return (
    <AppShell>
      <div>
        <Link href={`/showcases/${report.id}`} className="action-button-light">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Back to Report
        </Link>
      </div>

      <div className="mt-6 rounded-md bg-white p-6 shadow-sm ring-1 ring-slate-200">
        <OperationChainBoard steps={walkthrough.steps} showcaseId={report.id} />
      </div>

      <section className="mt-6 space-y-5">
        <div className="panel p-5">
          <div className="flex items-center justify-between gap-3 border-b border-slate-200 pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-amber-50 text-amber-700 ring-1 ring-amber-200">
                <Scale className="h-5 w-5" aria-hidden="true" />
              </div>
              <h2 className="text-lg font-semibold text-slate-950">Problematic Steps</h2>
            </div>
            <span className="rounded-md bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600">
              {walkthrough.problematicSteps.length} flagged
            </span>
          </div>
          <div className="mt-4 overflow-hidden rounded-md">
            {walkthrough.problematicSteps.length > 0 ? (
              walkthrough.problematicSteps.map((step, index) => <EvidenceStepCard key={step.id} step={step} index={index} showcaseId={report.id} />)
            ) : (
              <p className="rounded-md bg-slate-50 p-4 text-sm text-slate-600">No problematic step was flagged for this run.</p>
            )}
          </div>
        </div>

        <div className="panel p-5">
          <div className="flex items-center gap-3 border-b border-slate-200 pb-4">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-50 text-blue-700 ring-1 ring-blue-200">
              <Scale className="h-5 w-5" aria-hidden="true" />
            </div>
            <h2 className="text-lg font-semibold text-slate-950">Decision Basis</h2>
          </div>
          <div className="mt-4 rounded-md border border-red-200 bg-red-50 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-full bg-white text-red-600 ring-1 ring-red-200">
                  <Shield className="h-5 w-5" aria-hidden="true" />
                </div>
                <div>
                  <p className="text-xs font-semibold text-slate-500">Final Decision</p>
                  <h3 className="text-xl font-semibold text-slate-950">{walkthrough.decision.title}</h3>
                </div>
              </div>
              <span className="rounded-md border border-red-200 bg-white px-3 py-1 text-sm font-semibold text-red-700">
                {walkthrough.decision.riskLabel}
              </span>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-700">{walkthrough.decision.summary}</p>
          </div>
          <div className="mt-5">
            <h3 className="text-sm font-semibold text-slate-950">Key Reasoning</h3>
            <ul className="mt-3 space-y-2">
              {walkthrough.decision.reasoning.map((item) => (
                <li key={item} className="flex gap-2 text-sm leading-6 text-slate-700">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" aria-hidden="true" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
          {walkthrough.decision.chips.length > 0 ? (
            <div className="mt-5 rounded-md border border-slate-200 bg-white p-4">
              <p className="text-sm font-semibold text-slate-950">Evidence basis</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {walkthrough.decision.chips.map((chip) => (
                  <span key={chip} className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-600">
                    {chip}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
          <p className="mt-4 text-xs text-slate-500">
            Decision: {labelize(report.verdict)} · Risk: {labelize(report.riskLevel)}
          </p>
        </div>
      </section>
    </AppShell>
  );
}
