import Link from "next/link";
import { AlertTriangle, ArrowRight, CheckCircle2, FileWarning, Globe2, ShieldCheck } from "lucide-react";
import type { DetectionStep } from "@/lib/defense-walkthrough";

const tones: Record<DetectionStep["status"], string> = {
  context: "border-blue-200 bg-white text-blue-950",
  suspicious: "border-amber-300 bg-amber-50 text-amber-950",
  critical: "border-red-300 bg-red-50 text-red-950",
  blocked: "border-red-300 bg-white text-red-950"
};

const badgeTones: Record<DetectionStep["status"], string> = {
  context: "border-blue-200 bg-blue-50 text-blue-700",
  suspicious: "border-amber-200 bg-amber-50 text-amber-700",
  critical: "border-red-200 bg-red-50 text-red-700",
  blocked: "border-red-200 bg-red-50 text-red-700"
};

const labels: Record<DetectionStep["status"], string> = {
  context: "CONTEXT",
  suspicious: "SUSPICIOUS",
  critical: "CRITICAL",
  blocked: "BLOCKED"
};

export function OperationChainBoard({ steps, showcaseId }: { steps: DetectionStep[]; showcaseId: string }) {
  return (
    <section>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-600 text-sm font-semibold text-white">1</span>
            <h1 className="text-2xl font-semibold text-slate-950">Cross-Step Detection Flow</h1>
          </div>
          <p className="mt-2 text-sm text-slate-600">Trace-backed operation chain from low-trust trigger to runtime enforcement and audit judgment.</p>
        </div>
        <div className="rounded-md border border-slate-200 bg-white p-1 text-sm">
          <span className="inline-flex rounded bg-blue-50 px-4 py-2 font-semibold text-blue-700">Event Flow</span>
        </div>
      </div>
      <div className="mt-8 grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-5">
        {steps.map((step, index) => (
          <div key={step.id} className="relative flex min-w-0 flex-col">
            <p className="mb-2 text-center text-xs font-medium text-slate-500">Step {index + 1}</p>
            <div className={`flex h-72 flex-col rounded-md border p-4 shadow-sm ${tones[step.status]}`}>
              <div className="flex justify-center">
                <div className={`flex h-11 w-11 items-center justify-center rounded-full border bg-white ${badgeTones[step.status]}`}>
                  <StepIcon step={step} />
                </div>
              </div>
              <p className="mt-4 text-center text-xs font-semibold text-slate-500">Step {index + 1}</p>
              <h2 className="mt-1 text-center text-sm font-semibold text-slate-950">{step.title}</h2>
              <div className="mt-4 flex justify-center">
                <span className={`rounded-md border px-3 py-1 text-xs font-semibold ${badgeTones[step.status]}`}>{labels[step.status]}</span>
              </div>
              <div className="mt-auto flex justify-center pt-4">
                <Link
                  href={`/artifacts/${showcaseId}?path=${encodeURIComponent(step.artifactPath)}`}
                  className="rounded-md border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-600 shadow-sm transition hover:border-blue-300 hover:text-blue-700"
                  title={`Open ${step.artifactPath}`}
                >
                  {step.evidenceSource} · {step.evidenceCount} {step.evidenceCount === 1 ? "event" : "events"}
                </Link>
              </div>
            </div>
            <p className="mt-3 min-h-24 text-center text-sm leading-6 text-slate-600">{step.summary}</p>
            {index < steps.length - 1 ? (
              <ArrowRight className="absolute -right-4 top-24 hidden h-5 w-5 text-slate-400 xl:block" aria-hidden="true" />
            ) : null}
          </div>
        ))}
      </div>
    </section>
  );
}

function StepIcon({ step }: { step: DetectionStep }) {
  const title = step.title.toLowerCase();
  if (step.status === "blocked") return <ShieldCheck className="h-5 w-5" aria-hidden="true" />;
  if (step.status === "critical") return <FileWarning className="h-5 w-5" aria-hidden="true" />;
  if (title.includes("url") || title.includes("navigation") || title.includes("external")) return <Globe2 className="h-5 w-5" aria-hidden="true" />;
  return <AlertTriangle className="h-5 w-5" aria-hidden="true" />;
}
