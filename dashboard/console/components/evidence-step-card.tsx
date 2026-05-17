import Link from "next/link";
import { AlertTriangle, Ban, CircleDot, FileWarning } from "lucide-react";
import type { DetectionStep } from "@/lib/defense-walkthrough";

const rowTone: Record<DetectionStep["status"], string> = {
  context: "border-l-blue-400",
  suspicious: "border-l-amber-400",
  critical: "border-l-red-500",
  blocked: "border-l-red-600"
};

const badgeTone: Record<DetectionStep["status"], string> = {
  context: "bg-blue-50 text-blue-700 ring-blue-200",
  suspicious: "bg-amber-50 text-amber-700 ring-amber-200",
  critical: "bg-red-50 text-red-700 ring-red-200",
  blocked: "bg-red-600 text-white ring-red-600"
};

const labels: Record<DetectionStep["status"], string> = {
  context: "CONTEXT",
  suspicious: "SUSPICIOUS",
  critical: "CRITICAL",
  blocked: "BLOCKED"
};

export function EvidenceStepCard({ step, index, showcaseId }: { step: DetectionStep; index: number; showcaseId: string }) {
  return (
    <div className={`grid gap-3 border-l-4 border-y border-r border-slate-200 bg-white p-3 md:grid-cols-[220px_120px_1fr_150px] ${rowTone[step.status]}`}>
      <div className="flex items-center gap-3">
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full ring-1 ${badgeTone[step.status]}`}>
          <StepIcon step={step} />
        </div>
        <div>
          <p className="text-xs font-semibold text-slate-500">Step {index + 1}</p>
          <h3 className="text-sm font-semibold text-slate-950">{step.title}</h3>
        </div>
      </div>
      <div className="flex items-center">
        <span className={`rounded-md px-2.5 py-1 text-xs font-semibold ring-1 ${badgeTone[step.status]}`}>{labels[step.status]}</span>
      </div>
      <p className="text-sm leading-6 text-slate-600">{step.summary}</p>
      <div className="flex items-center justify-start md:justify-end">
        <Link
          href={`/artifacts/${showcaseId}?path=${encodeURIComponent(step.artifactPath)}`}
          className="rounded-md border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-600 transition hover:border-blue-300 hover:text-blue-700"
          title={`Open ${step.artifactPath}`}
        >
          {step.evidenceSource} · {step.evidenceCount} {step.evidenceCount === 1 ? "event" : "events"}
        </Link>
      </div>
    </div>
  );
}

function StepIcon({ step }: { step: DetectionStep }) {
  if (step.status === "blocked") return <Ban className="h-4 w-4" aria-hidden="true" />;
  if (step.status === "critical") return <FileWarning className="h-4 w-4" aria-hidden="true" />;
  if (step.status === "suspicious") return <AlertTriangle className="h-4 w-4" aria-hidden="true" />;
  return <CircleDot className="h-4 w-4" aria-hidden="true" />;
}
