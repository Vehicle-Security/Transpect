import { Activity, BrainCircuit, FileCheck2, RadioTower, Scale } from "lucide-react";
import type { SVGProps } from "react";
import type { PipelineStage } from "@/lib/report-model";
import { Badge } from "./verdict-badge";
import { outcomeLabel, statusLabel } from "@/lib/format";

const icons = {
  runtime: Activity,
  defense: ShieldLike,
  frida: RadioTower,
  codetracer: BrainCircuit,
  judgment: Scale
};

function ShieldLike(props: SVGProps<SVGSVGElement>) {
  return <FileCheck2 {...props} />;
}

export function PipelineStrip({ stages }: { stages: PipelineStage[] }) {
  return (
    <section className="panel p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-950">Detection Pipeline</h2>
        <span className="text-xs font-medium uppercase tracking-normal text-slate-500">Runtime to judgment</span>
      </div>
      <div className="grid gap-3 md:grid-cols-5">
        {stages.map((stage) => {
          const Icon = icons[stage.key as keyof typeof icons] ?? Activity;
          return (
            <div key={stage.key} className="flex min-h-56 flex-col rounded-md border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center justify-between gap-3">
                <Icon className="h-5 w-5 text-slate-600" aria-hidden="true" />
                <Badge value={stage.status} />
              </div>
              <p className="mt-4 text-xs font-semibold uppercase tracking-normal text-slate-500">
                {statusLabel(stage.status)} · {outcomeLabel(stage.outcome)}
              </p>
              <h3 className="mt-4 text-sm font-semibold text-slate-950">{stage.label}</h3>
              <p className="mt-2 flex-1 text-sm leading-6 text-slate-600">{stage.summary}</p>
              {typeof stage.count === "number" ? <p className="mt-3 text-xs font-medium text-slate-500">{stage.count} events</p> : null}
            </div>
          );
        })}
      </div>
    </section>
  );
}
