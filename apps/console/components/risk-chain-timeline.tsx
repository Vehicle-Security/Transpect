import { Badge } from "./verdict-badge";
import type { RiskChainNode } from "@/lib/report-model";

function sourceLabel(source: string) {
  if (source === "observed") return "Observed Evidence";
  if (source === "scenario") return "Scenario Stage";
  return source;
}

export function RiskChainTimeline({ nodes }: { nodes: RiskChainNode[] }) {
  return (
    <section className="panel p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-950">Risk Chain Timeline</h2>
        <span className="text-xs text-slate-500">Observed chains are separated from scenario-defined stages.</span>
      </div>
      {nodes.length === 0 ? (
        <div className="rounded-md border border-dashed border-slate-300 bg-slate-50 p-6">
          <h3 className="text-sm font-semibold text-slate-950">Risk chain unavailable</h3>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            This frozen run does not include structured chain nodes. Runtime, Frida, CodeTracer, and final judgment artifacts remain available below.
          </p>
        </div>
      ) : (
        <ol className="space-y-3">
          {nodes.map((node, index) => (
            <li key={`${node.id}-${index}`} className="grid gap-3 rounded-md border border-slate-200 bg-white p-4 md:grid-cols-[40px_1fr_auto]">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-slate-900 text-sm font-semibold text-white">{index + 1}</div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-sm font-semibold text-slate-950">{node.label}</h3>
                  <Badge value={sourceLabel(node.source)} />
                </div>
                {node.summary ? <p className="mt-2 text-sm leading-6 text-slate-600">{node.summary}</p> : null}
                {node.evidenceSource ? <p className="mt-2 text-xs font-medium text-slate-500">Evidence source: {node.evidenceSource}</p> : null}
              </div>
              <span className="self-start rounded bg-slate-100 px-2 py-1 text-xs font-semibold text-slate-600">
                {node.evidenceCount || 1} {(node.evidenceCount || 1) === 1 ? "event" : "events"}
              </span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
