import type { Finding } from "@/lib/report-model";
import { Badge } from "./verdict-badge";

export function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <section className="panel p-5">
      <h2 className="text-lg font-semibold text-slate-950">Findings</h2>
      <div className="mt-4 space-y-3">
        {findings.length === 0 ? (
          <p className="text-sm text-slate-600">No findings were generated for this report.</p>
        ) : (
          findings.map((item, index) => (
            <div key={`${item.title}-${index}`} className="rounded-md border border-slate-200 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge value={item.severity} />
                <span className="text-xs font-medium uppercase tracking-normal text-slate-500">{item.source}</span>
              </div>
              <h3 className="mt-3 text-sm font-semibold text-slate-950">{item.title}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-600">{item.summary}</p>
              {item.artifact ? <p className="mono mt-3 text-xs text-slate-500">{item.artifact}</p> : null}
            </div>
          ))
        )}
      </div>
    </section>
  );
}
