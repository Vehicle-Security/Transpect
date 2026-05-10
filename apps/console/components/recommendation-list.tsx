import { CheckCircle2 } from "lucide-react";

export function RecommendationList({ recommendations }: { recommendations: string[] }) {
  return (
    <section className="panel p-5">
      <h2 className="text-lg font-semibold text-slate-950">Recommendations</h2>
      <div className="mt-4 space-y-3">
        {recommendations.map((item, index) => (
          <div key={`${item}-${index}`} className="flex gap-3 rounded-md bg-slate-50 p-3 text-sm leading-6 text-slate-700">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-slate-600" aria-hidden="true" />
            <span>{item}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
