import type { LucideIcon } from "lucide-react";

type MetricCardProps = {
  label: string;
  value: string | number;
  caption?: string;
  icon?: LucideIcon;
};

export function MetricCard({ label, value, caption, icon: Icon }: MetricCardProps) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-medium text-slate-600">{label}</p>
        {Icon ? <Icon className="h-4 w-4 text-slate-500" aria-hidden="true" /> : null}
      </div>
      <p className="mt-3 text-3xl font-semibold tracking-normal text-slate-950">{value}</p>
      {caption ? <p className="mt-1 text-xs text-slate-500">{caption}</p> : null}
    </div>
  );
}
