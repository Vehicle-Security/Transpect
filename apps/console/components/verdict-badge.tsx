import { labelize, riskTone, statusTone, verdictTone } from "@/lib/format";

type BadgeProps = {
  value: string;
  tone?: "verdict" | "risk" | "status";
};

export function Badge({ value, tone = "status" }: BadgeProps) {
  const classes = tone === "verdict" ? verdictTone(value) : tone === "risk" ? riskTone(value) : statusTone(value);
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ${classes}`}>
      {labelize(value)}
    </span>
  );
}
