import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { ReportModel, RiskLevel, Verdict } from "./report-model";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function labelize(value: string | undefined | null) {
  if (!value) return "Unknown";
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function verdictTone(verdict: string | undefined) {
  switch (verdict) {
    case "block":
      return "bg-red-50 text-red-700 ring-red-200";
    case "require_confirmation":
      return "bg-amber-50 text-amber-800 ring-amber-200";
    case "allow":
      return "bg-emerald-50 text-emerald-700 ring-emerald-200";
    default:
      return "bg-slate-100 text-slate-700 ring-slate-200";
  }
}

export function riskTone(risk: string | undefined) {
  switch (risk) {
    case "critical":
      return "bg-red-600 text-white ring-red-600";
    case "high":
      return "bg-amber-500 text-white ring-amber-500";
    case "medium":
      return "bg-blue-100 text-blue-800 ring-blue-200";
    case "low":
      return "bg-emerald-100 text-emerald-800 ring-emerald-200";
    default:
      return "bg-slate-100 text-slate-700 ring-slate-200";
  }
}

export function statusTone(status: string | undefined) {
  if (["ok", "available", "allowed"].includes(status || "")) return "bg-emerald-50 text-emerald-700 ring-emerald-200";
  if (["blocked", "critical", "failed", "critical_risk"].includes(status || "")) return "bg-red-50 text-red-700 ring-red-200";
  if (["requires_confirmation", "high", "high_risk", "degraded", "attach_failed"].includes(status || "")) return "bg-amber-50 text-amber-800 ring-amber-200";
  return "bg-slate-100 text-slate-700 ring-slate-200";
}

export function statusLabel(status: string | undefined) {
  if (status === "ok") return "OK";
  return labelize(status);
}

export function outcomeLabel(outcome: string | undefined) {
  const labels: Record<string, string> = {
    events_captured: "Events Captured",
    blocked: "Blocked Action",
    allowed: "Allowed",
    requires_confirmation: "Requires Confirmation",
    attach_failed: "Attach Failed",
    evidence_found: "Evidence Found",
    diagnosis_ready: "Diagnosis Ready",
    critical_risk: "Critical Risk",
    high_risk: "High Risk",
    medium_risk: "Medium Risk",
    low_risk: "Low Risk",
    none: "No Finding"
  };
  return labels[outcome || ""] || labelize(outcome);
}

export function sortReportsForDemo(reports: ReportModel[]) {
  const verdictRank: Record<Verdict, number> = {
    block: 0,
    require_confirmation: 1,
    warn: 2,
    allow: 4,
    unknown: 5
  };
  const riskRank: Record<RiskLevel, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 4,
    unknown: 5
  };
  return [...reports].sort((a, b) => {
    const byVerdict = (verdictRank[a.verdict] ?? 6) - (verdictRank[b.verdict] ?? 6);
    if (byVerdict !== 0) return byVerdict;
    return (riskRank[a.riskLevel] ?? 6) - (riskRank[b.riskLevel] ?? 6);
  });
}

export function countBy<T>(items: T[], predicate: (item: T) => boolean) {
  return items.reduce((count, item) => count + (predicate(item) ? 1 : 0), 0);
}

export function artifactLabel(path: string) {
  return path.split("/").pop() || path;
}
