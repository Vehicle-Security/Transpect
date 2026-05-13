"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import type { Artifact, EventPreview, ReportModel } from "@/lib/report-model";
import { Badge } from "./verdict-badge";
import { outcomeLabel, statusLabel } from "@/lib/format";

const tabs = [
  { key: "runtime", label: "Runtime Trace" },
  { key: "defense", label: "Agent Defense" },
  { key: "frida", label: "Frida" },
  { key: "codetracer", label: "CodeTracer" },
  { key: "raw", label: "Raw Artifacts" }
];

export function EvidenceTabs({ report }: { report: ReportModel }) {
  const [active, setActive] = useState("runtime");
  const stage = useMemo(() => report.pipeline.find((item) => item.key === active), [active, report.pipeline]);
  const runtimePreview = report.previews?.runtime ?? [];
  const fridaPreview = report.previews?.frida ?? [];
  const runtimeArtifact = findArtifact(report.artifacts, ["merged-trace.jsonl", "behavior-events.jsonl"]);
  const fridaArtifact = findArtifact(report.artifacts, ["frida-events.jsonl"]);
  return (
    <section className="panel p-5">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 pb-4">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActive(tab.key)}
            className={`rounded-md px-3 py-2 text-sm font-semibold ${active === tab.key ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-700 hover:bg-slate-200"}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="mt-5">
        {active !== "raw" && stage ? (
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-lg font-semibold text-slate-950">{stage.label}</h2>
              <Badge value={stage.status} />
              {stage.outcome ? <Badge value={stage.outcome} /> : null}
            </div>
            <p className="mt-2 text-xs font-semibold uppercase tracking-normal text-slate-500">
              {statusLabel(stage.status)} · {outcomeLabel(stage.outcome)}
            </p>
            <p className="mt-3 text-sm leading-6 text-slate-600">{stage.summary}</p>
          </div>
        ) : null}
        {active === "runtime" ? (
          <EvidenceSummary
            count={stage?.count}
            artifact={runtimeArtifact}
            showcaseId={report.id}
            actionLabel="View raw events"
          >
            <PreviewList rows={runtimePreview} empty="No runtime event preview available." />
          </EvidenceSummary>
        ) : null}
        {active === "defense" ? <FindingPreview report={report} source="Agent Defense" /> : null}
        {active === "frida" ? (
          <EvidenceSummary
            count={stage?.count}
            artifact={fridaArtifact}
            showcaseId={report.id}
            actionLabel="View raw Frida evidence"
          >
            <CapabilityNote stageSummary={stage?.summary} />
            <PreviewList rows={fridaPreview} empty="No Frida event preview available; the status above records the capability state." />
          </EvidenceSummary>
        ) : null}
        {active === "codetracer" ? <ArtifactPreview report={report} source="CodeTracer" /> : null}
        {active === "raw" ? <ArtifactPreview report={report} /> : null}
      </div>
    </section>
  );
}

function findArtifact(artifacts: Artifact[], names: string[]) {
  return artifacts.find((artifact) => names.includes(artifact.path) || names.includes(artifact.name));
}

function EvidenceSummary({
  count,
  artifact,
  showcaseId,
  actionLabel,
  children
}: {
  count?: number;
  artifact?: Artifact;
  showcaseId: string;
  actionLabel: string;
  children: ReactNode;
}) {
  return (
    <div className="mt-4">
      <div className="grid gap-3 md:grid-cols-[180px_1fr_auto]">
        <div className="rounded-md bg-slate-50 p-4">
          <p className="text-xs font-semibold uppercase tracking-normal text-slate-500">Event Count</p>
          <p className="mt-2 text-2xl font-semibold text-slate-950">{count ?? 0}</p>
        </div>
        <div className="rounded-md bg-slate-50 p-4">
          <p className="text-xs font-semibold uppercase tracking-normal text-slate-500">Related Artifact</p>
          <p className="mono mt-2 text-sm text-slate-700">{artifact?.path || "No raw artifact linked"}</p>
        </div>
        {artifact ? (
          <Link
            href={`/artifacts/${showcaseId}?path=${encodeURIComponent(artifact.path)}`}
            className="action-button-light"
          >
            {actionLabel}
          </Link>
        ) : null}
      </div>
      {children}
    </div>
  );
}

function CapabilityNote({ stageSummary }: { stageSummary?: string }) {
  if (!stageSummary) return null;
  return <p className="mt-4 rounded-md border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-slate-600">{stageSummary}</p>;
}

function PreviewList({ rows, empty }: { rows: EventPreview[]; empty: string }) {
  if (rows.length === 0) {
    return <p className="mt-4 rounded-md bg-slate-50 p-4 text-sm text-slate-600">{empty}</p>;
  }
  return (
    <div className="mt-4 space-y-3">
      {rows.slice(0, 6).map((row, index) => (
        <div key={`${row.eventId || row.name || "event"}-${index}`} className="rounded-md border border-slate-200 bg-white p-4">
          <div className="flex flex-wrap items-center gap-2">
            {row.kind ? <Badge value={row.kind} /> : null}
            {row.status ? <Badge value={row.status} /> : null}
          </div>
          <h3 className="mt-3 text-sm font-semibold text-slate-950">{displayEventName(row.name) || "Runtime event"}</h3>
          <p className="mt-2 text-sm leading-6 text-slate-600">{row.summary}</p>
        </div>
      ))}
    </div>
  );
}

function displayEventName(name?: string | null) {
  const normalized = String(name || "").trim();
  const aliases: Record<string, string> = {
    "Agent Defense plan check": "External Link Inspection",
    "Agent turn result": "Agent Execution Interrupted",
    "openclaw.request": "Runtime Request",
    "policy warning": "Policy Warning",
    "security warn": "Policy Warning",
    "security.low_trust_comment_observed": "Low-trust Trigger",
    "security_intervention": "Runtime Decision",
    "security.decision": "Runtime Decision",
    "security.action": "Action Safety Review",
    "upload": "Sensitive Action Evidence",
    "file access": "Sensitive Action Evidence"
  };
  const direct = aliases[normalized];
  if (direct) return direct;
  const lowered = normalized.toLowerCase();
  if (lowered.includes("low_trust_comment")) return "Low-trust Trigger";
  if (lowered.includes("security_intervention") || lowered.includes("security.decision")) return "Runtime Decision";
  if (lowered.includes("security.action")) return "Action Safety Review";
  if (lowered.includes("upload") || lowered.includes("file access")) return "Sensitive Action Evidence";
  if (lowered.includes("policy") || lowered.includes("security warn")) return "Policy Warning";
  return normalized;
}

function FindingPreview({ report, source }: { report: ReportModel; source: string }) {
  const rows = report.findings.filter((finding) => finding.source === source || finding.source === "Final Judgment");
  return (
    <div className="mt-4 space-y-3">
      {rows.map((finding) => (
        <div key={finding.title} className="rounded-md border border-slate-200 p-4">
          <Badge value={finding.severity} />
          <h3 className="mt-3 text-sm font-semibold text-slate-950">{finding.title}</h3>
          <p className="mt-2 text-sm leading-6 text-slate-600">{finding.summary}</p>
        </div>
      ))}
    </div>
  );
}

function ArtifactPreview({ report, source }: { report: ReportModel; source?: string }) {
  const rows = source ? report.artifacts.filter((artifact) => artifact.source === source) : report.artifacts;
  if (rows.length === 0) {
    return <p className="mt-4 rounded-md bg-slate-50 p-4 text-sm text-slate-600">No artifacts are available for this section.</p>;
  }
  return (
    <div className="mt-4 grid gap-3 md:grid-cols-2">
      {rows.map((artifact) => (
        <div key={artifact.path} className="rounded-md border border-slate-200 p-4">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-sm font-semibold text-slate-950">{artifact.name}</h3>
            <Badge value={artifact.status} />
          </div>
          <p className="mono mt-2 text-xs text-slate-500">{artifact.path}</p>
        </div>
      ))}
    </div>
  );
}
