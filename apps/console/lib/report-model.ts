export type Verdict = "block" | "require_confirmation" | "allow" | "warn" | "unknown";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "unknown";
export type EvidenceStatus = "ok" | "available" | "blocked" | "requires_confirmation" | "allowed" | "critical" | "high" | "medium" | "low" | "degraded" | "unavailable" | "failed" | "unknown";

export type PipelineStage = {
  key: "runtime" | "defense" | "frida" | "codetracer" | "judgment" | string;
  label: string;
  status: EvidenceStatus | string;
  outcome?: string;
  summary: string;
  count?: number;
};

export type RiskChainNode = {
  id: string;
  label: string;
  summary?: string;
  source: "observed" | "scenario" | string;
  eventId?: string | null;
  relatedEvents?: string[];
  evidenceCount?: number;
  evidenceSource?: string;
  status?: string | null;
};

export type Finding = {
  severity: "critical" | "warning" | "info" | "low" | string;
  source: string;
  title: string;
  summary: string;
  artifact?: string;
  eventId?: string;
};

export type Artifact = {
  name: string;
  source: string;
  status: string;
  path: string;
  displayPath?: string;
  kind?: string;
  sizeBytes?: number;
};

export type EventPreview = {
  eventId?: string | null;
  kind?: string | null;
  name?: string | null;
  status?: string | null;
  summary: string;
};

export type ReportModel = {
  schemaVersion?: string;
  id: string;
  title: string;
  description: string;
  executiveSummary?: string;
  verdict: Verdict;
  riskLevel: RiskLevel;
  dataSource: "real_run" | "curated_fixture" | "unknown" | string;
  sourceRunId: string;
  reason: string;
  securityConclusion?: string;
  metrics: {
    runtimeEvents: number;
    fridaEvents: number;
    artifacts: number;
  };
  pipeline: PipelineStage[];
  riskChain: RiskChainNode[];
  findings: Finding[];
  recommendations: string[];
  artifacts: Artifact[];
  previews?: {
    runtime?: EventPreview[];
    frida?: EventPreview[];
  };
};

export type ShowcaseIndexEntry = {
  id: string;
  title: string;
  description?: string;
  runDir?: string;
  decision?: string;
  riskLevel?: string;
  fridaStatus?: string;
  fridaEventCount?: number;
  codeTracerStatus?: string;
  evidenceEventCount?: number;
  finalJudgmentPath?: string;
  viewerUrl?: string;
};

export type ShowcaseSummary = ShowcaseIndexEntry & {
  report?: ReportModel;
};
