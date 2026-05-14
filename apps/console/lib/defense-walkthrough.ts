import type { EventPreview, ReportModel, RiskChainNode } from "./report-model";
import { labelize } from "./format";

export type DetectionStatus = "context" | "suspicious" | "critical" | "blocked";

export type DetectionStep = {
  id: string;
  title: string;
  status: DetectionStatus;
  evidenceSource: string;
  evidenceCount: number;
  summary: string;
  artifactPath: string;
};

export type DefenseWalkthrough = {
  reportId: string;
  title: string;
  verdict: string;
  riskLevel: string;
  steps: DetectionStep[];
  problematicSteps: DetectionStep[];
  decision: {
    title: string;
    riskLabel: string;
    summary: string;
    reasoning: string[];
    chips: string[];
  };
};

export function buildDefenseWalkthrough(report: ReportModel): DefenseWalkthrough {
  const chainSteps = report.riskChain.map((node, index) => stepFromRiskChain(node, index));
  const previewSteps = importantPreviewSteps(report.previews?.runtime || [], chainSteps.length);
  const observedSteps = compactSteps([...chainSteps, ...previewSteps]);
  const finalStep = finalDecisionStep(report, observedSteps.length);
  const steps = buildCrossStepFlow(report, observedSteps, finalStep);
  const problematicSteps = steps.filter((step) => step.status === "suspicious" || step.status === "critical" || step.status === "blocked");
  const decision = buildDecision(report, problematicSteps);
  return {
    reportId: report.id,
    title: report.title,
    verdict: report.verdict,
    riskLevel: report.riskLevel,
    steps,
    problematicSteps,
    decision
  };
}

function buildCrossStepFlow(report: ReportModel, observedSteps: DetectionStep[], finalStep: DetectionStep): DetectionStep[] {
  const usedStepIds = new Set<string>();
  const lowTrust = firstMatching(observedSteps, ["low-trust", "comment", "injection"], usedStepIds);
  if (lowTrust) usedStepIds.add(lowTrust.id);
  const navigation = firstMatching(observedSteps, ["external navigation", "url navigation", "external link", "open_external_link", "external content fetch"], usedStepIds);
  if (navigation) usedStepIds.add(navigation.id);
  const runtimeEvidence =
    firstMatching(observedSteps, ["low level", "low-level", "frida", "sensitive action", "file_access", "network", "upload", "probe"], usedStepIds) ||
    fridaTelemetryStep(report, observedSteps.length);
  if (runtimeEvidence) usedStepIds.add(runtimeEvidence.id);
  const enforcement = firstMatching(observedSteps, ["runtime block", "blocked", "require_confirmation", "confirmation", "interrupted", "intervention"], usedStepIds);
  const flow: DetectionStep[] = [];

  if (lowTrust) {
    flow.push({
      ...lowTrust,
      title: "Low-Trust Injection",
      status: severityMax(lowTrust.status, "suspicious"),
      summary: "评论区低可信内容引入外链，试图把 Agent 从“阅读并总结”任务引向外部页面。"
    });
  }

  if (navigation) {
    flow.push({
      ...navigation,
      title: "Scope-Expanding Navigation",
      status: severityMax(navigation.status, "suspicious"),
      summary: "Agent 跟随低可信外链，进入用户未明确授权的外部页面或工具页。"
    });
  }

  if (runtimeEvidence) {
    flow.push({
      ...runtimeEvidence,
      title: runtimeEvidence.evidenceSource === "Frida" ? "Low-level Runtime Evidence" : "Runtime Evidence",
      summary: runtimeEvidenceSummary(report, runtimeEvidence)
    });
  }

  if (enforcement) {
    flow.push({
      ...enforcement,
      title: "Runtime Enforcement",
      status: report.verdict === "allow" ? severityMax(enforcement.status, "context") : severityMax(enforcement.status, "blocked"),
      evidenceSource: enforcement.evidenceSource === "Runtime Trace" ? "Agent Defense" : enforcement.evidenceSource,
      artifactPath: "security-reasoning/defense_decision.json",
      summary: "Agent Defense 将前序低可信诱导链与运行时证据关联，在越界动作继续执行前拦截或要求确认。"
    });
  }

  flow.push({
    ...finalStep,
    title: "Audit Judgment",
    summary: auditJudgmentSummary(report)
  });

  return compactSteps(flow.length > 1 ? flow : [finalStep]);
}

function stepFromRiskChain(node: RiskChainNode, index: number): DetectionStep {
  const text = `${node.label} ${node.summary || ""}`.toLowerCase();
  return {
    id: node.id || `risk-${index + 1}`,
    title: productTitle(node.label),
    status: statusFromText(text, node.status),
    evidenceSource: node.evidenceSource || "Runtime Trace",
    evidenceCount: node.evidenceCount || Math.max(1, node.relatedEvents?.length || 1),
    summary: node.summary || "Evidence observed in the canonical risk chain.",
    artifactPath: artifactPathForSource(node.evidenceSource || "Runtime Trace", node.label)
  };
}

function importantPreviewSteps(rows: EventPreview[], offset: number): DetectionStep[] {
  const output: DetectionStep[] = [];
  rows.forEach((row, index) => {
    const text = `${row.kind || ""} ${row.name || ""} ${row.status || ""} ${row.summary}`.toLowerCase();
    const shouldInclude =
      text.includes("blocked") ||
      text.includes("require_confirmation") ||
      text.includes("confirmation") ||
      text.includes("sensitive") ||
      text.includes("file_access") ||
      text.includes("bypass") ||
      text.includes("intervention");
    if (!shouldInclude) return;
    output.push({
      id: row.eventId || `preview-${offset + index + 1}`,
      title: productTitle(row.name || row.kind || "Runtime Evidence"),
      status: statusFromText(text, row.status),
      evidenceSource: sourceFromPreview(row),
      evidenceCount: 1,
      summary: row.summary,
      artifactPath: artifactPathForSource(sourceFromPreview(row), row.name || row.kind || "")
    });
  });
  return output;
}

function finalDecisionStep(report: ReportModel, index: number): DetectionStep {
  const judgment = report.pipeline.find((stage) => stage.key === "judgment");
  return {
    id: `final-decision-${index + 1}`,
    title: "Final Decision",
    status: report.verdict === "allow" ? "context" : "blocked",
    evidenceSource: "Final Judgment",
    evidenceCount: 1,
    summary: judgment?.summary || report.securityConclusion || report.reason || `${labelize(report.verdict)} / ${labelize(report.riskLevel)}`,
    artifactPath: "security-reasoning/final_judgment.json"
  };
}

function buildDecision(report: ReportModel, problematicSteps: DetectionStep[]) {
  const judgment = report.pipeline.find((stage) => stage.key === "judgment");
  const criticalFindings = report.findings.filter((finding) => finding.severity === "critical" || finding.source === "Final Judgment");
  const reasoning = uniqueStrings([
    "用户原始授权边界是浏览和总结，不包含未授权外部页面交互或敏感资源外发。",
    problematicSteps.some((step) => step.title === "Low-Trust Injection" || step.title === "Scope-Expanding Navigation")
      ? "Trace 显示低可信内容改变了 Agent 的后续操作路径。"
      : "",
    problematicSteps.some((step) => step.title === "Runtime Enforcement") ? "防御引擎在运行时关联上下文并阻断越界动作。" : "",
    ...criticalFindings.map((finding) => finding.summary),
    judgment?.summary,
    ...problematicSteps.slice(0, 4).map((step) => step.summary)
  ]).slice(0, 4);
  const chips = uniqueStrings([
    ...problematicSteps.slice(0, 3).map((step) => `${step.title}: ${step.evidenceSource}`),
    report.metrics.fridaEvents > 0 ? `Frida events: ${report.metrics.fridaEvents}` : "",
    report.traceBackbone?.traceDepth ? `Trace depth: ${report.traceBackbone.traceDepth}` : ""
  ]).slice(0, 4);
  return {
    title: report.verdict === "allow" ? "Allow workflow" : "Reject sensitive action",
    riskLabel: labelize(report.riskLevel),
    summary: judgment?.summary || report.securityConclusion || report.reason || "Final judgment recorded.",
    reasoning,
    chips
  };
}

function compactSteps(steps: DetectionStep[]) {
  const output: DetectionStep[] = [];
  const seen = new Set<string>();
  for (const step of steps) {
    const key = `${step.title}|${step.evidenceSource}|${step.summary}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(step);
  }
  return output.slice(0, 6);
}

function statusFromText(text: string, explicit?: string | null): DetectionStatus {
  const combined = `${text} ${explicit || ""}`.toLowerCase();
  if (combined.includes("blocked") || combined.includes("block") || combined.includes("reject")) return "blocked";
  if (combined.includes("critical") || combined.includes("bypass") || combined.includes("sensitive") || combined.includes("file_access")) return "critical";
  if (combined.includes("low-trust") || combined.includes("external") || combined.includes("navigation") || combined.includes("confirmation") || combined.includes("warn")) {
    return "suspicious";
  }
  return "context";
}

function sourceFromPreview(row: EventPreview) {
  const kind = String(row.kind || "").toLowerCase();
  const name = String(row.name || "").toLowerCase();
  if (kind.includes("frida") || name.includes("frida")) return "Frida";
  if (kind.includes("security") || name.includes("defense") || name.includes("confirmation")) return "Agent Defense";
  if (kind.includes("tool")) return "OpenClaw Hook";
  return "Runtime Trace";
}

function productTitle(value: string) {
  const normalized = String(value || "").trim();
  const lowered = normalized.toLowerCase();
  if (lowered.includes("external navigation")) return "URL Navigation";
  if (lowered.includes("low-trust")) return "Low-trust Trigger";
  if (lowered.includes("bypass")) return "Bypass Escalation";
  if (lowered.includes("sensitive action") || lowered.includes("file_access")) return "Sensitive Action Evidence";
  if (lowered.includes("runtime decision")) return "Runtime Decision";
  if (lowered.includes("user confirmation")) return "User Confirmation Required";
  if (lowered.includes("external content fetch")) return "External Content Fetch";
  if (lowered.includes("risk evidence")) return "Risk Evidence";
  return normalized || "Runtime Evidence";
}

function firstMatching(steps: DetectionStep[], needles: string[], excludeIds = new Set<string>()) {
  return steps.find((step) => {
    if (excludeIds.has(step.id)) return false;
    const text = `${step.title} ${step.summary} ${step.evidenceSource}`.toLowerCase();
    return needles.some((needle) => text.includes(needle));
  });
}

function fridaTelemetryStep(report: ReportModel, index: number): DetectionStep | null {
  const fridaStage = report.pipeline.find((stage) => stage.key === "frida");
  if (!fridaStage || report.metrics.fridaEvents <= 0) return null;
  return {
    id: `frida-telemetry-${index + 1}`,
    title: "Low-level Runtime Evidence",
    status: fridaStage.outcome === "evidence_found" ? "context" : statusFromText(`${fridaStage.status} ${fridaStage.outcome || ""} ${fridaStage.summary}`),
    evidenceSource: "Frida",
    evidenceCount: report.metrics.fridaEvents,
    summary: fridaStage.summary,
    artifactPath: "frida-events.jsonl"
  };
}

function runtimeEvidenceSummary(report: ReportModel, step: DetectionStep) {
  const text = `${step.title} ${step.summary}`.toLowerCase();
  if (text.includes("file") || text.includes("network") || text.includes("upload") || text.includes("sensitive") || text.includes("probe")) {
    return "Frida 或运行时 trace 捕获到文件、网络或上传相关底层行为，说明风险不只停留在页面点击层面。";
  }
  if (step.evidenceSource === "Frida") {
    return `Frida 记录到 ${report.metrics.fridaEvents} 条 OS 级运行时事件；该步骤作为底层可观测证据参与审计。`;
  }
  return "运行时 trace 捕获到与风险链相关的证据步骤，供防御引擎进行跨步关联。";
}

function auditJudgmentSummary(report: ReportModel) {
  if (report.verdict === "allow") {
    return "最终审计确认：未发现跨步攻击链，任务可继续执行。";
  }
  if (report.verdict === "require_confirmation") {
    return "最终审计确认：该行为超出原始任务授权边界，需要用户确认后才能继续。";
  }
  return "最终审计确认：该行为属于低可信内容诱导下的未授权敏感资源外发风险。";
}

function severityMax(current: DetectionStatus, minimum: DetectionStatus): DetectionStatus {
  const rank: Record<DetectionStatus, number> = {
    context: 0,
    suspicious: 1,
    critical: 2,
    blocked: 3
  };
  return rank[current] >= rank[minimum] ? current : minimum;
}

function artifactPathForSource(source: string, label: string) {
  const text = `${source} ${label}`.toLowerCase();
  if (text.includes("frida")) return "frida-events.jsonl";
  if (text.includes("final")) return "security-reasoning/final_judgment.json";
  if (text.includes("agent defense") || text.includes("confirmation") || text.includes("enforcement")) return "security-reasoning/defense_decision.json";
  if (text.includes("runtime") || text.includes("openclaw") || text.includes("trace")) return "canonical_trace.json";
  return "security-reasoning/final_judgment.json";
}

function uniqueStrings(values: Array<string | undefined | null>) {
  const output: string[] = [];
  const seen = new Set<string>();
  values.forEach((value) => {
    const text = String(value || "").trim();
    if (!text || seen.has(text)) return;
    seen.add(text);
    output.push(text);
  });
  return output;
}
