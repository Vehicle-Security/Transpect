from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import WORKSPACE_ROOT, normalize_path, read_json, write_json  # noqa: E402
from freeze_showcase_run import DEFAULT_SHOWCASE_ROOT, SHOWCASE_SCHEMA, normalize_status  # noqa: E402


REPORT_SCHEMA = "transpect.showcase.report-model.v1"
VALID_DECISIONS = {"block", "require_confirmation", "allow", "warn", "unknown"}
VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "unknown"}


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def read_jsonl_preview(path: Path, *, limit: int = 8) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if len(rows) >= limit:
                break
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def compact_text(value: Any, *, limit: int = 180) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def event_summary(row: dict[str, Any]) -> str:
    name = str(row.get("name") or "").lower()
    status = str(row.get("status") or "").lower()
    if "openclaw.agent.turn" in name and status == "error":
        return "Agent turn stopped after a security intervention or runtime error."
    if "web_fetch" in name:
        return "Agent attempted to fetch external content for the task."
    preview = row.get("preview") if isinstance(row.get("preview"), dict) else {}
    if preview.get("reason"):
        return compact_text(preview["reason"])
    if preview.get("url"):
        return compact_text(f"{row.get('name') or row.get('kind') or 'event'} -> {preview['url']}")
    if preview.get("prompt"):
        return compact_text(preview["prompt"])
    if preview.get("summary"):
        return compact_text(preview["summary"])
    target = row.get("target") if isinstance(row.get("target"), dict) else {}
    if target.get("url"):
        return compact_text(f"{row.get('name') or row.get('kind') or 'event'} -> {target['url']}")
    return compact_text(row.get("name") or row.get("kind") or row.get("eventId") or "Runtime event")


def product_event_name(row: dict[str, Any]) -> str:
    name = str(row.get("name") or "").lower()
    kind = str(row.get("kind") or row.get("type") or "").lower()
    status = str(row.get("status") or "").lower()
    preview = row.get("preview") if isinstance(row.get("preview"), dict) else {}
    reason = str(preview.get("reason") or "").lower()
    if "low_trust_comment" in name:
        return "Low-trust Trigger"
    if "security_intervention" in name or "security.decision" in name:
        if status in {"require_confirmation", "requires_confirmation", "confirm"}:
            return "User Confirmation Required"
        return "Runtime Decision"
    if "security.action" in name:
        return "Sensitive Action Evidence" if ("file" in reason or "upload" in reason) else "Action Safety Review"
    upload_or_file_signal = "upload" in name or "file_access" in name or "file access" in reason or "file_read" in name
    positive_upload_reason = "upload" in reason and "without sensitive upload evidence" not in reason
    if upload_or_file_signal or positive_upload_reason:
        return "Sensitive Action Evidence"
    if name == "openclaw.request":
        return "Runtime Request"
    if "security.plan" in name:
        return "External Link Inspection"
    if "policy" in name or "policy" in reason or status in {"warn", "warning"}:
        return "Policy Warning"
    if "security" in name or kind == "security":
        return "Agent Defense event"
    if "web_fetch" in name:
        return "External content fetch"
    if "browser" in name or kind == "browser":
        return "Browser action"
    if "tool" in name or kind == "tool":
        return "Tool call"
    if "network" in name or kind == "network":
        return "Network activity"
    if "frida" in name or kind == "frida":
        return "Frida runtime evidence"
    if "openclaw.agent.turn" in name:
        return "Agent Execution Interrupted" if status in {"error", "failed", "blocked", "block"} else "Agent Execution Result"
    if name.startswith("openclaw."):
        return "Agent runtime event"
    return str(row.get("name") or row.get("operation") or row.get("eventType") or "Runtime event")


def is_key_event(row: dict[str, Any]) -> bool:
    name = str(row.get("name") or "").lower()
    kind = str(row.get("kind") or row.get("type") or "").lower()
    status = str(row.get("status") or "").lower()
    preview = row.get("preview") if isinstance(row.get("preview"), dict) else {}
    if name == "openclaw.request" or (kind == "turn" and status == "started"):
        return False
    if status in {"warn", "blocked", "block", "failed", "error"}:
        return True
    if kind in {"security", "tool", "network", "command", "browser", "frida"}:
        return True
    if preview.get("url") or preview.get("reason"):
        return True
    return False


def summarize_event_preview(path: Path, *, limit: int = 8) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    rows = read_jsonl_preview(path, limit=80)
    key_rows = [row for row in rows if is_key_event(row)] or rows
    for row in key_rows[:limit]:
        summaries.append(
            {
                "eventId": row.get("eventId") or row.get("id"),
                "kind": row.get("kind") or row.get("type"),
                "name": product_event_name(row),
                "status": row.get("status") or row.get("level"),
                "summary": event_summary(row),
            }
        )
    return summaries


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return normalize_path(resolved.relative_to(WORKSPACE_ROOT)) or str(resolved)
    except ValueError:
        return normalize_path(resolved) or str(resolved)


def resolve_run_dir(showcase_root: Path, value: Any) -> Path:
    text = str(value or "").strip()
    if not text:
        return showcase_root / "__missing__"
    candidate = Path(text).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    workspace_candidate = (WORKSPACE_ROOT / candidate).resolve()
    if workspace_candidate.exists():
        return workspace_candidate
    return (showcase_root / candidate).resolve()


def normalize_decision(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in VALID_DECISIONS else "unknown"


def normalize_risk(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in VALID_RISK_LEVELS else "unknown"


def evidence(final_judgment: dict[str, Any]) -> dict[str, Any]:
    payload = final_judgment.get("evidence")
    return payload if isinstance(payload, dict) else {}


def first_reason(final_judgment: dict[str, Any]) -> str:
    reasons = final_judgment.get("reasons")
    if isinstance(reasons, list) and reasons:
        return str(reasons[0])
    return str(final_judgment.get("reason") or "")


def trace_sources(trace_index: dict[str, Any]) -> dict[str, Any]:
    sources = trace_index.get("sources")
    return sources if isinstance(sources, dict) else {}


def source_status(trace_index: dict[str, Any], key: str, default: str = "unavailable") -> str:
    source = trace_sources(trace_index).get(key)
    if isinstance(source, dict):
        return normalize_status(source.get("status"), default=default)
    return default


def source_count(trace_index: dict[str, Any], key: str) -> int:
    source = trace_sources(trace_index).get(key)
    if isinstance(source, dict):
        try:
            return int(source.get("eventCount") or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def runtime_event_count(run_dir: Path, trace_index: dict[str, Any]) -> int:
    return (
        source_count(trace_index, "behavior")
        or count_jsonl(run_dir / "merged-trace.jsonl")
        or count_jsonl(run_dir / "behavior-events.jsonl")
    )


def frida_status(final_judgment: dict[str, Any], trace_index: dict[str, Any]) -> str:
    frida = evidence(final_judgment).get("frida")
    if isinstance(frida, dict) and frida.get("status"):
        return normalize_status(frida.get("status"), default="unavailable")
    return source_status(trace_index, "frida")


def frida_event_count(run_dir: Path, final_judgment: dict[str, Any], trace_index: dict[str, Any]) -> int:
    frida = evidence(final_judgment).get("frida")
    if isinstance(frida, dict):
        try:
            return int(frida.get("eventCount") or 0)
        except (TypeError, ValueError):
            pass
    return source_count(trace_index, "frida") or count_jsonl(run_dir / "frida-events.jsonl")


def codetracer_status(run_dir: Path, final_judgment: dict[str, Any], diagnosis_report: dict[str, Any]) -> str:
    code = evidence(final_judgment).get("codeTracer")
    if isinstance(code, dict) and code.get("status"):
        return normalize_status(code.get("status"), default="unavailable")
    if isinstance(diagnosis_report, dict) and diagnosis_report:
        return "ok" if diagnosis_report.get("ok") is not False else normalize_status(diagnosis_report.get("status"), default="degraded")
    if (run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json").exists():
        return "ok"
    return "unavailable"


def data_source(run_dir: Path, manifest: dict[str, Any]) -> str:
    generated_by = str(manifest.get("generatedBy") or "").lower()
    if "fixture" in generated_by or "demo" in generated_by:
        return "curated_fixture"
    if (
        (run_dir / "artifacts" / "task_repo").exists()
        or manifest.get("taskRepo")
        or manifest.get("taskId")
        or manifest.get("runId")
    ):
        return "real_run"
    return "unknown"


def artifact_status(path: Path) -> str:
    return "available" if path.exists() else "unavailable"


def artifact_source(relative: str) -> str:
    if relative.startswith("diagnosis/codetracer"):
        return "CodeTracer"
    if relative.startswith("security-reasoning"):
        return "Agent Defense"
    if relative.startswith("frida"):
        return "Frida"
    if "trace" in relative or relative.startswith("behavior"):
        return "Runtime"
    return "Run"


def build_artifacts(run_dir: Path) -> list[dict[str, Any]]:
    relatives = [
        "manifest.json",
        "task_input.json",
        "security-reasoning/final_judgment.json",
        "security-reasoning/security_state.json",
        "security-reasoning/defense_decision.json",
        "security-reasoning/evidence_summary.json",
        "trace_index.json",
        "canonical_trace.json",
        "trace_quality.json",
        "behavior-events.jsonl",
        "merged-trace.jsonl",
        "frida-events.jsonl",
        "diagnosis/codetracer/bundle/steps.json",
        "diagnosis/codetracer/bundle/task.md",
        "diagnosis/codetracer/bundle/manifest.json",
        "diagnosis/codetracer/bundle/openclaw_runtime.json",
        "diagnosis/codetracer/bundle/stage_ranges.json",
        "diagnosis/codetracer/analysis/diagnosis_report.json",
        "diagnosis/codetracer/analysis/codetracer_analysis.json",
        "exports/openinference_spans.json",
    ]
    artifacts: list[dict[str, Any]] = []
    for relative in relatives:
        path = run_dir / relative
        if path.exists():
            artifacts.append(
                {
                    "name": Path(relative).name,
                    "source": artifact_source(relative),
                    "status": artifact_status(path),
                    "path": relative,
                    "displayPath": display_path(path),
                    "kind": path.suffix.removeprefix(".") or "file",
                    "sizeBytes": path.stat().st_size,
                }
            )
    return artifacts


def normalize_node_label(node: dict[str, Any]) -> str:
    return str(node.get("label") or node.get("name") or node.get("eventType") or node.get("title") or "")


def normalize_node_summary(node: dict[str, Any]) -> str:
    preview = node.get("preview")
    if isinstance(preview, dict):
        for key in ["reason", "summary", "prompt", "url", "label"]:
            if preview.get(key):
                return str(preview[key])
    return str(node.get("summary") or node.get("text") or node.get("reason") or node.get("name") or "")


def product_risk_label(label: str, summary: str) -> str:
    current = label.strip()
    if current and current.lower() not in {"risk step", "risk evidence", "step"}:
        return current
    text = f"{current} {summary}".lower()
    if "bypass escalation" in text or "command-line network" in text or "non-browser" in text:
        return "Bypass Escalation"
    if "low-trust" in text or "untrusted" in text or "comment" in text:
        return "Low-trust Trigger"
    if "deceptive" in text or "detail button" in text or "详情" in text:
        return "Deceptive Detail Button"
    if "file read" in text or "file access" in text:
        return "File Access Review"
    if "upload" in text or "sensitive" in text:
        return "Sensitive Upload Attempt"
    if "not covered by deterministic" in text or "command is not covered" in text:
        return "Runtime Decision"
    if "external navigation" in text or "external link" in text or "open_external_link" in text or "navigat" in text:
        return "External Navigation"
    if "blocked" in text or "decision" in text or "final judgment" in text:
        return "Runtime Decision"
    return "Risk Evidence"


def chain_from_nodes(nodes: list[Any], *, source: str) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for index, node in enumerate(nodes, start=1):
        if not isinstance(node, dict):
            continue
        summary = normalize_node_summary(node)
        raw_label = normalize_node_label(node)
        output.append(
            {
                "id": str(node.get("id") or node.get("eventId") or f"{source}-{index}"),
                "label": product_risk_label(raw_label, summary),
                "summary": summary,
                "source": source,
                "eventId": node.get("eventId") or node.get("id"),
                "relatedEvents": [str(node.get("eventId") or node.get("id"))] if node.get("eventId") or node.get("id") else [],
                "evidenceCount": 1,
                "evidenceSource": evidence_source_for_node(product_risk_label(raw_label, summary), summary),
                "status": node.get("status"),
            }
        )
    return output


def evidence_source_for_node(label: str, summary: str) -> str:
    text = f"{label} {summary}".lower()
    if "frida" in text or "low-level" in text:
        return "Frida"
    if "codetracer" in text or "diagnosis" in text:
        return "CodeTracer"
    if "blocked" in text or "decision" in text or "low-trust" in text or "agent defense" in text:
        return "Agent Defense"
    if "final judgment" in text or "critical risk" in text:
        return "Final Judgment"
    return "Runtime Trace"


def compress_risk_chain(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compressed: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for node in nodes:
        key = (str(node.get("label") or "Risk Evidence"), str(node.get("source") or "observed"))
        existing = by_key.get(key)
        related = [str(item) for item in node.get("relatedEvents", []) if item]
        event_id = node.get("eventId")
        if event_id and str(event_id) not in related:
            related.append(str(event_id))
        if existing is None:
            node["evidenceCount"] = max(1, int(node.get("evidenceCount") or 1))
            node["relatedEvents"] = related
            if not node.get("evidenceSource"):
                node["evidenceSource"] = evidence_source_for_node(str(node.get("label") or ""), str(node.get("summary") or ""))
            by_key[key] = node
            compressed.append(node)
            continue
        existing["evidenceCount"] = int(existing.get("evidenceCount") or 1) + max(1, int(node.get("evidenceCount") or 1))
        merged = list(existing.get("relatedEvents") or [])
        for item in related:
            if item not in merged:
                merged.append(item)
        existing["relatedEvents"] = merged
        if node.get("summary") and node.get("summary") != existing.get("summary") and "Additional related evidence" not in str(existing.get("summary")):
            existing["summary"] = f"{existing.get('summary')} Additional related evidence is available in the audit artifacts."
    return compressed


def build_risk_chain(final_judgment: dict[str, Any], security_state: dict[str, Any]) -> list[dict[str, Any]]:
    chain = final_judgment.get("riskChain")
    if isinstance(chain, dict) and isinstance(chain.get("nodes"), list) and chain.get("nodes"):
        return compress_risk_chain(chain_from_nodes(chain["nodes"], source="observed"))
    for key in ["causalTriggerChain", "riskTimeline"]:
        rows = security_state.get(key)
        if isinstance(rows, list) and rows:
            return compress_risk_chain(chain_from_nodes(rows, source="observed"))
    task = final_judgment.get("task") if isinstance(final_judgment.get("task"), dict) else {}
    stages = task.get("stages")
    if isinstance(stages, list) and stages:
        return compress_risk_chain(chain_from_nodes(stages, source="scenario"))
    return []


def pipeline_status_for_decision(verdict: str) -> str:
    if verdict == "block":
        return "blocked"
    if verdict == "require_confirmation":
        return "requires_confirmation"
    if verdict == "allow":
        return "allowed"
    return "unknown"


def defense_outcome(verdict: str) -> str:
    if verdict == "block":
        return "blocked"
    if verdict == "require_confirmation":
        return "requires_confirmation"
    if verdict == "allow":
        return "allowed"
    return "none"


def frida_outcome(status: str, event_count: int, summary: str) -> str:
    text = summary.lower()
    if "attach" in text and status == "degraded":
        return "attach_failed"
    if event_count:
        return "evidence_found"
    if status == "degraded":
        return "attach_failed"
    if status == "failed":
        return "failed"
    return "none"


def codetracer_outcome(status: str) -> str:
    if status in {"ok", "available"}:
        return "diagnosis_ready"
    if status in {"degraded", "failed"}:
        return status
    return "none"


def final_outcome(risk_level: str) -> str:
    if risk_level == "critical":
        return "critical_risk"
    if risk_level == "high":
        return "high_risk"
    if risk_level == "medium":
        return "medium_risk"
    if risk_level == "low":
        return "low_risk"
    return "none"


def build_pipeline(
    *,
    run_dir: Path,
    final_judgment: dict[str, Any],
    trace_index: dict[str, Any],
    diagnosis_report: dict[str, Any],
    verdict: str,
    risk_level: str,
    reason: str,
) -> list[dict[str, Any]]:
    runtime_count = runtime_event_count(run_dir, trace_index)
    frida = evidence(final_judgment).get("frida")
    code = evidence(final_judgment).get("codeTracer")
    f_status = frida_status(final_judgment, trace_index)
    f_count = frida_event_count(run_dir, final_judgment, trace_index)
    c_status = codetracer_status(run_dir, final_judgment, diagnosis_report)
    code_summary = ""
    if isinstance(code, dict):
        code_summary = str(code.get("summary") or "")
    if not code_summary and isinstance(diagnosis_report.get("analysis"), dict):
        code_summary = str(diagnosis_report["analysis"].get("summary") or "")
    if not code_summary:
        code_summary = "CodeTracer diagnosis unavailable." if c_status == "unavailable" else "CodeTracer diagnosis ready."
    frida_summary = str(frida.get("summary") or frida.get("degradedReason") or f"Frida status is {f_status}.") if isinstance(frida, dict) else f"Frida status is {f_status}."
    return [
        {
            "key": "runtime",
            "label": "Runtime Trace",
            "status": "ok" if runtime_count else "unavailable",
            "outcome": "events_captured" if runtime_count else "none",
            "summary": f"{runtime_count} runtime events captured." if runtime_count else "No runtime events available.",
            "count": runtime_count,
        },
        {
            "key": "defense",
            "label": "Agent Defense",
            "status": "ok" if verdict in {"block", "require_confirmation", "allow"} else "unavailable",
            "outcome": defense_outcome(verdict),
            "summary": reason or "Agent Defense decision unavailable.",
        },
        {
            "key": "frida",
            "label": "Frida OS Evidence",
            "status": f_status,
            "outcome": frida_outcome(f_status, f_count, frida_summary),
            "summary": frida_summary,
            "count": f_count,
        },
        {
            "key": "codetracer",
            "label": "CodeTracer Diagnosis",
            "status": c_status,
            "outcome": codetracer_outcome(c_status),
            "summary": code_summary,
        },
        {
            "key": "judgment",
            "label": "Final Judgment",
            "status": "ok" if risk_level != "unknown" else "unavailable",
            "outcome": final_outcome(risk_level),
            "summary": reason or f"Final decision: {verdict}.",
        },
    ]


def executive_summary(entry: dict[str, Any], *, verdict: str, risk_level: str) -> str:
    showcase_id = str(entry.get("id") or "")
    if verdict == "block" and "low_level" in showcase_id:
        return "浏览器层轨迹之外出现 OS 级低层行为证据，Transpect 将其纳入最终安全判断。"
    if verdict == "block" or risk_level == "critical":
        return "Agent 被低可信评论诱导跳转至外部页面，并在敏感上传前被 Transpect 阻断。"
    if verdict == "require_confirmation":
        return "系统发现外部跳转风险，但缺少敏感上传证据，因此要求用户确认。"
    if verdict == "allow":
        return "未发现跨步骤攻击链，系统允许任务继续执行。"
    return str(entry.get("description") or "Frozen showcase report is ready for review.")


def security_conclusion(*, verdict: str, risk_level: str) -> str:
    if verdict == "block" or risk_level == "critical":
        return "Transpect correlated runtime behavior, Agent Defense decisions, and diagnostic evidence, then identified a cross-step risk chain from low-trust content to a sensitive upload attempt."
    if verdict == "require_confirmation":
        return "Transpect identified a suspicious cross-step chain but did not observe enough sensitive-action evidence to block automatically, so the workflow requires user confirmation."
    if verdict == "allow":
        return "Transpect observed normal browsing behavior and did not identify a cross-step attack chain or sensitive action requiring intervention."
    return "Transpect generated a frozen security report; review the evidence artifacts before using this case in a product demonstration."


def finding(severity: str, source: str, title: str, summary: str, *, artifact: str | None = None, event_id: str | None = None) -> dict[str, Any]:
    payload = {
        "severity": severity,
        "source": source,
        "title": title,
        "summary": summary,
    }
    if artifact:
        payload["artifact"] = artifact
    if event_id:
        payload["eventId"] = event_id
    return payload


def build_findings(final_judgment: dict[str, Any], *, verdict: str, risk_level: str, pipeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    reason = first_reason(final_judgment) or f"Final decision is {verdict}."
    if verdict == "block" or risk_level == "critical":
        rows.append(finding("critical", "Final Judgment", "Critical workflow blocked", reason, artifact="security-reasoning/final_judgment.json"))
    elif verdict == "require_confirmation":
        rows.append(finding("warning", "Agent Defense", "User confirmation required", reason, artifact="security-reasoning/defense_decision.json"))
    elif verdict == "allow":
        rows.append(finding("info", "Final Judgment", "Workflow allowed", reason or "No cross-step risk chain detected.", artifact="security-reasoning/final_judgment.json"))
    ev = evidence(final_judgment)
    if ev.get("bypassDetected"):
        rows.append(finding("critical", "Runtime Trace", "Bypass escalation detected", "Merged trace contains bypass escalation evidence.", artifact="merged-trace.jsonl"))
    frida = ev.get("frida") if isinstance(ev.get("frida"), dict) else {}
    f_status = next((item["status"] for item in pipeline if item.get("key") == "frida"), "unavailable")
    if f_status in {"degraded", "unavailable"}:
        rows.append(
            finding(
                "info",
                "Frida",
                "Frida evidence capability degraded",
                str(frida.get("degradedReason") or frida.get("summary") or f"Frida status is {f_status}."),
                artifact="frida-events.jsonl",
            )
        )
    try:
        critical_frida = int(ev.get("fridaCriticalEvidenceCount") or frida.get("criticalEvidenceCount") or 0)
    except (TypeError, ValueError):
        critical_frida = 0
    if critical_frida > 0:
        rows.append(finding("critical", "Frida", "Low-level runtime evidence observed", f"{critical_frida} high-risk Frida evidence item(s) correlated with the workflow.", artifact="frida-events.jsonl"))
    code = ev.get("codeTracer") if isinstance(ev.get("codeTracer"), dict) else {}
    c_status = next((item["status"] for item in pipeline if item.get("key") == "codetracer"), "unavailable")
    if c_status in {"ok", "available"}:
        rows.append(finding("info", "CodeTracer", "CodeTracer diagnosis available", str(code.get("summary") or "Diagnosis bundle and analysis are linked to the final judgment."), artifact="diagnosis/codetracer/analysis/diagnosis_report.json"))
    return rows


def build_recommendations(*, verdict: str, pipeline: list[dict[str, Any]]) -> list[str]:
    recommendations: list[str] = []
    if verdict == "block":
        recommendations.append("Stop the workflow before any sensitive action and require the user to verify the external page, destination, and data boundary.")
    elif verdict == "require_confirmation":
        recommendations.append("Ask the user to confirm the external navigation or action before continuing the agent workflow.")
    elif verdict == "allow":
        recommendations.append("Continue monitoring; no cross-step risk chain was detected for this frozen run.")
    else:
        recommendations.append("Review the final judgment and evidence artifacts before using this run in a product demo.")
    statuses = {str(item.get("key")): str(item.get("status")) for item in pipeline}
    if statuses.get("frida") in {"degraded", "unavailable"}:
        recommendations.append("Repair local Frida permissions/tooling before a live production demo; the degraded state is recorded for audit transparency.")
    if statuses.get("codetracer") in {"degraded", "unavailable", "failed"}:
        recommendations.append("Regenerate CodeTracer diagnosis before using this run for audit-focused demonstrations.")
    return recommendations


def load_canonical_trace(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "canonical_trace.json", default={})
    if isinstance(payload, dict) and payload.get("schemaVersion") == "transpect.canonical_trace.v1":
        return payload
    return {}


def canonical_quality(run_dir: Path, canonical_trace: dict[str, Any]) -> dict[str, Any]:
    if not canonical_trace:
        return {
            "traceDepth": "unknown",
            "score": 0.0,
            "coverage": {},
            "gaps": ["canonical_trace.json unavailable"],
        }
    try:
        from tools.validate.evaluate_trace_quality import evaluate_trace_quality

        return evaluate_trace_quality(run_dir)
    except Exception as error:  # noqa: BLE001
        return {
            "traceDepth": "unknown",
            "score": 0.0,
            "coverage": {},
            "gaps": [f"trace quality evaluation failed: {error}"],
        }


def canonical_metrics(run_dir: Path, canonical_trace: dict[str, Any], quality: dict[str, Any]) -> dict[str, Any]:
    spans = canonical_trace.get("spans") if isinstance(canonical_trace.get("spans"), list) else []
    events = canonical_trace.get("events") if isinstance(canonical_trace.get("events"), list) else []
    trace_backbone = trace_backbone_summary(run_dir, canonical_trace, quality)
    return {
        "canonicalSpans": len(spans),
        "canonicalEvents": len(events),
        "traceQuality": quality.get("traceDepth") or "unknown",
        "traceQualityScore": quality.get("score") or 0.0,
        "coverage": quality.get("coverage") if isinstance(quality.get("coverage"), dict) else {},
        "exportAvailable": trace_backbone["exportAvailable"],
        "primarySpanCount": trace_backbone["primarySpanCount"],
        "evidenceSpanCount": trace_backbone["evidenceSpanCount"],
        "rawSpanCount": trace_backbone["rawSpanCount"],
    }


def trace_backbone_summary(run_dir: Path, canonical_trace: dict[str, Any], quality: dict[str, Any]) -> dict[str, Any]:
    if not canonical_trace:
        fallback_available = (run_dir / "merged-trace.jsonl").exists() or (run_dir / "behavior-events.jsonl").exists()
        return {
            "status": "fallback" if fallback_available else "unavailable",
            "traceDepth": quality.get("traceDepth") or "unknown",
            "spanCount": 0,
            "primarySpanCount": 0,
            "evidenceSpanCount": 0,
            "rawSpanCount": 0,
            "exportAvailable": False,
            "missingSources": ["canonical_trace.json"],
            "warnings": list(quality.get("gaps") or ["canonical_trace.json unavailable"]),
        }
    spans = canonical_trace.get("spans") if isinstance(canonical_trace.get("spans"), list) else []
    tier_counts = {"primary": 0, "evidence": 0, "raw": 0}
    for span in spans:
        if not isinstance(span, dict):
            continue
        default_tier = "primary" if span.get("kind") in {"AGENT_RUN", "AGENT_TURN", "TOOL_CALL", "BROWSER_ACTION", "AGENT_DEFENSE", "FINAL_JUDGMENT"} else "evidence"
        tier = str(span.get("displayTier") or default_tier)
        if tier not in tier_counts:
            tier = "evidence"
        tier_counts[tier] += 1
    coverage = quality.get("coverage") if isinstance(quality.get("coverage"), dict) else {}
    missing_sources: list[str] = []
    for key, value in coverage.items():
        if value:
            continue
        if key == "browser" and coverage.get("tool"):
            continue
        if key == "tool" and coverage.get("browser"):
            continue
        missing_sources.append(key)
    return {
        "status": "available",
        "traceDepth": quality.get("traceDepth") or "unknown",
        "spanCount": len(spans),
        "primarySpanCount": tier_counts["primary"],
        "evidenceSpanCount": tier_counts["evidence"],
        "rawSpanCount": tier_counts["raw"],
        "exportAvailable": (run_dir / "exports" / "openinference_spans.json").exists(),
        "missingSources": missing_sources,
        "warnings": list(quality.get("gaps") or []),
    }


def build_report_model(showcase_root: Path, entry: dict[str, Any]) -> dict[str, Any]:
    run_dir = resolve_run_dir(showcase_root, entry.get("runDir"))
    final_judgment = read_json(run_dir / "security-reasoning" / "final_judgment.json", default={})
    final_judgment = final_judgment if isinstance(final_judgment, dict) else {}
    security_state = read_json(run_dir / "security-reasoning" / "security_state.json", default={})
    security_state = security_state if isinstance(security_state, dict) else {}
    trace_index = read_json(run_dir / "trace_index.json", default={})
    trace_index = trace_index if isinstance(trace_index, dict) else {}
    manifest = read_json(run_dir / "manifest.json", default={})
    manifest = manifest if isinstance(manifest, dict) else {}
    diagnosis_report = read_json(run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json", default={})
    diagnosis_report = diagnosis_report if isinstance(diagnosis_report, dict) else {}
    canonical_trace = load_canonical_trace(run_dir)
    quality = canonical_quality(run_dir, canonical_trace)
    verdict = normalize_decision(final_judgment.get("finalDecision") or final_judgment.get("decision") or entry.get("decision"))
    risk_level = normalize_risk(final_judgment.get("riskLevel") or final_judgment.get("risk_level") or entry.get("riskLevel"))
    reason = first_reason(final_judgment)
    source_run_id = str(final_judgment.get("runId") or manifest.get("runId") or entry.get("id") or "unknown")
    artifacts = build_artifacts(run_dir)
    pipeline = build_pipeline(
        run_dir=run_dir,
        final_judgment=final_judgment,
        trace_index=trace_index,
        diagnosis_report=diagnosis_report,
        verdict=verdict,
        risk_level=risk_level,
        reason=reason,
    )
    return {
        "schemaVersion": REPORT_SCHEMA,
        "id": str(entry.get("id") or run_dir.name),
        "title": str(entry.get("title") or final_judgment.get("title") or run_dir.name),
        "description": str(entry.get("description") or ""),
        "executiveSummary": executive_summary(entry, verdict=verdict, risk_level=risk_level),
        "verdict": verdict,
        "riskLevel": risk_level,
        "dataSource": data_source(run_dir, manifest),
        "sourceRunId": source_run_id,
        "reason": reason,
        "securityConclusion": security_conclusion(verdict=verdict, risk_level=risk_level),
        "metrics": {
            "runtimeEvents": runtime_event_count(run_dir, trace_index),
            "fridaEvents": frida_event_count(run_dir, final_judgment, trace_index),
            "artifacts": len(artifacts),
            **canonical_metrics(run_dir, canonical_trace, quality),
        },
        "traceBackbone": {
            **trace_backbone_summary(run_dir, canonical_trace, quality),
            "path": "canonical_trace.json" if canonical_trace else None,
            "eventCount": len(canonical_trace.get("events") or []) if canonical_trace else 0,
            "quality": quality,
        },
        "pipeline": pipeline,
        "riskChain": build_risk_chain(final_judgment, security_state),
        "findings": build_findings(final_judgment, verdict=verdict, risk_level=risk_level, pipeline=pipeline),
        "recommendations": build_recommendations(verdict=verdict, pipeline=pipeline),
        "artifacts": artifacts,
        "previews": {
            "runtime": summarize_event_preview(run_dir / "merged-trace.jsonl") or summarize_event_preview(run_dir / "behavior-events.jsonl"),
            "frida": summarize_event_preview(run_dir / "frida-events.jsonl"),
        },
    }


def load_showcase_index(showcase_root: Path) -> dict[str, Any]:
    payload = read_json(showcase_root / "index.json", default={})
    return payload if isinstance(payload, dict) else {}


def build_showcase_reports(*, showcase_root: Path | str = DEFAULT_SHOWCASE_ROOT) -> dict[str, Any]:
    root = Path(showcase_root).expanduser().resolve()
    index = load_showcase_index(root)
    entries = index.get("showcases")
    if not isinstance(entries, list):
        entries = []
    reports: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        report = build_report_model(root, entry)
        run_dir = resolve_run_dir(root, entry.get("runDir"))
        write_json(run_dir / "report_model.json", report)
        reports.append({"id": report["id"], "path": display_path(run_dir / "report_model.json"), "verdict": report["verdict"], "riskLevel": report["riskLevel"]})
    return {
        "schemaVersion": SHOWCASE_SCHEMA,
        "ok": bool(entries),
        "showcaseRoot": display_path(root),
        "reportCount": len(reports),
        "reports": reports,
        "issues": [] if entries else [f"showcase index missing or empty: {display_path(root / 'index.json')}"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build front-end friendly report_model.json files for frozen showcases.")
    parser.add_argument("--showcase-root", default=str(DEFAULT_SHOWCASE_ROOT), help="Showcase root containing index.json.")
    args = parser.parse_args()
    result = build_showcase_reports(showcase_root=args.showcase_root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
