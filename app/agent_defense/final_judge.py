# Post-run offline analysis.  This module produces the final_judgment.json
# artifact from merged traces + online decisions + CodeTracer diagnosis.  It
# has zero dependencies on app.security and could be moved to a dedicated
# app/post_run/ package in a future refactoring round.

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.common.trace_common import normalize_path, now_utc_iso, read_json, write_json, write_runs_index

from .trace_merge import read_jsonl


FINAL_SCHEMA = "transpect.agent-defense.final-judgment.v1"
CRITICAL_FRIDA_TAGS = {
    "upload_candidate",
    "no_user_consent",
    "sensitive_file_access",
    "credential_file_candidate",
    "non_browser_network_bypass",
    "exfiltration_candidate",
}


def _online_decision(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "security-reasoning" / "defense_decision.json", default=None)
    return payload if isinstance(payload, dict) else {}


def _diagnosis(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json", default=None)
    return payload if isinstance(payload, dict) else {}


def _task_metadata(run_dir: Path) -> dict[str, Any]:
    for relative in (
        Path("artifacts") / "task_repo" / "source_task.json",
        Path("task_input.json"),
    ):
        payload = read_json(run_dir / relative, default=None)
        if isinstance(payload, dict):
            return payload
    return {}


def _trace_index(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "trace_index.json", default=None)
    return payload if isinstance(payload, dict) else {}


def _interventions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        status = str(row.get("status") or "")
        name = str(row.get("name") or "")
        kind = str(row.get("kind") or "")
        if status in {"block", "blocked", "require_confirmation"} or name == "security_intervention" or kind == "security":
            output.append(row)
    return output


def _frida_risk(rows: list[dict[str, Any]]) -> tuple[bool, list[str], list[dict[str, Any]]]:
    tags: list[str] = []
    evidence: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("source") or row.get("traceSource") or "") != "frida":
            continue
        row_tags = [str(tag) for tag in (row.get("riskTags") or row.get("risk_tags") or [])]
        tags.extend(row_tags)
        if set(row_tags).intersection(CRITICAL_FRIDA_TAGS):
            evidence.append(row)
    return bool(evidence), sorted(set(tags)), evidence


def run_final_judgment(run_dir: Path | str) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    merged_rows = read_jsonl(resolved / "merged-trace.jsonl")
    if not merged_rows:
        merged_rows = read_jsonl(resolved / "behavior-events.jsonl")
    frida_rows = read_jsonl(resolved / "frida-events.jsonl")
    if frida_rows and not any(str(row.get("source") or "") == "frida" for row in merged_rows):
        merged_rows.extend({"source": "frida", "riskTags": row.get("risk_tags") or [], **row} for row in frida_rows)

    online = _online_decision(resolved)
    diagnosis = _diagnosis(resolved)
    index = _trace_index(resolved)
    task = _task_metadata(resolved)
    interventions = _interventions(merged_rows)
    frida_critical, frida_tags, frida_evidence = _frida_risk(merged_rows)
    bypass_detected = any(
        "bypass" in str(row.get("name") or "").lower()
        or "bypass" in " ".join(str(tag).lower() for tag in (row.get("riskTags") or row.get("risk_tags") or []))
        or "bypass" in str(row.get("preview") or "").lower()
        for row in merged_rows
    )

    online_decision = str(online.get("decision") or "")
    if bypass_detected:
        final_decision = "block"
        risk_level = "critical"
        reasons = ["Bypass escalation evidence was found in the merged trace."]
    elif frida_critical:
        final_decision = "block"
        risk_level = "critical"
        reasons = ["Frida runtime evidence observed sensitive or unauthorized behavior."]
    elif online_decision == "block" or any(str(row.get("status") or "") in {"block", "blocked"} for row in interventions):
        final_decision = "block"
        risk_level = "critical"
        reasons = ["Online Agent Defense blocked a high-risk action."]
    elif online_decision == "require_confirmation" or any(str(row.get("status") or "") == "require_confirmation" for row in interventions):
        final_decision = "require_confirmation"
        risk_level = "high"
        reasons = ["Online Agent Defense required confirmation before a sensitive action."]
    elif online_decision == "warn" or interventions:
        final_decision = "warn"
        risk_level = "medium"
        reasons = ["Trace contains warning-level Agent Defense evidence."]
    else:
        final_decision = "allow"
        risk_level = "low"
        reasons = ["No blocking Agent Defense evidence found in merged trace."]

    diagnosis_sources = diagnosis.get("inputTraceSources") if isinstance(diagnosis.get("inputTraceSources"), list) else []
    frida_included = bool(frida_rows) or bool(diagnosis.get("fridaIncluded"))
    code_tracer_included = bool(diagnosis)
    judgment = {
        "schemaVersion": FINAL_SCHEMA,
        "generatedAt": now_utc_iso(),
        "runId": resolved.name,
        "finalDecision": final_decision,
        "riskLevel": risk_level,
        "reasons": reasons,
        "task": task,
        "evidence": {
            "traceIndexPath": normalize_path((resolved / "trace_index.json").resolve()) if (resolved / "trace_index.json").exists() else None,
            "mergedTracePath": normalize_path((resolved / "merged-trace.jsonl").resolve()) if (resolved / "merged-trace.jsonl").exists() else None,
            "onlineDecision": online_decision or None,
            "securityInterventionCount": len(interventions),
            "fridaIncluded": frida_included,
            "fridaRiskTags": frida_tags,
            "fridaCriticalEvidenceCount": len(frida_evidence),
            "bypassDetected": bypass_detected,
            "codeTracerIncluded": code_tracer_included,
            "codeTracerOk": diagnosis.get("ok"),
            "inputTraceSources": diagnosis_sources,
            "traceSources": (index.get("sources") if isinstance(index, dict) else None),
        },
        "diagnosis": {
            "path": normalize_path((resolved / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json").resolve())
            if diagnosis
            else None,
            "summary": (diagnosis.get("analysis") or {}).get("summary") if isinstance(diagnosis.get("analysis"), dict) else None,
            "fridaIncluded": bool(diagnosis.get("fridaIncluded")),
        },
    }
    output_path = resolved / "security-reasoning" / "final_judgment.json"
    write_json(output_path, judgment)

    manifest_path = resolved / "manifest.json"
    manifest = read_json(manifest_path, default={}) or {}
    if isinstance(manifest, dict):
        manifest.setdefault("securityReasoning", {})["finalJudgment"] = {
            "decision": final_decision,
            "riskLevel": risk_level,
            "path": "security-reasoning/final_judgment.json",
            "generatedAt": judgment["generatedAt"],
        }
        manifest.setdefault("paths", {})["finalJudgment"] = "security-reasoning/final_judgment.json"
        write_json(manifest_path, manifest)
    write_runs_index(resolved.parent)
    return judgment
