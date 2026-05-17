from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.common.trace_common import read_json

CRITICAL_FRIDA_TAGS = {
    "upload_candidate",
    "no_user_consent",
    "sensitive_file_access",
    "credential_file_candidate",
    "non_browser_network_bypass",
    "exfiltration_candidate",
}
HIGH_FRIDA_TAGS = CRITICAL_FRIDA_TAGS | {"post_request", "process_spawn", "suspicious_upload_related_file_read"}

from .schema import artifact_ref, make_artifact, make_event, make_span, normalize_status, stable_id


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def event_time(row: dict[str, Any]) -> Any:
    return row.get("ts") or row.get("timestamp") or row.get("time") or row.get("startedAt") or row.get("createdAt")


def row_event_id(row: dict[str, Any], *, fallback: str) -> str:
    return str(row.get("eventId") or row.get("event_id") or row.get("id") or row.get("spanId") or fallback)


def behavior_span_kind(row: dict[str, Any]) -> str:
    name = str(row.get("name") or row.get("event") or "").lower()
    kind = str(row.get("kind") or row.get("type") or "").lower()
    if "llm" in name or kind == "llm":
        return "LLM_CALL"
    if "security" in name or kind in {"security", "guardrail", "agent_defense"}:
        return "AGENT_DEFENSE"
    if "tool" in name or kind == "tool":
        return "TOOL_CALL"
    if "browser" in name or kind == "browser" or any(token in name for token in ["web_fetch", "goto", "click", "navigate"]):
        return "BROWSER_ACTION"
    if "turn" in name or kind == "turn":
        return "AGENT_TURN"
    if name.startswith("openclaw."):
        return "AGENT_TURN"
    return "TOOL_CALL" if kind else "AGENT_TURN"


def confidence_for_behavior(row: dict[str, Any]) -> str:
    if row.get("eventId") or row.get("id"):
        return "high"
    return "medium"


def normalize_behavior_rows(run_dir: Path, root_span_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    merged_path = run_dir / "merged-trace.jsonl"
    behavior_path = run_dir / "behavior-events.jsonl"
    source_path = merged_path if merged_path.exists() else behavior_path
    rows = read_jsonl(source_path)
    spans: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        if str(row.get("source") or row.get("traceSource") or "").lower() == "frida":
            continue
        event_id = row_event_id(row, fallback=f"behavior-{index}")
        span_id = stable_id("span", run_dir.name, "behavior", event_id, index)
        kind = behavior_span_kind(row)
        name = str(row.get("name") or row.get("operation") or row.get("kind") or kind)
        source = "openclaw_stream" if name.startswith("openclaw.stream.") else "behavior_mediator"
        attributes = {
            "eventId": event_id,
            "kind": row.get("kind"),
            "type": row.get("type"),
            "preview": row.get("preview") if isinstance(row.get("preview"), dict) else None,
            "target": row.get("target") if isinstance(row.get("target"), dict) else None,
            "riskTags": row.get("riskTags") or row.get("risk_tags") or [],
            "rawName": row.get("name"),
        }
        spans.append(
            make_span(
                span_id=span_id,
                parent_span_id=root_span_id,
                kind=kind,
                name=name,
                source=source,
                start_time=event_time(row),
                status=row.get("status") or row.get("level") or "ok",
                attributes={key: value for key, value in attributes.items() if value is not None},
                artifact_refs=[artifact_ref(run_dir, source_path)],
                source_confidence=confidence_for_behavior(row),
            )
        )
        events.append(
            make_event(
                event_id=event_id,
                span_id=span_id,
                name=name,
                source=source,
                timestamp=event_time(row),
                attributes={"status": row.get("status"), "kind": row.get("kind")},
            )
        )
    return spans, events, {
        "status": "ok" if rows else ("unavailable" if not source_path.exists() else "empty"),
        "path": artifact_ref(run_dir, source_path),
        "eventCount": len(rows),
    }


def normalize_frida_rows(run_dir: Path, root_span_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    path = run_dir / "frida-events.jsonl"
    rows = read_jsonl(path)
    spans: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    if rows:
        critical_rows: list[tuple[int, dict[str, Any], list[str]]] = []
        sensitive_file_access = 0
        network_bypass = 0
        for index, row in enumerate(rows, start=1):
            tags = [str(tag) for tag in (row.get("riskTags") or row.get("risk_tags") or [])]
            normalized_tags = {tag.lower() for tag in tags}
            event_type = str(row.get("event_type") or row.get("eventType") or row.get("name") or "").lower()
            if "sensitive_file_access" in normalized_tags or "file_access" in event_type:
                sensitive_file_access += 1
            if "non_browser_network_bypass" in normalized_tags or "network" in event_type:
                network_bypass += 1
            if normalized_tags.intersection(HIGH_FRIDA_TAGS):
                critical_rows.append((index, row, tags))

        summary_id = stable_id("span", run_dir.name, "frida", "summary")
        degraded_reason = ""
        if not critical_rows and rows:
            degraded_reason = ""
        summary_span = make_span(
            span_id=summary_id,
            parent_span_id=root_span_id,
            kind="FRIDA_EVIDENCE",
            name="Frida low-level evidence summary",
            source="frida",
            start_time=event_time(rows[0]),
            end_time=event_time(rows[-1]),
            status="ok",
            attributes={
                "totalEvents": len(rows),
                "criticalEvents": len(critical_rows),
                "sensitiveFileAccess": sensitive_file_access,
                "networkBypass": network_bypass,
                "degradedReason": degraded_reason,
                "rawRef": artifact_ref(run_dir, path),
                "sampleEventIds": [row_event_id(row, fallback=f"frida-{index}") for index, row in enumerate(rows[:10], start=1)],
            },
            artifact_refs=[artifact_ref(run_dir, path)],
            source_confidence="high",
            display_tier="evidence",
            importance="high" if critical_rows else "medium",
        )
        spans.append(summary_span)
        events.append(
            make_event(
                event_id=stable_id("event", summary_id),
                span_id=summary_id,
                name="Frida evidence summary",
                source="frida",
                timestamp=event_time(rows[0]),
                attributes={"totalEvents": len(rows), "criticalEvents": len(critical_rows)},
            )
        )
        rows_to_emit = critical_rows
    else:
        rows_to_emit = []
    for index, row, tags in rows_to_emit:
        event_id = row_event_id(row, fallback=f"frida-{index}")
        span_id = stable_id("span", run_dir.name, "frida", event_id, index)
        event_type = str(row.get("event_type") or row.get("eventType") or row.get("name") or "frida_event")
        spans.append(
            make_span(
                span_id=span_id,
                parent_span_id=root_span_id,
                kind="FRIDA_EVIDENCE",
                name=event_type,
                source="frida",
                start_time=event_time(row),
                status=row.get("status") or "ok",
                attributes={
                    "eventId": event_id,
                    "eventType": event_type,
                    "riskTags": tags,
                    "normalized": row.get("normalized") if isinstance(row.get("normalized"), dict) else None,
                    "attribution": row.get("attribution"),
                },
                artifact_refs=[artifact_ref(run_dir, path)],
                source_confidence="high" if tags else "medium",
                display_tier="evidence",
            )
        )
        events.append(
            make_event(
                event_id=event_id,
                span_id=span_id,
                name=event_type,
                source="frida",
                timestamp=event_time(row),
                attributes={"riskTags": tags},
            )
        )
    return spans, events, {
        "status": "ok" if rows else ("unavailable" if not path.exists() else "empty"),
        "path": artifact_ref(run_dir, path),
        "eventCount": len(rows),
    }


def normalize_codetracer(run_dir: Path, root_span_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    path = run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json"
    report = read_json(path, default=None)
    if not isinstance(report, dict):
        return [], [], {"status": "unavailable", "path": artifact_ref(run_dir, path), "eventCount": 0}
    ok = report.get("ok") is not False
    analysis = report.get("analysis") if isinstance(report.get("analysis"), dict) else {}
    summary = analysis.get("summary") or report.get("summary") or "CodeTracer diagnosis ready."
    span_id = stable_id("span", run_dir.name, "codetracer", path)
    span = make_span(
        span_id=span_id,
        parent_span_id=root_span_id,
        kind="CODETRACER_DIAGNOSIS",
        name="CodeTracer diagnosis",
        source="codetracer",
        status="ok" if ok else normalize_status(report.get("status"), default="degraded"),
        attributes={
            "summary": summary,
            "ok": ok,
            "inputTraceSources": report.get("inputTraceSources") or [],
            "invalidAnalysisReason": ((report.get("diagnosisRun") or {}).get("invalidAnalysisReason") if isinstance(report.get("diagnosisRun"), dict) else None),
        },
        artifact_refs=[artifact_ref(run_dir, path)],
        source_confidence="high",
    )
    return [span], [make_event(event_id=stable_id("event", span_id), span_id=span_id, name="CodeTracer diagnosis ready", source="codetracer", attributes={"summary": summary})], {
        "status": "ok" if ok else "degraded",
        "path": artifact_ref(run_dir, path),
        "eventCount": 1,
    }


def normalize_final_judgment(run_dir: Path, root_span_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    path = run_dir / "security-reasoning" / "final_judgment.json"
    judgment = read_json(path, default=None)
    if not isinstance(judgment, dict):
        return [], [], {"status": "unavailable", "path": artifact_ref(run_dir, path), "eventCount": 0}
    decision = str(judgment.get("finalDecision") or judgment.get("decision") or "unknown")
    risk_level = str(judgment.get("riskLevel") or judgment.get("risk_level") or "unknown")
    span_id = stable_id("span", run_dir.name, "final_judgment")
    span = make_span(
        span_id=span_id,
        parent_span_id=root_span_id,
        kind="FINAL_JUDGMENT",
        name=f"Final judgment: {decision}",
        source="final_judgment",
        start_time=judgment.get("generatedAt"),
        status="blocked" if decision == "block" else "ok",
        attributes={
            "decision": decision,
            "riskLevel": risk_level,
            "reasons": judgment.get("reasons") or ([judgment.get("reason")] if judgment.get("reason") else []),
            "evidence": judgment.get("evidence") if isinstance(judgment.get("evidence"), dict) else {},
        },
        artifact_refs=[artifact_ref(run_dir, path)],
        source_confidence="high",
    )
    return [span], [make_event(event_id=stable_id("event", span_id), span_id=span_id, name="Final judgment", source="final_judgment", timestamp=judgment.get("generatedAt"), attributes={"decision": decision, "riskLevel": risk_level})], {
        "status": "ok",
        "path": artifact_ref(run_dir, path),
        "eventCount": 1,
    }


def collect_artifacts(run_dir: Path) -> list[dict[str, Any]]:
    relatives = [
        ("manifest.json", "manifest"),
        ("task_input.json", "runtime"),
        ("behavior-events.jsonl", "behavior_mediator"),
        ("merged-trace.jsonl", "behavior_mediator"),
        ("frida-events.jsonl", "frida"),
        ("trace_index.json", "behavior_mediator"),
        ("security-reasoning/final_judgment.json", "final_judgment"),
        ("security-reasoning/security_state.json", "agent_defense"),
        ("security-reasoning/defense_decision.json", "agent_defense"),
        ("diagnosis/codetracer/analysis/diagnosis_report.json", "codetracer"),
        ("diagnosis/codetracer/analysis/codetracer_analysis.json", "codetracer"),
        ("diagnosis/codetracer/bundle/steps.json", "codetracer"),
        ("diagnosis/codetracer/bundle/task.md", "codetracer"),
        ("diagnosis/codetracer/bundle/stage_ranges.json", "codetracer"),
        ("diagnosis/codetracer/bundle/manifest.json", "codetracer"),
        ("diagnosis/codetracer/bundle/openclaw_runtime.json", "codetracer"),
        ("exports/openinference_spans.json", "openinference"),
    ]
    artifacts: list[dict[str, Any]] = []
    for relative, source in relatives:
        artifact = make_artifact(run_dir, relative, source=source)
        if artifact:
            artifacts.append(artifact)
    return artifacts
