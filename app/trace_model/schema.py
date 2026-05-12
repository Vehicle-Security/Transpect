from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from scripts.common.trace_common import normalize_path


CANONICAL_TRACE_SCHEMA = "transpect.canonical_trace.v1"

SPAN_KINDS = {
    "AGENT_RUN",
    "AGENT_TURN",
    "LLM_CALL",
    "TOOL_CALL",
    "BROWSER_ACTION",
    "AGENT_DEFENSE",
    "FRIDA_EVIDENCE",
    "CODETRACER_DIAGNOSIS",
    "FINAL_JUDGMENT",
    "ARTIFACT",
}

SPAN_STATUSES = {"ok", "error", "blocked", "degraded", "unavailable"}
DISPLAY_TIERS = {"primary", "evidence", "raw"}
IMPORTANCE_LEVELS = {"critical", "high", "medium", "low", "debug"}


def stable_id(prefix: str, *parts: Any) -> str:
    joined = "|".join(str(part) for part in parts if part is not None)
    digest = hashlib.sha1(joined.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def normalize_status(value: Any, *, default: str = "ok") -> str:
    text = str(value or default).strip().lower()
    if text in {"block", "blocked", "security_intervened"}:
        return "blocked"
    if text in {"fail", "failed", "failure", "error"}:
        return "error"
    if text in {"degraded", "attach_failed", "disabled", "empty", "timeout"}:
        return "degraded"
    if text in {"missing", "unknown", "unavailable", "pending"}:
        return "unavailable"
    if text in {"ok", "success", "completed", "allow", "allowed", "warn", "warning", "require_confirmation", "requires_confirmation"}:
        return "ok"
    return default if default in SPAN_STATUSES else "ok"


def default_display_tier(kind: str) -> str:
    if kind in {"AGENT_RUN", "AGENT_TURN", "LLM_CALL", "TOOL_CALL", "BROWSER_ACTION", "AGENT_DEFENSE", "FINAL_JUDGMENT"}:
        return "primary"
    if kind in {"FRIDA_EVIDENCE", "CODETRACER_DIAGNOSIS"}:
        return "evidence"
    return "raw"


def infer_importance(kind: str, status: Any, attributes: dict[str, Any] | None) -> str:
    attrs = attributes or {}
    tags = {str(tag).lower() for tag in (attrs.get("riskTags") or attrs.get("risk_tags") or [])}
    if normalize_status(status) == "blocked":
        return "critical"
    decision = str(attrs.get("decision") or "").lower()
    risk_level = str(attrs.get("riskLevel") or attrs.get("risk_level") or "").lower()
    if decision == "block" or risk_level == "critical":
        return "critical"
    if decision == "require_confirmation" or risk_level == "high":
        return "high"
    if tags.intersection({"sensitive_file_access", "credential_file_candidate", "non_browser_network_bypass", "exfiltration_candidate", "upload_candidate", "no_user_consent"}):
        return "critical"
    if tags:
        return "high"
    if kind in {"AGENT_RUN", "AGENT_TURN", "TOOL_CALL", "BROWSER_ACTION", "AGENT_DEFENSE", "FINAL_JUDGMENT"}:
        return "medium"
    if kind == "CODETRACER_DIAGNOSIS" and attrs.get("ok") is not False:
        return "medium"
    if kind == "ARTIFACT":
        return "debug"
    return "low"


def normalize_display_tier(value: Any, kind: str) -> str:
    text = str(value or "").strip().lower()
    return text if text in DISPLAY_TIERS else default_display_tier(kind)


def normalize_importance(value: Any, kind: str, status: Any, attributes: dict[str, Any] | None) -> str:
    text = str(value or "").strip().lower()
    return text if text in IMPORTANCE_LEVELS else infer_importance(kind, status, attributes)


def artifact_ref(run_dir: Path, path: Path) -> str:
    try:
        return normalize_path(path.resolve().relative_to(run_dir.resolve())) or path.name
    except ValueError:
        return normalize_path(path.resolve()) or str(path)


def make_span(
    *,
    span_id: str,
    parent_span_id: str | None,
    kind: str,
    name: str,
    source: str,
    start_time: Any = None,
    end_time: Any = None,
    status: Any = "ok",
    attributes: dict[str, Any] | None = None,
    artifact_refs: list[str] | None = None,
    source_confidence: str = "medium",
    display_tier: str | None = None,
    importance: str | None = None,
) -> dict[str, Any]:
    normalized_kind = kind if kind in SPAN_KINDS else "ARTIFACT"
    normalized_attrs = attributes or {}
    normalized_status = normalize_status(status)
    return {
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "kind": normalized_kind,
        "name": str(name or normalized_kind),
        "source": source,
        "sourceConfidence": source_confidence,
        "startTime": start_time,
        "endTime": end_time or start_time,
        "status": normalized_status,
        "displayTier": normalize_display_tier(display_tier, normalized_kind),
        "importance": normalize_importance(importance, normalized_kind, normalized_status, normalized_attrs),
        "attributes": normalized_attrs,
        "artifactRefs": artifact_refs or [],
    }


def make_event(
    *,
    event_id: str,
    span_id: str | None,
    name: str,
    source: str,
    timestamp: Any = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "eventId": event_id,
        "spanId": span_id,
        "name": str(name or event_id),
        "source": source,
        "timestamp": timestamp,
        "attributes": attributes or {},
    }


def make_artifact(run_dir: Path, relative: str, *, source: str) -> dict[str, Any] | None:
    path = run_dir / relative
    if not path.exists():
        return None
    return {
        "artifactId": stable_id("artifact", run_dir.name, relative),
        "path": relative,
        "source": source,
        "kind": path.suffix.removeprefix(".") or "file",
        "sizeBytes": path.stat().st_size,
    }
