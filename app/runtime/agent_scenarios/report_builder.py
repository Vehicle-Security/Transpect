from __future__ import annotations

from collections import Counter
from typing import Any

from app.runtime.agent_scenarios.openclaw_client import AgentRunResult
from app.runtime.agent_scenarios.schema import AgentScenario
from app.runtime.agent_scenarios.trace_collector import TraceBundle
from app.security.browser_event_normalizer import BrowserEvent
from app.security.security_chain_analyzer import ChainDecision


def summarize_tools(events: list[BrowserEvent]) -> dict[str, int]:
    counts = Counter(event.tool_name.replace(".", "_") for event in events if event.tool_name)
    return {
        "browser_open": counts.get("browser_open", 0) + counts.get("browser_navigate", 0),
        "browser_snapshot": counts.get("browser_snapshot", 0),
        "browser_click": counts.get("browser_click", 0),
        "browser_type": counts.get("browser_type", 0),
        "browser_upload": counts.get("browser_upload", 0),
        "browser_download": counts.get("browser_download", 0),
    }


def _frida_events_summary(frida_events: list[dict[str, Any]]) -> dict[str, int]:
    """Aggregate frida event counts by category."""
    summary: dict[str, int] = {
        "network_events": 0,
        "command_events": 0,
        "file_access_events": 0,
        "upload_candidates": 0,
        "sensitive_file_access": 0,
    }
    for event in frida_events:
        event_type = event.get("event_type", "")
        tags = event.get("risk_tags") or []
        if event_type == "network_event":
            summary["network_events"] += 1
        if event_type == "command_execution_event":
            summary["command_events"] += 1
        if event_type == "file_access_event":
            summary["file_access_events"] += 1
        if "upload_candidate" in tags or "no_user_consent" in tags:
            summary["upload_candidates"] += 1
        if "sensitive_file_access" in tags or "credential_file_candidate" in tags:
            summary["sensitive_file_access"] += 1
    return summary


def _build_frida_trace_section(
    *,
    frida_config: Any | None,
    frida_start_result: Any | None,
    frida_stop_result: Any | None,
    event_count_total: int,
    event_count_in_window: int,
    event_count_used_by_analyzer: int,
) -> dict[str, Any]:
    """Build the ``frida_trace`` section for report.json."""
    if frida_config is None or not getattr(frida_config, "enabled", False):
        return {
            "enabled": False,
            "package_available": False,
            "attach_ready": False,
            "available": False,
            "targets": [],
            "event_count_total": 0,
            "event_count_in_window": 0,
            "event_count_used_by_analyzer": 0,
            "path": None,
            "warnings": [],
            "frida_resolution": None,
        }

    targets = []
    warnings: list[str] = []
    available = True
    package_available = False
    attach_ready = False
    frida_resolution = None

    if frida_start_result is not None:
        start_dict = frida_start_result if isinstance(frida_start_result, dict) else frida_start_result.to_dict()
        available = start_dict.get("ok", False)
        frida_resolution = start_dict.get("resolution")
        if frida_resolution:
            package_available = frida_resolution.get("package_available", False)
            attach_ready = frida_resolution.get("attach_ready", False)
        for t in start_dict.get("targets", []):
            if isinstance(t, dict):
                td = t
            else:
                td = t.to_dict() if hasattr(t, "to_dict") else vars(t)
            if td.get("role") == "chrome_browser":
                td["experimental"] = True
            targets.append(td)
        warnings.extend(start_dict.get("warnings", []))

    if frida_stop_result is not None:
        stop_dict = frida_stop_result if isinstance(frida_stop_result, dict) else frida_stop_result.to_dict()
        warnings.extend(stop_dict.get("warnings", []))

    return {
        "enabled": True,
        "package_available": package_available,
        "attach_ready": attach_ready,
        "available": available,
        "targets": targets,
        "event_count_total": event_count_total,
        "event_count_in_window": event_count_in_window,
        "event_count_used_by_analyzer": event_count_used_by_analyzer,
        "path": getattr(frida_config, "output", None),
        "warnings": warnings,
        "frida_resolution": frida_resolution,
    }


def build_trace_bundle_payload(trace_bundle: TraceBundle, browser_events: list[BrowserEvent], openclaw_resolution: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = trace_bundle.to_dict()
    payload["browser_events"] = [event.to_dict() for event in browser_events]
    payload["tool_call_summary"] = summarize_tools(browser_events)
    payload["openclaw_resolution"] = openclaw_resolution
    return payload


def build_report(
    scenario: AgentScenario,
    trace_bundle: TraceBundle,
    browser_events: list[BrowserEvent],
    decision: ChainDecision,
    *,
    agent_result: AgentRunResult | None,
    started_at: str | None = None,
    ended_at: str | None = None,
    frida_start_result: Any | None = None,
    frida_stop_result: Any | None = None,
    frida_events: list[dict[str, Any]] | None = None,
    frida_event_count_total: int = 0,
    frida_config: Any | None = None,
    timeline_path: str | None = None,
    openclaw_resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    warnings = list(trace_bundle.warnings)
    if decision.evidence_quality.get("status") == "insufficient":
        warnings.append("insufficient evidence / no browser tool calls observed")

    frida_events = frida_events or []

    report: dict[str, Any] = {
        "scenario_id": scenario.id,
        "run_id": trace_bundle.run_id or (agent_result.run_id if agent_result else None),
        "mode": scenario.mode,
        "user_prompt": scenario.user_prompt,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": trace_bundle.status,
        "final_answer": trace_bundle.final_answer,
        "tool_call_summary": summarize_tools(browser_events),
        "browser_events": [event.to_dict() for event in browser_events],
        "security_decision": decision.to_dict(),
        "evidence_quality": decision.evidence_quality,
        "trace_source": trace_bundle.trace_source,
        "missing_artifacts": trace_bundle.missing_artifacts,
        "warnings": warnings,
        "artifacts": {
            "trace_bundle": None,
            "raw_behavior_events": f"{trace_bundle.run_dir}/behavior-events.jsonl" if trace_bundle.run_dir else None,
            "media": sorted({path for event in browser_events for path in event.media_paths}),
            "sidecars": sorted(trace_bundle.sidecars.keys()),
            "timeline": timeline_path,
        },
        "agent_result": agent_result.to_dict() if agent_result else None,
        "openclaw_resolution": openclaw_resolution,
    }

    # ---- Frida trace sections ----
    report["frida_trace"] = _build_frida_trace_section(
        frida_config=frida_config,
        frida_start_result=frida_start_result,
        frida_stop_result=frida_stop_result,
        event_count_total=frida_event_count_total,
        event_count_in_window=len(frida_events),
        event_count_used_by_analyzer=len(frida_events),  # We use all windowed events for analysis
    )
    report["frida_events_summary"] = _frida_events_summary(frida_events)
    report["runtime_evidence"] = decision.runtime_evidence
    report["trace_confidence"] = decision.trace_confidence

    return report
