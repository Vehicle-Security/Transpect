from __future__ import annotations

from pathlib import Path
from typing import Any

from app.trace_model.normalizers import event_time, read_jsonl, row_event_id
from app.trace_model.schema import artifact_ref, make_event, make_span, stable_id
from scripts.common.trace_common import read_json

from .schema import OPENCLAW_NATIVE_SOURCES


def native_kind(source_key: str, row: dict[str, Any]) -> str:
    name = str(row.get("name") or row.get("event") or row.get("type") or "").lower()
    if source_key == "assistant":
        return "LLM_CALL" if "llm" in name or source_key == "assistant" else "AGENT_TURN"
    if source_key == "tool" or "tool" in name or source_key == "plugin_hooks" and "tool" in name:
        return "TOOL_CALL"
    if source_key == "lifecycle":
        return "AGENT_TURN"
    return "AGENT_TURN"


def native_span_name(source_key: str, row: dict[str, Any]) -> str:
    event = str(row.get("event") or row.get("hook") or row.get("name") or row.get("type") or "").lower()
    if source_key == "lifecycle":
        if event in {"message_received", "request_started"}:
            return "openclaw.request"
        if event in {"before_agent_start", "agent_start", "agent_end"}:
            return "openclaw.agent.turn"
        if event == "request_completed":
            return "openclaw.request"
        return f"openclaw.lifecycle.{event or 'event'}"
    if source_key == "assistant":
        model = row.get("model") or ((row.get("target") or {}).get("model") if isinstance(row.get("target"), dict) else None)
        return f"llm.{model or 'call'}"
    if source_key == "tool":
        tool_name = row.get("toolName") or ((row.get("target") or {}).get("toolName") if isinstance(row.get("target"), dict) else None)
        return f"tool.{tool_name or 'unknown'}"
    if source_key == "plugin_hooks":
        return f"openclaw.hook.{row.get('hook') or event or 'event'}"
    return source_key.replace("_", " ")


def native_span_id(run_dir: Path, source_key: str, row: dict[str, Any], index: int) -> str:
    if source_key == "plugin_hooks":
        return stable_id("span", run_dir.name, "openclaw_native", source_key, row_event_id(row, fallback=f"{source_key}-{index}"), index)
    explicit = row.get("spanId") or row.get("span_id")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    grouping = row.get("toolCallId") or row.get("llmCallId") or row.get("event") or row.get("hook") or index
    return stable_id("span", run_dir.name, "openclaw_native", source_key, grouping)


def native_parent_span_id(root_span_id: str, row: dict[str, Any]) -> str:
    explicit = row.get("parentSpanId") or row.get("parent_span_id")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    return root_span_id


def normalize_native_jsonl(run_dir: Path, root_span_id: str, source_key: str, relative: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    path = run_dir / relative
    rows = read_jsonl(path)
    span_builders: dict[str, dict[str, Any]] = {}
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        event_id = row_event_id(row, fallback=f"{source_key}-{index}")
        span_id = native_span_id(run_dir, source_key, row, index)
        name = native_span_name(source_key, row)
        timestamp = event_time(row)
        builder = span_builders.setdefault(
            span_id,
            {
                "spanId": span_id,
                "parentSpanId": native_parent_span_id(root_span_id, row),
                "kind": native_kind(source_key, row),
                "name": name,
                "startTime": timestamp,
                "endTime": row.get("endTime") or row.get("completedAt") or timestamp,
                "status": row.get("status") or "ok",
                "eventIds": [],
                "attributes": {
                    "stream": source_key,
                    "toolCallId": row.get("toolCallId"),
                    "llmCallId": row.get("llmCallId"),
                    "toolName": row.get("toolName"),
                    "model": row.get("model"),
                    "agentId": row.get("agentId"),
                },
            },
        )
        builder["eventIds"].append(event_id)
        if timestamp and (not builder.get("startTime") or str(timestamp) < str(builder["startTime"])):
            builder["startTime"] = timestamp
        end_time = row.get("endTime") or row.get("completedAt") or timestamp
        if end_time and (not builder.get("endTime") or str(end_time) > str(builder["endTime"])):
            builder["endTime"] = end_time
        if str(row.get("status") or "").lower() in {"error", "failed", "blocked"}:
            builder["status"] = row.get("status")
        events.append(make_event(event_id=event_id, span_id=span_id, name=name, source="openclaw_stream", timestamp=event_time(row), attributes={"stream": source_key}))
    spans = [
        make_span(
            span_id=str(builder["spanId"]),
            parent_span_id=str(builder["parentSpanId"]),
            kind=str(builder["kind"]),
            name=str(builder["name"]),
            source="openclaw_stream",
            start_time=builder.get("startTime"),
            end_time=builder.get("endTime"),
            status=builder.get("status") or "ok",
            attributes={key: value for key, value in {**builder.get("attributes", {}), "eventIds": builder.get("eventIds", [])}.items() if value is not None},
            artifact_refs=[artifact_ref(run_dir, path)],
            source_confidence="high",
            display_tier="raw" if source_key == "plugin_hooks" else None,
            importance="debug" if source_key == "plugin_hooks" else None,
        )
        for builder in span_builders.values()
    ]
    return spans, events, {"status": "ok" if rows else ("unavailable" if not path.exists() else "empty"), "path": artifact_ref(run_dir, path), "eventCount": len(rows)}


def normalize_native_json(run_dir: Path, root_span_id: str, source_key: str, relative: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    path = run_dir / relative
    payload = read_json(path, default=None)
    if not isinstance(payload, dict):
        return [], [], {"status": "unavailable", "path": artifact_ref(run_dir, path), "eventCount": 0}
    span_id = stable_id("span", run_dir.name, "openclaw_native", source_key)
    span = make_span(
        span_id=span_id,
        parent_span_id=root_span_id,
        kind="AGENT_TURN",
        name=source_key.replace("_", " "),
        source="openclaw_stream",
        status=payload.get("status") or "ok",
        attributes={"stream": source_key, "payload": payload},
        artifact_refs=[artifact_ref(run_dir, path)],
        source_confidence="high",
    )
    return [span], [make_event(event_id=stable_id("event", span_id), span_id=span_id, name=span["name"], source="openclaw_stream", attributes={"stream": source_key})], {
        "status": "ok",
        "path": artifact_ref(run_dir, path),
        "eventCount": 1,
    }


def normalize_openclaw_native_sources(run_dir: Path, root_span_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    source_details: dict[str, Any] = {}
    for key, relative in OPENCLAW_NATIVE_SOURCES.items():
        if relative.endswith(".jsonl"):
            next_spans, next_events, detail = normalize_native_jsonl(run_dir, root_span_id, key, relative)
        else:
            next_spans, next_events, detail = normalize_native_json(run_dir, root_span_id, key, relative)
        spans.extend(next_spans)
        events.extend(next_events)
        source_details[key] = detail
    available = sum(1 for detail in source_details.values() if detail.get("status") == "ok")
    aggregate = {
        "status": "ok" if available else "unavailable",
        "eventCount": sum(int(detail.get("eventCount") or 0) for detail in source_details.values()),
        "streams": source_details,
    }
    return spans, events, aggregate
