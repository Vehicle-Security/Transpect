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
        return "LLM_CALL" if "llm" in name else "AGENT_TURN"
    if source_key == "tool" or "tool" in name:
        return "TOOL_CALL"
    if source_key == "plugin_hooks" and ("before_tool_call" in name or "after_tool_call" in name or "tool_result" in name):
        return "TOOL_CALL"
    if source_key == "lifecycle":
        return "AGENT_TURN"
    return "AGENT_TURN"


def normalize_native_jsonl(run_dir: Path, root_span_id: str, source_key: str, relative: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    path = run_dir / relative
    rows = read_jsonl(path)
    spans: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        event_id = row_event_id(row, fallback=f"{source_key}-{index}")
        name = str(row.get("name") or row.get("event") or row.get("type") or source_key)
        span_id = stable_id("span", run_dir.name, "openclaw_native", source_key, event_id, index)
        span = make_span(
            span_id=span_id,
            parent_span_id=root_span_id,
            kind=native_kind(source_key, row),
            name=name,
            source="openclaw_stream",
            start_time=event_time(row),
            end_time=row.get("endTime") or row.get("completedAt"),
            status=row.get("status") or "ok",
            attributes={
                "stream": source_key,
                "eventId": event_id,
                "payload": row.get("payload") if isinstance(row.get("payload"), dict) else None,
            },
            artifact_refs=[artifact_ref(run_dir, path)],
            source_confidence="high",
        )
        spans.append(span)
        events.append(make_event(event_id=event_id, span_id=span_id, name=name, source="openclaw_stream", timestamp=event_time(row), attributes={"stream": source_key}))
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
