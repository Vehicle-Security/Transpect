from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.runtime.openclaw_trace_ingest import ingest_openclaw_native_trace
from scripts.common.trace_common import normalize_path, now_utc_iso, read_json, write_json, write_runs_index

from app.trace_model.normalizers import (
    collect_artifacts,
    normalize_behavior_rows,
    normalize_codetracer,
    normalize_final_judgment,
    normalize_frida_rows,
)
from app.trace_model.schema import CANONICAL_TRACE_SCHEMA, make_span, stable_id


def _manifest(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "manifest.json", default={})
    return payload if isinstance(payload, dict) else {}


def _root_status(manifest: dict[str, Any]) -> str:
    status = str(manifest.get("status") or "").lower()
    if status in {"failed", "error"}:
        return "error"
    if status in {"security_intervened", "blocked"}:
        return "blocked"
    if status in {"timeout", "timeout_with_trace"}:
        return "degraded"
    return "ok"


def _source_status_from_spans(spans: list[dict[str, Any]], source: str, fallback: dict[str, Any]) -> dict[str, Any]:
    count = sum(1 for span in spans if span.get("source") == source)
    if count:
        return {"status": "ok", "eventCount": count}
    return fallback


def _security_edges(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    prior_runtime: str | None = None
    for span in spans:
        kind = span.get("kind")
        if kind in {"TOOL_CALL", "BROWSER_ACTION", "AGENT_TURN"}:
            prior_runtime = str(span.get("spanId"))
        if kind in {"AGENT_DEFENSE", "FINAL_JUDGMENT"} and prior_runtime:
            edges.append(
                {
                    "edgeId": stable_id("edge", prior_runtime, span.get("spanId")),
                    "fromSpanId": prior_runtime,
                    "toSpanId": span.get("spanId"),
                    "type": "runtime_to_security_decision",
                    "confidence": "medium",
                }
            )
    return edges


def build_canonical_trace(run_dir: Path | str) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    manifest = _manifest(resolved)
    run_id = str(manifest.get("runId") or resolved.name)
    trace_id = str(manifest.get("traceId") or stable_id("trace", run_id))
    session_id = str(manifest.get("sessionId") or manifest.get("sessionKey") or "")
    root_span_id = stable_id("span", run_id, "root")
    root_span = make_span(
        span_id=root_span_id,
        parent_span_id=None,
        kind="AGENT_RUN",
        name="Agent run",
        source="manifest",
        start_time=manifest.get("startedAt") or manifest.get("createdAt"),
        end_time=manifest.get("completedAt"),
        status=_root_status(manifest),
        attributes={"runId": run_id, "traceId": trace_id, "sessionId": session_id, "manifestStatus": manifest.get("status")},
        artifact_refs=["manifest.json"] if (resolved / "manifest.json").exists() else [],
        source_confidence="high" if manifest else "medium",
    )

    spans: list[dict[str, Any]] = [root_span]
    events: list[dict[str, Any]] = []
    sources: dict[str, Any] = {
        "manifest": {"status": "ok" if manifest else "unavailable", "path": "manifest.json", "eventCount": 1 if manifest else 0},
    }

    native_spans, native_events, native_source = ingest_openclaw_native_trace(resolved, root_span_id)
    behavior_spans, behavior_events, behavior_source = normalize_behavior_rows(resolved, root_span_id)
    frida_spans, frida_events, frida_source = normalize_frida_rows(resolved, root_span_id)
    codetracer_spans, codetracer_events, codetracer_source = normalize_codetracer(resolved, root_span_id)
    judgment_spans, judgment_events, judgment_source = normalize_final_judgment(resolved, root_span_id)

    for next_spans, next_events in [
        (native_spans, native_events),
        (behavior_spans, behavior_events),
        (frida_spans, frida_events),
        (codetracer_spans, codetracer_events),
        (judgment_spans, judgment_events),
    ]:
        spans.extend(next_spans)
        events.extend(next_events)

    sources["openclaw_stream"] = native_source
    sources["behavior_mediator"] = _source_status_from_spans(behavior_spans, "behavior_mediator", behavior_source)
    sources["frida"] = frida_source
    sources["codetracer"] = codetracer_source
    sources["final_judgment"] = judgment_source

    trace = {
        "schemaVersion": CANONICAL_TRACE_SCHEMA,
        "generatedAt": now_utc_iso(),
        "traceId": trace_id,
        "runId": run_id,
        "sessionId": session_id,
        "rootSpanId": root_span_id,
        "spans": spans,
        "events": events,
        "artifacts": collect_artifacts(resolved),
        "securityEdges": _security_edges(spans),
        "sources": sources,
    }
    output_path = write_json(resolved / "canonical_trace.json", trace)

    manifest_path = resolved / "manifest.json"
    if manifest_path.exists():
        manifest.setdefault("paths", {})["canonicalTrace"] = "canonical_trace.json"
        manifest.setdefault("traceBackbone", {})["canonicalTrace"] = {
            "schemaVersion": CANONICAL_TRACE_SCHEMA,
            "path": "canonical_trace.json",
            "spanCount": len(spans),
            "eventCount": len(events),
            "generatedAt": trace["generatedAt"],
        }
        write_json(manifest_path, manifest)
        if resolved.parent.exists() and resolved.parent.name == "runs":
            write_runs_index(resolved.parent)

    trace["path"] = normalize_path(output_path.resolve())
    return trace


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Transpect canonical Agent Trace for a run directory.")
    parser.add_argument("--run-dir", required=True, help="Run directory containing behavior/Frida/diagnosis/final judgment artifacts.")
    args = parser.parse_args()
    trace = build_canonical_trace(Path(args.run_dir))
    print(json.dumps({"ok": True, "path": trace.get("path"), "spanCount": len(trace["spans"]), "eventCount": len(trace["events"])}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
