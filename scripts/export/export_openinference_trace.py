from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.trace_model.build_canonical_trace import build_canonical_trace  # noqa: E402
from scripts.common.trace_common import read_json, write_json  # noqa: E402


KIND_MAP = {
    "AGENT_RUN": "AGENT",
    "AGENT_TURN": "AGENT",
    "LLM_CALL": "LLM",
    "TOOL_CALL": "TOOL",
    "BROWSER_ACTION": "TOOL",
    "AGENT_DEFENSE": "GUARDRAIL",
    "FRIDA_EVIDENCE": "TOOL",
    "CODETRACER_DIAGNOSIS": "EVALUATOR",
    "FINAL_JUDGMENT": "EVALUATOR",
    "ARTIFACT": "CHAIN",
}


def _load_or_build(run_dir: Path) -> dict[str, Any]:
    trace = read_json(run_dir / "canonical_trace.json", default=None)
    if isinstance(trace, dict) and trace.get("schemaVersion") == "transpect.canonical_trace.v1":
        return trace
    return build_canonical_trace(run_dir)


def _export_span(span: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
    kind = str(span.get("kind") or "ARTIFACT")
    attributes = dict(span.get("attributes") if isinstance(span.get("attributes"), dict) else {})
    attributes.update(
        {
            "openinference.span.kind": KIND_MAP.get(kind, "CHAIN"),
            "transpect.span.kind": kind,
            "transpect.source": span.get("source"),
            "transpect.source_confidence": span.get("sourceConfidence"),
            "transpect.display_tier": span.get("displayTier"),
            "transpect.importance": span.get("importance"),
            "transpect.artifact_refs": span.get("artifactRefs") or [],
        }
    )
    if kind == "FRIDA_EVIDENCE":
        attributes["transpect.os_evidence"] = True
    if kind == "AGENT_DEFENSE":
        attributes["transpect.guardrail.type"] = "agent_defense"
    if kind == "FINAL_JUDGMENT":
        attributes["transpect.guardrail.type"] = "final_judgment"
    return {
        "traceId": trace.get("traceId"),
        "spanId": span.get("spanId"),
        "parentSpanId": span.get("parentSpanId"),
        "name": span.get("name"),
        "kind": KIND_MAP.get(kind, "CHAIN"),
        "startTime": span.get("startTime"),
        "endTime": span.get("endTime"),
        "status": span.get("status"),
        "attributes": attributes,
    }


def export_openinference_trace(run_dir: Path | str, *, output: Path | str | None = None) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    trace = _load_or_build(resolved)
    spans = [_export_span(span, trace) for span in trace.get("spans") or [] if isinstance(span, dict)]
    payload = {
        "schemaVersion": "transpect.openinference.spans.v1",
        "sourceSchemaVersion": trace.get("schemaVersion"),
        "traceId": trace.get("traceId"),
        "runId": trace.get("runId"),
        "spans": spans,
    }
    output_path = Path(output).resolve() if output else resolved / "exports" / "openinference_spans.json"
    write_json(output_path, payload)
    return {"ok": True, "path": str(output_path), "spanCount": len(spans)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Export canonical Transpect trace as OpenInference-style spans JSON.")
    parser.add_argument("--run-dir", required=True, help="Run directory containing canonical_trace.json or source artifacts.")
    parser.add_argument("--output", help="Optional output JSON path.")
    args = parser.parse_args()
    result = export_openinference_trace(Path(args.run_dir), output=Path(args.output) if args.output else None)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
