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
from scripts.common.trace_common import now_utc_iso, read_json, write_json  # noqa: E402


TRACE_QUALITY_SCHEMA = "transpect.trace-quality.v1"


def _load_or_build(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "canonical_trace.json", default=None)
    if isinstance(payload, dict) and payload.get("schemaVersion") == "transpect.canonical_trace.v1":
        return payload
    return build_canonical_trace(run_dir)


def _count_by_kind(spans: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for span in spans:
        kind = str(span.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _source_ok(trace: dict[str, Any], source: str) -> bool:
    sources = trace.get("sources") if isinstance(trace.get("sources"), dict) else {}
    detail = sources.get(source) if isinstance(sources.get(source), dict) else {}
    try:
        count = int(detail.get("eventCount") or 0)
    except (TypeError, ValueError):
        count = 0
    return detail.get("status") == "ok" and count > 0


def _coverage(trace: dict[str, Any], counts: dict[str, int]) -> dict[str, bool]:
    streams = (((trace.get("sources") or {}).get("openclaw_stream") or {}).get("streams") or {}) if isinstance(trace.get("sources"), dict) else {}
    return {
        "lifecycle": isinstance(streams.get("lifecycle"), dict) and streams["lifecycle"].get("status") == "ok",
        "assistant": isinstance(streams.get("assistant"), dict) and streams["assistant"].get("status") == "ok",
        "openclawTool": isinstance(streams.get("tool"), dict) and streams["tool"].get("status") == "ok",
        "pluginHooks": isinstance(streams.get("plugin_hooks"), dict) and streams["plugin_hooks"].get("status") == "ok",
        "sessionTranscript": isinstance(streams.get("session_transcript"), dict) and streams["session_transcript"].get("status") == "ok",
        "llm": counts.get("LLM_CALL", 0) > 0,
        "tool": counts.get("TOOL_CALL", 0) > 0,
        "browser": counts.get("BROWSER_ACTION", 0) > 0,
        "agentDefense": counts.get("AGENT_DEFENSE", 0) > 0,
        "frida": counts.get("FRIDA_EVIDENCE", 0) > 0 and _source_ok(trace, "frida"),
        "codetracer": counts.get("CODETRACER_DIAGNOSIS", 0) > 0 and _source_ok(trace, "codetracer"),
        "finalJudgment": counts.get("FINAL_JUDGMENT", 0) > 0 and _source_ok(trace, "final_judgment"),
    }


def _has_no_substantive_codetracer(trace: dict[str, Any]) -> bool:
    for span in trace.get("spans") or []:
        if not isinstance(span, dict) or span.get("kind") != "CODETRACER_DIAGNOSIS":
            continue
        attrs = span.get("attributes") if isinstance(span.get("attributes"), dict) else {}
        reason = str(attrs.get("invalidAnalysisReason") or attrs.get("summary") or "").lower()
        if "no substantive agent behavior" in reason:
            return True
    return False


def _depth(coverage: dict[str, bool], counts: dict[str, int]) -> str:
    total = sum(counts.values())
    non_root = total - counts.get("AGENT_RUN", 0)
    if non_root <= 0:
        return "empty"
    substantive_runtime = coverage["tool"] or coverage["browser"] or coverage["agentDefense"] or coverage["frida"]
    if not substantive_runtime:
        return "shallow"
    native_core = coverage["lifecycle"] and coverage["assistant"] and coverage["openclawTool"]
    diagnosis_complete = coverage["agentDefense"] and coverage["finalJudgment"] and coverage["codetracer"]
    runtime_complete = coverage["llm"] and (coverage["tool"] or coverage["browser"])
    if native_core and runtime_complete and diagnosis_complete and coverage["frida"]:
        return "deep"
    return "moderate"


def _score(depth: str, coverage: dict[str, bool]) -> float:
    base = {"empty": 0.0, "shallow": 0.25, "moderate": 0.6, "deep": 0.9}[depth]
    bonus = sum(1 for value in coverage.values() if value) / max(1, len(coverage)) * 0.1
    return round(min(1.0, base + bonus), 3)


def evaluate_trace_quality(run_dir: Path | str, *, write: bool = False) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    trace = _load_or_build(resolved)
    spans = [span for span in trace.get("spans") or [] if isinstance(span, dict)]
    counts = _count_by_kind(spans)
    coverage = _coverage(trace, counts)
    depth = _depth(coverage, counts)
    gaps: list[str] = []
    recommendations: list[str] = []
    if not coverage["lifecycle"] and _source_ok(trace, "behavior_mediator"):
        gaps.append("OpenClaw native lifecycle stream unavailable; behavior-mediator provides partial runtime coverage.")
        recommendations.append("Enable OpenClaw native lifecycle stream export for deeper turn reconstruction.")
    if not coverage["assistant"]:
        gaps.append("OpenClaw assistant stream unavailable.")
    if not coverage["openclawTool"]:
        gaps.append("OpenClaw native tool stream unavailable.")
    if not coverage["pluginHooks"]:
        gaps.append("OpenClaw plugin hook stream unavailable.")
    if not coverage["sessionTranscript"]:
        gaps.append("OpenClaw session transcript unavailable.")
    if not coverage["llm"]:
        gaps.append("LLM call spans not observed.")
    if not coverage["frida"]:
        gaps.append("Frida evidence unavailable or empty.")
    if not coverage["codetracer"]:
        gaps.append("CodeTracer diagnosis unavailable.")
    if _has_no_substantive_codetracer(trace):
        gaps.append("CodeTracer reported no substantive agent behavior.")
    if depth in {"empty", "shallow"}:
        recommendations.append("Capture substantive tool/browser events before using this run as a trace-depth demo.")
    if not coverage["finalJudgment"]:
        recommendations.append("Run final judgment generation to connect runtime trace with security outcome.")

    report = {
        "schemaVersion": TRACE_QUALITY_SCHEMA,
        "evaluatedAt": now_utc_iso(),
        "ok": depth in {"moderate", "deep"},
        "traceDepth": depth,
        "substantiveAgentBehavior": depth in {"moderate", "deep"},
        "coverage": coverage,
        "counts": counts,
        "gaps": gaps,
        "score": _score(depth, coverage),
        "recommendations": recommendations,
    }
    if write:
        write_json(resolved / "trace_quality.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Transpect canonical trace quality for a run.")
    parser.add_argument("--run-dir", required=True, help="Run directory to evaluate.")
    parser.add_argument("--write", action="store_true", help="Write trace_quality.json into the run directory.")
    args = parser.parse_args()
    report = evaluate_trace_quality(Path(args.run_dir), write=args.write)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
