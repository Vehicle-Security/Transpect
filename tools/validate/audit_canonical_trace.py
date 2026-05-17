from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from monitor.trace_model.build_canonical_trace import build_canonical_trace  # noqa: E402
from monitor.trace_model.schema import default_display_tier  # noqa: E402
from tools.common.trace_common import read_json  # noqa: E402


def _load_or_build(run_dir: Path) -> dict[str, Any]:
    payload = read_json(run_dir / "canonical_trace.json", default=None)
    if isinstance(payload, dict) and payload.get("schemaVersion") == "transpect.canonical_trace.v1":
        return payload
    return build_canonical_trace(run_dir)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def _artifact_paths(trace: dict[str, Any]) -> set[str]:
    artifacts = trace.get("artifacts") if isinstance(trace.get("artifacts"), list) else []
    return {str(item.get("path")) for item in artifacts if isinstance(item, dict) and item.get("path")}


def _span_fingerprint(span: dict[str, Any]) -> tuple[str, str, str, str]:
    attrs = span.get("attributes") if isinstance(span.get("attributes"), dict) else {}
    return (
        str(span.get("kind") or ""),
        str(span.get("source") or ""),
        str(span.get("name") or ""),
        str(attrs.get("eventId") or attrs.get("eventType") or ""),
    )


def audit_canonical_trace(run_dir: Path | str) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    trace = _load_or_build(resolved)
    spans = [span for span in (trace.get("spans") or []) if isinstance(span, dict)]
    span_ids = {str(span.get("spanId")) for span in spans if span.get("spanId")}
    root_span_id = str(trace.get("rootSpanId") or "")
    warnings: list[str] = []
    recommendations: list[str] = []

    span_kinds = Counter(str(span.get("kind") or "unknown") for span in spans)
    sources = Counter(str(span.get("source") or "unknown") for span in spans)
    display_tiers = Counter(str(span.get("displayTier") or default_display_tier(str(span.get("kind") or ""))) for span in spans)
    importance = Counter(str(span.get("importance") or "medium") for span in spans)

    non_root = [span for span in spans if span.get("spanId") != root_span_id]
    valid_parent_count = sum(1 for span in non_root if span.get("parentSpanId") in span_ids)
    parent_coverage = _ratio(valid_parent_count, len(non_root))

    artifact_paths = _artifact_paths(trace)
    refs: list[str] = []
    valid_refs = 0
    for span in spans:
        for ref in span.get("artifactRefs") or []:
            ref_text = str(ref)
            refs.append(ref_text)
            if ref_text in artifact_paths or (resolved / ref_text).exists():
                valid_refs += 1
    artifact_ref_coverage = _ratio(valid_refs, len(refs))

    fingerprints = [_span_fingerprint(span) for span in spans]
    duplicate_count = len(fingerprints) - len(set(fingerprints))
    duplicate_span_rate = _ratio(duplicate_count, len(spans))

    if not root_span_id or root_span_id not in span_ids:
        warnings.append("Root span missing or not present in spans.")
    if parent_coverage < 0.95 and non_root:
        warnings.append("Some spans have missing or invalid parentSpanId.")
    if artifact_ref_coverage < 0.8 and refs:
        warnings.append("Some artifactRefs do not resolve to run artifacts.")
    if duplicate_span_rate > 0.05:
        warnings.append("Duplicate span rate is elevated.")
    frida_ratio = _ratio(span_kinds.get("FRIDA_EVIDENCE", 0), len(spans))
    if frida_ratio > 0.6 and len(spans) > 10:
        warnings.append("Frida spans dominate canonical trace; summarize low-value events before product display.")
        recommendations.append("Keep raw Frida events in frida-events.jsonl and expose only summary plus high-risk evidence spans.")

    openclaw_source = (trace.get("sources") or {}).get("openclaw_stream") if isinstance(trace.get("sources"), dict) else {}
    if not isinstance(openclaw_source, dict) or openclaw_source.get("status") != "ok":
        warnings.append("OpenClaw native stream unavailable.")
        recommendations.append("Enable OpenClaw lifecycle/assistant/tool stream export to improve trace depth.")
    else:
        streams = openclaw_source.get("streams") if isinstance(openclaw_source.get("streams"), dict) else {}
        missing_streams = [
            key
            for key in ["lifecycle", "assistant", "tool", "plugin_hooks", "session_transcript"]
            if not isinstance(streams.get(key), dict) or streams[key].get("status") != "ok"
        ]
        if missing_streams:
            warnings.append(f"OpenClaw native source coverage incomplete: {', '.join(missing_streams)}.")
            recommendations.append("Capture all native source files before using this run as a deep trace demo.")

    for span in spans:
        if span.get("kind") != "CODETRACER_DIAGNOSIS":
            continue
        attrs = span.get("attributes") if isinstance(span.get("attributes"), dict) else {}
        reason = str(attrs.get("invalidAnalysisReason") or attrs.get("summary") or "").lower()
        if "no substantive agent behavior" in reason:
            warnings.append("CodeTracer reported no substantive agent behavior.")
            recommendations.append("Capture a run with substantive agent tool/browser activity before audit demonstration.")
            break

    result = {
        "ok": bool(spans) and bool(root_span_id in span_ids) and parent_coverage >= 0.8,
        "spanCount": len(spans),
        "spanKinds": dict(span_kinds),
        "sources": dict(sources),
        "displayTiers": dict(display_tiers),
        "importance": dict(importance),
        "parentCoverage": parent_coverage,
        "artifactRefCoverage": artifact_ref_coverage,
        "duplicateSpanRate": duplicate_span_rate,
        "warnings": warnings,
        "recommendations": recommendations,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit a Transpect canonical_trace.json file.")
    parser.add_argument("--run-dir", required=True, help="Run directory containing canonical_trace.json.")
    args = parser.parse_args()
    result = audit_canonical_trace(Path(args.run_dir))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
