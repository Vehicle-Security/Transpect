from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.common.trace_common import read_json  # noqa: E402


def _value(span: dict[str, Any], camel: str, snake: str) -> Any:
    return span.get(camel) if span.get(camel) is not None else span.get(snake)


def validate_openinference_export(path: Path | str) -> dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    warnings: list[str] = []
    errors: list[str] = []
    payload = read_json(resolved, default=None)
    if not isinstance(payload, dict):
        return {"ok": False, "path": str(resolved), "spanCount": 0, "warnings": warnings, "errors": [f"file is not readable JSON: {resolved}"]}
    spans = payload.get("spans")
    if not isinstance(spans, list) or not spans:
        return {"ok": False, "path": str(resolved), "spanCount": 0, "warnings": warnings, "errors": ["spans must be a non-empty list"]}

    span_ids = {str(_value(span, "spanId", "span_id")) for span in spans if isinstance(span, dict) and _value(span, "spanId", "span_id")}
    for index, span in enumerate(spans):
        if not isinstance(span, dict):
            errors.append(f"span[{index}] is not an object")
            continue
        span_id = _value(span, "spanId", "span_id")
        trace_id = _value(span, "traceId", "trace_id")
        name = span.get("name")
        attrs = span.get("attributes")
        if not trace_id:
            errors.append(f"span[{index}] missing trace_id")
        if not span_id:
            errors.append(f"span[{index}] missing span_id")
        if not name:
            errors.append(f"span[{index}] missing name")
        if not isinstance(attrs, dict):
            errors.append(f"span[{index}] attributes must be a dict")
            attrs = {}
        kind = span.get("kind") or attrs.get("openinference.span.kind") or attrs.get("span.kind")
        if not kind:
            errors.append(f"span[{index}] missing kind")
        parent = _value(span, "parentSpanId", "parent_span_id")
        if parent and str(parent) not in span_ids:
            errors.append(f"span[{index}] missing parent span: {parent}")
        if "startTime" not in span and "start_time" not in span:
            warnings.append(f"span[{index}] missing start timestamp")
    return {
        "ok": not errors,
        "path": str(resolved),
        "spanCount": len(spans),
        "warnings": warnings,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a Transpect OpenInference-style spans export.")
    parser.add_argument("--path", required=True, help="Path to exports/openinference_spans.json.")
    args = parser.parse_args()
    result = validate_openinference_export(Path(args.path))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
