from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from monitor.runtime.openclaw_trace_ingest.schema import OPENCLAW_NATIVE_SOURCES  # noqa: E402
from tools.common.trace_common import (  # noqa: E402
    BEHAVIOR_PLUGIN_VENDOR_PATH,
    OBSERVABILITY_PLUGIN_VENDOR_PATH,
    get_openclaw_install_info,
    read_json,
    run_openclaw_gateway_call,
)


CORE_NATIVE_SOURCES = {"lifecycle", "assistant", "tool", "plugin_hooks", "session_transcript"}
OPTIONAL_NATIVE_SOURCES = {"gateway_diagnostics"}


def _jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def _source_status(run_dir: Path, key: str, relative: str) -> dict[str, Any]:
    path = run_dir / relative
    if not path.exists():
        return {"status": "missing", "path": relative, "eventCount": 0}
    if relative.endswith(".jsonl"):
        count = _jsonl_count(path)
    else:
        payload = read_json(path, default=None)
        if isinstance(payload, dict):
            count = len(payload.get("messages") or []) if key == "session_transcript" else 1
        else:
            count = 0
    return {
        "status": "ok" if count > 0 else "empty",
        "path": relative,
        "eventCount": count,
        "sizeBytes": path.stat().st_size,
    }


def _behavior_status(timeout_seconds: int) -> dict[str, Any]:
    try:
        payload = run_openclaw_gateway_call("behavior-mediator.status", timeout_seconds=timeout_seconds)
        result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        return {
            "status": "active" if payload.get("ok") and result.get("active") is not False else "inactive",
            "hooksRegistered": result.get("hooksRegistered"),
            "hookNames": result.get("hookNames") or [],
            "eventsWritten": result.get("eventsWritten"),
        }
    except Exception as error:  # noqa: BLE001
        return {"status": "unknown", "reason": str(error)}


def discover_openclaw_native_sources(run_dir: Path | str | None = None, *, timeout_seconds: int = 4) -> dict[str, Any]:
    resolved_run_dir = Path(run_dir).resolve() if run_dir else None
    openclaw = get_openclaw_install_info()
    behavior_plugin = {
        "status": "available" if (BEHAVIOR_PLUGIN_VENDOR_PATH / "index.js").exists() else "missing",
        "path": str(BEHAVIOR_PLUGIN_VENDOR_PATH),
    }
    observability_plugin = {
        "status": "available" if (OBSERVABILITY_PLUGIN_VENDOR_PATH / "index.ts").exists() else "missing",
        "path": str(OBSERVABILITY_PLUGIN_VENDOR_PATH),
    }
    run_sources = {
        key: _source_status(resolved_run_dir, key, relative)
        for key, relative in OPENCLAW_NATIVE_SOURCES.items()
    } if resolved_run_dir else {}
    missing_core = [
        detail["path"]
        for key, detail in run_sources.items()
        if key in CORE_NATIVE_SOURCES and detail.get("status") != "ok"
    ]
    missing_optional = [
        detail["path"]
        for key, detail in run_sources.items()
        if key in OPTIONAL_NATIVE_SOURCES and detail.get("status") != "ok"
    ]
    recommendations: list[str] = []
    if behavior_plugin["status"] != "available":
        recommendations.append("Install or restore monitor/vendor/runtime-hooks/openclaw-behavior-mediator before native source capture.")
    if missing_core:
        recommendations.extend(f"Generate {item} by running a new OpenClaw task with the updated behavior-mediator plugin." for item in missing_core)
    if missing_optional:
        recommendations.extend(f"Optionally capture {item} for gateway-level diagnostics." for item in missing_optional)
    if not resolved_run_dir:
        recommendations.append("Pass --run-dir monitor/live/runs/<runId> to inspect native source file coverage for a specific run.")

    ok = bool(openclaw.get("version")) and behavior_plugin["status"] == "available" and (not run_sources or not missing_core)
    return {
        "schemaVersion": "transpect.openclaw-native-source-discovery.v1",
        "ok": ok,
        "openclaw": openclaw,
        "behaviorMediator": {
            **behavior_plugin,
            "runtime": _behavior_status(timeout_seconds),
        },
        "observabilityPlugin": observability_plugin,
        "runDir": str(resolved_run_dir) if resolved_run_dir else None,
        "runSources": run_sources,
        "recommendations": recommendations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover OpenClaw native trace source availability for Transpect.")
    parser.add_argument("--run-dir", help="Optional run directory to inspect for native OpenClaw source files.")
    parser.add_argument("--timeout", type=int, default=4, help="Gateway status timeout in seconds.")
    args = parser.parse_args()
    report = discover_openclaw_native_sources(Path(args.run_dir) if args.run_dir else None, timeout_seconds=args.timeout)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
