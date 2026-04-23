from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import (
    BEHAVIOR_PLUGIN_VENDOR_PATH,
    OBSERVABILITY_PLUGIN_VENDOR_PATH,
    OPENCLAW_CONFIG_PATH,
    OTEL_COLLECTOR_CONFIG_PATH,
    TRACE_LIVE_ARCHIVE_DIR,
    TRACE_LIVE_DIR,
    TRACE_LIVE_LOGS_DIR,
    TRACE_LIVE_PLUGIN_DIR,
    TRACE_LIVE_RUNS_DIR,
    TRACE_ROOT,
    build_runs_index_payload,
    get_gateway_status,
    read_json,
    run_openclaw_gateway_call,
)


CANONICAL_REQUIRED_FIELDS = [
    "schemaVersion",
    "seq",
    "ts",
    "traceId",
    "spanId",
    "kind",
    "name",
    "status",
]

EXPECTED_BEHAVIOR_CONFIG = {
    "runsDirectory": str(TRACE_LIVE_RUNS_DIR.resolve()),
    "artifactsEnabled": True,
    "autoDiagnosisEnabled": True,
    "capturePreviewChars": 2000,
    "captureNetwork": True,
    "traceEval": False,
}


def inspect_runs(root: Path) -> dict[str, Any]:
    payload = build_runs_index_payload(root)
    latest = payload.get("latestRun") if isinstance(payload, dict) else None
    return {
        "path": str(root.resolve()),
        "exists": root.exists(),
        "runCount": payload.get("runCount"),
        "latestRun": latest,
        "indexSchemaVersion": payload.get("schemaVersion"),
    }


def infer_mode(behavior_enabled: bool, otel_enabled: bool) -> str:
    if behavior_enabled and otel_enabled:
        return "hybrid"
    if behavior_enabled:
        return "core"
    if otel_enabled:
        return "otel"
    return "unknown"


def get_runtime_config() -> dict[str, Any]:
    config = read_json(OPENCLAW_CONFIG_PATH, default={}) or {}
    plugins = config.get("plugins") if isinstance(config, dict) else {}
    entries = plugins.get("entries") if isinstance(plugins, dict) else {}
    load = plugins.get("load") if isinstance(plugins, dict) else {}
    behavior = entries.get("behavior-mediator") if isinstance(entries, dict) else {}
    otel = entries.get("otel-observability") if isinstance(entries, dict) else {}
    diagnostics = config.get("diagnostics") if isinstance(config, dict) else {}
    gateway = config.get("gateway") if isinstance(config, dict) else {}
    behavior_config = behavior.get("config") if isinstance(behavior, dict) else {}
    otel_config = otel.get("config") if isinstance(otel, dict) else {}

    checks = {
        "configPath": str(OPENCLAW_CONFIG_PATH),
        "exists": OPENCLAW_CONFIG_PATH.exists(),
        "behaviorEnabled": isinstance(behavior, dict) and behavior.get("enabled") is True,
        "behaviorConfig": behavior_config,
        "otelPluginEnabled": isinstance(otel, dict) and otel.get("enabled") is True,
        "otelPluginConfig": otel_config,
        "loadPaths": list(load.get("paths") or []) if isinstance(load, dict) else [],
        "gatewayPort": int(gateway.get("port") or 18789) if isinstance(gateway, dict) else 18789,
        "diagnosticsEnabled": bool(diagnostics.get("enabled")) if isinstance(diagnostics, dict) else None,
        "diagnosticsOtelEnabled": bool((diagnostics.get("otel") or {}).get("enabled")) if isinstance(diagnostics, dict) else None,
        "otelCollectorConfigExists": OTEL_COLLECTOR_CONFIG_PATH.exists(),
    }

    load_paths = {str(item).lower() for item in checks["loadPaths"]}
    behavior_path = str(BEHAVIOR_PLUGIN_VENDOR_PATH.resolve()).lower()
    observability_path = str(OBSERVABILITY_PLUGIN_VENDOR_PATH.resolve()).lower()
    behavior_matches = all(behavior_config.get(key) == value for key, value in EXPECTED_BEHAVIOR_CONFIG.items())
    otel_matches = bool(otel_config.get("endpoint")) and bool(otel_config.get("protocol")) and bool(otel_config.get("serviceName"))

    checks["behaviorConfigAligned"] = checks["behaviorEnabled"] and behavior_path in load_paths and behavior_matches
    checks["otelConfigAligned"] = checks["otelPluginEnabled"] and observability_path in load_paths and otel_matches
    checks["mode"] = infer_mode(checks["behaviorEnabled"], checks["otelPluginEnabled"])
    return checks


def probe_url(url: str, timeout_seconds: int = 5) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="replace")
            content_type = response.headers.get("Content-Type", "")
            parsed = None
            if "json" in content_type.lower():
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    parsed = None
            return {
                "ok": True,
                "status": response.status,
                "contentType": content_type,
                "body": parsed if parsed is not None else body[:1000],
            }
    except urllib.error.HTTPError as error:
        return {
            "ok": False,
            "status": error.code,
            "error": str(error),
        }
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "status": None,
            "error": str(error),
        }


def compact_rpc_payload(payload: dict[str, Any], *, result_keys: list[str]) -> dict[str, Any]:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    compact_result = {key: result.get(key) for key in result_keys if key in result}
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    return {
        "ok": payload.get("ok"),
        "status": payload.get("status"),
        "attempts": payload.get("attempts"),
        "successfulAttempts": payload.get("successfulAttempts"),
        "result": compact_result or None,
        "error": payload.get("error"),
        "raw": {
            "command": raw.get("command"),
            "returncode": raw.get("returncode"),
        },
    }


def run_gateway_status(timeout_seconds: int) -> dict[str, Any]:
    try:
        payload = get_gateway_status(include_probe=False, timeout_seconds=timeout_seconds)
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "status": "handler_error",
            "result": None,
            "error": {"message": str(error)},
            "raw": None,
        }
    return {
        "ok": True,
        "status": "ok",
        "result": {
            "runtimeVersion": payload.get("runtimeVersion"),
            "heartbeat": payload.get("heartbeat"),
            "channelSummary": payload.get("channelSummary"),
            "queuedSystemEvents": payload.get("queuedSystemEvents"),
            "tasks": payload.get("tasks"),
            "taskAudit": payload.get("taskAudit"),
        },
        "error": None,
        "raw": {"command": "openclaw gateway status --json --no-probe", "timeoutSeconds": timeout_seconds},
    }


def run_behavior_status(timeout_seconds: int) -> dict[str, Any]:
    return compact_rpc_payload(
        run_openclaw_gateway_call("behavior-mediator.status", timeout_seconds=timeout_seconds),
        result_keys=[
            "ok",
            "method",
            "active",
            "runsDirectory",
            "capturePreviewChars",
            "captureNetwork",
            "traceEval",
            "artifactsEnabled",
            "autoDiagnosisEnabled",
            "diagnosesTriggered",
            "hooksRegistered",
            "hookNames",
            "hookEventsObserved",
            "eventsWritten",
            "lastEventTs",
            "lastWriteOk",
            "lastWriteError",
        ],
    )


def run_otel_status(timeout_seconds: int) -> dict[str, Any]:
    return compact_rpc_payload(
        run_openclaw_gateway_call("otel-observability.status", timeout_seconds=timeout_seconds),
        result_keys=[
            "initialized",
            "config",
        ],
    )


def collect_runtime_residue() -> dict[str, Any]:
    tmp_artifacts = sorted(path for path in TRACE_ROOT.glob("tmp-*") if path.is_file())
    legacy_root_logs = sorted(
        path
        for path in TRACE_LIVE_DIR.iterdir()
        if path.is_file() and path.suffix == ".log" and path.parent == TRACE_LIVE_DIR
    )
    legacy_openclaw_files = sorted(path for path in TRACE_LIVE_PLUGIN_DIR.rglob("*") if path.is_file()) if TRACE_LIVE_PLUGIN_DIR.exists() else []
    archive_dirs = sorted(path for path in TRACE_LIVE_ARCHIVE_DIR.iterdir() if path.is_dir()) if TRACE_LIVE_ARCHIVE_DIR.exists() else []
    latest_archive = archive_dirs[-1] if archive_dirs else None
    return {
        "tmpArtifacts": {
            "path": str(TRACE_ROOT.resolve()),
            "fileCount": len(tmp_artifacts),
            "files": [str(path.resolve()) for path in tmp_artifacts],
        },
        "legacyRootLogs": {
            "path": str(TRACE_LIVE_DIR.resolve()),
            "fileCount": len(legacy_root_logs),
            "files": [str(path.resolve()) for path in legacy_root_logs],
        },
        "legacyOpenclawFiles": {
            "path": str(TRACE_LIVE_PLUGIN_DIR.resolve()),
            "exists": TRACE_LIVE_PLUGIN_DIR.exists(),
            "fileCount": len(legacy_openclaw_files),
            "files": [str(path.resolve()) for path in legacy_openclaw_files],
        },
        "archivePath": str(latest_archive.resolve()) if latest_archive else None,
        "runtimeLogsDir": str(TRACE_LIVE_LOGS_DIR.resolve()),
    }


def build_summary(report: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    warnings: list[str] = []
    runtime = report["runtimeConfig"]
    mode = runtime["mode"]

    if mode in {"core", "hybrid"}:
        if not runtime["behaviorEnabled"]:
            issues.append("behavior-mediator is not enabled")
        if not runtime["behaviorConfigAligned"]:
            issues.append("behavior-mediator configuration is not aligned with the repository defaults")
        if not report["runs"]["exists"]:
            issues.append("live/runs is missing")
        elif not report["runs"]["runCount"]:
            warnings.append("live/runs exists but does not contain any completed or active run manifests yet")
        if not report["viewerHealth"]["ok"]:
            issues.append("viewer /health is not available")

    if mode in {"hybrid", "otel"}:
        if not runtime["otelPluginEnabled"]:
            issues.append("otel-observability is not enabled")
        if not runtime["otelConfigAligned"]:
            issues.append("otel-observability configuration is incomplete")
        if not runtime["otelCollectorConfigExists"]:
            warnings.append("config/otel-collector.local.yaml has not been rendered yet")
        if runtime["diagnosticsEnabled"] is not True:
            warnings.append("OpenClaw diagnostics are not enabled; cost telemetry may be incomplete")

    if not report["gatewayHealth"]["ok"]:
        issues.append("gateway /health is not available")
    if not report["gatewayRpc"]["ok"]:
        warnings.append(f"gateway status probe failed: {report['gatewayRpc'].get('status') or 'unknown'}")
    if mode in {"core", "hybrid"} and not report["behaviorMediatorStatus"]["ok"]:
        issues.append(f"behavior-mediator.status is not available: {report['behaviorMediatorStatus'].get('status') or 'unknown'}")
    if mode in {"hybrid", "otel"} and not report["otelStatus"]["ok"]:
        warnings.append(f"otel-observability.status is not available: {report['otelStatus'].get('status') or 'unknown'}")

    residue = report["runtimeResidue"]
    if residue["tmpArtifacts"]["fileCount"] > 0:
        warnings.append("legacy tmp-* files are present in the repository root")
    if residue["legacyRootLogs"]["fileCount"] > 0:
        warnings.append("legacy log files are present directly under live/")
    if residue["legacyOpenclawFiles"]["fileCount"] > 0:
        warnings.append("legacy files are present under live/openclaw/")

    verdict = "ok"
    if issues:
        verdict = "broken"
    elif warnings:
        verdict = "degraded"
    return {
        "mode": mode,
        "verdict": verdict,
        "issues": issues,
        "warnings": warnings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Diagnose the Transpect runtime.")
    parser.add_argument("--host", default="127.0.0.1", help="Host for viewer and gateway health probes.")
    parser.add_argument("--port", type=int, default=8711, help="Viewer port to probe.")
    parser.add_argument("--gateway-timeout", type=int, default=6, help="Gateway probe timeout in seconds.")
    args = parser.parse_args()

    viewer_url = f"http://{args.host}:{args.port}/viewer/index.html"
    health_url = f"http://{args.host}:{args.port}/health"
    runtime_config = get_runtime_config()
    gateway_port = runtime_config["gatewayPort"]
    gateway_health_url = f"http://{args.host}:{gateway_port}/health"

    report = {
        "runtimeConfig": runtime_config,
        "runs": inspect_runs(TRACE_LIVE_RUNS_DIR),
        "viewer": {
            "viewerUrl": viewer_url,
            "healthUrl": health_url,
        },
        "viewerHealth": probe_url(health_url),
        "gateway": {
            "healthUrl": gateway_health_url,
            "port": gateway_port,
        },
        "gatewayHealth": probe_url(gateway_health_url),
        "gatewayRpc": run_gateway_status(args.gateway_timeout),
        "behaviorMediatorStatus": run_behavior_status(args.gateway_timeout),
        "otelStatus": run_otel_status(args.gateway_timeout),
        "runtimeResidue": collect_runtime_residue(),
    }
    report["summary"] = build_summary(report)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
