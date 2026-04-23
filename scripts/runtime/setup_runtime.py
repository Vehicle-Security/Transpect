from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import (
    BEHAVIOR_PLUGIN_VENDOR_PATH,
    OBSERVABILITY_PLUGIN_VENDOR_PATH,
    OPENCLAW_CONFIG_PATH,
    OTEL_COLLECTOR_CONFIG_PATH,
    OTEL_COLLECTOR_TEMPLATE_PATH,
    TRACE_CONFIG_DIR,
    TRACE_LIVE_DIR,
    TRACE_LIVE_RUNS_DIR,
    TRACE_SCRIPTS_DIR,
    ensure_dir,
    ensure_trace_layout,
    get_gateway_log_path,
    get_gateway_status,
    now_utc_iso,
    openclaw_executable,
    read_json,
    run_command,
    write_json,
)


BEHAVIOR_RUNS_DIR = TRACE_LIVE_RUNS_DIR
CODETRACER_DIAGNOSIS_SCRIPT = TRACE_SCRIPTS_DIR / "diagnosis" / "run_codetracer_diagnosis.py"
OTEL_DEFAULTS = {
    "endpoint": "http://127.0.0.1:4318",
    "protocol": "http",
    "serviceName": "transpect-gateway",
    "traces": True,
    "metrics": True,
    "logs": True,
    "captureContent": False,
    "metricsIntervalMs": 30000,
    "headers": {},
    "resourceAttributes": {
        "deployment.environment": "local",
        "transpect.runtime": "openclaw",
    },
}
DIAGNOSTICS_OTEL_DEFAULTS = {
    "endpoint": "http://127.0.0.1:4318",
    "protocol": "http/protobuf",
    "serviceName": "transpect-gateway",
    "traces": True,
    "metrics": True,
    "logs": True,
    "headers": {},
}


def normalize_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in paths:
        if not isinstance(item, str) or not item.strip():
            continue
        resolved = str(Path(item).resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        output.append(resolved)
    return output


def configure_plugin_paths(config: dict, *, enable_behavior: bool, enable_otel: bool) -> None:
    plugins = config.setdefault("plugins", {})
    load = plugins.setdefault("load", {})
    paths = normalize_paths(load.get("paths") or [])

    behavior_path = str(BEHAVIOR_PLUGIN_VENDOR_PATH.resolve())
    observability_path = str(OBSERVABILITY_PLUGIN_VENDOR_PATH.resolve())
    filtered = []
    for item in paths:
        lowered = str(item).lower()
        if lowered.endswith("openclaw-behavior-mediator") or lowered.endswith("openclaw-observability-plugin"):
            continue
        filtered.append(item)
    if enable_behavior:
        filtered.append(behavior_path)
    if enable_otel:
        filtered.append(observability_path)
    load["paths"] = normalize_paths(filtered)


def configure_behavior_plugin(config: dict, *, enabled: bool) -> None:
    plugins = config.setdefault("plugins", {})
    entries = plugins.setdefault("entries", {})
    entries["behavior-mediator"] = {
        "enabled": enabled,
        "config": {
            "runsDirectory": str(BEHAVIOR_RUNS_DIR.resolve()),
            "artifactsEnabled": True,
            "autoDiagnosisEnabled": True,
            "diagnosisScript": str(CODETRACER_DIAGNOSIS_SCRIPT.resolve()),
            "diagnosisPython": sys.executable,
            "capturePreviewChars": 2000,
            "captureNetwork": True,
            "traceEval": False,
            "redactHeaders": [
                "authorization",
                "cookie",
                "set-cookie",
                "x-api-key",
                "proxy-authorization",
            ],
            "redactPatterns": [
                r"Bearer\s+[A-Za-z0-9._-]+",
                r"sk-[A-Za-z0-9_-]+",
                r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s,}]+",
            ],
        },
    }

    allow = plugins.get("allow")
    if isinstance(allow, list):
        while "behavior-mediator" in allow:
            allow.remove("behavior-mediator")
        if enabled:
            allow.append("behavior-mediator")


def configure_otel_plugin(config: dict, *, enabled: bool) -> None:
    plugins = config.setdefault("plugins", {})
    entries = plugins.setdefault("entries", {})
    if enabled:
        entries["otel-observability"] = {
            "enabled": True,
            "config": dict(OTEL_DEFAULTS),
        }
    else:
        entries.pop("otel-observability", None)

    installs = plugins.get("installs")
    if isinstance(installs, dict) and not enabled:
        installs.pop("otel-observability", None)

    allow = plugins.get("allow")
    if isinstance(allow, list):
        while "otel-observability" in allow:
            allow.remove("otel-observability")
        if enabled:
            allow.append("otel-observability")


def configure_diagnostics(config: dict, *, enable_otel: bool) -> None:
    diagnostics = config.setdefault("diagnostics", {})
    diagnostics["enabled"] = bool(enable_otel)
    otel = diagnostics.setdefault("otel", {})
    otel["enabled"] = False
    if enable_otel:
        otel["endpoint"] = DIAGNOSTICS_OTEL_DEFAULTS["endpoint"]
        otel["protocol"] = DIAGNOSTICS_OTEL_DEFAULTS["protocol"]
        otel["serviceName"] = DIAGNOSTICS_OTEL_DEFAULTS["serviceName"]
        otel["traces"] = DIAGNOSTICS_OTEL_DEFAULTS["traces"]
        otel["metrics"] = DIAGNOSTICS_OTEL_DEFAULTS["metrics"]
        otel["logs"] = DIAGNOSTICS_OTEL_DEFAULTS["logs"]
        otel["headers"] = DIAGNOSTICS_OTEL_DEFAULTS["headers"]
    else:
        for key in ["endpoint", "protocol", "serviceName", "traces", "metrics", "logs", "headers"]:
            otel.pop(key, None)


def render_otel_collector() -> str | None:
    if not OTEL_COLLECTOR_TEMPLATE_PATH.exists():
        return None
    replacements = {
        "__TRACE_OTEL_TRACES__": str((TRACE_LIVE_DIR / "otel" / "traces.jsonl").resolve()).replace("\\", "/"),
        "__TRACE_OTEL_LOGS__": str((TRACE_LIVE_DIR / "otel" / "logs.jsonl").resolve()).replace("\\", "/"),
        "__TRACE_OTEL_METRICS__": str((TRACE_LIVE_DIR / "otel" / "metrics.jsonl").resolve()).replace("\\", "/"),
    }
    template = OTEL_COLLECTOR_TEMPLATE_PATH.read_text(encoding="utf-8")
    rendered = template
    for key, value in replacements.items():
        rendered = rendered.replace(key, value)
    OTEL_COLLECTOR_CONFIG_PATH.write_text(rendered, encoding="utf-8")
    return str(OTEL_COLLECTOR_CONFIG_PATH.resolve())


def apply_mode(config: dict, mode: str) -> dict[str, bool]:
    enable_behavior = mode in {"core", "hybrid"}
    enable_otel = mode in {"hybrid", "otel"}
    configure_plugin_paths(config, enable_behavior=enable_behavior, enable_otel=enable_otel)
    configure_behavior_plugin(config, enabled=enable_behavior)
    configure_otel_plugin(config, enabled=enable_otel)
    configure_diagnostics(config, enable_otel=enable_otel)
    return {
        "behavior": enable_behavior,
        "otel": enable_otel,
    }


def setup_runtime(*, mode: str, restart_gateway: bool, render_otel_config: bool) -> dict[str, Any]:
    ensure_trace_layout()
    if not OPENCLAW_CONFIG_PATH.exists():
        raise SystemExit(f"OpenClaw config not found: {OPENCLAW_CONFIG_PATH}")

    config = read_json(OPENCLAW_CONFIG_PATH, default={}) or {}
    if not isinstance(config, dict):
        raise SystemExit(f"Invalid OpenClaw config: {OPENCLAW_CONFIG_PATH}")

    ensure_dir(BEHAVIOR_RUNS_DIR)
    ensure_dir(TRACE_CONFIG_DIR / "applied")

    applied_dir = ensure_dir(TRACE_CONFIG_DIR / "applied")
    stamp = now_utc_iso().replace(":", "").replace("-", "")
    backup_path = applied_dir / f"{stamp}-openclaw-backup.json"
    shutil.copy2(OPENCLAW_CONFIG_PATH, backup_path)

    enabled = apply_mode(config, mode)
    write_json(OPENCLAW_CONFIG_PATH, config)

    otel_config_path = None
    if render_otel_config:
        otel_config_path = render_otel_collector()

    restart_result = None
    status = None
    log_path = None
    if restart_gateway:
        try:
            completed = run_command(
                [openclaw_executable(), "gateway", "restart", "--json"],
                timeout=240,
                check=False,
            )
            restart_result = {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "timedOut": False,
            }
        except subprocess.TimeoutExpired as error:
            restart_result = {
                "returncode": None,
                "stdout": error.stdout or "",
                "stderr": error.stderr or "",
                "timedOut": True,
                "timeoutSeconds": error.timeout,
            }
        time.sleep(4)
        status = get_gateway_status()
        log_path = get_gateway_log_path(status)

    result = {
        "appliedAt": now_utc_iso(),
        "mode": mode,
        "enabled": enabled,
        "runsDirectory": str(BEHAVIOR_RUNS_DIR.resolve()),
        "diagnosisScript": str(CODETRACER_DIAGNOSIS_SCRIPT.resolve()),
        "backupConfig": str(backup_path),
        "configPath": str(OPENCLAW_CONFIG_PATH),
        "otelCollectorConfig": otel_config_path,
        "restartGateway": restart_gateway,
        "restart": restart_result,
        "gatewayStatus": status,
        "gatewayLog": str(log_path) if log_path else None,
    }
    write_json(applied_dir / "runtime.last-apply.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare OpenClaw runtime settings for Transpect.")
    parser.add_argument("--mode", choices=["core", "hybrid", "otel"], default="core")
    parser.add_argument("--no-restart", action="store_true", help="Only rewrite config, do not restart the gateway.")
    parser.add_argument(
        "--render-otel-config",
        action="store_true",
        help="Render config/otel-collector.local.yaml from the template.",
    )
    args = parser.parse_args()
    result = setup_runtime(
        mode=args.mode,
        restart_gateway=not args.no_restart,
        render_otel_config=args.render_otel_config,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
