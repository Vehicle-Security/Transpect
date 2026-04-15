from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

from trace_common import (
    TRACE_LIVE_LOGS_DIR,
    TRACE_SCRIPTS_DIR,
    WORKSPACE_ROOT,
    ensure_trace_layout,
    get_gateway_log_path,
    get_gateway_status,
    get_trace_runtime_log_paths,
    openclaw_executable,
    python_executable,
)


def run_command(args: list[str], *, timeout: int = 180, check: bool = False) -> dict[str, Any]:
    completed = subprocess.run(
        args,
        cwd=str(WORKSPACE_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    payload = {
        "args": args,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return payload


def probe_health(url: str, timeout_seconds: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            return response.status == 200
    except Exception:
        return False


def wait_for_health(url: str, *, timeout_seconds: int = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if probe_health(url):
            return True
        time.sleep(1)
    return False


def stringify_log_paths(log_paths: dict[str, Path]) -> dict[str, str]:
    return {key: str(value) for key, value in log_paths.items()}


def spawn_detached(args: list[str], *, log_name: str | None = None) -> dict[str, Any]:
    ensure_trace_layout()
    log_paths = get_trace_runtime_log_paths(log_name) if log_name else None
    kwargs: dict[str, Any] = {
        "cwd": str(WORKSPACE_ROOT),
    }
    stdout_handle = None
    stderr_handle = None
    if log_paths:
        stdout_handle = log_paths["stdout"].open("ab")
        stderr_handle = log_paths["stderr"].open("ab")
        kwargs["stdout"] = stdout_handle
        kwargs["stderr"] = stderr_handle
    else:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    if os.name == "nt":
        creationflags = 0
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
        if creationflags:
            kwargs["creationflags"] = creationflags
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(args, **kwargs)
    finally:
        if stdout_handle:
            stdout_handle.close()
        if stderr_handle:
            stderr_handle.close()

    payload: dict[str, Any] = {"pid": process.pid}
    if log_paths:
        payload["logFiles"] = stringify_log_paths(log_paths)
    return payload


def normalize_probe_host(host: str) -> str:
    text = str(host or "").strip()
    if text in {"", "0.0.0.0", "::", "[::]"}:
        return "127.0.0.1"
    return text


def configure_runtime(mode: str, *, render_otel_config: bool) -> dict[str, Any]:
    args = [
        python_executable(),
        str(TRACE_SCRIPTS_DIR / "setup_runtime.py"),
        "--mode",
        mode,
        "--no-restart",
    ]
    if render_otel_config:
        args.append("--render-otel-config")
    return run_command(args, timeout=180, check=True)


def ensure_gateway_running(port: int) -> dict[str, Any]:
    gateway_cli = openclaw_executable()
    local_health_url = f"http://127.0.0.1:{port}/health"
    if wait_for_health(local_health_url, timeout_seconds=3):
        try:
            status = get_gateway_status(include_probe=False)
        except Exception:
            status = None
        log_path = get_gateway_log_path(status) if status else None
        return {
            "healthy": True,
            "started": False,
            "fallbackRun": False,
            "healthUrl": local_health_url,
            "logFile": str(log_path) if log_path else None,
        }

    start_result = run_command(
        [gateway_cli, "gateway", "--port", str(port), "start", "--json"],
        timeout=180,
        check=False,
    )
    if wait_for_health(local_health_url, timeout_seconds=60):
        try:
            status = get_gateway_status(include_probe=False)
        except Exception:
            status = None
        log_path = get_gateway_log_path(status) if status else None
        return {
            "healthy": True,
            "started": True,
            "fallbackRun": False,
            "healthUrl": local_health_url,
            "start": start_result,
            "logFile": str(log_path) if log_path else None,
        }

    spawn_info = spawn_detached(
        [gateway_cli, "gateway", "run", "--port", str(port)],
        log_name="gateway-run",
    )
    healthy = wait_for_health(local_health_url, timeout_seconds=60)
    return {
        "healthy": healthy,
        "started": True,
        "fallbackRun": True,
        "healthUrl": local_health_url,
        "start": start_result,
        "spawn": spawn_info,
    }


def ensure_viewer_running(host: str, port: int) -> dict[str, Any]:
    probe_host = normalize_probe_host(host)
    health_url = f"http://{probe_host}:{port}/health"
    viewer_logs = stringify_log_paths(get_trace_runtime_log_paths("viewer-server"))
    if wait_for_health(health_url, timeout_seconds=3):
        return {
            "healthy": True,
            "started": False,
            "healthUrl": health_url,
            "logFiles": viewer_logs,
        }

    spawn_info = spawn_detached(
        [
            python_executable(),
            str(TRACE_SCRIPTS_DIR / "serve_viewer.py"),
            "--host",
            host,
            "--port",
            str(port),
        ],
        log_name="viewer-server",
    )
    healthy = wait_for_health(health_url, timeout_seconds=20)
    return {
        "healthy": healthy,
        "started": True,
        "healthUrl": health_url,
        "logFiles": viewer_logs,
        "spawn": spawn_info,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Start the Transpect trace runtime.")
    parser.add_argument("--mode", choices=["core", "hybrid", "otel"], default="core")
    parser.add_argument("--viewer-host", default="127.0.0.1")
    parser.add_argument("--viewer-port", type=int, default=8711)
    parser.add_argument("--gateway-port", type=int, default=18789)
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser automatically.")
    args = parser.parse_args()

    ensure_trace_layout()
    render_otel_config = args.mode in {"hybrid", "otel"}
    setup_result = configure_runtime(args.mode, render_otel_config=render_otel_config)
    gateway_result = ensure_gateway_running(args.gateway_port)

    open_host = normalize_probe_host(args.viewer_host)
    viewer_url = f"http://{open_host}:{args.viewer_port}/viewer/index.html?view=traces"
    viewer_result: dict[str, Any] = {
        "healthy": True,
        "started": False,
        "skipped": args.mode == "otel",
        "healthUrl": None,
        "logFiles": None,
    }

    if args.mode != "otel":
        viewer_result = ensure_viewer_running(args.viewer_host, args.viewer_port)

    opened = False
    if args.mode != "otel" and not args.no_open and viewer_result.get("healthy"):
        opened = webbrowser.open(viewer_url, new=2)

    ok = bool(gateway_result.get("healthy") and viewer_result.get("healthy"))
    payload = {
        "ok": ok,
        "mode": args.mode,
        "viewerUrl": None if args.mode == "otel" else viewer_url,
        "gatewayHealthUrl": gateway_result.get("healthUrl"),
        "runtimeLogsDir": str(TRACE_LIVE_LOGS_DIR.resolve()),
        "opened": opened,
        "setupRuntime": setup_result,
        "gateway": gateway_result,
        "viewer": viewer_result,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
