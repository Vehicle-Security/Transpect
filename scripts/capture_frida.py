from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from trace_common import (
    DEFAULT_PATH_PREFIXES,
    DEFAULT_PROCESS_TOKENS,
    TRACE_FRIDA_DIR,
    TRACE_LIVE_FRIDA_DIR,
    append_jsonl,
    ensure_dir,
    get_gateway_pid,
    get_gateway_status,
    now_utc_iso,
)


def build_script_source(template_path: Path) -> str:
    template = template_path.read_text(encoding="utf-8")
    path_prefixes = [str(Path(prefix).resolve()).replace("/", "\\").lower() for prefix in DEFAULT_PATH_PREFIXES if prefix]
    process_tokens = [token.lower() for token in DEFAULT_PROCESS_TOKENS]
    return (
        template.replace("__TRACE_PATH_PREFIXES__", json.dumps(path_prefixes))
        .replace("__PROCESS_INCLUDE__", json.dumps(process_tokens))
    )


def map_trace_kind(event: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    kind = str(event.get("kind") or "unknown")
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    pid = event.get("pid")
    base = {
        "ts": event.get("ts") or now_utc_iso(),
        "sessionKey": None,
        "runId": None,
        "taskId": None,
        "toolCallId": None,
        "llmCallId": None,
        "pid": pid,
        "tid": None,
        "payload": payload,
        "evidence": {"surface": "frida"},
    }

    if kind == "process_spawn":
        return (
            "process",
            {
                **base,
                "source": "frida.process",
                "category": "process",
                "action": "spawn",
                "target": {
                    "api": payload.get("api"),
                    "applicationName": payload.get("applicationName"),
                    "commandLine": payload.get("commandLine"),
                    "cwd": payload.get("cwd"),
                    "childPid": payload.get("childPid"),
                },
                "result": {"success": payload.get("success")},
            },
        )

    if kind in {"file_open", "file_read", "file_write", "file_close"}:
        action = kind.replace("file_", "")
        return (
            "file",
            {
                **base,
                "source": "frida.file",
                "category": "file",
                "action": action,
                "target": {"path": payload.get("path"), "handle": payload.get("handle")},
                "result": {
                    "success": payload.get("success"),
                    "bytesRequested": payload.get("bytesRequested"),
                },
            },
        )

    if kind in {"socket_bind", "socket_listen"}:
        action = "open" if kind == "socket_bind" else "listen"
        return (
            "port",
            {
                **base,
                "source": "frida.port",
                "category": "port",
                "action": action,
                "target": {
                    "socket": payload.get("socket"),
                    "localIp": payload.get("localIp"),
                    "localPort": payload.get("localPort"),
                    "family": payload.get("family"),
                },
                "result": {"backlog": payload.get("backlog")},
            },
        )

    if kind == "socket_close":
        category = "port" if payload.get("localPort") and not payload.get("remotePort") else "network"
        channel = "port" if category == "port" else "network"
        return (
            channel,
            {
                **base,
                "source": f"frida.{channel}",
                "category": category,
                "action": "close",
                "target": {
                    "socket": payload.get("socket"),
                    "localIp": payload.get("localIp"),
                    "localPort": payload.get("localPort"),
                    "remoteIp": payload.get("remoteIp"),
                    "remotePort": payload.get("remotePort"),
                },
                "result": {"success": payload.get("success")},
            },
        )

    if kind in {"socket_connect", "socket_accept", "socket_send", "socket_recv"}:
        action_by_kind = {
            "socket_connect": "connect",
            "socket_accept": "connect",
            "socket_send": "send",
            "socket_recv": "recv",
        }
        return (
            "network",
            {
                **base,
                "source": "frida.network",
                "category": "network",
                "action": action_by_kind[kind],
                "target": {
                    "socket": payload.get("socket"),
                    "localIp": payload.get("localIp"),
                    "localPort": payload.get("localPort"),
                    "remoteIp": payload.get("remoteIp"),
                    "remotePort": payload.get("remotePort"),
                    "api": payload.get("api"),
                },
                "result": {
                    "bytesRequested": payload.get("bytesRequested"),
                    "bytesRead": payload.get("bytesRead"),
                    "bytesReported": payload.get("bytesReported"),
                    "success": payload.get("success"),
                },
            },
        )

    return (
        "control",
        {
            **base,
            "source": "frida.control",
            "category": "session",
            "action": "response",
            "target": {"kind": kind},
            "result": None,
        },
    )


def append_control(output_dir: Path, kind: str, payload: dict[str, Any] | None = None) -> None:
    append_jsonl(
        output_dir / "frida-control.jsonl",
        {
            "ts": now_utc_iso(),
            "source": "frida.control",
            "category": "session",
            "action": "response",
            "sessionKey": None,
            "runId": None,
            "taskId": None,
            "toolCallId": None,
            "llmCallId": None,
            "pid": payload.get("pid") if isinstance(payload, dict) else None,
            "tid": None,
            "target": {"kind": kind},
            "result": None,
            "payload": payload or {},
            "evidence": {"surface": "frida-control"},
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--output-dir", default=str(TRACE_LIVE_FRIDA_DIR))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    ensure_dir(output_dir)
    template_path = TRACE_FRIDA_DIR / "openclaw_gateway_windows.js"

    try:
        import frida
    except ImportError as exc:
        raise SystemExit("frida package is not installed") from exc

    append_control(output_dir, "frida_bootstrap")

    session = None
    try:
        status = {}
        pid = args.pid
        if not pid:
            status = get_gateway_status()
            pid = get_gateway_pid(status)
        if not pid:
            raise RuntimeError("unable to resolve gateway PID")

        append_control(output_dir, "frida_attach_start", {"pid": pid})
        session = frida.attach(pid)
        append_control(output_dir, "frida_attached", {"pid": pid})

        script = session.create_script(build_script_source(template_path))

        def on_message(message, data) -> None:
            if message.get("type") != "send":
                append_control(output_dir, "frida_message", {"message": message, "dataLength": len(data) if data else 0})
                return

            payload = message.get("payload") or {}
            channel, record = map_trace_kind(payload)
            append_jsonl(output_dir / f"frida-{channel}.jsonl", record)

        script.on("message", on_message)
        script.load()
        append_control(output_dir, "frida_script_loaded", {"pid": pid, "logFile": status.get("logFile")})

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            append_control(output_dir, "frida_detach", {"pid": pid})
    except Exception as exc:
        append_control(output_dir, "frida_error", {"error": repr(exc)})
        raise
    finally:
        if session is not None:
            session.detach()


if __name__ == "__main__":
    main()
