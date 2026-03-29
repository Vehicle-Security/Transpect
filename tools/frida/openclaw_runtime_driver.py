#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

import frida


SCRIPT_DIR = Path(__file__).resolve().parent
AGENT_PATH = SCRIPT_DIR / "openclaw_runtime_hook.js"
DEFAULT_MAX_CHUNK_BYTES = 16384
EVENT_KEYS = [
    "ts",
    "parent_pid",
    "child_pid",
    "phase",
    "exe",
    "argv",
    "fd",
    "chunk",
    "blocked",
    "errno",
    "exit_code",
    "resource",
    "op",
    "path",
    "path2",
    "family",
    "address",
    "port",
    "rule_id",
]


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z"


class JsonlWriter:
    def __init__(self, path: Path | None) -> None:
        self._lock = threading.Lock()
        self._path = path
        self._stream = path.open("a", encoding="utf-8") if path else sys.stdout

    def write(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._stream.flush()

    def close(self) -> None:
        if self._path is not None:
            self._stream.close()


class RuntimeHookDriver:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.policy = load_policy(args)
        self.enable_filesystem_hooks = args.enable_filesystem_hooks or bool(self.policy.get("filesystem"))
        self.enable_network_hooks = args.enable_network_hooks or bool(self.policy.get("network"))
        self.device = frida.get_local_device()
        self.writer = JsonlWriter(Path(args.jsonl).expanduser() if args.jsonl else None)
        self.base_agent_source = AGENT_PATH.read_text(encoding="utf-8")
        self.sessions: dict[int, frida.core.Session] = {}
        self.scripts: dict[int, frida.core.Script] = {}
        self.session_roles: dict[int, str] = {}
        self.session_parent_pids: dict[int, int | None] = {}
        self.root_pid: int | None = None
        self.stop_event = threading.Event()
        self.root_detached = threading.Event()
        self.recursive_child_gating = args.child_gating == "on"
        self.should_attach_child_sessions = (
            args.mode == "observe" or self.enable_filesystem_hooks or self.enable_network_hooks
        )
        self._lock = threading.Lock()

    def log(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    def normalize_record(self, record: dict[str, Any]) -> dict[str, Any]:
        normalized = {key: record.get(key) for key in EVENT_KEYS}
        for key, value in record.items():
            if key not in normalized:
                normalized[key] = value
        if normalized["ts"] is None:
            normalized["ts"] = iso_now()
        return normalized

    def emit_record(self, record: dict[str, Any]) -> None:
        self.writer.write(self.normalize_record(record))

    def build_agent_source(
        self,
        *,
        role: str,
        parent_pid: int | None,
        target_path: str | None = None,
        target_argv: list[str] | None = None,
    ) -> str:
        config = {
            "mode": self.args.mode,
            "role": role,
            "parentPid": parent_pid,
            "maxChunkBytes": self.args.max_chunk_bytes,
            "denyExeRegex": self.args.deny_exe_regex or "",
            "denyArgvRegex": self.args.deny_argv_regex or "",
            "policy": self.policy,
            "enableFilesystemHooks": self.enable_filesystem_hooks,
            "enableNetworkHooks": self.enable_network_hooks,
            "targetPath": target_path,
            "targetArgv": target_argv or [],
        }
        return self.base_agent_source.replace("__HOOK_CONFIG__", json.dumps(config, ensure_ascii=False))

    def on_script_message(self, pid: int, role: str, message: dict[str, Any], data: bytes | None) -> None:
        message_type = message.get("type")
        if message_type == "send":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                self.emit_record(
                    {
                        "phase": "driver_warning",
                        "parent_pid": self.session_parent_pids.get(pid),
                        "child_pid": pid if role == "child" else None,
                        "detail": f"unexpected payload type from pid {pid}: {type(payload).__name__}",
                    }
                )
                return
            record = dict(payload)
            if data:
                record["chunk"] = data.decode("utf-8", errors="replace")
                record["chunk_bytes"] = len(data)
            self.emit_record(record)
            return
        if message_type == "error":
            self.emit_record(
                {
                    "phase": "agent_error",
                    "parent_pid": self.session_parent_pids.get(pid),
                    "child_pid": pid if role == "child" else None,
                    "detail": message.get("description"),
                    "stack": message.get("stack"),
                    "file_name": message.get("fileName"),
                    "line_number": message.get("lineNumber"),
                    "column_number": message.get("columnNumber"),
                }
            )

    def on_session_detached(self, pid: int, role: str, reason: str, crash: Any) -> None:
        self.emit_record(
            {
                "phase": "detached",
                "parent_pid": self.session_parent_pids.get(pid),
                "child_pid": pid if role == "child" else None,
                "detail": reason,
                "crash": str(crash) if crash is not None else None,
            }
        )
        with self._lock:
            self.sessions.pop(pid, None)
            self.scripts.pop(pid, None)
            self.session_roles.pop(pid, None)
            self.session_parent_pids.pop(pid, None)
        if pid == self.root_pid:
            self.root_detached.set()
            if self.args.exit_on_root_detach:
                self.stop_event.set()

    def attach_session(
        self,
        pid: int,
        *,
        role: str,
        parent_pid: int | None,
        auto_resume: bool,
        target_path: str | None = None,
        target_argv: list[str] | None = None,
    ) -> None:
        session = self.device.attach(pid)
        def _on_detached(reason: str, crash: Any) -> None:
            self.on_session_detached(pid, role, reason, crash)

        session.on("detached", _on_detached)
        if self.recursive_child_gating:
            session.enable_child_gating()
        script = session.create_script(
            self.build_agent_source(
                role=role,
                parent_pid=parent_pid,
                target_path=target_path,
                target_argv=target_argv,
            ),
            name=f"openclaw-runtime-{role}-{pid}",
        )
        script.on("message", lambda message, data, _pid=pid, _role=role: self.on_script_message(_pid, _role, message, data))
        script.load()
        with self._lock:
            self.sessions[pid] = session
            self.scripts[pid] = script
            self.session_roles[pid] = role
            self.session_parent_pids[pid] = parent_pid
        self.emit_record(
            {
                "phase": "attached",
                "parent_pid": parent_pid,
                "child_pid": pid if role == "child" else None,
                "role": role,
            }
        )
        if auto_resume:
            self.device.resume(pid)

    def emit_child_event(self, phase: str, child: Any) -> None:
        self.emit_record(
            {
                "phase": phase,
                "parent_pid": getattr(child, "parent_pid", self.root_pid),
                "child_pid": getattr(child, "pid", None),
                "origin": getattr(child, "origin", None),
                "identifier": getattr(child, "identifier", None),
                "path": getattr(child, "path", None),
                "argv": list(getattr(child, "argv", []) or []),
            }
        )

    def on_child_added(self, child: Any) -> None:
        child_pid = getattr(child, "pid", None)
        if child_pid is None:
            return
        self.emit_child_event("child_added", child)
        if not self.should_attach_child_sessions:
            try:
                self.device.resume(child_pid)
            except Exception:
                pass
            return
        try:
            self.attach_session(
                child_pid,
                role="child",
                parent_pid=getattr(child, "parent_pid", self.root_pid),
                auto_resume=True,
                target_path=getattr(child, "path", None),
                target_argv=list(getattr(child, "argv", []) or []),
            )
        except Exception as exc:  # pragma: no cover - depends on runtime timing
            self.emit_record(
                {
                    "phase": "attach_failed",
                    "parent_pid": getattr(child, "parent_pid", self.root_pid),
                    "child_pid": child_pid,
                    "detail": str(exc),
                }
            )
            try:
                self.device.resume(child_pid)
            except Exception:
                pass

    def on_child_removed(self, child: Any) -> None:
        self.emit_child_event("child_removed", child)

    def on_process_crashed(self, crash: Any) -> None:
        self.emit_record(
            {
                "phase": "process_crashed",
                "parent_pid": None,
                "child_pid": getattr(crash, "pid", None),
                "detail": str(crash),
            }
        )

    def resolve_target_pid(self) -> int:
        if self.args.pid is not None:
            return self.args.pid
        if self.args.process_name:
            return self.device.get_process(self.args.process_name).pid
        if self.args.spawn_program:
            argv = [self.args.spawn_program, *self.args.spawn_arg]
            return self.device.spawn(
                argv,
                cwd=self.args.spawn_cwd,
                stdio=self.args.spawn_stdio,
            )
        raise ValueError("one of --pid, --process-name, or --spawn-program is required")

    def attach_pending_children(self) -> None:
        try:
            pending = self.device.enumerate_pending_children()
        except Exception:
            return
        for child in pending:
            child_parent = getattr(child, "parent_pid", None)
            if self.root_pid is not None and child_parent not in (self.root_pid, None):
                continue
            self.on_child_added(child)

    def install_signal_handlers(self) -> None:
        def _handle_signal(signum: int, _frame: Any) -> None:
            self.emit_record(
                {
                    "phase": "driver_signal",
                    "parent_pid": self.root_pid,
                    "child_pid": None,
                    "detail": f"received signal {signum}",
                }
            )
            self.stop_event.set()

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

    def run(self) -> int:
        self.install_signal_handlers()
        self.device.on("child-added", self.on_child_added)
        self.device.on("child-removed", self.on_child_removed)
        self.device.on("process-crashed", self.on_process_crashed)
        self.root_pid = self.resolve_target_pid()
        target_role = "parent"
        auto_resume_root = bool(self.args.spawn_program)
        self.attach_session(self.root_pid, role=target_role, parent_pid=None, auto_resume=auto_resume_root)
        self.attach_pending_children()
        self.log(f"[driver] attached to pid={self.root_pid} mode={self.args.mode} child_gating={self.args.child_gating}")
        if self.args.spawn_program:
            self.log(f"[driver] spawned root process {self.args.spawn_program} with pid={self.root_pid}")
        while not self.stop_event.is_set():
            if self.args.exit_on_root_detach and self.root_detached.is_set():
                break
            time.sleep(0.2)
        self.shutdown()
        return 0

    def shutdown(self) -> None:
        with self._lock:
            pids = list(self.sessions.keys())
        for pid in pids:
            session = self.sessions.get(pid)
            if session is None:
                continue
            try:
                session.detach()
            except Exception:
                pass
        self.writer.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Frida/OpenClaw runtime hook PoC driver")
    parser.add_argument("--mode", choices=("observe", "block"), default="observe")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int, help="attach to a running PID")
    target.add_argument("--process-name", help="attach to a running process by exact name/pattern")
    target.add_argument("--spawn-program", help="spawn a fresh root process under Frida before attaching")
    parser.add_argument("--spawn-arg", action="append", default=[], help="argument for --spawn-program; may be repeated")
    parser.add_argument("--spawn-cwd", help="cwd used with --spawn-program")
    parser.add_argument("--spawn-stdio", default="inherit", help="stdio passed to device.spawn (default: inherit)")
    parser.add_argument("--deny-exe-regex", help="regex applied to executable path in block mode")
    parser.add_argument("--deny-argv-regex", help="regex applied to joined argv in block mode")
    parser.add_argument("--policy-file", help="JSON policy file for exec/filesystem/network rules")
    parser.add_argument(
        "--enable-filesystem-hooks",
        action="store_true",
        default=False,
        help="enable filesystem hook instrumentation for child processes",
    )
    parser.add_argument(
        "--enable-network-hooks",
        action="store_true",
        default=False,
        help="enable network hook instrumentation for child processes",
    )
    parser.add_argument("--jsonl", help="write normalized JSONL events to this file instead of stdout")
    parser.add_argument("--child-gating", choices=("on", "off"), default="on")
    parser.add_argument("--max-chunk-bytes", type=int, default=DEFAULT_MAX_CHUNK_BYTES)
    parser.add_argument(
        "--exit-on-root-detach",
        action="store_true",
        default=False,
        help="exit automatically when the root target detaches/terminates",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    driver = RuntimeHookDriver(args)
    return driver.run()


def load_policy(args: argparse.Namespace) -> dict[str, list[dict[str, Any]]]:
    policy: dict[str, list[dict[str, Any]]] = {
        "exec": [],
        "filesystem": [],
        "network": [],
    }
    if args.policy_file:
        policy_path = Path(args.policy_file).expanduser()
        raw_policy = json.loads(policy_path.read_text(encoding="utf-8"))
        if not isinstance(raw_policy, dict):
            raise ValueError(f"policy file must contain a JSON object: {policy_path}")
        for section in policy:
            entries = raw_policy.get(section, [])
            if entries is None:
                entries = []
            if not isinstance(entries, list):
                raise ValueError(f"policy section '{section}' must be a list: {policy_path}")
            normalized_entries: list[dict[str, Any]] = []
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise ValueError(f"policy section '{section}' entry {index} must be an object: {policy_path}")
                if not entry.get("id"):
                    raise ValueError(f"policy section '{section}' entry {index} is missing required field 'id': {policy_path}")
                normalized_entries.append(dict(entry))
            policy[section] = normalized_entries
    if args.deny_exe_regex:
        policy["exec"].append(
            {
                "id": "cli-exe-regex",
                "exeRegex": args.deny_exe_regex,
            }
        )
    if args.deny_argv_regex:
        policy["exec"].append(
            {
                "id": "cli-argv-regex",
                "argvRegex": args.deny_argv_regex,
            }
        )
    return policy
if __name__ == "__main__":
    raise SystemExit(main())
