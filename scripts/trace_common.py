from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from uuid import uuid4
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def resolve_workspace_root() -> Path:
    override = os.environ.get("TRANSPECT_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


WORKSPACE_ROOT = resolve_workspace_root()
TRACE_ROOT = WORKSPACE_ROOT
TRACE_CONFIG_DIR = TRACE_ROOT / "config"
TRACE_CAPTURES_DIR = TRACE_ROOT / "captures"
TRACE_FIXTURE_DIR = TRACE_ROOT / "tests" / "fixtures"
TRACE_FRIDA_DIR = TRACE_ROOT / "frida"
TRACE_LIVE_DIR = TRACE_ROOT / "live"
TRACE_LIVE_LOGS_DIR = TRACE_LIVE_DIR / "logs"
TRACE_LIVE_ARCHIVE_DIR = TRACE_LIVE_DIR / "archive"
TRACE_LIVE_OTEL_DIR = TRACE_LIVE_DIR / "otel"
TRACE_LIVE_FRIDA_DIR = TRACE_LIVE_DIR / "frida"
TRACE_LIVE_HARVEST_DIR = TRACE_LIVE_DIR / "harvest"
TRACE_LIVE_PLUGIN_DIR = TRACE_LIVE_DIR / "openclaw"
TRACE_LIVE_PORTS_DIR = TRACE_LIVE_DIR / "ports"
TRACE_SCRIPTS_DIR = TRACE_ROOT / "scripts"
TRACE_VENDOR_DIR = TRACE_ROOT / "vendor"
TRACE_BIN_DIR = TRACE_ROOT / "bin"

OPENCLAW_HOME = Path.home() / ".openclaw"
OPENCLAW_CONFIG_PATH = OPENCLAW_HOME / "openclaw.json"
OPENCLAW_TASKS_DIR = OPENCLAW_HOME / "tasks"
OPENCLAW_TASKS_DB = OPENCLAW_TASKS_DIR / "runs.sqlite"
OPENCLAW_LOGS_DIR = OPENCLAW_HOME / "logs"
OPENCLAW_AGENTS_DIR = OPENCLAW_HOME / "agents"
OBSERVABILITY_PLUGIN_VENDOR_PATH = TRACE_VENDOR_DIR / "openclaw-observability-plugin"
BEHAVIOR_PLUGIN_VENDOR_PATH = TRACE_VENDOR_DIR / "openclaw-behavior-mediator"
PLUGIN_VENDOR_PATH = OBSERVABILITY_PLUGIN_VENDOR_PATH
OTEL_COLLECTOR_TEMPLATE_PATH = TRACE_CONFIG_DIR / "otel-collector.template.yaml"
OTEL_COLLECTOR_CONFIG_PATH = TRACE_CONFIG_DIR / "otel-collector.local.yaml"

DEFAULT_PATH_PREFIXES = [
    str(WORKSPACE_ROOT),
    str(OPENCLAW_HOME),
    str(Path(os.environ.get("LOCALAPPDATA", "")) / "Temp" / "openclaw"),
]
DEFAULT_PROCESS_TOKENS = ["openclaw", "node", "powershell", "cmd"]


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_utc_iso() -> str:
    return now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_trace_layout() -> None:
    for directory in [
        TRACE_ROOT,
        TRACE_CONFIG_DIR,
        TRACE_CAPTURES_DIR,
        TRACE_FIXTURE_DIR,
        TRACE_FRIDA_DIR,
        TRACE_LIVE_DIR,
        TRACE_LIVE_LOGS_DIR,
        TRACE_LIVE_ARCHIVE_DIR,
        TRACE_LIVE_OTEL_DIR,
        TRACE_LIVE_FRIDA_DIR,
        TRACE_LIVE_HARVEST_DIR,
        TRACE_LIVE_PLUGIN_DIR,
        TRACE_LIVE_PORTS_DIR,
        TRACE_SCRIPTS_DIR,
        TRACE_VENDOR_DIR,
        TRACE_BIN_DIR,
    ]:
        ensure_dir(directory)


def read_json(path: Path, default: Any | None = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> Path:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_text(path: Path, content: str) -> Path:
    ensure_dir(path.parent)
    path.write_text(content, encoding="utf-8")
    return path


def append_jsonl(path: Path, payload: Any) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[Any]:
    if not path.exists():
        return []
    rows: list[Any] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line})
    return rows


def extract_json_from_text(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ValueError("command produced no stdout")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    matches = re.findall(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    for candidate in reversed(matches):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ValueError(f"unable to parse JSON from stdout: {text[:200]}")


def run_command(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
    check: bool = False,
    env: dict[str, str] | None = None,
) -> CommandResult:
    merged_env = os.environ.copy()
    merged_env.setdefault("PYTHONUTF8", "1")
    merged_env.setdefault("PYTHONIOENCODING", "utf-8")
    if env:
        merged_env.update(env)
    completed = subprocess.run(
        args,
        cwd=str(cwd or WORKSPACE_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=merged_env,
    )
    result = CommandResult(
        args=args,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return result


def run_command_json(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> Any:
    result = run_command(args, cwd=cwd, timeout=timeout, check=check, env=env)
    return extract_json_from_text(result.stdout)


def parse_json_command_output(result: CommandResult) -> tuple[Any | None, str | None]:
    last_error: str | None = None
    for raw in [result.stdout, result.stderr]:
        if not raw.strip():
            continue
        try:
            return extract_json_from_text(raw), None
        except ValueError as error:
            last_error = str(error)
    return None, last_error


def openclaw_executable() -> str:
    resolved = shutil.which("openclaw")
    if resolved:
        return resolved
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidate = Path(appdata) / "npm" / "openclaw.cmd"
        if candidate.exists():
            return str(candidate)
    return "openclaw"


def node_executable() -> str:
    resolved = shutil.which("node")
    if resolved:
        return resolved
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    candidate = program_files / "nodejs" / "node.exe"
    if candidate.exists():
        return str(candidate)
    return "node"


def get_gateway_status(include_probe: bool = False) -> dict[str, Any]:
    args = [openclaw_executable(), "gateway", "status", "--json"]
    if not include_probe:
        args.append("--no-probe")
    return run_command_json(args, timeout=180)


def get_gateway_pid(status: dict[str, Any] | None = None) -> int | None:
    status = status or get_gateway_status()
    listeners = status.get("port", {}).get("listeners") or []
    for listener in listeners:
        pid = listener.get("pid")
        command = str(listener.get("command") or "").lower()
        if pid and ("node" in command or not command):
            return int(pid)
    return None


def get_gateway_log_path(status: dict[str, Any] | None = None) -> Path | None:
    status = status or get_gateway_status()
    raw = status.get("logFile")
    return Path(raw) if raw else None


def get_trace_runtime_log_paths(name: str) -> dict[str, Path]:
    stem = re.sub(r"[^a-z0-9._-]+", "-", str(name or "").strip().lower()).strip("-") or "process"
    return {
        "stdout": TRACE_LIVE_LOGS_DIR / f"{stem}.out.log",
        "stderr": TRACE_LIVE_LOGS_DIR / f"{stem}.err.log",
    }


def make_trace_archive_dir(label: str = "runtime-cleanup") -> Path:
    stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
    stem = re.sub(r"[^a-z0-9._-]+", "-", str(label or "").strip().lower()).strip("-") or "archive"
    candidate = TRACE_LIVE_ARCHIVE_DIR / f"{stamp}-{stem}"
    counter = 1
    while candidate.exists():
        counter += 1
        candidate = TRACE_LIVE_ARCHIVE_DIR / f"{stamp}-{stem}-{counter}"
    ensure_dir(candidate)
    return candidate


def copy_file_if_exists(source: Path, target: Path) -> Path | None:
    if not source.exists():
        return None
    ensure_dir(target.parent)
    shutil.copy2(source, target)
    return target


def copy_sqlite_family(source: Path, target_dir: Path) -> list[Path]:
    ensure_dir(target_dir)
    copied: list[Path] = []
    for suffix in ["", "-wal", "-shm"]:
        candidate = Path(str(source) + suffix)
        if candidate.exists():
            destination = target_dir / candidate.name
            shutil.copy2(candidate, destination)
            copied.append(destination)
    return copied


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_files(root: Path, pattern: str) -> list[Path]:
    return sorted(root.rglob(pattern)) if root.exists() else []


def resolve_otelcol_binary() -> Path | None:
    candidates = list(TRACE_BIN_DIR.rglob("otelcol-contrib.exe"))
    return candidates[0] if candidates else None


def find_openclaw_cmd() -> str | None:
    result = run_command(["where", "openclaw"], timeout=30, check=False)
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            return line
    candidate = openclaw_executable()
    return candidate if candidate != "openclaw" else None


def get_openclaw_install_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "version": None,
        "installSource": None,
        "cliPath": find_openclaw_cmd(),
        "packagePath": None,
    }
    version_result = run_command([openclaw_executable(), "--version"], timeout=60, check=False)
    version_match = re.search(r"OpenClaw\s+([0-9][^\s(]+)", version_result.stdout + version_result.stderr)
    if version_match:
        info["version"] = version_match.group(1)

    cli_path = info["cliPath"]
    if cli_path:
        cli = Path(cli_path)
        npm_root = cli.parent / "node_modules" / "openclaw"
        if npm_root.exists():
            info["installSource"] = "npm-global"
            info["packagePath"] = str(npm_root)
            package_json = npm_root / "package.json"
            package = read_json(package_json, default={}) or {}
            info["version"] = package.get("version", info["version"])
    return info


def find_recent_gateway_log_lines(
    log_path: Path,
    start_time: datetime | None = None,
    max_lines: int = 5000,
) -> list[str]:
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def collect_session_files() -> list[Path]:
    if not OPENCLAW_AGENTS_DIR.exists():
        return []
    return sorted(OPENCLAW_AGENTS_DIR.rglob("sessions/*.jsonl"))


def normalize_session_key(raw: str | None) -> str | None:
    if raw is None:
        return None
    return str(raw)


def list_command_logger_candidates() -> list[Path]:
    candidates = []
    for name in ["commands.log", "command-logger.log"]:
        candidate = OPENCLAW_LOGS_DIR / name
        if candidate.exists():
            candidates.append(candidate)
    return candidates


def utc_from_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def python_executable() -> str:
    return sys.executable


def extract_run_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    candidates = [
        payload.get("runId"),
        (payload.get("result") or {}).get("runId") if isinstance(payload.get("result"), dict) else None,
        (payload.get("data") or {}).get("runId") if isinstance(payload.get("data"), dict) else None,
        (payload.get("started") or {}).get("runId") if isinstance(payload.get("started"), dict) else None,
        ((payload.get("started") or {}).get("result") or {}).get("runId")
        if isinstance((payload.get("started") or {}).get("result"), dict)
        else None,
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def run_openclaw_gateway_call(
    method: str,
    *,
    params: dict[str, Any] | None = None,
    timeout_seconds: int = 90,
    url: str | None = None,
    token: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    timeout_ms = max(int(timeout_seconds * 1000), 1_000)
    timeout_budget_seconds = max(int(timeout_seconds) + 15, 120)
    args = [
        openclaw_executable(),
        "gateway",
        "call",
        method,
        "--json",
        "--timeout",
        str(timeout_ms),
        "--params",
        json.dumps(params or {}, ensure_ascii=False),
    ]
    if url:
        args.extend(["--url", url])
    if token:
        args.extend(["--token", token])
    if password:
        args.extend(["--password", password])

    try:
        result = run_command(args, cwd=WORKSPACE_ROOT, timeout=timeout_budget_seconds, check=False)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "timeout",
            "result": None,
            "error": {
                "message": f"openclaw gateway call timed out after {timeout_budget_seconds} seconds",
                "exitCode": None,
                "parseError": None,
            },
            "attempts": 1,
            "successfulAttempts": 0,
            "raw": {
                "command": args,
                "stdout": "",
                "stderr": "",
                "returncode": None,
                "parsed": None,
            },
        }
    parsed, parse_error = parse_json_command_output(result)
    ok_from_payload = isinstance(parsed, dict) and parsed.get("ok") is not False
    ok = result.returncode == 0 and isinstance(parsed, dict) and ok_from_payload

    return {
        "ok": ok,
        "status": "ok" if ok else "handler_error",
        "result": parsed if ok else None,
        "error": None
        if ok
        else {
            "message": result.stderr.strip()
            or result.stdout.strip()
            or (parse_error or f"openclaw gateway call failed with exit code {result.returncode}"),
            "exitCode": result.returncode,
            "parseError": parse_error,
        },
        "attempts": 1,
        "successfulAttempts": 1 if ok else 0,
        "raw": {
            "command": args,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "parsed": parsed,
        },
    }


def run_openclaw_agent(
    *,
    message: str,
    timeout_seconds: int = 180,
    agent_id: str = "main",
    session_id: str | None = None,
    thinking: str | None = None,
    target: str | None = None,
    no_wait: bool = False,
) -> dict[str, Any]:
    resolved_session_id = (session_id or str(uuid4())).strip()
    args = [
        openclaw_executable(),
        "agent",
        "--json",
        "--agent",
        agent_id,
        "--session-id",
        resolved_session_id,
        "--message",
        message,
        "--timeout",
        str(timeout_seconds),
    ]
    if thinking:
        args.extend(["--thinking", thinking])
    if target:
        args.extend(["--to", target])

    result = run_command(args, cwd=WORKSPACE_ROOT, timeout=max(timeout_seconds + 30, 60), check=False)
    parsed, parse_error = parse_json_command_output(result)
    run_id = extract_run_id(parsed)
    ok = result.returncode == 0 and parsed is not None

    payload: dict[str, Any] = {
        "command": "agent",
        "agentId": agent_id,
        "sessionId": resolved_session_id,
        "runId": run_id,
        "ok": ok,
        "started": {
            "result": {"runId": run_id},
            "raw": parsed,
        }
        if parsed is not None
        else None,
        "waited": None if no_wait else parsed,
        "raw": {
            "command": args,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "parseError": parse_error,
        },
    }
    if not ok:
        payload["error"] = result.stderr.strip() or result.stdout.strip() or parse_error or "openclaw agent failed"
    return payload
