#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = REPO_ROOT / "tools" / "frida" / "openclaw_runtime_driver.py"
PROBE_PATH = REPO_ROOT / "tools" / "frida" / "openclaw_exec_probe.mjs"
DEFAULT_OUTPUT_ROOT = Path("/tmp/transpect-openclaw-frida-smoke")
OPENCLAW_GATEWAY_ENTRYPOINT = Path("/usr/lib/node_modules/openclaw/openclaw.mjs")
OPENCLAW_CONFIG_PATH = Path("/root/.openclaw/openclaw.json")
DEFAULT_GATEWAY_PORT = 19001
DEFAULT_COMMAND_TIMEOUT_SECONDS = 30.0
DEFAULT_GATEWAY_ACTIVITY_TIMEOUT_SECONDS = 75.0
DEFAULT_AGENT_TIMEOUT_SECONDS = 90.0
DEFAULT_PORT_SCAN_COUNT = 100
LOCAL_HTTP_PORT_SCAN_START = 24080
LOCAL_HTTP_PORT_SCAN_COUNT = 50
AGENT_TARGET = "+15555550123"
AGENT_MESSAGE = (
    'You must use the exec or bash tool. Run /bin/sh -lc "printf FRIDA_STDOUT; '
    'printf FRIDA_STDERR >&2" and return the exact tool output. Do not answer from memory.'
)
FILE_OBSERVE_SNIPPET = (
    "from pathlib import Path; import sys; "
    "src=Path(sys.argv[1]); dst=Path(sys.argv[2]); "
    "dst.write_text(src.read_text() + '\\nfile-observe'); "
    "print('FILE_OBSERVE_OK')"
)
FILE_BLOCK_SNIPPET = (
    "from pathlib import Path; import sys; "
    "Path(sys.argv[1]).write_text('blocked'); "
    "print('FILE_BLOCK_SHOULD_NOT_SUCCEED')"
)
NETWORK_REQUEST_SNIPPET = (
    "import sys, urllib.request; "
    "print(urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())"
)


class VerificationError(RuntimeError):
    pass


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    output_dir: Path
    details: list[str] = field(default_factory=list)


@dataclass
class GatewayDriver:
    process: subprocess.Popen[str]
    output_dir: Path
    jsonl_path: Path
    stdout_path: Path
    stderr_path: Path
    port: int


@dataclass
class ProbeRun:
    command_result: CommandResult
    payload: dict[str, Any]
    records: list[dict[str, Any]]
    jsonl_path: Path
    stdout_path: Path
    stderr_path: Path


class LocalHttpFixture:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.requests: list[str] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = reserve_port(LOCAL_HTTP_PORT_SCAN_START, LOCAL_HTTP_PORT_SCAN_COUNT)
        self.request_log_path = output_dir / "http.requests.json"

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/demo"

    def start(self) -> None:
        requests = self.requests
        request_log_path = self.request_log_path

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib naming
                requests.append(self.path)
                request_log_path.write_text(json.dumps(requests, indent=2), encoding="utf-8")
                body = b"NETWORK_OBSERVE_OK"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - stdlib signature
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Repeatable smoke verification for the OpenClaw Frida PoC")
    parser.add_argument(
        "--scenario",
        choices=(
            "all",
            "isolated-observe",
            "isolated-block",
            "gateway-startup",
            "gateway-agent",
            "sandbox-all",
            "file-observe",
            "file-block",
            "network-observe",
            "network-block",
        ),
        default="all",
    )
    parser.add_argument("--output-dir", help="directory where scenario artifacts will be written")
    parser.add_argument("--gateway-port", type=int, help="gateway port override; defaults to the first free port at or above 19001")
    parser.add_argument("--gateway-token", help="override the gateway token used by the gateway-agent scenario")
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="accepted for compatibility; smoke artifacts are always kept under the output directory",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_prerequisites()
    output_root = resolve_output_root(args.output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    scenario_names = resolve_scenarios(args.scenario)
    results: list[ScenarioResult] = []

    for scenario_name in scenario_names:
        try:
            result = run_scenario(scenario_name, output_root, args)
        except VerificationError as exc:
            scenario_output = output_root / scenario_name
            scenario_output.mkdir(parents=True, exist_ok=True)
            result = ScenarioResult(name=scenario_name, passed=False, output_dir=scenario_output, details=[str(exc)])
        results.append(result)

    print_summary(output_root, results)
    return 0 if all(result.passed for result in results) else 1


def resolve_scenarios(scenario: str) -> list[str]:
    if scenario == "all":
        return ["isolated-observe", "isolated-block", "gateway-startup"]
    if scenario == "sandbox-all":
        return ["file-observe", "file-block", "network-observe", "network-block"]
    return [scenario]


def ensure_prerequisites() -> None:
    missing = [path for path in (DRIVER_PATH, PROBE_PATH, OPENCLAW_GATEWAY_ENTRYPOINT) if not path.exists()]
    if missing:
        raise VerificationError(f"missing required files: {', '.join(str(path) for path in missing)}")


def resolve_output_root(explicit_output_dir: str | None) -> Path:
    if explicit_output_dir:
        return Path(explicit_output_dir).expanduser().resolve()
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return DEFAULT_OUTPUT_ROOT / timestamp


def run_scenario(name: str, output_root: Path, args: argparse.Namespace) -> ScenarioResult:
    scenario_output = output_root / name
    scenario_output.mkdir(parents=True, exist_ok=True)

    handlers: dict[str, Callable[[Path, argparse.Namespace], ScenarioResult]] = {
        "isolated-observe": run_isolated_observe,
        "isolated-block": run_isolated_block,
        "gateway-startup": run_gateway_startup,
        "gateway-agent": run_gateway_agent,
        "file-observe": run_file_observe,
        "file-block": run_file_block,
        "network-observe": run_network_observe,
        "network-block": run_network_block,
    }
    return handlers[name](scenario_output, args)


def run_isolated_observe(output_dir: Path, _args: argparse.Namespace) -> ScenarioResult:
    probe_run = run_driver_probe(output_dir, mode="observe", sample="observe")

    require_success(probe_run.command_result, "isolated-observe driver/probe invocation failed")
    assert_event(probe_run.records, lambda event: event.get("phase") == "spawn_intent", "missing spawn_intent event")
    assert_event(
        probe_run.records,
        lambda event: event.get("phase") == "exec_call" and event.get("exe") == "/bin/sh",
        "missing /bin/sh exec_call event",
    )
    assert_event(
        probe_run.records,
        lambda event: event.get("phase") == "stdout" and "FRIDA_STDOUT" in str(event.get("chunk", "")),
        "missing stdout chunk containing FRIDA_STDOUT",
    )
    assert_event(probe_run.records, lambda event: event.get("phase") == "exit", "missing exit event")
    assert_probe_field(probe_run.payload, ("ok",), True, "probe did not report ok=true")
    assert_probe_field(probe_run.payload, ("result", "stdout"), "FRIDA_STDOUT", "probe stdout mismatch")
    assert_probe_field(probe_run.payload, ("result", "stderr"), "FRIDA_STDERR", "probe stderr mismatch")

    return probe_run_result("isolated-observe", output_dir, probe_run)


def run_isolated_block(output_dir: Path, _args: argparse.Namespace) -> ScenarioResult:
    probe_run = run_driver_probe(output_dir, mode="block", sample="block", deny_exe_regex="^/usr/bin/id$")

    require_success(probe_run.command_result, "isolated-block driver/probe invocation failed")
    assert_event(
        probe_run.records,
        lambda event: event.get("phase") == "spawn_intent" and event.get("blocked") is True,
        "missing blocked spawn_intent event",
    )
    assert_event(probe_run.records, lambda event: event.get("phase") == "spawn_blocked", "missing spawn_blocked event")
    assert_probe_field(probe_run.payload, ("ok",), True, "probe did not report ok=true")
    assert_probe_field(probe_run.payload, ("blocked",), True, "probe did not report blocked=true")

    return probe_run_result("isolated-block", output_dir, probe_run)


def run_file_observe(output_dir: Path, _args: argparse.Namespace) -> ScenarioResult:
    source_path = output_dir / "source.txt"
    dest_path = output_dir / "dest.txt"
    source_path.write_text("sandbox source\n", encoding="utf-8")

    probe_run = run_driver_probe(
        output_dir,
        mode="observe",
        enable_filesystem_hooks=True,
        argv=[
            "/usr/bin/python3",
            "-c",
            FILE_OBSERVE_SNIPPET,
            str(source_path),
            str(dest_path),
        ],
    )

    require_success(probe_run.command_result, "file-observe driver/probe invocation failed")
    assert_probe_field(probe_run.payload, ("ok",), True, "file-observe probe did not report ok=true")
    assert_probe_field(
        probe_run.payload,
        ("result", "stdout"),
        "FILE_OBSERVE_OK\n",
        "file-observe runtime stdout mismatch",
    )
    assert_event(
        probe_run.records,
        lambda event: event.get("resource") == "filesystem"
        and event.get("op") == "open_read"
        and event.get("path") == str(source_path),
        "missing file_open_read event for the source file",
    )
    assert_event(
        probe_run.records,
        lambda event: event.get("resource") == "filesystem"
        and event.get("path") == str(dest_path)
        and event.get("op") in {"create", "open_write"},
        "missing file write/create event for the destination file",
    )
    if not dest_path.exists():
        raise VerificationError(f"file-observe did not create the destination file: {dest_path}")

    return ScenarioResult(
        name="file-observe",
        passed=True,
        output_dir=output_dir,
        details=[
            f"source={source_path}",
            f"dest={dest_path}",
            f"stdout={probe_run.stdout_path}",
            f"stderr={probe_run.stderr_path}",
            f"jsonl={probe_run.jsonl_path}",
        ],
    )


def run_file_block(output_dir: Path, _args: argparse.Namespace) -> ScenarioResult:
    protected_path = output_dir / "protected-write.txt"
    policy_path = output_dir / "policy.json"
    write_json(
        policy_path,
        {
            "exec": [],
            "filesystem": [
                {
                    "id": "deny-protected-write",
                    "pathRegex": f"^{re.escape(str(protected_path))}$",
                    "ops": ["create", "open_write"],
                }
            ],
            "network": [],
        },
    )

    probe_run = run_driver_probe(
        output_dir,
        mode="block",
        enable_filesystem_hooks=True,
        argv=[
            "/usr/bin/python3",
            "-c",
            FILE_BLOCK_SNIPPET,
            str(protected_path),
        ],
        expect_block=True,
        policy_file=policy_path,
    )

    require_success(probe_run.command_result, "file-block driver/probe invocation failed")
    assert_probe_field(probe_run.payload, ("ok",), True, "file-block probe did not report ok=true")
    assert_probe_field(probe_run.payload, ("blocked",), True, "file-block probe did not report blocked=true")
    assert_event(
        probe_run.records,
        lambda event: event.get("resource") == "filesystem"
        and event.get("path") == str(protected_path)
        and event.get("blocked") is True
        and event.get("rule_id") == "deny-protected-write",
        "missing blocked filesystem event for the protected path",
    )
    if protected_path.exists():
        raise VerificationError(f"file-block unexpectedly created the protected file: {protected_path}")

    return ScenarioResult(
        name="file-block",
        passed=True,
        output_dir=output_dir,
        details=[
            f"protected_path={protected_path}",
            f"policy={policy_path}",
            f"stdout={probe_run.stdout_path}",
            f"stderr={probe_run.stderr_path}",
            f"jsonl={probe_run.jsonl_path}",
        ],
    )


def run_network_observe(output_dir: Path, _args: argparse.Namespace) -> ScenarioResult:
    fixture = LocalHttpFixture(output_dir)
    fixture.start()
    try:
        probe_run = run_driver_probe(
            output_dir,
            mode="observe",
            enable_network_hooks=True,
            argv=[
                "/usr/bin/python3",
                "-c",
                NETWORK_REQUEST_SNIPPET,
                fixture.url,
            ],
        )
    finally:
        fixture.stop()

    require_success(probe_run.command_result, "network-observe driver/probe invocation failed")
    assert_probe_field(probe_run.payload, ("ok",), True, "network-observe probe did not report ok=true")
    assert_probe_field(
        probe_run.payload,
        ("result", "stdout"),
        "NETWORK_OBSERVE_OK\n",
        "network-observe runtime stdout mismatch",
    )
    assert_event(
        probe_run.records,
        lambda event: event.get("resource") == "network"
        and event.get("phase") in {"net_connect", "dns_query"},
        "missing network observe event",
    )
    assert_event(
        probe_run.records,
        lambda event: event.get("resource") == "network"
        and event.get("phase") == "net_connect"
        and event.get("address") == "127.0.0.1"
        and event.get("port") == fixture.port,
        "missing net_connect event for the local HTTP server",
    )
    if not fixture.requests:
        raise VerificationError("network-observe did not reach the local HTTP server")

    return ScenarioResult(
        name="network-observe",
        passed=True,
        output_dir=output_dir,
        details=[
            f"url={fixture.url}",
            f"requests={fixture.request_log_path}",
            f"stdout={probe_run.stdout_path}",
            f"stderr={probe_run.stderr_path}",
            f"jsonl={probe_run.jsonl_path}",
        ],
    )


def run_network_block(output_dir: Path, _args: argparse.Namespace) -> ScenarioResult:
    fixture = LocalHttpFixture(output_dir)
    fixture.start()
    policy_path = output_dir / "policy.json"
    write_json(
        policy_path,
        {
            "exec": [],
            "filesystem": [],
            "network": [
                {
                    "id": "deny-local-http",
                    "addressRegex": r"^127\.0\.0\.1$",
                    "ports": [fixture.port],
                    "ops": ["connect", "sendto"],
                }
            ],
        },
    )
    try:
        probe_run = run_driver_probe(
            output_dir,
            mode="block",
            enable_network_hooks=True,
            argv=[
                "/usr/bin/python3",
                "-c",
                NETWORK_REQUEST_SNIPPET,
                fixture.url,
            ],
            expect_block=True,
            policy_file=policy_path,
        )
    finally:
        fixture.stop()

    require_success(probe_run.command_result, "network-block driver/probe invocation failed")
    assert_probe_field(probe_run.payload, ("ok",), True, "network-block probe did not report ok=true")
    assert_probe_field(probe_run.payload, ("blocked",), True, "network-block probe did not report blocked=true")
    assert_event(
        probe_run.records,
        lambda event: event.get("resource") == "network"
        and event.get("phase") in {"net_connect", "net_sendto"}
        and event.get("blocked") is True
        and event.get("rule_id") == "deny-local-http",
        "missing blocked network event for the local HTTP server",
    )
    if fixture.requests:
        raise VerificationError(f"network-block unexpectedly reached the local HTTP server: {fixture.requests}")

    return ScenarioResult(
        name="network-block",
        passed=True,
        output_dir=output_dir,
        details=[
            f"url={fixture.url}",
            f"policy={policy_path}",
            f"requests={fixture.request_log_path}",
            f"stdout={probe_run.stdout_path}",
            f"stderr={probe_run.stderr_path}",
            f"jsonl={probe_run.jsonl_path}",
        ],
    )


def run_gateway_startup(output_dir: Path, args: argparse.Namespace) -> ScenarioResult:
    gateway_port = resolve_gateway_port(args.gateway_port)
    gateway = start_gateway_driver(output_dir, gateway_port)
    port_ready = False
    matched_event: dict[str, Any] | None = None

    try:
        deadline = time.monotonic() + DEFAULT_GATEWAY_ACTIVITY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if not port_ready and is_tcp_port_open(gateway_port):
                port_ready = True

            records = load_jsonl(gateway.jsonl_path)
            matched_event = find_gateway_activity(records)
            if matched_event is not None:
                break

            if gateway.process.poll() is not None:
                raise VerificationError(
                    "gateway-startup exited before expected runtime activity appeared; "
                    f"see {gateway.stderr_path}"
                )
            time.sleep(0.25)

        if matched_event is None:
            raise VerificationError(
                "gateway-startup did not capture expected runtime child activity within timeout; "
                f"see {gateway.jsonl_path} and {gateway.stderr_path}"
            )
    finally:
        stop_process_tree(gateway.process)

    detail = format_gateway_match(matched_event)
    if port_ready:
        detail = f"port={gateway_port} ready; {detail}"

    return ScenarioResult(
        name="gateway-startup",
        passed=True,
        output_dir=output_dir,
        details=[
            detail,
            f"stdout={gateway.stdout_path}",
            f"stderr={gateway.stderr_path}",
            f"jsonl={gateway.jsonl_path}",
        ],
    )


def run_gateway_agent(output_dir: Path, args: argparse.Namespace) -> ScenarioResult:
    gateway_port = resolve_gateway_port(args.gateway_port)
    gateway = start_gateway_driver(output_dir, gateway_port)
    token = args.gateway_token or load_gateway_token()
    agent_stdout = output_dir / "agent.stdout"
    agent_stderr = output_dir / "agent.stderr"

    try:
        wait_for_condition(
            lambda: is_tcp_port_open(gateway_port),
            timeout_seconds=DEFAULT_GATEWAY_ACTIVITY_TIMEOUT_SECONDS,
            failure_message=f"gateway port {gateway_port} did not become ready",
        )
        agent_env = os.environ.copy()
        agent_env["OPENCLAW_GATEWAY_URL"] = f"ws://127.0.0.1:{gateway_port}"
        agent_env["OPENCLAW_GATEWAY_TOKEN"] = token
        agent_result = run_command(
            [
                "openclaw",
                "agent",
                "--to",
                AGENT_TARGET,
                "--message",
                AGENT_MESSAGE,
                "--json",
                "--timeout",
                str(int(DEFAULT_AGENT_TIMEOUT_SECONDS)),
            ],
            agent_stdout,
            agent_stderr,
            timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
            env=agent_env,
        )
        require_success(agent_result, "gateway-agent command failed")

        target_event = wait_for_condition(
            lambda: find_agent_activity(load_jsonl(gateway.jsonl_path)),
            timeout_seconds=10.0,
            failure_message=(
                "gateway-agent completed without matching runtime activity; "
                f"see {gateway.jsonl_path}, {agent_stdout}, and {agent_stderr}"
            ),
        )
    finally:
        stop_process_tree(gateway.process)

    return ScenarioResult(
        name="gateway-agent",
        passed=True,
        output_dir=output_dir,
        details=[
            format_gateway_match(target_event),
            f"agent_stdout={agent_stdout}",
            f"agent_stderr={agent_stderr}",
            f"jsonl={gateway.jsonl_path}",
        ],
    )


def run_driver_probe(
    output_dir: Path,
    *,
    mode: str,
    sample: str | None = None,
    argv: list[str] | None = None,
    expect_block: bool = False,
    policy_file: Path | None = None,
    deny_exe_regex: str | None = None,
    enable_filesystem_hooks: bool = False,
    enable_network_hooks: bool = False,
) -> ProbeRun:
    jsonl_path = output_dir / "events.jsonl"
    stdout_path = output_dir / "probe.stdout"
    stderr_path = output_dir / "probe.stderr"
    driver_argv = [
        "python3",
        str(DRIVER_PATH),
        "--mode",
        mode,
        "--spawn-program",
        "/usr/bin/node",
        f"--spawn-arg={PROBE_PATH}",
        "--jsonl",
        str(jsonl_path),
        "--exit-on-root-detach",
    ]
    if enable_filesystem_hooks:
        driver_argv.append("--enable-filesystem-hooks")
    if enable_network_hooks:
        driver_argv.append("--enable-network-hooks")
    if deny_exe_regex:
        driver_argv.extend(["--deny-exe-regex", deny_exe_regex])
    if policy_file is not None:
        driver_argv.extend(["--policy-file", str(policy_file)])
    if sample is not None:
        driver_argv.extend(["--spawn-arg=--sample", f"--spawn-arg={sample}"])
    if argv is not None:
        driver_argv.extend(["--spawn-arg=--argv-json", f"--spawn-arg={json.dumps(argv)}"])
    if expect_block:
        driver_argv.append("--spawn-arg=--expect-block")

    command_result = run_command(
        driver_argv,
        stdout_path,
        stderr_path,
        timeout_seconds=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    payload = load_json_payload(stdout_path)
    records = load_jsonl(jsonl_path)
    return ProbeRun(
        command_result=command_result,
        payload=payload,
        records=records,
        jsonl_path=jsonl_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def probe_run_result(name: str, output_dir: Path, probe_run: ProbeRun) -> ScenarioResult:
    return ScenarioResult(
        name=name,
        passed=True,
        output_dir=output_dir,
        details=[
            f"events={len(probe_run.records)}",
            f"stdout={probe_run.stdout_path}",
            f"stderr={probe_run.stderr_path}",
            f"jsonl={probe_run.jsonl_path}",
        ],
    )


def start_gateway_driver(output_dir: Path, gateway_port: int) -> GatewayDriver:
    jsonl_path = output_dir / "gateway.events.jsonl"
    stdout_path = output_dir / "gateway.stdout"
    stderr_path = output_dir / "gateway.stderr"
    argv = [
        "python3",
        str(DRIVER_PATH),
        "--mode",
        "observe",
        "--spawn-program",
        "/usr/bin/node",
        f"--spawn-arg={OPENCLAW_GATEWAY_ENTRYPOINT}",
        "--spawn-arg=gateway",
        "--spawn-arg=--port",
        f"--spawn-arg={gateway_port}",
        "--jsonl",
        str(jsonl_path),
    ]
    stdout_handle = stdout_path.open("w", encoding="utf-8")
    stderr_handle = stderr_path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(REPO_ROOT),
            env=os.environ.copy(),
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            start_new_session=True,
        )
    finally:
        stdout_handle.close()
        stderr_handle.close()
    return GatewayDriver(
        process=process,
        output_dir=output_dir,
        jsonl_path=jsonl_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        port=gateway_port,
    )


def run_command(
    argv: list[str],
    stdout_path: Path,
    stderr_path: Path,
    *,
    timeout_seconds: float,
    env: dict[str, str] | None = None,
) -> CommandResult:
    try:
        completed = subprocess.run(
            argv,
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout_path.write_text(completed.stdout, encoding="utf-8")
        stderr_path.write_text(completed.stderr, encoding="utf-8")
        return CommandResult(argv=argv, returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        return CommandResult(argv=argv, returncode=124, stdout=stdout, stderr=stderr, timed_out=True)


def require_success(result: CommandResult, message: str) -> None:
    if result.timed_out:
        raise VerificationError(f"{message}: command timed out: {' '.join(result.argv)}")
    if result.returncode != 0:
        raise VerificationError(f"{message}: exit={result.returncode}: {' '.join(result.argv)}")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def load_json_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise VerificationError(f"missing expected JSON output: {path}")
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise VerificationError(f"empty expected JSON output: {path}")
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"invalid JSON output in {path}: {exc}") from exc


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def assert_event(records: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool], message: str) -> dict[str, Any]:
    for event in records:
        if predicate(event):
            return event
    raise VerificationError(message)


def assert_probe_field(payload: dict[str, Any], path: tuple[str, ...], expected: Any, message: str) -> None:
    value: Any = payload
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise VerificationError(f"{message}: missing {'.'.join(path)}")
        value = value[key]
    if value != expected:
        raise VerificationError(f"{message}: expected {expected!r}, got {value!r}")


def ensure_port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise VerificationError(f"gateway port {port} is already in use; rerun with --gateway-port: {exc}") from exc


def reserve_port(start_port: int, scan_count: int) -> int:
    for port in range(start_port, start_port + scan_count):
        try:
            ensure_port_available(port)
            return port
        except VerificationError:
            continue
    raise VerificationError(f"no free local port found in range {start_port}-{start_port + scan_count - 1}")


def resolve_gateway_port(requested_port: int | None) -> int:
    if requested_port is not None:
        ensure_port_available(requested_port)
        return requested_port
    return reserve_port(DEFAULT_GATEWAY_PORT, DEFAULT_PORT_SCAN_COUNT)


def is_tcp_port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def wait_for_condition(
    callback: Callable[[], Any],
    *,
    timeout_seconds: float,
    failure_message: str,
) -> Any:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        value = callback()
        if value:
            return value
        time.sleep(0.25)
    raise VerificationError(failure_message)


def stop_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=5)


def find_gateway_activity(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in records:
        if event.get("phase") not in {"spawn_intent", "exec_call"}:
            continue
        joined = event_text(event)
        if "ip neigh show" in joined or "/usr/bin/ip" in joined or "sqlite3 -version" in joined or "sqlite3" in joined:
            return event
    return None


def find_agent_activity(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in records:
        if event.get("phase") not in {"spawn_intent", "exec_call"}:
            continue
        joined = event_text(event)
        if "FRIDA_STDOUT" in joined or "FRIDA_STDERR" in joined:
            return event
    return None


def event_text(event: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("exe", "argv", "chunk", "path", "path2", "address"):
        value = event.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, list):
            parts.append(" ".join(str(item) for item in value))
        else:
            parts.append(str(value))
    if event.get("port") is not None:
        parts.append(str(event["port"]))
    return " ".join(parts)


def format_gateway_match(event: dict[str, Any] | None) -> str:
    if event is None:
        return "no matching runtime event recorded"
    return (
        f"matched phase={event.get('phase')} resource={event.get('resource')} "
        f"op={event.get('op')} exe={event.get('exe')} path={event.get('path')} "
        f"address={event.get('address')} port={event.get('port')} argv={event.get('argv')}"
    )


def load_gateway_token() -> str:
    if not OPENCLAW_CONFIG_PATH.exists():
        raise VerificationError(f"missing OpenClaw config: {OPENCLAW_CONFIG_PATH}")
    payload = json.loads(OPENCLAW_CONFIG_PATH.read_text(encoding="utf-8"))
    try:
        token = payload["gateway"]["auth"]["token"]
    except Exception as exc:  # pragma: no cover - defensive
        raise VerificationError(f"missing gateway token in {OPENCLAW_CONFIG_PATH}") from exc
    if not token:
        raise VerificationError(f"empty gateway token in {OPENCLAW_CONFIG_PATH}")
    return str(token)


def print_summary(output_root: Path, results: list[ScenarioResult]) -> None:
    print(f"Artifacts: {output_root}")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.name} -> {result.output_dir}")
        for detail in result.details:
            print(f"  - {detail}")


if __name__ == "__main__":
    raise SystemExit(main())
