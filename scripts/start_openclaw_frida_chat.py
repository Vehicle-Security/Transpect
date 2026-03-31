#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from verify_openclaw_frida import (
    DRIVER_PATH,
    LocalHttpFixture,
    OPENCLAW_GATEWAY_ENTRYPOINT,
    REPO_ROOT,
    SIMPLE_SANDBOX_PRESET_NAME,
    SimpleSandboxPreset,
    is_tcp_port_open,
    load_gateway_token,
    materialize_simple_demo_preset,
    resolve_gateway_port,
    stop_process_tree,
)


DEFAULT_CHAT_OUTPUT_ROOT = REPO_ROOT / "artifacts" / "openclaw-chat"
DEFAULT_AGENT_TARGET = "+15555550123"
DEFAULT_AGENT_TIMEOUT_SECONDS = 600
DEFAULT_GATEWAY_READY_TIMEOUT_SECONDS = 75.0
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(line_buffering=True)


@dataclass
class GatewayRuntime:
    process: subprocess.Popen[str]
    port: int
    output_dir: Path
    jsonl_path: Path
    stdout_path: Path
    stderr_path: Path
    sandbox_preset: SimpleSandboxPreset | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Start a Frida-wrapped OpenClaw Gateway and chat through it while recording JSONL events"
    )
    parser.add_argument("--mode", choices=("observe", "block"), default="observe")
    parser.add_argument(
        "--output-dir",
        help="artifact directory; defaults to <repo>/artifacts/openclaw-chat/<timestamp>",
    )
    parser.add_argument("--gateway-port", type=int, help="gateway port override")
    parser.add_argument("--gateway-token", help="gateway token override")
    parser.add_argument("--policy-file", help="optional policy file for block mode or sandbox rules")
    parser.add_argument(
        "--sandbox-preset",
        choices=(SIMPLE_SANDBOX_PRESET_NAME,),
        help="start with a built-in sandbox preset instead of a custom policy file",
    )
    parser.add_argument("--to", default=DEFAULT_AGENT_TARGET, help="OpenClaw session target used by `openclaw agent`")
    parser.add_argument("--agent", help="optional OpenClaw agent id")
    parser.add_argument("--thinking", choices=("off", "minimal", "low", "medium", "high"))
    parser.add_argument("--timeout", type=int, default=DEFAULT_AGENT_TIMEOUT_SECONDS, help="agent turn timeout in seconds")
    parser.add_argument("--message", help="send one message and exit; omit to enter interactive mode")
    parser.add_argument(
        "--dashboard",
        action="store_true",
        default=False,
        help="open the OpenClaw dashboard URL and keep the gateway running instead of entering terminal chat mode",
    )
    parser.add_argument(
        "--no-dashboard-open",
        action="store_true",
        default=False,
        help="with --dashboard, print the dashboard URL without attempting to launch a browser",
    )
    parser.add_argument("--json", action="store_true", help="pass --json to `openclaw agent`")
    parser.add_argument(
        "--disable-filesystem-hooks",
        action="store_true",
        default=False,
        help="do not enable filesystem hook instrumentation",
    )
    parser.add_argument(
        "--disable-network-hooks",
        action="store_true",
        default=False,
        help="do not enable network hook instrumentation",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.mode == "block" and not args.policy_file:
        if args.sandbox_preset is None:
            raise SystemExit("--mode block requires --policy-file")
    if args.dashboard and args.message:
        raise SystemExit("--dashboard cannot be combined with --message")
    if args.sandbox_preset and args.policy_file:
        raise SystemExit("--sandbox-preset cannot be combined with --policy-file")
    if args.sandbox_preset and args.disable_filesystem_hooks:
        raise SystemExit("--sandbox-preset requires filesystem hooks; remove --disable-filesystem-hooks")
    if args.sandbox_preset and args.disable_network_hooks:
        raise SystemExit("--sandbox-preset requires network hooks; remove --disable-network-hooks")


def resolve_output_dir(explicit_output_dir: str | None) -> Path:
    if explicit_output_dir:
        return Path(explicit_output_dir).expanduser().resolve()
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return DEFAULT_CHAT_OUTPUT_ROOT / timestamp


def resolve_effective_mode(args: argparse.Namespace) -> str:
    if args.sandbox_preset == SIMPLE_SANDBOX_PRESET_NAME:
        return "block"
    return args.mode


def start_gateway(
    args: argparse.Namespace,
    output_dir: Path,
    *,
    mode: str,
    policy_file: Path | None,
    enable_filesystem_hooks: bool,
    enable_network_hooks: bool,
    sandbox_preset: SimpleSandboxPreset | None = None,
) -> GatewayRuntime:
    gateway_port = resolve_gateway_port(args.gateway_port)
    jsonl_path = output_dir / "gateway.events.jsonl"
    stdout_path = output_dir / "gateway.stdout"
    stderr_path = output_dir / "gateway.stderr"
    argv = [
        "python3",
        str(DRIVER_PATH),
        "--mode",
        mode,
        "--spawn-program",
        "/usr/bin/node",
        f"--spawn-arg={OPENCLAW_GATEWAY_ENTRYPOINT}",
        "--spawn-arg=gateway",
        "--spawn-arg=--port",
        f"--spawn-arg={gateway_port}",
        "--jsonl",
        str(jsonl_path),
    ]
    if enable_filesystem_hooks:
        argv.append("--enable-filesystem-hooks")
    if enable_network_hooks:
        argv.append("--enable-network-hooks")
    if policy_file is not None:
        argv.extend(["--policy-file", str(policy_file)])
    if args.gateway_token:
        argv.extend(["--spawn-arg=--token", f"--spawn-arg={args.gateway_token}"])

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

    deadline = time.monotonic() + DEFAULT_GATEWAY_READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if is_tcp_port_open(gateway_port):
            break
        if process.poll() is not None:
            raise RuntimeError(f"gateway exited before it became ready; see {stderr_path}")
        time.sleep(0.25)
    else:
        raise RuntimeError(f"gateway port {gateway_port} did not become ready; see {stderr_path}")
    return GatewayRuntime(
        process=process,
        port=gateway_port,
        output_dir=output_dir,
        jsonl_path=jsonl_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        sandbox_preset=sandbox_preset,
    )


def run_agent_turn(
    *,
    message: str,
    turn_index: int,
    args: argparse.Namespace,
    gateway: GatewayRuntime,
    gateway_token: str,
) -> int:
    turn_prefix = gateway.output_dir / f"turn-{turn_index:03d}"
    stdout_path = turn_prefix.with_suffix(".agent.stdout")
    stderr_path = turn_prefix.with_suffix(".agent.stderr")
    env = os.environ.copy()
    env["OPENCLAW_GATEWAY_URL"] = f"ws://127.0.0.1:{gateway.port}"
    env["OPENCLAW_GATEWAY_TOKEN"] = gateway_token
    argv = [
        "openclaw",
        "agent",
        "--to",
        args.to,
        "--message",
        message,
        "--timeout",
        str(args.timeout),
    ]
    if args.agent:
        argv.extend(["--agent", args.agent])
    if args.thinking:
        argv.extend(["--thinking", args.thinking])
    if args.json:
        argv.append("--json")

    completed = subprocess.run(
        argv,
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")

    if completed.stdout:
        print(completed.stdout.rstrip())
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr)
    print(f"[turn {turn_index}] stdout={stdout_path}")
    print(f"[turn {turn_index}] stderr={stderr_path}")
    print(f"[turn {turn_index}] jsonl={gateway.jsonl_path}")
    return completed.returncode


def print_banner(gateway: GatewayRuntime) -> None:
    print("Frida-wrapped OpenClaw session is ready.")
    print(f"gateway url: ws://127.0.0.1:{gateway.port}")
    if gateway.sandbox_preset is not None:
        print(f"sandbox preset: {gateway.sandbox_preset.name}")
        print(f"protected path: {gateway.sandbox_preset.protected_path}")
        print(f"blocked url: {gateway.sandbox_preset.blocked_url}")
        print(f"policy path: {gateway.sandbox_preset.policy_path}")
        print(f"targets path: {gateway.sandbox_preset.targets_path}")
    print(f"jsonl path: {gateway.jsonl_path}")
    print(f"gateway stdout: {gateway.stdout_path}")
    print(f"gateway stderr: {gateway.stderr_path}")
    print("type /exit to quit")
    print("type /paths to print artifact paths again")


def build_dashboard_url(gateway: GatewayRuntime, gateway_token: str) -> str:
    base_url = f"http://127.0.0.1:{gateway.port}/"
    if gateway_token:
        return f"{base_url}#token={quote(gateway_token)}"
    return base_url


def dashboard_loop(args: argparse.Namespace, gateway: GatewayRuntime, gateway_token: str) -> int:
    dashboard_url = build_dashboard_url(gateway, gateway_token)
    print("Frida-wrapped OpenClaw dashboard mode is ready.")
    print(f"gateway url: ws://127.0.0.1:{gateway.port}")
    print(f"dashboard url: {dashboard_url}")
    if gateway.sandbox_preset is not None:
        print(f"sandbox preset: {gateway.sandbox_preset.name}")
        print(f"protected path: {gateway.sandbox_preset.protected_path}")
        print(f"blocked url: {gateway.sandbox_preset.blocked_url}")
        print(f"policy path: {gateway.sandbox_preset.policy_path}")
        print(f"targets path: {gateway.sandbox_preset.targets_path}")
    print(f"jsonl path: {gateway.jsonl_path}")
    print(f"gateway stdout: {gateway.stdout_path}")
    print(f"gateway stderr: {gateway.stderr_path}")

    if args.no_dashboard_open:
        print("browser launch skipped (--no-dashboard-open)")
    else:
        try:
            opened = webbrowser.open(dashboard_url, new=2)
        except Exception as exc:  # pragma: no cover - desktop integration varies by host
            opened = False
            print(f"browser launch failed: {exc}", file=sys.stderr)
        if opened:
            print("opened dashboard in your browser")
        else:
            print("browser launch unavailable; open the dashboard URL manually")

    print("press Ctrl-C to stop the gateway")
    while True:
        return_code = gateway.process.poll()
        if return_code is not None:
            print(f"gateway exited with code {return_code}", file=sys.stderr)
            return return_code
        time.sleep(1.0)


def install_signal_handlers(gateway: GatewayRuntime) -> None:
    def _handle_signal(signum: int, _frame: object) -> None:
        print(f"\nreceived signal {signum}, stopping gateway...", file=sys.stderr)
        stop_process_tree(gateway.process)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)


def interactive_loop(args: argparse.Namespace, gateway: GatewayRuntime, gateway_token: str) -> int:
    print_banner(gateway)
    turn_index = 1
    while True:
        try:
            message = input("openclaw> ").strip()
        except EOFError:
            print()
            return 0
        if not message:
            continue
        if message in {"/exit", "exit", "quit"}:
            return 0
        if message == "/paths":
            print_banner(gateway)
            continue
        exit_code = run_agent_turn(
            message=message,
            turn_index=turn_index,
            args=args,
            gateway=gateway,
            gateway_token=gateway_token,
        )
        turn_index += 1
        if exit_code != 0:
            print(f"agent exited with code {exit_code}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    validate_args(args)
    output_dir = resolve_output_dir(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    sandbox_fixture: LocalHttpFixture | None = None
    sandbox_preset: SimpleSandboxPreset | None = None
    gateway: GatewayRuntime | None = None
    if args.sandbox_preset == SIMPLE_SANDBOX_PRESET_NAME:
        sandbox_fixture = LocalHttpFixture(output_dir)
        sandbox_fixture.start()
        sandbox_preset = materialize_simple_demo_preset(output_dir, blocked_port=sandbox_fixture.port)

    try:
        gateway_token = args.gateway_token or load_gateway_token()
        policy_file = sandbox_preset.policy_path if sandbox_preset is not None else (
            Path(args.policy_file).expanduser().resolve() if args.policy_file else None
        )
        gateway = start_gateway(
            args,
            output_dir,
            mode=resolve_effective_mode(args),
            policy_file=policy_file,
            enable_filesystem_hooks=sandbox_preset is not None or not args.disable_filesystem_hooks,
            enable_network_hooks=sandbox_preset is not None or not args.disable_network_hooks,
            sandbox_preset=sandbox_preset,
        )
        install_signal_handlers(gateway)
        if args.message:
            return run_agent_turn(
                message=args.message,
                turn_index=1,
                args=args,
                gateway=gateway,
                gateway_token=gateway_token,
            )
        if args.dashboard:
            return dashboard_loop(args, gateway, gateway_token)
        return interactive_loop(args, gateway, gateway_token)
    finally:
        if gateway is not None:
            stop_process_tree(gateway.process)
        if sandbox_fixture is not None:
            sandbox_fixture.stop()


if __name__ == "__main__":
    raise SystemExit(main())
