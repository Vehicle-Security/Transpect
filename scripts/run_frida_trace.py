"""Standalone Frida trace smoke-test tool.

Usage examples:

    # Trace all auto-detected targets for 30 seconds
    python scripts/run_frida_trace.py --target auto --duration 30 --output live/frida/frida-smoke.jsonl

    # Trace a specific Node process
    python scripts/run_frida_trace.py --target node --duration 60

    # Trace by PID
    python scripts/run_frida_trace.py --target pid:12345 --duration 30
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.instrumentation.frida.config import FridaTraceConfig
from app.instrumentation.frida.frida_manager import FridaTraceManager


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Standalone Frida runtime trace smoke test.")
    parser.add_argument("--target", default="auto", help="auto|node|chrome|pid:<PID>|name:<NAME>")
    parser.add_argument("--duration", type=int, default=30, help="Seconds to trace (default: 30).")
    parser.add_argument("--output", default="live/frida/frida-smoke.jsonl", help="Output JSONL path.")
    parser.add_argument("--self-test", action="store_true", help="Run Frida preflight and print resolution, then exit unless tracing is explicitly requested.")
    parser.add_argument("--print-frida-resolution", action="store_true", help="Print FridaResolution JSON before attaching.")
    parser.add_argument("--frida-self-attach-check", action="store_true", help="Attempt to attach to the current process on macOS to verify task_for_pid authorization.")
    args = parser.parse_args(argv)

    from app.instrumentation.frida.frida_resolver import FridaResolver
    resolver = FridaResolver()
    res = resolver.resolve(self_attach_check=args.frida_self_attach_check)

    if args.self_test or args.print_frida_resolution:
        print(json.dumps(res.to_dict(), indent=2, default=str))

    if args.self_test:
        sys.exit(0 if res.attach_ready else 1)

    config = FridaTraceConfig(
        enabled=True,
        target=args.target,
        output=args.output,
        timeout_seconds=args.duration,
    )
    manager = FridaTraceManager(config)

    started_at = _now_iso()
    print(f"Starting Frida trace: target={args.target}, duration={args.duration}s, output={args.output}")

    start_result = manager.start(run_id="smoke-test", session_id=None, started_at=started_at)
    print(json.dumps(start_result.to_dict(), indent=2, default=str))

    if not start_result.ok:
        print("Frida trace could not attach. See warnings above.", file=sys.stderr)
        sys.exit(1)

    print(f"Tracing for {args.duration} seconds... (Ctrl-C to stop early)")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")

    stop_result = manager.stop()
    print(json.dumps(stop_result.to_dict(), indent=2, default=str))
    print(f"Done. {stop_result.event_count} event(s) written to {args.output}")


if __name__ == "__main__":
    main()
