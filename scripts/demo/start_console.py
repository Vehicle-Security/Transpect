#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urljoin
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[2]
CONSOLE_DIR = REPO_ROOT / "apps" / "console"
SHOWCASE_ROOT = REPO_ROOT / "state" / "showcase"
NEXT_CACHE = CONSOLE_DIR / ".next"


def can_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.75):
            return True
    except OSError:
        return False


def http_status(url: str) -> int | None:
    request = Request(url, method="HEAD")
    try:
        with urlopen(request, timeout=2) as response:
            return int(response.status)
    except HTTPError as exc:
        return int(exc.code)
    except (OSError, TimeoutError, URLError):
        return None


def read_url(url: str) -> str | None:
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=3) as response:
            return response.read().decode("utf-8", errors="replace")
    except (OSError, TimeoutError, URLError):
        return None


def clean_next_cache() -> None:
    shutil.rmtree(NEXT_CACHE, ignore_errors=True)


def stop_port_listeners(port: int) -> None:
    try:
        result = subprocess.run(
            ["lsof", f"-tiTCP:{port}", "-sTCP:LISTEN", "-n", "-P"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return
    pids = [pid.strip() for pid in result.stdout.splitlines() if pid.strip()]
    if not pids:
        return
    subprocess.run(["kill", *pids], check=False)


def stylesheet_status(url: str) -> tuple[bool, str]:
    html = read_url(url)
    if not html:
        return False, "home page unavailable"
    match = re.search(r'href="([^"]*\.css[^"]*)"', html)
    if not match:
        return False, "no stylesheet link found"
    stylesheet_url = urljoin(url + "/", match.group(1))
    status = http_status(stylesheet_url)
    if status == 200:
        return True, match.group(1)
    return False, f"{match.group(1)} returned HTTP {status or 'unavailable'}"


def check_console_app() -> list[str]:
    issues: list[str] = []
    if not (CONSOLE_DIR / "package.json").exists():
        issues.append(f"Missing {CONSOLE_DIR / 'package.json'}")
    if not (CONSOLE_DIR / "node_modules").exists():
        issues.append("Missing apps/console/node_modules. Run: cd apps/console && npm ci")
    return issues


def check_showcase_reports() -> tuple[list[str], int]:
    issues: list[str] = []
    index_path = SHOWCASE_ROOT / "index.json"
    if not index_path.exists():
        return [f"Missing {index_path}. Freeze showcase runs before starting the console."], 0
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"Invalid showcase index JSON: {exc}"], 0
    showcases = index.get("showcases")
    if not isinstance(showcases, list) or not showcases:
        return ["state/showcase/index.json does not list any showcases."], 0
    for showcase in showcases:
        if not isinstance(showcase, dict):
            issues.append("Showcase index contains a non-object entry.")
            continue
        showcase_id = str(showcase.get("id") or "<missing-id>")
        run_dir_text = str(showcase.get("runDir") or "").strip()
        run_dir = (REPO_ROOT / run_dir_text).resolve() if run_dir_text else SHOWCASE_ROOT / showcase_id
        report_model = run_dir / "report_model.json"
        if not report_model.exists():
            issues.append(f"Missing report model for {showcase_id}: {report_model}")
    return issues, len(showcases)


def print_check(label: str, ok: bool, detail: str = "") -> None:
    state = "OK" if ok else "FAILED"
    suffix = f"  {detail}" if detail else ""
    print(f"{label:<24} {state}{suffix}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start the Transpect Next.js Console with prerequisite checks.")
    parser.add_argument("--host", default="127.0.0.1", help="Host for Next.js dev server.")
    parser.add_argument("--port", type=int, default=5000, help="Port for Next.js dev server.")
    parser.add_argument("--check-only", action="store_true", help="Only check prerequisites and server state.")
    parser.add_argument("--clean", action="store_true", help="Remove apps/console/.next before starting.")
    parser.add_argument("--restart", action="store_true", help="Stop any listener on the target port before starting.")
    args = parser.parse_args(argv)

    url = f"http://{args.host}:{args.port}"
    if args.restart:
        stop_port_listeners(args.port)
    if args.clean or args.restart:
        clean_next_cache()

    app_issues = check_console_app()
    showcase_issues, showcase_count = check_showcase_reports()
    server_running = can_connect(args.host, args.port)
    status = http_status(url) if server_running else None
    styles_ok, styles_detail = stylesheet_status(url) if status == 200 else (False, "not checked")

    print("Transpect Console")
    print_check("Console app", not app_issues)
    print_check("Showcase reports", not showcase_issues, f"{showcase_count} showcase(s)")
    print_check("Console server", server_running and status == 200, url if server_running else "not running")
    if server_running and status == 200:
        print_check("Console styles", styles_ok, styles_detail)

    for issue in app_issues + showcase_issues:
        print(f"- {issue}", file=sys.stderr)
    if app_issues or showcase_issues:
        return 2

    if server_running:
        if status == 200 and styles_ok:
            print(f"\nOpen: {url}")
            return 0
        if not args.check_only:
            print("- Existing Console server is unhealthy. Restarting with a clean Next.js cache.", file=sys.stderr)
            stop_port_listeners(args.port)
            clean_next_cache()
            server_running = False
        else:
            if status == 200:
                print(
                    "- Console HTML is reachable, but its stylesheet is not. "
                    "Restart with: python scripts/demo/start_console.py --port "
                    f"{args.port} --restart",
                    file=sys.stderr,
                )
                return 3
            print(f"- Port {args.port} is in use, but {url} did not return HTTP 200.", file=sys.stderr)
            return 3

    if server_running:
        # This branch is intentionally unreachable after the restart path above,
        # but keeps the control flow explicit for future edits.
        return 3

    if args.check_only:
        print(f"\nConsole is ready to start: cd apps/console && npm run dev -- --hostname {args.host} --port {args.port}")
        return 0

    print(f"\nStarting Next.js Console at {url}")
    print("Press Ctrl+C to stop the console.")
    return subprocess.call(
        ["npm", "run", "dev", "--", "--hostname", args.host, "--port", str(args.port)],
        cwd=CONSOLE_DIR,
    )


if __name__ == "__main__":
    raise SystemExit(main())
