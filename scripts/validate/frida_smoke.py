#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "common"))

from app.instrumentation.frida import FridaTraceConfig, FridaTraceManager  # noqa: E402
from trace_common import now_utc_iso  # noqa: E402


class SmokeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b'{"ok":true,"source":"transpect-frida-smoke"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


HELPER_JS = r"""
'use strict';

const fs = require('fs');
const http = require('http');
const childProcess = require('child_process');

const sensitivePath = process.argv[2];
const port = Number(process.argv[3]);

setTimeout(() => {
  try {
    fs.readFileSync(sensitivePath, 'utf8');
    fs.statSync(sensitivePath);
  } catch (error) {
    console.error('file smoke failed', error.message);
  }

  try {
    childProcess.spawnSync(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore' });
  } catch (error) {
    console.error('spawn smoke failed', error.message);
  }

  try {
    const request = http.request({
      hostname: '127.0.0.1',
      port,
      path: '/frida-smoke?upload=false&file=demo',
      method: 'GET'
    }, (response) => {
      response.resume();
      response.on('end', () => {});
    });
    request.on('error', (error) => {
      console.error('http smoke failed', error.message);
    });
    request.end();
  } catch (error) {
    console.error('http smoke setup failed', error.message);
  }
}, 2500);

setTimeout(() => {
  process.exit(0);
}, 6500);
"""


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def resolve_node(explicit: str | None) -> str:
    if explicit:
        return explicit
    for candidate in ("/opt/homebrew/bin/node", shutil.which("node")):
        if candidate and Path(candidate).exists():
            return str(candidate)
    raise FileNotFoundError("node executable not found; pass --node")


def start_http_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), SmokeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def event_preview(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    preview: list[dict[str, Any]] = []
    for row in rows[:8]:
        preview.append(
            {
                "event_type": row.get("event_type"),
                "pid": row.get("pid"),
                "process_name": row.get("process_name"),
                "risk_tags": row.get("risk_tags"),
                "normalized": row.get("normalized"),
            }
        )
    return preview


def run_smoke(args: argparse.Namespace) -> dict[str, Any]:
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    node = resolve_node(args.node)
    server, _thread = start_http_server()
    port = int(server.server_address[1])
    started_at = now_utc_iso()

    with tempfile.TemporaryDirectory(prefix="transpect-openclaw-frida-smoke-") as tmp:
        tmp_dir = Path(tmp)
        helper_path = tmp_dir / "openclaw-frida-smoke.js"
        sensitive_path = tmp_dir / ".env.transpect-frida-smoke"
        helper_path.write_text(HELPER_JS, encoding="utf-8")
        sensitive_path.write_text("TRANSPECT_FRIDA_SMOKE_TOKEN=demo-only\n", encoding="utf-8")

        process = subprocess.Popen(
            [node, str(helper_path), str(sensitive_path), str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        manager = FridaTraceManager(
            FridaTraceConfig(
                enabled=True,
                target=f"pid:{process.pid}",
                output=str(output),
            )
        )
        start_result = manager.start(run_id="frida-smoke", session_id="smoke", started_at=started_at)
        try:
            try:
                stdout, stderr = process.communicate(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
        finally:
            stop_result = manager.stop().to_dict()
            server.shutdown()

    rows = read_jsonl(output)
    evidence_rows = [row for row in rows if row.get("event_type") not in {"process_event", ""}]
    event_types = sorted({str(row.get("event_type") or "") for row in rows if row.get("event_type")})
    risk_tags = sorted({str(tag) for row in rows for tag in (row.get("risk_tags") or [])})
    ok = bool(start_result.ok and evidence_rows)
    status = "ok" if ok else ("attach_failed" if not start_result.ok else "no_evidence")
    return {
        "schemaVersion": "transpect.frida-smoke.v1",
        "ok": ok,
        "status": status,
        "startedAt": started_at,
        "node": node,
        "target": f"pid:{process.pid}",
        "outputPath": str(output),
        "eventCount": len(rows),
        "evidenceEventCount": len(evidence_rows),
        "eventTypes": event_types,
        "riskTags": risk_tags,
        "start": start_result.to_dict(),
        "stop": stop_result,
        "helper": {
            "returncode": process.returncode,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
        },
        "eventsPreview": event_preview(rows),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a real Frida attach smoke test against a temporary Node helper.")
    parser.add_argument("--output", default=str(ROOT / "live" / "frida" / "smoke" / "frida-events.jsonl"))
    parser.add_argument("--node", help="Node executable used for the temporary smoke helper.")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--report", help="Write the JSON smoke report to this path in addition to stdout.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_smoke(args)
    if args.report:
        report_path = Path(args.report).expanduser().resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
