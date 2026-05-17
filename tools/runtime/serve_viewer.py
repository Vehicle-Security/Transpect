from __future__ import annotations

import argparse
import json
import posixpath
import sys
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import (
    TRACE_LIVE_RUNS_DIR,
    TRACE_LIVE_RUNS_INDEX_PATH,
    TRACE_LIVE_DIR,
    TRACE_DASHBOARD_STATE_DIR,
    TRACE_VIEWER_DIR,
    WORKSPACE_ROOT,
    build_runs_index_payload,
)


def iso_from_mtime(path: Path) -> str | None:
    if not path.exists():
        return None
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def count_events(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


class ViewerHandler(SimpleHTTPRequestHandler):
    def _health_payload(self) -> dict[str, object]:
        runs_index = build_runs_index_payload(TRACE_LIVE_RUNS_DIR)
        latest = runs_index.get("latestRun") if isinstance(runs_index, dict) else None
        host = getattr(self.server, "public_host", "127.0.0.1")
        return {
            "ok": True,
            "viewerRoot": str(TRACE_VIEWER_DIR.resolve()),
            "viewerUrl": f"http://{host}:{self.server.server_port}/viewer/index.html",
            "runsRoot": str(TRACE_LIVE_RUNS_DIR.resolve()),
            "runsIndexPath": str(TRACE_LIVE_RUNS_INDEX_PATH.resolve()),
            "runsIndexExists": TRACE_LIVE_RUNS_INDEX_PATH.exists(),
            "runCount": runs_index.get("runCount"),
            "latestRun": latest,
        }

    def _send_runs_index(self) -> None:
        payload = json.dumps(build_runs_index_payload(TRACE_LIVE_RUNS_DIR), ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_health(self) -> None:
        payload = json.dumps(self._health_payload(), ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_health()
            return
        if self.path.startswith("/live/runs/index.json"):
            self._send_runs_index()
            return
        super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_health()
            return
        if self.path.startswith("/live/runs/index.json"):
            self._send_runs_index()
            return
        super().do_HEAD()

    def translate_path(self, path: str) -> str:
        if path == "/viewer" or path.startswith("/viewer/"):
            parsed_path = unquote(urlsplit(path).path)
            viewer_relative_path = posixpath.normpath(parsed_path.removeprefix("/viewer")).lstrip("/")
            safe_parts = [part for part in viewer_relative_path.split("/") if part and part not in {".", ".."}]
            return str(TRACE_VIEWER_DIR.joinpath(*safe_parts).resolve())
        if path == "/live" or path.startswith("/live/"):
            parsed_path = unquote(urlsplit(path).path)
            live_relative_path = posixpath.normpath(parsed_path.removeprefix("/live")).lstrip("/")
            safe_parts = [part for part in live_relative_path.split("/") if part and part not in {".", ".."}]
            return str(TRACE_LIVE_DIR.joinpath(*safe_parts).resolve())
        if path == "/state" or path.startswith("/state/"):
            parsed_path = unquote(urlsplit(path).path)
            state_relative_path = posixpath.normpath(parsed_path.removeprefix("/state")).lstrip("/")
            safe_parts = [part for part in state_relative_path.split("/") if part and part not in {".", ".."}]
            return str(TRACE_DASHBOARD_STATE_DIR.joinpath(*safe_parts).resolve())
        return super().translate_path(path)

    def log_message(self, format: str, *args: object) -> None:
        message = "%s - - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args,
        )
        sys.stdout.write(message)
        sys.stdout.flush()


class ViewerServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the Transpect viewer.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8711)
    args = parser.parse_args()

    handler = lambda *handler_args, **handler_kwargs: ViewerHandler(  # noqa: E731
        *handler_args,
        directory=str(WORKSPACE_ROOT),
        **handler_kwargs,
    )

    with ViewerServer((args.host, args.port), handler) as server:
        server.public_host = args.host
        viewer_url = f"http://{args.host}:{args.port}/viewer/index.html"
        health_url = f"http://{args.host}:{args.port}/health"
        print(
            json.dumps(
                {
                    "host": args.host,
                    "port": args.port,
                    "viewerUrl": viewer_url,
                    "healthUrl": health_url,
                    "runsRoot": str(TRACE_LIVE_RUNS_DIR.resolve()),
                    "runsIndexPath": str(TRACE_LIVE_RUNS_INDEX_PATH.resolve()),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
