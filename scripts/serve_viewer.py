from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from trace_common import TRACE_LIVE_DIR, WORKSPACE_ROOT


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
        live_path = TRACE_LIVE_DIR / "behavior-events.jsonl"
        host = getattr(self.server, "public_host", "127.0.0.1")
        return {
            "ok": True,
            "viewerRoot": str((WORKSPACE_ROOT / "viewer").resolve()),
            "viewerUrl": f"http://{host}:{self.server.server_port}/viewer/index.html",
            "liveJsonlPath": str(live_path.resolve()),
            "liveExists": live_path.exists(),
            "liveBytes": live_path.stat().st_size if live_path.exists() else 0,
            "liveMtime": iso_from_mtime(live_path),
            "eventCount": count_events(live_path),
        }

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
        super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_health()
            return
        super().do_HEAD()

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
                    "liveJsonlPath": str((TRACE_LIVE_DIR / "behavior-events.jsonl").resolve()),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
