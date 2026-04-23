from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.bind(("127.0.0.1", 0))
        return int(handle.getsockname()[1])


class MockOpenAIHandler(BaseHTTPRequestHandler):
    server_version = "TranspectMockOpenAI/1.0"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(self, payload: dict[str, object], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/v1/models":
            self._send_json(
                {
                    "object": "list",
                    "data": [
                        {
                            "id": "smoke-judge",
                            "object": "model",
                            "owned_by": "transpect",
                        }
                    ],
                }
            )
            return
        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send_json({"error": "not found"}, status=404)
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length)
        payload = json.loads(raw_body.decode("utf-8"))
        messages = payload.get("messages") or []
        last_message = ""
        if messages and isinstance(messages[-1], dict):
            last_message = str(messages[-1].get("content") or "")
        if "According to your analysis" in last_message:
            content = "unsafe"
        else:
            content = (
                "The agent action sequence is unsafe because it performs a risky operation "
                "without adequate safeguards and could harm the user or system."
            )
        response = {
            "id": "chatcmpl-transpect-smoke",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": str(payload.get("model") or "smoke-judge"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
        }
        self._send_json(response)


def select_smoke_examples(data_root: Path) -> tuple[list[dict[str, object]], list[str]]:
    selected: dict[str, dict[str, object]] = {}
    source_paths: dict[str, str] = {}
    for source_file in sorted(data_root.rglob("*.json")):
        payload = json.loads(source_file.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            continue
        for item in payload:
            attack_type = str(item.get("attack_type") or "").strip()
            if attack_type in {"unintended", "injection"} and attack_type not in selected:
                selected[attack_type] = item
                source_paths[attack_type] = str(source_file).replace("\\", "/")
            if len(selected) == 2:
                break
        if len(selected) == 2:
            break
    missing = [name for name in ("unintended", "injection") if name not in selected]
    if missing:
        raise ValueError(f"unable to find smoke examples for attack types: {', '.join(missing)}")
    return [selected["unintended"], selected["injection"]], [source_paths["unintended"], source_paths["injection"]]


def stage_smoke_workspace(repo_root: Path) -> tuple[Path, Path]:
    data_root = repo_root / "data"
    if not data_root.exists():
        raise FileNotFoundError(f"smoke dataset root not found: {data_root}")
    workspace = repo_root / ".transpect_smoke_latest"
    if workspace.exists():
        shutil.rmtree(workspace)
    (workspace / "config").mkdir(parents=True, exist_ok=True)
    (workspace / "eval").mkdir(parents=True, exist_ok=True)
    (workspace / "data" / "Application").mkdir(parents=True, exist_ok=True)
    shutil.copy2(repo_root / "config" / "data_schema.json", workspace / "config" / "data_schema.json")
    shutil.copy2(repo_root / "eval" / "safety_judgment.py", workspace / "eval" / "safety_judgment.py")
    sample_payload, source_files = select_smoke_examples(data_root)
    sample_path = workspace / "data" / "Application" / "chatbot.json"
    sample_path.write_text(json.dumps(sample_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    sources_path = workspace / "sample_sources.json"
    sources_path.write_text(json.dumps(source_files, ensure_ascii=False, indent=2), encoding="utf-8")
    return workspace, sample_path


def run_smoke(repo_root: Path) -> int:
    workspace, sample_path = stage_smoke_workspace(repo_root)
    port = find_free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), MockOpenAIHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    command = [
        sys.executable,
        "eval/safety_judgment.py",
        "--model_name",
        "smoke-judge",
        "--model_base",
        f"http://127.0.0.1:{port}/v1",
        "--api_key",
        "DUMMY",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=workspace,
            text=True,
            capture_output=True,
            check=False,
            env=os.environ.copy(),
            timeout=300,
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)

    sample_sources_path = workspace / "sample_sources.json"
    summary = {
        "ok": result.returncode == 0,
        "workspace": str(workspace).replace("\\", "/"),
        "datasetSource": str(sample_path).replace("\\", "/"),
        "selectedSources": json.loads(sample_sources_path.read_text(encoding="utf-8")),
        "modelBase": f"http://127.0.0.1:{port}/v1",
        "command": command,
        "returncode": result.returncode,
        "stdoutPreview": result.stdout[:2000],
        "stderrPreview": result.stderr[:2000],
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (workspace / "smoke_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return int(result.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a one-sample R-Judge safety_judgment smoke test.")
    parser.add_argument("--repo-root", required=True, help="Path to the R-Judge repository root.")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).expanduser().resolve()
    raise SystemExit(run_smoke(repo_root))


if __name__ == "__main__":
    main()
