from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT / "common"))
sys.path.insert(0, str(SCRIPTS_ROOT / "demo"))

from trace_common import build_runs_index_payload, write_json  # noqa: E402


class ShowcaseWrapperTests(unittest.TestCase):
    def make_run(self, root: Path, name: str, *, created_at: str, status: str = "completed", showcase: bool = False) -> Path:
        run_dir = root / name
        write_json(
            run_dir / "manifest.json",
            {
                "schemaVersion": "openclaw.run.v1",
                "runId": name,
                "traceId": f"trace-{name}",
                "createdAt": created_at,
                "completedAt": None if status == "running" else created_at,
                "status": status,
                "eventCount": 1,
                "showcase": showcase,
            },
        )
        (run_dir / "behavior-events.jsonl").write_text(
            json.dumps(
                {
                    "schemaVersion": "2.0.0",
                    "seq": 1,
                    "ts": created_at,
                    "traceId": f"trace-{name}",
                    "spanId": "span-1",
                    "kind": "request",
                    "name": "request.started",
                    "status": "ok",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return run_dir

    def test_mark_showcase_run_updates_manifest_and_index_priority(self) -> None:
        from mark_showcase_run import mark_showcase_run

        root = Path(tempfile.mkdtemp(prefix="showcase-index-"))
        self.make_run(root, "old-failed", created_at="2026-04-28T10:00:00Z", status="failed")
        target = self.make_run(root, "showcase-run", created_at="2026-04-27T10:00:00Z")

        result = mark_showcase_run(target, reason="demo test")
        payload = build_runs_index_payload(root)

        self.assertEqual(result["runId"], "showcase-run")
        self.assertTrue(json.loads((target / "manifest.json").read_text(encoding="utf-8"))["showcase"])
        self.assertEqual(payload["runs"][0]["dirName"], "showcase-run")
        self.assertTrue(payload["runs"][0]["showcase"])

    def test_run_showcase_reuse_latest_prints_a_single_viewer_url(self) -> None:
        import run_showcase

        root = Path(tempfile.mkdtemp(prefix="showcase-wrapper-"))
        run_dir = self.make_run(root, "showcase-run", created_at="2026-05-07T10:00:00Z", showcase=True)
        write_json(
            run_dir / "security-reasoning" / "final_judgment.json",
            {
                "schemaVersion": "transpect.agent-defense.final-judgment.v1",
                "finalDecision": "block",
                "riskLevel": "critical",
                "evidence": {
                    "frida": {"status": "degraded", "eventCount": 0, "summary": "permission required"},
                    "codeTracer": {"status": "ok", "summary": "diagnosis ready"},
                },
            },
        )

        output = io.StringIO()
        with patch.object(sys, "argv", ["run_showcase.py", "--reuse-latest"]), patch.object(
            run_showcase,
            "TRACE_LIVE_RUNS_DIR",
            root,
        ), patch.object(run_showcase, "ensure_demo_site", return_value={"status": "ok", "detail": "already running"}), patch.object(
            run_showcase,
            "ensure_viewer",
            return_value={"status": "ok", "detail": "already running"},
        ), redirect_stdout(output):
            run_showcase.main()

        rendered = output.getvalue()
        self.assertIn("Transpect Showcase", rendered)
        self.assertIn("Final judgment", rendered)
        self.assertIn("BLOCK / critical", rendered)
        self.assertIn("http://127.0.0.1:8711/viewer/index.html?view=traces&run=showcase-run", rendered)
        self.assertNotIn("run_task_repo.py", rendered)

    def test_run_agent_trace_accepts_custom_task_id(self) -> None:
        import run_showcase

        root = Path(tempfile.mkdtemp(prefix="showcase-custom-task-"))
        run_dir = self.make_run(root, "custom-run", created_at="2026-05-08T10:00:00Z")
        captured: dict[str, list[str]] = {}

        def fake_subprocess_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            captured["command"] = command
            stdout = kwargs.get("stdout")
            if hasattr(stdout, "write"):
                stdout.write(json.dumps({"resolvedRunDir": str(run_dir)}))
            return subprocess.CompletedProcess(command, 0)

        custom_task_id = "data/showcase_cases.json#xhs-waterhole-confirm-001"
        with patch.object(run_showcase.subprocess, "run", fake_subprocess_run), patch.object(run_showcase, "TRACE_LIVE_RUNS_DIR", root):
            resolved = run_showcase.run_agent_trace(task_id=custom_task_id, timeout_seconds=10, verbose=False)

        self.assertEqual(resolved, run_dir.resolve())
        self.assertIn(custom_task_id, captured["command"])


if __name__ == "__main__":
    unittest.main()
