from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
_SCRIPTS_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(_SCRIPTS_ROOT / "common"))
sys.path.insert(0, str(_SCRIPTS_ROOT / "export"))

from export_codetracer_bundle import export_bundles  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


class CodeTracerExportTests(unittest.TestCase):
    maxDiff = None

    def test_export_from_run_dir_keeps_taxonomy_and_policy_metadata(self) -> None:
        temp_dir = Path(tempfile.mkdtemp(prefix="transpect-export-"))
        run_dir = temp_dir / "run-main"
        write_json(run_dir / "manifest.json", {"schemaVersion": "openclaw.run.v1", "runId": "run-main", "traceId": "trace-main"})
        write_json(run_dir / "runtime_status.json", {"schemaVersion": "openclaw.run.runtime.v1"})
        write_json(run_dir / "task_input.json", {"schemaVersion": "openclaw.run.task-input.v1"})

        write_json(run_dir / "artifacts" / "tc-read" / "input.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"path": "README.md"}})
        write_json(run_dir / "artifacts" / "tc-read" / "output.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"result": {"content": "ok"}}})
        write_json(run_dir / "artifacts" / "tc-edit" / "input.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"path": "src/app.py"}})
        write_json(run_dir / "artifacts" / "tc-edit" / "output.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"result": {"content": "patched"}}})
        write_json(run_dir / "artifacts" / "tc-test" / "input.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"command": "pytest -q"}})
        write_json(run_dir / "artifacts" / "tc-test" / "output.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"result": {"content": "4 passed"}}})

        rows = [
            {
                "schemaVersion": "2.0.0",
                "seq": 1,
                "ts": "2026-04-22T00:00:01Z",
                "traceId": "trace-main",
                "spanId": "req-1",
                "kind": "request",
                "name": "openclaw.request",
                "status": "started",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "preview": {"message": "Fix TODOs and verify"},
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 2,
                "ts": "2026-04-22T00:00:02Z",
                "traceId": "trace-main",
                "spanId": "turn-1",
                "parentSpanId": "req-1",
                "kind": "turn",
                "name": "openclaw.agent.turn",
                "status": "started",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "preview": {"prompt": "Fix TODOs and verify"},
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 3,
                "ts": "2026-04-22T00:00:03Z",
                "traceId": "trace-main",
                "spanId": "policy-read",
                "parentSpanId": "turn-1",
                "kind": "tool",
                "name": "tool.Read",
                "status": "would_block",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "toolCallId": "tc-read",
                "target": {"toolName": "Read", "path": "README.md"},
                "evidence": {
                    "policy": {
                        "mode": "audit",
                        "decision": "block",
                        "outcome": "would_block",
                        "ruleId": "read-policy",
                        "pathSecurity": {"withinWorkspace": True},
                    },
                    "securityScenario": {
                        "id": "scenario-read",
                        "expectedMode": "audit",
                        "expectedOutcome": "would_block_allowed",
                        "observedOutcome": "would_block_allowed",
                        "expectationMatched": True,
                    },
                },
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 4,
                "ts": "2026-04-22T00:00:04Z",
                "traceId": "trace-main",
                "spanId": "tool-read",
                "parentSpanId": "turn-1",
                "kind": "tool",
                "name": "tool.Read",
                "status": "started",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "toolCallId": "tc-read",
                "target": {"toolName": "Read", "path": "README.md"},
                "evidence": {"artifacts": {"input": "artifacts/tc-read/input.json"}},
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 5,
                "ts": "2026-04-22T00:00:05Z",
                "traceId": "trace-main",
                "spanId": "tool-read",
                "parentSpanId": "turn-1",
                "kind": "tool",
                "name": "tool.Read",
                "status": "ok",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "toolCallId": "tc-read",
                "target": {"toolName": "Read", "path": "README.md"},
                "evidence": {"artifacts": {"output": "artifacts/tc-read/output.json"}},
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 6,
                "ts": "2026-04-22T00:00:06Z",
                "traceId": "trace-main",
                "spanId": "tool-edit",
                "parentSpanId": "turn-1",
                "kind": "tool",
                "name": "tool.Edit",
                "status": "started",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "toolCallId": "tc-edit",
                "target": {"toolName": "Edit", "path": "src/app.py"},
                "evidence": {"artifacts": {"input": "artifacts/tc-edit/input.json"}},
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 7,
                "ts": "2026-04-22T00:00:07Z",
                "traceId": "trace-main",
                "spanId": "tool-edit",
                "parentSpanId": "turn-1",
                "kind": "tool",
                "name": "tool.Edit",
                "status": "ok",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "toolCallId": "tc-edit",
                "target": {"toolName": "Edit", "path": "src/app.py"},
                "evidence": {"artifacts": {"output": "artifacts/tc-edit/output.json"}},
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 8,
                "ts": "2026-04-22T00:00:08Z",
                "traceId": "trace-main",
                "spanId": "tool-test",
                "parentSpanId": "turn-1",
                "kind": "tool",
                "name": "tool.exec",
                "status": "started",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "toolCallId": "tc-test",
                "target": {"toolName": "exec", "commandLine": "pytest -q"},
                "evidence": {"artifacts": {"input": "artifacts/tc-test/input.json"}},
            },
            {
                "schemaVersion": "2.0.0",
                "seq": 9,
                "ts": "2026-04-22T00:00:09Z",
                "traceId": "trace-main",
                "spanId": "tool-test",
                "parentSpanId": "turn-1",
                "kind": "tool",
                "name": "tool.exec",
                "status": "ok",
                "runId": "run-main",
                "sessionKey": "sess-main",
                "toolCallId": "tc-test",
                "target": {"toolName": "exec", "commandLine": "pytest -q"},
                "evidence": {"artifacts": {"output": "artifacts/tc-test/output.json"}},
            },
        ]
        write_jsonl(run_dir / "behavior-events.jsonl", rows)

        with patch("export_codetracer_bundle.call_runtime_statuses", return_value=({}, {})):
            payload = export_bundles(run_dir=run_dir)

        bundle_dir = run_dir / "diagnosis" / "codetracer" / "bundle"
        steps = json.loads((bundle_dir / "steps.json").read_text(encoding="utf-8"))
        stages = json.loads((bundle_dir / "stage_ranges.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["bundleCount"], 1)
        self.assertEqual([step["step_kind"] for step in steps], ["explore", "state_change", "verify"])
        self.assertEqual(steps[0]["openclaw_meta"]["policyObservation"]["status"], "would_block")
        self.assertEqual(steps[0]["openclaw_meta"]["securityScenario"]["id"], "scenario-read")
        self.assertEqual([stage["stage"] for stage in stages], ["setup_context", "state_change", "verification_completion"])


if __name__ == "__main__":
    unittest.main()
