from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
_SCRIPTS_ROOT = SCRIPT_DIR.parents[2] / "tools"
sys.path.insert(0, str(_SCRIPTS_ROOT / "common"))
sys.path.insert(0, str(_SCRIPTS_ROOT / "export"))
sys.path.insert(0, str(_SCRIPTS_ROOT / "diagnosis"))

from export_codetracer_bundle import export_bundles  # noqa: E402
from run_codetracer_diagnosis import detect_codetracer_src_dir, run_codetracer_diagnosis  # noqa: E402
from trace_common import CommandResult, build_runs_index_payload  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


class TracePipelineTests(unittest.TestCase):
    maxDiff = None

    def make_run_dir(self, *, run_id: str, trace_id: str) -> Path:
        root = Path(tempfile.mkdtemp(prefix="transpect-run-"))
        run_dir = root / run_id
        write_json(
            run_dir / "manifest.json",
            {
                "schemaVersion": "openclaw.run.v1",
                "runId": run_id,
                "traceId": trace_id,
                "sessionKey": "sess-test",
                "createdAt": "2026-04-22T10:00:00Z",
                "completedAt": "2026-04-22T10:00:03Z",
                "status": "completed",
                "eventCount": 4,
                "artifactCount": 2,
                "hasRuntimeStatus": True,
                "hasTaskInput": True,
                "paths": {
                    "events": "behavior-events.jsonl",
                    "runtimeStatus": "runtime_status.json",
                    "taskInput": "task_input.json",
                    "artifacts": "artifacts",
                    "codetracerBundle": None,
                    "codetracerAnalysis": None,
                },
                "diagnosis": {
                    "codetracer": {
                        "bundleReady": False,
                        "analysisReady": False,
                        "analysisOk": None,
                        "lastRunAt": None,
                    }
                },
            },
        )
        write_json(
            run_dir / "runtime_status.json",
            {
                "schemaVersion": "openclaw.run.runtime.v1",
                "behaviorMediator": {"result": {"runsDirectory": str(run_dir.parent)}},
                "ruleGuard": None,
            },
        )
        write_json(
            run_dir / "task_input.json",
            {
                "schemaVersion": "openclaw.run.task-input.v1",
                "userInput": {"message": "Read README and explain it"},
                "agentTask": {"prompt": "Read README and explain it"},
                "securityScenario": None,
                "policyObservations": [],
            },
        )
        return run_dir

    def make_index_run_dir(self, runs_root: Path, *, run_id: str, trace_id: str = "trace-index") -> Path:
        run_dir = runs_root / run_id
        write_json(
            run_dir / "manifest.json",
            {
                "schemaVersion": "openclaw.run.v1",
                "runId": run_id,
                "traceId": trace_id,
                "sessionKey": "sess-test",
                "createdAt": "2026-04-24T04:00:00Z",
                "completedAt": "2026-04-24T04:00:10Z",
                "status": "completed",
                "eventCount": 8,
                "artifactCount": 0,
                "diagnosis": {"codetracer": {"analysisReady": True, "analysisOk": True}},
            },
        )
        return run_dir

    def test_runs_index_includes_task_repo_metadata(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="transpect-index-"))
        runs_root = root / "runs"
        run_dir = self.make_index_run_dir(runs_root, run_id="run-task-meta")
        write_json(
            run_dir / "task_input.json",
            {
                "schemaVersion": "openclaw.run.task-input.v1",
                "taskRepo": {
                    "sourceRepo": "rjudge",
                    "taskId": "data/Application/chatbot.json#37",
                    "sourcePath": "data/Application/chatbot.json",
                    "scenario": "psychological",
                    "attackType": "unintended",
                    "expectedLabel": 0,
                    "harnessMode": "agent-trace",
                },
            },
        )

        payload = build_runs_index_payload(runs_root)

        self.assertEqual(payload["runCount"], 1)
        run = payload["runs"][0]
        self.assertEqual(run["taskRepo"]["taskId"], "data/Application/chatbot.json#37")
        self.assertEqual(run["taskRepo"]["sourcePath"], "data/Application/chatbot.json")
        self.assertEqual(run["taskRepo"]["attackType"], "unintended")
        self.assertEqual(run["taskRepo"]["expectedLabel"], 0)
        self.assertIsNone(run["batchId"])
        self.assertIsNone(run["labelMatched"])

    def test_runs_index_links_batch_reports_and_label_mismatches(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="transpect-index-batch-"))
        runs_root = root / "runs"
        self.make_index_run_dir(runs_root, run_id="run-match")
        self.make_index_run_dir(runs_root, run_id="run-mismatch")
        reports_root = root / "reports"
        write_json(
            reports_root / "rjudge-batch-2-20260424T043618Z.json",
            {
                "sample": [],
                "results": [
                    {
                        "taskId": "data/Application/chatbot.json#37",
                        "sourcePath": "data/Application/chatbot.json",
                        "attackType": "unintended",
                        "expectedLabel": 0,
                        "startedAt": "2026-04-24T04:36:18Z",
                        "payload": {"agentRunId": "run-match"},
                    },
                    {
                        "taskId": "data/Finance/moneymanagement.json#13",
                        "sourcePath": "data/Finance/moneymanagement.json",
                        "attackType": "unintended",
                        "expectedLabel": 1,
                        "startedAt": "2026-04-24T04:37:18Z",
                        "payload": {"agentRunId": "run-mismatch"},
                    },
                ],
            },
        )
        write_json(
            reports_root / "rjudge-batch-2-20260424T043618Z.summary.json",
            {
                "matchedLabels": 1,
                "parsedLabels": 2,
                "accuracy": 0.5,
                "mismatches": [
                    {
                        "taskId": "data/Finance/moneymanagement.json#13",
                        "expectedLabel": 1,
                        "predictedLabel": 0,
                        "runId": "run-mismatch",
                    }
                ],
            },
        )

        payload = build_runs_index_payload(runs_root)
        by_run_id = {run["runId"]: run for run in payload["runs"]}

        self.assertEqual(by_run_id["run-match"]["batchId"], "rjudge-batch-2-20260424T043618Z")
        self.assertEqual(by_run_id["run-match"]["batchName"], "rjudge-batch-2-20260424T043618Z")
        self.assertEqual(by_run_id["run-match"]["batchStartedAt"], "2026-04-24T04:36:18Z")
        self.assertEqual(by_run_id["run-match"]["predictedLabel"], 0)
        self.assertTrue(by_run_id["run-match"]["labelMatched"])
        self.assertEqual(by_run_id["run-mismatch"]["predictedLabel"], 0)
        self.assertFalse(by_run_id["run-mismatch"]["labelMatched"])

    def test_runs_index_links_custom_named_reports(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="transpect-index-custom-report-"))
        runs_root = root / "runs"
        self.make_index_run_dir(runs_root, run_id="run-custom")
        reports_root = root / "reports"
        write_json(
            reports_root / "custom-smoke.json",
            {
                "sample": [],
                "results": [
                    {
                        "taskId": "data/Program/terminal.json#0",
                        "sourcePath": "data/Program/terminal.json",
                        "expectedLabel": 1,
                        "startedAt": "2026-04-24T04:36:18Z",
                        "payload": {"agentRunId": "run-custom"},
                    }
                ],
            },
        )
        write_json(
            reports_root / "custom-smoke.summary.json",
            {
                "matchedLabels": 1,
                "parsedLabels": 1,
                "accuracy": 1.0,
                "mismatches": [],
            },
        )

        payload = build_runs_index_payload(runs_root)

        self.assertEqual(payload["runs"][0]["batchId"], "custom-smoke")
        self.assertTrue(payload["runs"][0]["labelMatched"])

    def test_export_bundle_from_run_dir_updates_run_manifest(self) -> None:
        run_id = "run-readme"
        trace_id = "trace-readme"
        run_dir = self.make_run_dir(run_id=run_id, trace_id=trace_id)
        artifact_root = run_dir / "artifacts" / "tc-read"
        write_json(artifact_root / "input.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"path": "README.md"}})
        write_json(artifact_root / "output.json", {"schemaVersion": "openclaw.tool-sidecar.v1", "payload": {"result": "ok"}})
        write_jsonl(
            run_dir / "behavior-events.jsonl",
            [
                {
                    "schemaVersion": "2.0.0",
                    "seq": 1,
                    "ts": "2026-04-22T10:00:00Z",
                    "traceId": trace_id,
                    "spanId": "req-1",
                    "kind": "request",
                    "name": "openclaw.request",
                    "status": "started",
                    "runId": run_id,
                    "sessionKey": "sess-test",
                    "preview": {"message": "Read README and explain it"},
                },
                {
                    "schemaVersion": "2.0.0",
                    "seq": 2,
                    "ts": "2026-04-22T10:00:01Z",
                    "traceId": trace_id,
                    "spanId": "turn-1",
                    "parentSpanId": "req-1",
                    "kind": "turn",
                    "name": "openclaw.agent.turn",
                    "status": "started",
                    "runId": run_id,
                    "sessionKey": "sess-test",
                    "preview": {"prompt": "Read README and explain it"},
                },
                {
                    "schemaVersion": "2.0.0",
                    "seq": 3,
                    "ts": "2026-04-22T10:00:02Z",
                    "traceId": trace_id,
                    "spanId": "tool-1",
                    "parentSpanId": "turn-1",
                    "kind": "tool",
                    "name": "tool.Read",
                    "status": "started",
                    "runId": run_id,
                    "sessionKey": "sess-test",
                    "toolCallId": "tc-read",
                    "target": {"toolName": "Read", "path": "README.md"},
                    "evidence": {"artifacts": {"input": "artifacts/tc-read/input.json"}},
                },
                {
                    "schemaVersion": "2.0.0",
                    "seq": 4,
                    "ts": "2026-04-22T10:00:03Z",
                    "traceId": trace_id,
                    "spanId": "tool-1",
                    "parentSpanId": "turn-1",
                    "kind": "tool",
                    "name": "tool.Read",
                    "status": "ok",
                    "runId": run_id,
                    "sessionKey": "sess-test",
                    "toolCallId": "tc-read",
                    "target": {"toolName": "Read", "path": "README.md"},
                    "evidence": {"artifacts": {"output": "artifacts/tc-read/output.json"}},
                },
            ],
        )

        payload = export_bundles(run_dir=run_dir, include_runtime_status=False)
        bundle_dir = run_dir / "diagnosis" / "codetracer" / "bundle"
        run_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        bundle_manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["bundleCount"], 1)
        self.assertEqual(bundle_manifest["sourceKind"], "run")
        self.assertEqual(bundle_manifest["sourceRunPath"], str(run_dir.resolve()).replace("\\", "/"))
        self.assertEqual(run_manifest["paths"]["codetracerBundle"], "diagnosis/codetracer/bundle")
        self.assertTrue(run_manifest["diagnosis"]["codetracer"]["bundleReady"])

    def test_diagnosis_runner_writes_analysis_and_updates_manifest(self) -> None:
        run_id = "run-diagnosis"
        trace_id = "trace-diagnosis"
        run_dir = self.make_run_dir(run_id=run_id, trace_id=trace_id)
        write_jsonl(
            run_dir / "behavior-events.jsonl",
            [
                {
                    "schemaVersion": "2.0.0",
                    "seq": 1,
                    "ts": "2026-04-22T10:00:00Z",
                    "traceId": trace_id,
                    "spanId": "turn-1",
                    "kind": "turn",
                    "name": "openclaw.agent.turn",
                    "status": "started",
                    "runId": run_id,
                    "sessionKey": "sess-test",
                    "preview": {"prompt": "Run verification"},
                }
            ],
        )

        def fake_run_command(*args, **kwargs) -> CommandResult:
            output_path = Path(args[0][args[0].index("--output") + 1])
            write_json(
                output_path,
                {
                    "root_cause_chain": [],
                    "critical_decision_points": [],
                    "correct_strategy": "retry with better plan",
                    "stage_labels": ["exploration"],
                    "summary": "diagnosis ok",
                },
            )
            write_json(output_path.parent / "codetracer_analysis.traj.json", {"ok": True})
            return CommandResult(args=["python"], returncode=0, stdout='{"ok":true}', stderr="")

        with patch("run_codetracer_diagnosis.run_command", side_effect=fake_run_command), patch(
            "run_codetracer_diagnosis.detect_codetracer_src_dir",
            return_value=Path(tempfile.mkdtemp(prefix="codetracer-src-")),
        ), patch("export_codetracer_bundle.call_runtime_statuses", return_value=({}, {})):
            result = run_codetracer_diagnosis(run_dir=run_dir, dry_run=False, model="gpt-test")

        run_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        diagnosis_run = json.loads(
            (run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_run.json").read_text(encoding="utf-8")
        )
        diagnosis_report = json.loads(
            (run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json").read_text(encoding="utf-8")
        )
        self.assertTrue(result["ok"])
        self.assertEqual(diagnosis_run["status"], "success")
        self.assertEqual(diagnosis_report["role"], "trajectory_diagnosis_not_benchmark_evaluation")
        self.assertEqual(diagnosis_report["analysis"]["summary"], "diagnosis ok")
        self.assertTrue(result["diagnosisReportPath"].endswith("/diagnosis_report.json"))
        self.assertTrue(run_manifest["diagnosis"]["codetracer"]["analysisReady"])
        self.assertTrue(run_manifest["diagnosis"]["codetracer"]["analysisOk"])

    def test_diagnosis_runner_redacts_api_key_and_recovers_misplaced_analysis_output(self) -> None:
        run_id = "run-recovery"
        trace_id = "trace-recovery"
        run_dir = self.make_run_dir(run_id=run_id, trace_id=trace_id)
        write_jsonl(
            run_dir / "behavior-events.jsonl",
            [
                {
                    "schemaVersion": "2.0.0",
                    "seq": 1,
                    "ts": "2026-04-22T10:00:00Z",
                    "traceId": trace_id,
                    "spanId": "turn-1",
                    "kind": "turn",
                    "name": "openclaw.agent.turn",
                    "status": "started",
                    "runId": run_id,
                    "sessionKey": "sess-test",
                    "preview": {"prompt": "Run diagnosis"},
                }
            ],
        )

        secret_api_key = "sk-test-secret"

        def fake_run_command(*args, **kwargs) -> CommandResult:
            command = args[0]
            output_path = Path(command[command.index("--output") + 1])
            bundle_dir = Path(command[4])
            misplaced_output = bundle_dir / output_path.name
            write_json(
                misplaced_output,
                {
                    "root_cause_chain": [],
                    "critical_decision_points": [],
                    "correct_strategy": "recover from bundle output",
                    "stage_labels": ["verification_completion"],
                    "summary": "analysis was recovered from bundle dir",
                },
            )
            write_json(bundle_dir / "codetracer_analysis.traj.json", {"ok": True})
            return CommandResult(
                args=["python"],
                returncode=0,
                stdout=f'{{"ok":true,"api_key":"{secret_api_key}"}}',
                stderr=f"traceback included {secret_api_key}",
            )

        with patch("run_codetracer_diagnosis.run_command", side_effect=fake_run_command), patch(
            "run_codetracer_diagnosis.detect_codetracer_src_dir",
            return_value=Path(tempfile.mkdtemp(prefix="codetracer-src-")),
        ), patch("export_codetracer_bundle.call_runtime_statuses", return_value=({}, {})):
            result = run_codetracer_diagnosis(
                run_dir=run_dir,
                dry_run=False,
                model="gpt-test",
                api_key=secret_api_key,
            )

        analysis_dir = run_dir / "diagnosis" / "codetracer" / "analysis"
        diagnosis_run = json.loads((analysis_dir / "diagnosis_run.json").read_text(encoding="utf-8"))
        self.assertTrue(result["ok"])
        self.assertTrue((analysis_dir / "codetracer_analysis.json").exists())
        self.assertTrue((analysis_dir / "codetracer_analysis.traj.json").exists())
        self.assertTrue(diagnosis_run["analysisRecovered"])
        self.assertIn("--api-key", diagnosis_run["command"])
        self.assertIn("[REDACTED]", diagnosis_run["command"])
        self.assertNotIn(secret_api_key, json.dumps(diagnosis_run, ensure_ascii=False))
        self.assertNotIn(secret_api_key, json.dumps(result, ensure_ascii=False))

    def test_detect_codetracer_sibling_src_dir(self) -> None:
        sibling_src = Path(__file__).resolve().parents[3] / "CodeTracer" / "src"
        if not sibling_src.exists():
            self.skipTest("local sibling CodeTracer checkout is not available")
        with patch.dict("os.environ", {"CODETRACER_ROOT": "", "CODETRACER_SRC": ""}, clear=False):
            self.assertEqual(detect_codetracer_src_dir(), sibling_src.resolve())

    def test_failed_diagnosis_writes_structured_report(self) -> None:
        run_id = "run-diagnosis-failed"
        trace_id = "trace-diagnosis-failed"
        run_dir = self.make_run_dir(run_id=run_id, trace_id=trace_id)
        write_json(
            run_dir / "artifacts" / "task_repo" / "evaluation_inputs_seed.json",
            {
                "schemaVersion": "transpect.evaluation-inputs-seed.v1",
                "diagnosis": {
                    "tool": "CodeTracer",
                    "role": "diagnosis_not_benchmark_judge",
                    "diagnosisReportPath": None,
                },
            },
        )
        write_jsonl(
            run_dir / "behavior-events.jsonl",
            [
                {
                    "schemaVersion": "2.0.0",
                    "seq": 1,
                    "ts": "2026-04-22T10:00:00Z",
                    "traceId": trace_id,
                    "spanId": "turn-1",
                    "kind": "turn",
                    "name": "openclaw.agent.turn",
                    "status": "started",
                    "runId": run_id,
                    "sessionKey": "sess-test",
                    "preview": {"prompt": "Run diagnosis"},
                }
            ],
        )

        with patch(
            "run_codetracer_diagnosis.run_command",
            return_value=CommandResult(args=["python"], returncode=1, stdout="", stderr="diagnosis failed"),
        ), patch(
            "run_codetracer_diagnosis.detect_codetracer_src_dir",
            return_value=Path(tempfile.mkdtemp(prefix="codetracer-src-")),
        ), patch("export_codetracer_bundle.call_runtime_statuses", return_value=({}, {})):
            result = run_codetracer_diagnosis(run_dir=run_dir, dry_run=False, model="gpt-test")

        analysis_dir = run_dir / "diagnosis" / "codetracer" / "analysis"
        diagnosis_report = json.loads((analysis_dir / "diagnosis_report.json").read_text(encoding="utf-8"))
        seed = json.loads(
            (run_dir / "artifacts" / "task_repo" / "evaluation_inputs_seed.json").read_text(encoding="utf-8")
        )
        self.assertFalse(result["ok"])
        self.assertFalse(diagnosis_report["ok"])
        self.assertEqual(diagnosis_report["status"], "failed")
        self.assertEqual(diagnosis_report["diagnosisRun"]["invalidAnalysisReason"], "analysis_output_missing")
        self.assertEqual(seed["diagnosis"]["status"], "failed")
        self.assertTrue(seed["diagnosis"]["diagnosisReportPath"].endswith("/diagnosis_report.json"))


if __name__ == "__main__":
    unittest.main()
