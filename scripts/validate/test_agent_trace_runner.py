from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPTS_ROOT / "runtime"))
sys.path.insert(0, str(SCRIPTS_ROOT / "common"))

import run_task_repo  # noqa: E402


class FakeSourceAdapter:
    def __init__(self) -> None:
        self.task = {
            "taskId": "data/Application/chatbot.json#37",
            "sourcePath": "data/Application/chatbot.json",
            "scenario": "psychological",
            "attack_type": "unintended",
            "label": 1,
            "profile": "You are a counselor.",
            "goal": "Continue naturally.",
            "contents": [],
        }

    def list_tasks(self, manifest: dict[str, object], prepared_env: dict[str, object]) -> list[dict[str, object]]:
        return [
            {
                "taskId": self.task["taskId"],
                "sampleId": 37,
                "sourcePath": self.task["sourcePath"],
                "scenario": self.task["scenario"],
                "attackType": self.task["attack_type"],
                "label": self.task["label"],
            }
        ]

    def load_task(self, manifest: dict[str, object], prepared_env: dict[str, object], task_id: str) -> dict[str, object]:
        if task_id != self.task["taskId"]:
            raise LookupError(task_id)
        return dict(self.task)

    def build_agent_input(self, manifest: dict[str, object], prepared_env: dict[str, object], task: dict[str, object]) -> str:
        return "agent prompt"


class AgentTraceRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = {
            "name": "R-Judge",
            "repo_root": "D:/code/R-Judge",
            "type": "task_benchmark",
            "python": {"preferred": "3.11", "supported": ["3.11"]},
            "preflight": {},
            "run": {"commands": [{"name": "demo", "cmd": "python demo.py"}]},
        }
        self.adapter = FakeSourceAdapter()
        self.prepared_env = {"commonEnv": {}, "repoEnv": {}, "templateEnv": {}}

    def run_main(self, argv: list[str]) -> dict[str, object]:
        output = io.StringIO()
        with patch.object(sys, "argv", ["run_task_repo.py", *argv]), patch(
            "run_task_repo.load_task_repo_manifest",
            return_value=self.manifest,
        ), patch(
            "run_task_repo.load_task_repo_adapter",
            return_value=self.adapter,
        ), patch(
            "run_task_repo.prepare_environment",
            return_value=self.prepared_env,
        ), patch(
            "task_repo_common.load_task_repo_source_preflight",
            return_value=None,
        ), redirect_stdout(output):
            run_task_repo.main()
        return json.loads(output.getvalue())

    def test_mode_list_tasks_output(self) -> None:
        report = self.run_main(["--repo", "rjudge", "--mode", "list-tasks"])
        self.assertTrue(report["ok"])
        self.assertEqual(report["mode"], "list-tasks")
        self.assertEqual(report["taskCount"], 1)
        self.assertEqual(report["tasks"][0]["taskId"], "data/Application/chatbot.json#37")

    def test_mode_show_task_output(self) -> None:
        report = self.run_main(
            ["--repo", "rjudge", "--mode", "show-task", "--task-id", "data/Application/chatbot.json#37"]
        )
        self.assertTrue(report["ok"])
        self.assertEqual(report["mode"], "show-task")
        self.assertEqual(report["task"]["profile"], "You are a counselor.")

    def test_mode_agent_trace_with_mock_openclaw(self) -> None:
        run_dir = Path(tempfile.mkdtemp(prefix="agent-trace-run-"))
        with patch("run_task_repo.run_openclaw_agent", return_value={"ok": True, "runId": "run-123"}), patch(
            "run_task_repo.wait_for_agent_trace_run",
            return_value={
                "ok": True,
                "timedOut": False,
                "attempts": 1,
                "runDir": run_dir,
                "eventCount": 2,
                "terminalSeen": True,
            },
        ), patch(
            "run_task_repo.attach_source_metadata_to_run",
            return_value={"artifactManifestPath": str(run_dir / "artifacts" / "task_repo" / "artifact_manifest.json")},
        ) as attach, patch(
            "run_task_repo.run_codetracer_diagnosis",
            return_value={
                "ok": True,
                "diagnosisReportPath": str(run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json"),
                "diagnosisRunPath": str(run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_run.json"),
                "analysisPath": str(run_dir / "diagnosis" / "codetracer" / "analysis" / "codetracer_analysis.json"),
                "bundleDir": str(run_dir / "diagnosis" / "codetracer" / "bundle"),
            },
        ) as diagnosis, patch("run_task_repo.create_task_repo_run") as create_task_repo_run:
            report = self.run_main(
                ["--repo", "rjudge", "--mode", "agent-trace", "--task-id", "data/Application/chatbot.json#37"]
            )
        self.assertTrue(report["ok"])
        self.assertTrue(report["frameworkSuccess"])
        self.assertTrue(report["agentRunSuccess"])
        self.assertEqual(report["agentRunId"], "run-123")
        self.assertEqual(report["diagnosis"]["diagnosisReportPath"], str(run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json"))
        self.assertTrue(diagnosis.called)
        self.assertTrue(attach.called)
        self.assertIn("evaluation_inputs_seed", attach.call_args.kwargs)
        self.assertFalse(create_task_repo_run.called)

    def test_mode_agent_trace_skip_diagnosis(self) -> None:
        run_dir = Path(tempfile.mkdtemp(prefix="agent-trace-skip-diagnosis-"))
        with patch("run_task_repo.run_openclaw_agent", return_value={"ok": True, "runId": "run-123"}), patch(
            "run_task_repo.wait_for_agent_trace_run",
            return_value={
                "ok": True,
                "timedOut": False,
                "attempts": 1,
                "runDir": run_dir,
                "eventCount": 2,
                "terminalSeen": True,
            },
        ), patch(
            "run_task_repo.attach_source_metadata_to_run",
            return_value={"artifactManifestPath": str(run_dir / "artifacts" / "task_repo" / "artifact_manifest.json")},
        ) as attach, patch("run_task_repo.run_codetracer_diagnosis") as diagnosis:
            report = self.run_main(
                [
                    "--repo",
                    "rjudge",
                    "--mode",
                    "agent-trace",
                    "--task-id",
                    "data/Application/chatbot.json#37",
                    "--skip-diagnosis",
                ]
            )
        self.assertTrue(report["ok"])
        self.assertEqual(report["diagnosis"]["status"], "skipped")
        self.assertFalse(diagnosis.called)
        self.assertIn("evaluation_inputs_seed", attach.call_args.kwargs)

    def test_mode_agent_trace_failure_path(self) -> None:
        with patch("run_task_repo.run_openclaw_agent", return_value={"ok": True, "runId": None}):
            report = self.run_main(
                ["--repo", "rjudge", "--mode", "agent-trace", "--task-id", "data/Application/chatbot.json#37"]
            )
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "agent_launch_failed")
        self.assertFalse(report["runIdObtained"])

    def test_mode_agent_trace_timeout_path(self) -> None:
        run_dir = Path(tempfile.mkdtemp(prefix="agent-trace-timeout-"))
        with patch("run_task_repo.run_openclaw_agent", return_value={"ok": True, "runId": "run-123"}), patch(
            "run_task_repo.wait_for_agent_trace_run",
            return_value={
                "ok": False,
                "timedOut": True,
                "attempts": 150,
                "runDir": run_dir,
                "eventCount": 1,
                "terminalSeen": False,
            },
        ), patch(
            "run_task_repo.attach_source_metadata_to_run",
            return_value={"artifactManifestPath": str(run_dir / "artifacts" / "task_repo" / "artifact_manifest.json")},
        ):
            report = self.run_main(
                ["--repo", "rjudge", "--mode", "agent-trace", "--task-id", "data/Application/chatbot.json#37"]
            )
        self.assertFalse(report["ok"])
        self.assertEqual(report["reason"], "agent_run_timeout")

    def test_mode_repo_native_backward_compatible(self) -> None:
        with patch("run_task_repo._run_repo_native", return_value={"mode": "repo-native", "ok": True}) as repo_native:
            report = self.run_main(["--repo", "rjudge"])
        self.assertTrue(report["ok"])
        self.assertEqual(report["mode"], "repo-native")
        self.assertTrue(repo_native.called)


if __name__ == "__main__":
    unittest.main()
