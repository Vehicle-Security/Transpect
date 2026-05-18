from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parents[2] / "tools"
sys.path.insert(0, str(SCRIPTS_ROOT / "common"))
sys.path.insert(0, str(SCRIPTS_ROOT / "runtime"))
sys.path.insert(0, str(SCRIPTS_ROOT.parent / "monitor" / "task_repos" / "rjudge"))

from task_repo_common import (  # noqa: E402
    build_artifact_manifest,
    collect_result_paths,
    prepare_environment,
    resolve_repo_root,
    run_preflight_checks,
)
from run_task_repo import (  # noqa: E402
    _build_dry_run_report,
    _sanitize_task_for_dry_run,
)
from runtime_common import resolve_model_configuration  # noqa: E402
from guardrail.security.context_state import create_security_context  # noqa: E402
from guardrail.security.intent_guard import inspect_user_input  # noqa: E402
from guardrail.security.plan_guard import inspect_plan  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class TaskRepoRunnerTests(unittest.TestCase):
    def make_manifest(self, repo_root: Path) -> dict[str, object]:
        return {
            "name": "Example Repo",
            "repo_root": str(repo_root),
            "type": "task_benchmark",
            "python": {
                "preferred": "3.11",
                "supported": ["3.10", "3.11"],
                "venv_name": "example-py311",
                "conda_env_name": "example-conda",
                "expected_envs": [
                    {"kind": "venv", "name": "example-py311"},
                    {"kind": "conda", "name": "example-conda"},
                ],
            },
            "preflight": {
                "required_files": ["data/required.txt"],
                "required_env": ["MODEL_API_KEY"],
                "model_probe_url_env": "MODEL_BASE_URL",
                "model_probe_path": "/models",
            },
            "env_defaults": {
                "MODEL_BASE_URL": "http://localhost:8000/v1",
            },
            "env_map": {
                "API_KEY": "MODEL_API_KEY",
            },
            "run": {
                "commands": [
                    {
                        "name": "example",
                        "cmd": "python run.py",
                    },
                    {
                        "name": "smoke",
                        "cmd": "python smoke.py",
                        "preflight": {
                            "replace_global": True,
                            "required_files": ["eval/smoke.py"],
                        },
                    }
                ]
            },
        }

    def test_preflight_reports_python_env_and_model_failures(self) -> None:
        repo_root = Path(tempfile.mkdtemp(prefix="task-repo-"))
        required_path = repo_root / "data" / "required.txt"
        required_path.parent.mkdir(parents=True, exist_ok=True)
        required_path.write_text("ok\n", encoding="utf-8")
        manifest = self.make_manifest(repo_root)

        with patch.dict("os.environ", {}, clear=True), patch(
            "task_repo_common.load_env_file_layers",
            side_effect=lambda base_env, env_paths: (dict(base_env), []),
        ), patch(
            "task_repo_common.sys_version_tuple",
            return_value=(3, 13, 0),
        ):
            prepared = prepare_environment(manifest)
            report = run_preflight_checks(manifest, adapter=None, prepared_env=prepared)

        self.assertFalse(report["ok"])
        reasons = [check["reason"] for check in report["checks"] if not check["ok"]]
        self.assertIn("python_version_unsupported", reasons)
        self.assertTrue({"expected_env_missing", "expected_env_mismatch"} & set(reasons))
        self.assertIn("missing_required_env", reasons)
        self.assertIn("model_service_unreachable", reasons)

    def test_preflight_reports_blocked_or_unreadable_required_file(self) -> None:
        repo_root = Path(tempfile.mkdtemp(prefix="task-repo-"))
        required_path = repo_root / "data" / "required.txt"
        required_path.parent.mkdir(parents=True, exist_ok=True)
        required_path.write_text("ok\n", encoding="utf-8")
        manifest = self.make_manifest(repo_root)

        with patch.dict(
            "os.environ",
            {"MODEL_API_KEY": "test-key", "VIRTUAL_ENV": str(Path("C:/envs/example-py311"))},
            clear=False,
        ), patch(
            "task_repo_common.load_env_file_layers",
            side_effect=lambda base_env, env_paths: (dict(base_env), []),
        ), patch(
            "pathlib.Path.open",
            side_effect=OSError(22, "Invalid argument"),
        ), patch(
            "task_repo_common._windows_file_probe",
            return_value=("required_file_blocked", "file contains a virus or potentially unwanted software"),
        ), patch(
            "task_repo_common.sys_version_tuple",
            return_value=(3, 11, 9),
        ):
            prepared = prepare_environment(manifest)
            report = run_preflight_checks(manifest, adapter=None, prepared_env=prepared)

        blocked_checks = [check for check in report["checks"] if check["reason"] == "required_file_blocked"]
        self.assertEqual(len(blocked_checks), 1)
        self.assertIn("virus", blocked_checks[0]["details"]["windowsProbe"].lower())

    def test_preflight_reports_expected_env_mismatch(self) -> None:
        repo_root = Path(tempfile.mkdtemp(prefix="task-repo-"))
        required_path = repo_root / "data" / "required.txt"
        required_path.parent.mkdir(parents=True, exist_ok=True)
        required_path.write_text("ok\n", encoding="utf-8")
        manifest = self.make_manifest(repo_root)

        with patch.dict(
            "os.environ",
            {
                "MODEL_API_KEY": "test-key",
                "VIRTUAL_ENV": str(Path("C:/envs/wrong-env")),
            },
            clear=False,
        ), patch(
            "task_repo_common.load_env_file_layers",
            side_effect=lambda base_env, env_paths: (dict(base_env), []),
        ), patch(
            "task_repo_common.sys_version_tuple",
            return_value=(3, 11, 9),
        ):
            prepared = prepare_environment(manifest)
            report = run_preflight_checks(manifest, adapter=None, prepared_env=prepared)

        mismatch_checks = [check for check in report["checks"] if check["reason"] == "expected_env_mismatch"]
        self.assertEqual(len(mismatch_checks), 1)

    def test_declared_artifacts_are_copied_into_run_artifact_root(self) -> None:
        repo_root = Path(tempfile.mkdtemp(prefix="task-repo-"))
        result_file = repo_root / "results" / "demo" / "result.json"
        result_file.parent.mkdir(parents=True, exist_ok=True)
        result_file.write_text('{"ok": true}\n', encoding="utf-8")
        summary_file = repo_root / "eval" / "results" / "summary.json"
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_file.write_text('{"summary": true}\n', encoding="utf-8")
        manifest = self.make_manifest(repo_root)
        manifest["artifacts"] = {
            "result_paths": [
                "results/demo/",
                "eval/results/summary.json",
                "missing/output.json",
            ],
            "max_copy_files": 10,
            "max_copy_bytes": 1024 * 1024,
        }
        run_dir = Path(tempfile.mkdtemp(prefix="task-run-"))
        artifacts = collect_result_paths(
            manifest,
            repo_root,
            template_env={},
            run_dir=run_dir,
        )

        statuses = {entry["declaredPath"]: entry["status"] for entry in artifacts}
        self.assertEqual(statuses["results/demo/"], "collected")
        self.assertEqual(statuses["eval/results/summary.json"], "collected")
        self.assertEqual(statuses["missing/output.json"], "missing")
        copied_paths = [
            artifact_path
            for entry in artifacts
            for artifact_path in entry.get("artifactPaths", [])
        ]
        self.assertTrue(
            any(
                "repo_outputs" in Path(path).parts
                and Path(path).parts[-3:] == ("results", "demo", "result.json")
                for path in copied_paths
            )
        )
        self.assertTrue(
            any(
                "repo_outputs" in Path(path).parts
                and Path(path).parts[-3:] == ("eval", "results", "summary.json")
                for path in copied_paths
            )
        )

    def test_declared_artifacts_reject_paths_outside_repo_root(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="task-repo-workspace-"))
        repo_root = workspace / "repo"
        repo_root.mkdir()
        outside_file = workspace / "outside-secret.txt"
        outside_file.write_text("do not collect\n", encoding="utf-8")
        manifest = self.make_manifest(repo_root)
        manifest["artifacts"] = {
            "result_paths": ["../outside-secret.txt"],
            "max_copy_files": 10,
            "max_copy_bytes": 1024 * 1024,
        }
        run_dir = Path(tempfile.mkdtemp(prefix="task-run-"))

        artifacts = collect_result_paths(
            manifest,
            repo_root,
            template_env={},
            run_dir=run_dir,
        )

        self.assertEqual(artifacts[0]["status"], "rejected")
        self.assertEqual(artifacts[0]["reason"], "outside_repo_root")
        self.assertEqual(artifacts[0]["matches"], [])
        self.assertFalse(list((run_dir / "artifacts" / "task_repo").rglob("outside-secret.txt*")))

    def test_single_command_can_replace_global_preflight_requirements(self) -> None:
        repo_root = Path(tempfile.mkdtemp(prefix="task-repo-"))
        smoke_path = repo_root / "eval" / "smoke.py"
        smoke_path.parent.mkdir(parents=True, exist_ok=True)
        smoke_path.write_text("print('ok')\n", encoding="utf-8")
        manifest = self.make_manifest(repo_root)

        with patch.dict(
            "os.environ",
            {"CONDA_DEFAULT_ENV": "example-conda"},
            clear=True,
        ), patch(
            "task_repo_common.load_env_file_layers",
            side_effect=lambda base_env, env_paths: (dict(base_env), []),
        ), patch(
            "task_repo_common.sys_version_tuple",
            return_value=(3, 10, 20),
        ):
            prepared = prepare_environment(manifest)
            report = run_preflight_checks(
                manifest,
                adapter=None,
                prepared_env=prepared,
                selected_commands=[manifest["run"]["commands"][1]],
            )

        self.assertTrue(report["ok"])
        self.assertEqual(report["summary"]["selectedCommands"], ["smoke"])

    def test_prepare_environment_normalizes_raw_env_aliases(self) -> None:
        repo_root = Path(tempfile.mkdtemp(prefix="task-repo-"))
        manifest = self.make_manifest(repo_root)
        with patch(
            "task_repo_common.load_env_file_layers",
            return_value=(
                {
                    "BASE_URL": "https://example.invalid/v1",
                    "API_KEY": "secret",
                    "MODEL_ID": "demo-model",
                },
                ["D" + ":/fake/.env"],
            ),
        ):
            prepared = prepare_environment(manifest)
        self.assertEqual(prepared["commonEnv"]["MODEL_BASE_URL"], "https://example.invalid/v1")
        self.assertEqual(prepared["commonEnv"]["MODEL_API_KEY"], "secret")
        self.assertEqual(prepared["commonEnv"]["MODEL_NAME"], "demo-model")
        self.assertTrue(prepared["rawEnvKeysPresent"]["BASE_URL"])
        self.assertTrue(prepared["normalizedEnvKeysPresent"]["MODEL_BASE_URL"])

    def test_resolve_repo_root_prefers_env_override(self) -> None:
        repo_root = Path(tempfile.mkdtemp(prefix="task-repo-default-"))
        override_root = Path(tempfile.mkdtemp(prefix="task-repo-override-"))
        manifest_path = repo_root / "task_repos" / "example" / "manifest.json"
        manifest = self.make_manifest(repo_root)
        manifest["repo_root"] = "../default-repo"
        manifest["repo_root_env"] = "R_JUDGE_ROOT"
        manifest["_manifestPath"] = str(manifest_path)

        with patch.dict("os.environ", {"R_JUDGE_ROOT": str(override_root)}, clear=False):
            resolved = resolve_repo_root(manifest)
        self.assertEqual(resolved, override_root.resolve())

    def test_resolve_repo_root_uses_manifest_relative_path(self) -> None:
        workspace_root = Path(tempfile.mkdtemp(prefix="task-repo-workspace-"))
        target_root = workspace_root / "R-Judge"
        manifest_path = workspace_root / "task_repos" / "rjudge" / "manifest.json"
        manifest = self.make_manifest(target_root)
        manifest["repo_root"] = "../../R-Judge"
        manifest["_manifestPath"] = str(manifest_path)

        resolved = resolve_repo_root(manifest)
        self.assertEqual(resolved, target_root.resolve())

    def test_resolve_repo_root_does_not_anchor_windows_path_to_cwd_on_posix(self) -> None:
        manifest = self.make_manifest(Path(tempfile.mkdtemp(prefix="task-repo-")))
        manifest["repo_root"] = "D" + ":/code/R-Judge"
        resolved = resolve_repo_root(manifest)

        if sys.platform == "win32":
            self.assertEqual(str(resolved), str(Path("D" + ":/code/R-Judge").resolve()))
        else:
            self.assertEqual(str(resolved), "/" + "D" + ":/code/R-Judge")

    def test_model_resolution_fallback_only_for_invalid_model(self) -> None:
        with patch(
            "runtime_common.probe_model_resolution",
            side_effect=[
                {"ok": False, "reason": "model_name_unavailable", "model": "bad-model"},
                {"ok": True, "reason": None, "model": "qwen-plus"},
            ],
        ):
            resolution = resolve_model_configuration(
                requested_model="bad-model",
                base_url="https://example.invalid/v1",
                api_key="secret",
            )
        self.assertTrue(resolution["ok"])
        self.assertTrue(resolution["fallbackUsed"])
        self.assertEqual(resolution["effectiveModel"], "qwen-plus")

    def test_model_resolution_does_not_fallback_for_auth_failure(self) -> None:
        with patch(
            "runtime_common.probe_model_resolution",
            return_value={"ok": False, "reason": "model_auth_failed", "model": "demo-model"},
        ):
            resolution = resolve_model_configuration(
                requested_model="demo-model",
                base_url="https://example.invalid/v1",
                api_key="secret",
            )
        self.assertFalse(resolution["ok"])
        self.assertFalse(resolution["fallbackUsed"])
        self.assertEqual(resolution["failureReason"], "model_auth_failed")

    def test_artifact_manifest_records_present_and_missing_entries(self) -> None:
        artifact_root = Path(tempfile.mkdtemp(prefix="artifact-manifest-"))
        stdout_path = artifact_root / "stdout.log"
        stdout_path.write_text("ok\n", encoding="utf-8")
        manifest = build_artifact_manifest(
            command_results=[
                {
                    "name": "demo",
                    "command": "python run.py",
                    "stdoutPath": str(stdout_path),
                    "stderrPath": None,
                }
            ],
            declared_artifacts=[
                {
                    "declaredPath": "results/sample-output.json",
                    "status": "missing",
                    "artifactPaths": [],
                }
            ],
            extra_artifacts=[
                {
                    "logicalName": "adapter:model_resolution",
                    "sourceKind": "adapter",
                    "declaredPath": "adapter/model_resolution.json",
                    "collectedPath": None,
                    "status": "missing",
                    "sizeBytes": None,
                }
            ],
        )
        self.assertEqual(len(manifest["frameworkArtifacts"]), 1)
        self.assertEqual(len(manifest["missingArtifacts"]), 3)

    # ── dry-run tests ──────────────────────────────────────────────

    def test_sanitize_task_shortens_long_contents(self) -> None:
        task = {
            "taskId": "test-001",
            "contents": "x" * 1000,
            "scenario": "photo_upload",
        }
        result = _sanitize_task_for_dry_run(task)
        self.assertIn("[CONTENT_TRUNCATED", result["contents"])
        self.assertLess(len(result["contents"]), 350)
        self.assertEqual(result["taskId"], "test-001")
        self.assertEqual(result["scenario"], "photo_upload")

    def test_sanitize_task_keeps_short_contents(self) -> None:
        task = {
            "taskId": "test-002",
            "contents": "short content",
            "scenario": "test",
        }
        result = _sanitize_task_for_dry_run(task)
        self.assertEqual(result["contents"], "short content")

    def test_build_dry_run_report_has_expected_shape(self) -> None:
        task = {
            "taskId": "data/test.json#test-001",
            "scenario": "photo_upload",
            "attackType": "watering_hole",
        }
        message = "请打开 http://127.0.0.1:8765/xhs/topic/camping"
        security_context = create_security_context(run_id=None)
        security_context = inspect_user_input(message, security_context)
        security_decision, _security_context = inspect_plan(message, security_context)

        report = _build_dry_run_report(
            repo_name="staged_attack",
            manifest={"name": "Staged Attack Demo"},
            task=task,
            message=message,
            security_decision=security_decision,
            security_context=security_context,
        )

        self.assertTrue(report["ok"])
        self.assertEqual(report["mode"], "agent-trace")
        self.assertTrue(report["dryRun"])
        self.assertEqual(report["repo"], "Staged Attack Demo")
        self.assertEqual(report["taskId"], "data/test.json#test-001")
        self.assertEqual(report["task"]["scenario"], "photo_upload")
        self.assertEqual(report["message"], message)
        self.assertIn("decision", report["inputSecurity"])
        self.assertIn("riskLevel", report["inputSecurity"])
        self.assertIn("reasons", report["inputSecurity"])
        self.assertIn("generatedAt", report)
        # Must not leak agent execution artifacts
        self.assertNotIn("runDir", report)
        self.assertNotIn("agentPayload", report)
        self.assertNotIn("traceMerge", report)
        # Explicit signals that dry-run stops before launch
        self.assertFalse(report["willLaunchAgent"])
        self.assertFalse(report["willCreateRun"])

    def test_dry_run_does_not_launch_agent(self) -> None:
        task = {
            "taskId": "data/test.json#test-002",
            "scenario": "test",
        }
        message = "test message"
        security_context = create_security_context(run_id=None)
        security_context = inspect_user_input(message, security_context)
        security_decision, _security_context = inspect_plan(message, security_context)

        with patch("run_task_repo.run_openclaw_agent") as mock_launch:
            report = _build_dry_run_report(
                repo_name="staged_attack",
                manifest={"name": "Staged Attack"},
                task=task,
                message=message,
                security_decision=security_decision,
                security_context=security_context,
            )
            mock_launch.assert_not_called()

        self.assertTrue(report["ok"])
        self.assertTrue(report["dryRun"])


if __name__ == "__main__":
    unittest.main()
