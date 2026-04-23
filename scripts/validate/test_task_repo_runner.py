from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPTS_ROOT / "common"))
sys.path.insert(0, str(SCRIPTS_ROOT.parent / "task_repos" / "rjudge"))

from task_repo_common import (  # noqa: E402
    build_artifact_manifest,
    collect_result_paths,
    prepare_environment,
    run_preflight_checks,
)
from runtime_common import resolve_model_configuration  # noqa: E402


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
        self.assertIn("expected_env_missing", reasons)
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
        self.assertTrue(any(path.endswith("/artifacts/task_repo/repo_outputs/results/demo/result.json") for path in copied_paths))
        self.assertTrue(any(path.endswith("/artifacts/task_repo/repo_outputs/eval/results/summary.json") for path in copied_paths))

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
                ["D:/fake/.env"],
            ),
        ):
            prepared = prepare_environment(manifest)
        self.assertEqual(prepared["commonEnv"]["MODEL_BASE_URL"], "https://example.invalid/v1")
        self.assertEqual(prepared["commonEnv"]["MODEL_API_KEY"], "secret")
        self.assertEqual(prepared["commonEnv"]["MODEL_NAME"], "demo-model")
        self.assertTrue(prepared["rawEnvKeysPresent"]["BASE_URL"])
        self.assertTrue(prepared["normalizedEnvKeysPresent"]["MODEL_BASE_URL"])

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
                    "declaredPath": "results/demo.json",
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


if __name__ == "__main__":
    unittest.main()
