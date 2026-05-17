import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "tools" / "demo"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "diagnosis"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "validate"))


class DeploymentHardeningTests(unittest.TestCase):
    def test_sanitize_showcase_paths_rewrites_local_paths(self) -> None:
        from sanitize_showcase_paths import sanitize_showcase_paths

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state" / "showcase"
            run_dir = root / "case"
            run_dir.mkdir(parents=True)
            artifact = run_dir / "report_model.json"
            repo_root_text = REPO_ROOT.as_posix()
            artifact.write_text(
                json.dumps(
                    {
                        "path": f"{repo_root_text}/monitor/live/runs/run-1",
                        "home": str(Path.home() / ".openclaw" / "session"),
                        "python": "/opt/anaconda3/bin/python",
                        "venv": f"{repo_root_text}/.venv-frida-arm64/bin/python",
                    }
                ),
                encoding="utf-8",
            )

            check_report = sanitize_showcase_paths(root, check=True)
            self.assertFalse(check_report["ok"])
            self.assertGreaterEqual(check_report["replacementCount"], 4)

            rewrite_report = sanitize_showcase_paths(root)
            self.assertTrue(rewrite_report["ok"])

            text = artifact.read_text(encoding="utf-8")
            self.assertNotIn(repo_root_text, text)
            self.assertNotIn("/opt/anaconda3", text)
            self.assertNotIn(".venv-frida-arm64", text)
            self.assertIn("<transpect_root>", text)
            self.assertIn("<openclaw_home>", text)
            self.assertIn("<python_env>", text)

    def test_check_portability_reports_local_paths(self) -> None:
        from check_portability import check_portability

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            (docs / "bad.md").write_text(
                "Use /Users/qwer/Documents/code/Transpect for local testing.",
                encoding="utf-8",
            )

            report = check_portability(root)
            self.assertFalse(report["ok"])
            self.assertEqual(report["matches"][0]["path"], "docs/bad.md")

    def test_deployment_doctor_replay_does_not_require_live_components(self) -> None:
        from deployment_doctor import evaluate_deployment

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\n", encoding="utf-8")
            console = root / "dashboard" / "console"
            (console / "node_modules").mkdir(parents=True)
            (console / "package.json").write_text("{}", encoding="utf-8")
            showcase = root / "dashboard" / "state" / "showcase"
            showcase.mkdir(parents=True)
            (showcase / "index.json").write_text(
                json.dumps(
                    {
                        "showcases": [
                            {
                                "id": "demo",
                                "runDir": "dashboard/state/showcase/demo",
                                "finalJudgmentPath": "dashboard/state/showcase/demo/security-reasoning/final_judgment.json",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            demo_dir = showcase / "demo" / "security-reasoning"
            demo_dir.mkdir(parents=True)
            (demo_dir / "final_judgment.json").write_text("{}", encoding="utf-8")
            (showcase / "demo" / "report_model.json").write_text("{}", encoding="utf-8")

            report = evaluate_deployment(root, mode="replay")
            self.assertTrue(report["ok"], report)
            component_names = {component["name"] for component in report["components"]}
            self.assertIn("showcase_data", component_names)
            self.assertNotIn("openclaw_gateway", component_names)
            self.assertNotIn("rjudge_dataset", component_names)

    def test_codetracer_missing_writes_unavailable_report(self) -> None:
        from run_codetracer_diagnosis import run_codetracer_diagnosis

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            (run_dir / "manifest.json").write_text('{"runId":"run"}', encoding="utf-8")
            (run_dir / "task_input.json").write_text('{"task":"demo"}', encoding="utf-8")
            (run_dir / "behavior-events.jsonl").write_text('{"eventId":"evt-1","type":"agent.start"}\n', encoding="utf-8")

            def fake_export_bundles(*, run_dir: Path, output_root: Path, include_runtime_status: bool) -> dict:
                output_root.mkdir(parents=True, exist_ok=True)
                (output_root / "manifest.json").write_text(
                    json.dumps({"traceSources": {}}),
                    encoding="utf-8",
                )
                return {"bundles": [{"bundlePath": str(output_root)}]}

            with patch("run_codetracer_diagnosis.export_bundles", side_effect=fake_export_bundles), patch(
                "run_codetracer_diagnosis.detect_codetracer_src_dir"
            ) as detect_src:
                detect_src.side_effect = FileNotFoundError("CodeTracer src directory not found")
                result = run_codetracer_diagnosis(run_dir=run_dir)

            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["reason"], "codetracer_not_installed")

            report_path = run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json"
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "unavailable")
            self.assertEqual(report["reason"], "codetracer_not_installed")
            self.assertIn("CODETRACER_ROOT", report["suggestion"])


if __name__ == "__main__":
    unittest.main()
