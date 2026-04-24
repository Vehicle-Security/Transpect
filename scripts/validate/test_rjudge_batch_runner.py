from __future__ import annotations

import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPTS_ROOT / "runtime"))

import run_rjudge_batch  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class RJudgeBatchRunnerTests(unittest.TestCase):
    def sample_tasks(self) -> list[dict]:
        return [
            {
                "taskId": "data/Application/chatbot.json#37",
                "sourcePath": "data/Application/chatbot.json",
                "scenario": "psychological",
                "attackType": "unintended",
                "label": 0,
            },
            {
                "taskId": "data/Program/terminal.json#0",
                "sourcePath": "data/Program/terminal.json",
                "scenario": "os",
                "attackType": "unintended",
                "label": 1,
            },
            {
                "taskId": "data/Program/ds_program.json#2009",
                "sourcePath": "data/Program/ds_program.json",
                "scenario": "",
                "attackType": "injection",
                "label": 1,
            },
        ]

    def test_filter_tasks_by_source_path_label_and_attack_type(self) -> None:
        filtered = run_rjudge_batch.filter_tasks(
            self.sample_tasks(),
            task_ids=[],
            source_paths=["data/Program"],
            labels=[1],
            attack_types=["injection"],
            scenario=None,
        )

        self.assertEqual([task["taskId"] for task in filtered], ["data/Program/ds_program.json#2009"])

    def test_select_tasks_is_deterministic_without_shuffle(self) -> None:
        selected = run_rjudge_batch.select_tasks(self.sample_tasks(), count=2, shuffle=False, seed=123)

        self.assertEqual(
            [task["taskId"] for task in selected],
            ["data/Application/chatbot.json#37", "data/Program/terminal.json#0"],
        )

    def test_extract_predicted_label_from_codetracer_bundle(self) -> None:
        run_dir = Path(tempfile.mkdtemp(prefix="rjudge-batch-label-"))
        write_json(
            run_dir / "diagnosis" / "codetracer" / "bundle" / "steps.json",
            [
                {
                    "step_id": 3,
                    "openclaw_meta": {"syntheticReason": "final_assistant_answer"},
                    "observation_ref": {
                        "content": json.dumps(
                            {
                                "payload": {
                                    "preview": {
                                        "assistant": "1\n\n**Reason:** The operation is unsafe.",
                                    }
                                }
                            }
                        )
                    },
                }
            ],
        )

        self.assertEqual(run_rjudge_batch.extract_predicted_label(run_dir), 1)

    def test_dry_run_writes_selected_report(self) -> None:
        temp_root = Path(tempfile.mkdtemp(prefix="rjudge-batch-dry-run-"))
        args = Namespace(
            repo="rjudge",
            task_id=[],
            source_path=["data/Program"],
            label=[1],
            attack_type=[],
            scenario=None,
            count=1,
            shuffle=False,
            seed=0,
            batch_name="dry-run-test",
            dry_run=True,
            start_runtime=False,
            open_viewer=False,
        )

        with patch.object(run_rjudge_batch, "REPORTS_DIR", temp_root), patch.object(
            run_rjudge_batch,
            "list_rjudge_tasks",
            return_value=self.sample_tasks(),
        ):
            result = run_rjudge_batch.run_batch(args)

        report = json.loads((temp_root / "dry-run-test.json").read_text(encoding="utf-8"))
        self.assertTrue(result["ok"])
        self.assertTrue(result["dryRun"])
        self.assertEqual(report["sample"]["selectedTaskCount"], 1)
        self.assertEqual(report["sample"]["tasks"][0]["taskId"], "data/Program/terminal.json#0")


if __name__ == "__main__":
    unittest.main()
