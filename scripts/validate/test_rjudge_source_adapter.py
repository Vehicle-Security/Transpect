from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(REPO_ROOT / "task_repos" / "rjudge"))

import adapter  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class RJudgeSourceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(tempfile.mkdtemp(prefix="rjudge-source-"))
        self.sample = {
            "id": 37,
            "scenario": "psychological",
            "profile": "You are a psychological counselor.",
            "goal": "Below is an interaction process between a user and an agent.",
            "contents": [
                [
                    {"role": "user", "content": "hello"},
                    {"role": "agent", "action": "hi there"},
                ],
                [
                    {"role": "user", "content": "follow up"},
                    {"role": "environment", "content": None},
                ],
            ],
            "label": 999,
            "risk_description": "UNIQUE_RISK_DESCRIPTION_SHOULD_NOT_APPEAR",
            "attack_type": "unintended",
        }
        write_json(self.repo_root / "data" / "Application" / "chatbot.json", [self.sample])
        self.manifest = {
            "repo_root": str(self.repo_root),
            "source": {
                "data_root": "data",
                "data_pattern": "**/*.json",
                "task_id_format": "data/<category>/<file>.json#<sample_id>",
            },
        }
        self.prepared_env: dict[str, object] = {}

    def test_list_tasks_enumerates_from_data_directory(self) -> None:
        tasks = adapter.list_tasks(self.manifest, self.prepared_env)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["sourcePath"], "data/Application/chatbot.json")

    def test_list_tasks_stable_task_ids(self) -> None:
        tasks = adapter.list_tasks(self.manifest, self.prepared_env)
        self.assertEqual(tasks[0]["taskId"], "data/Application/chatbot.json#37")

    def test_load_task_returns_full_sample(self) -> None:
        task = adapter.load_task(self.manifest, self.prepared_env, "data/Application/chatbot.json#37")
        self.assertEqual(task["profile"], self.sample["profile"])
        self.assertEqual(task["risk_description"], self.sample["risk_description"])
        self.assertEqual(task["taskId"], "data/Application/chatbot.json#37")

    def test_load_task_not_found_raises(self) -> None:
        with self.assertRaises(LookupError):
            adapter.load_task(self.manifest, self.prepared_env, "data/Application/chatbot.json#404")

    def test_build_agent_input_excludes_label_and_risk(self) -> None:
        task = adapter.load_task(self.manifest, self.prepared_env, "data/Application/chatbot.json#37")
        prompt = adapter.build_agent_input(self.manifest, self.prepared_env, task)
        self.assertNotIn("UNIQUE_RISK_DESCRIPTION_SHOULD_NOT_APPEAR", prompt)
        self.assertNotIn("999", prompt)
        self.assertNotIn("label", prompt.lower())
        self.assertNotIn("risk_description", prompt)

    def test_build_agent_input_includes_profile_goal_contents(self) -> None:
        task = adapter.load_task(self.manifest, self.prepared_env, "data/Application/chatbot.json#37")
        prompt = adapter.build_agent_input(self.manifest, self.prepared_env, task)
        self.assertIn("You are a psychological counselor.", prompt)
        self.assertIn("Below is an interaction process", prompt)
        self.assertIn("Round 1:", prompt)
        self.assertIn("Round 2:", prompt)
        self.assertIn("user: hello", prompt)
        self.assertIn("agent: hi there", prompt)


if __name__ == "__main__":
    unittest.main()
