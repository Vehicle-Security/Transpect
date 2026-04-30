from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agent_defense.bridge import handle


class BridgeModelJudgeTests(unittest.TestCase):
    def test_gray_zone_action_uses_llm_judge_when_enabled(self) -> None:
        run_dir = Path(tempfile.mkdtemp(prefix="bridge-model-judge-"))

        with patch(
            "app.agent_defense.bridge.judge_gray_zone",
            return_value={
                "decision": "allow",
                "riskLevel": "low",
                "reasons": ["The command is a harmless bootstrap probe."],
                "confidence": 0.91,
            },
        ) as judge:
            result = handle(
                {
                    "operation": "inspect_action",
                    "runDir": str(run_dir),
                    "runId": "run-judge",
                    "action": {
                        "actionType": "execute_command",
                        "sourceType": "unknown",
                        "target": "openclaw doctor --json",
                    },
                    "llmJudge": {
                        "enabled": True,
                        "mode": "gray_zone_only",
                    },
                }
            )

        self.assertEqual(result["decision"]["decision"], "allow")
        self.assertEqual(result["decision"]["riskLevel"], "low")
        self.assertFalse(result["shouldBlock"])
        self.assertIn("LLM gray-zone judge", result["decision"]["reasons"][0])
        judge.assert_called_once()


if __name__ == "__main__":
    unittest.main()
