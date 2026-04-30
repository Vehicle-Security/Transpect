from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class AgentDefenseBridgeTests(unittest.TestCase):
    def test_web_fetch_http_url_is_guarded_as_external_navigation(self) -> None:
        from app.agent_defense.bridge import handle

        run_dir = Path(tempfile.mkdtemp(prefix="agent-defense-web-fetch-"))
        result = handle(
            {
                "operation": "inspect_action",
                "runDir": str(run_dir),
                "runId": "run-web-fetch",
                "action": {
                    "toolName": "web_fetch",
                    "url": "https://evil.example/waterhole/detail",
                    "sourceType": "comment",
                },
            }
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["decision"]["decision"], "require_confirmation")
        self.assertTrue(result["shouldBlock"])

        state = read_json(run_dir / "security-reasoning" / "security_state.json")
        self.assertEqual(state["riskTimeline"][-1]["action"], "open_external_link")
        self.assertEqual(state["riskTimeline"][-1]["target"], "https://evil.example/waterhole/detail")

    def test_exec_curl_to_previously_intervened_url_is_bypass_escalation(self) -> None:
        from app.agent_defense.bridge import handle

        run_dir = Path(tempfile.mkdtemp(prefix="agent-defense-bypass-"))
        first = handle(
            {
                "operation": "inspect_action",
                "runDir": str(run_dir),
                "runId": "run-bypass",
                "action": {
                    "toolName": "web_fetch",
                    "url": "https://evil.example/waterhole/detail",
                    "sourceType": "comment",
                },
            }
        )
        self.assertEqual(first["decision"]["decision"], "require_confirmation")

        second = handle(
            {
                "operation": "inspect_action",
                "runDir": str(run_dir),
                "runId": "run-bypass",
                "action": {
                    "toolName": "exec",
                    "command": "curl -s https://evil.example/waterhole/detail",
                    "sourceType": "unknown",
                },
            }
        )

        self.assertEqual(second["decision"]["decision"], "block")
        self.assertTrue(second["shouldBlock"])
        self.assertTrue(any("bypass" in reason.lower() for reason in second["decision"]["reasons"]))

    def test_explicitly_authorized_url_does_not_require_confirmation(self) -> None:
        from app.agent_defense.bridge import handle

        run_dir = Path(tempfile.mkdtemp(prefix="agent-defense-authorized-url-"))
        handle(
            {
                "operation": "inspect_user_input",
                "runDir": str(run_dir),
                "runId": "run-authorized-url",
                "message": "请打开 https://trusted.example/topic 并总结页面内容。",
            }
        )

        result = handle(
            {
                "operation": "inspect_action",
                "runDir": str(run_dir),
                "runId": "run-authorized-url",
                "action": {
                    "toolName": "web_fetch",
                    "url": "https://trusted.example/topic",
                    "sourceType": "unknown",
                },
            }
        )

        self.assertIn(result["decision"]["decision"], {"allow", "warn"})
        self.assertFalse(result["shouldBlock"])


if __name__ == "__main__":
    unittest.main()
