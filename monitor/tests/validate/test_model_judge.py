from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardrail.security.model_judge import _default_env_path, judge_gray_zone, load_model_config


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class CapturingOpener:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.requests = []

    def __call__(self, request, timeout: int):
        self.requests.append((request, timeout))
        return FakeResponse(self.payload)


class ModelJudgeTests(unittest.TestCase):
    def test_loads_openai_compatible_config_from_dotenv(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="model-judge-env-"))
        env_path = root / ".env"
        env_path.write_text(
            "BASE_URL=https://api.example.com/v1\nAPI_KEY=test-secret\nMODEL_ID=judge-model\n",
            encoding="utf-8",
        )

        config = load_model_config(env_path)

        self.assertTrue(config.enabled)
        self.assertEqual(config.endpoint, "https://api.example.com/v1/chat/completions")
        self.assertEqual(config.model, "judge-model")
        self.assertEqual(config.api_key, "test-secret")

    def test_judges_gray_zone_with_dotenv_config_without_exposing_secret(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="model-judge-call-"))
        env_path = root / ".env"
        env_path.write_text(
            "BASE_URL=https://api.example.com\nAPI_KEY=test-secret\nMODEL_ID=judge-model\n",
            encoding="utf-8",
        )
        opener = CapturingOpener(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "decision": "allow",
                                    "risk": "low",
                                    "reasons": ["User explicitly requested bootstrap file initialization."],
                                    "confidence": 0.82,
                                }
                            )
                        }
                    }
                ]
            }
        )

        result = judge_gray_zone(
            {
                "action": {"actionType": "execute_command", "target": "cat ~/.openclaw/workspace/BOOTSTRAP.md"},
                "decision": {"decision": "require_confirmation", "riskLevel": "high", "reasons": ["gray zone"]},
            },
            env_path=env_path,
            opener=opener,
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["riskLevel"], "low")
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 30)
        self.assertEqual(request.full_url, "https://api.example.com/chat/completions")
        self.assertEqual(request.headers["Authorization"], "Bearer test-secret")
        self.assertNotIn("test-secret", request.data.decode("utf-8"))

    def test_default_env_path_falls_back_to_repo_root_when_cwd_has_no_env(self) -> None:
        empty_dir = Path(tempfile.mkdtemp(prefix="model-judge-empty-cwd-"))

        with patch.object(Path, "cwd", return_value=empty_dir):
            self.assertEqual(_default_env_path(), Path(os.getcwd()) / ".env")


if __name__ == "__main__":
    unittest.main()
