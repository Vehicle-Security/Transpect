from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agent_defense.policy import (
    domain_matches,
    evaluate_policy,
    load_policy,
    resolve_policy_path,
)


class PolicyEvaluateTests(unittest.TestCase):
    """Tests for evaluate_policy() and _rule_matches()."""

    def _minimal_policy(self, **overrides: object) -> dict[str, object]:
        base: dict[str, object] = {
            "schemaVersion": "transpect.agent-defense.policy.v1",
            "allow": [],
            "block": [],
            "confirm": [],
            "sensitiveMarkers": [],
            "trustedDomains": [],
            "bypassRules": [],
        }
        base.update(overrides)
        return base

    def test_no_match_returns_none(self) -> None:
        policy = self._minimal_policy()
        result = evaluate_policy({"actionType": "read_local_file", "target": "/tmp/foo.txt"}, policy)
        self.assertIsNone(result)

    def test_block_rule_matches_by_action_only(self) -> None:
        policy = self._minimal_policy(
            block=[
                {
                    "id": "block-cmd",
                    "description": "Block all execute_command actions.",
                    "actions": ["execute_command"],
                }
            ]
        )
        result = evaluate_policy({"actionType": "execute_command", "target": "rm -rf /tmp"}, policy)
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["riskLevel"], "critical")
        self.assertEqual(result["riskScore"], 10)

    def test_block_rule_no_match_wrong_action(self) -> None:
        policy = self._minimal_policy(
            block=[
                {
                    "id": "block-cmd",
                    "description": "Block execute_command only.",
                    "actions": ["execute_command"],
                }
            ]
        )
        result = evaluate_policy({"actionType": "read_local_file", "target": "/etc/passwd"}, policy)
        self.assertIsNone(result)

    def test_block_rule_matches_by_marker(self) -> None:
        policy = self._minimal_policy(
            sensitiveMarkers=[".env", ".ssh"],
            block=[
                {
                    "id": "block-credentials",
                    "description": "Block access to credential files.",
                    "markers": [".env", ".ssh", "id_rsa"],
                }
            ],
        )
        result = evaluate_policy(
            {"actionType": "read_local_file", "target": "/home/user/.env"},
            policy,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")

    def test_marker_match_case_insensitive(self) -> None:
        policy = self._minimal_policy(
            sensitiveMarkers=["token"],
            block=[
                {
                    "id": "block-token",
                    "description": "Block token access.",
                    "markers": ["token"],
                }
            ],
        )
        result = evaluate_policy(
            {"actionType": "read_local_file", "target": "/app/API_TOKEN.txt"},
            policy,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")

    def test_domain_matches_exact_and_wildcard(self) -> None:
        self.assertTrue(domain_matches("example.com", ["example.com"]))
        self.assertTrue(domain_matches("sub.example.com", ["*.example.com"]))
        self.assertFalse(domain_matches("other.com", ["example.com"]))
        self.assertFalse(domain_matches("notexample.com", ["example.com"]))
        self.assertTrue(domain_matches("deep.sub.example.com", ["*.example.com"]))

    def test_domain_matches_wildcard_not_bare_domain(self) -> None:
        self.assertFalse(domain_matches("example.com", ["*.example.com"]))

    def test_domain_rule_triggers_match(self) -> None:
        policy = self._minimal_policy(
            block=[
                {
                    "id": "block-evil",
                    "description": "Block evil.com domain.",
                    "domains": ["evil.com", "*.evil.net"],
                }
            ],
        )
        result = evaluate_policy(
            {"actionType": "open_external_link", "url": "https://evil.com/phish"},
            policy,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")

        result2 = evaluate_policy(
            {"actionType": "open_external_link", "url": "https://safe.com/page"},
            policy,
        )
        self.assertIsNone(result2)

    def test_path_matches_with_fnmatch(self) -> None:
        policy = self._minimal_policy(
            allow=[
                {
                    "id": "allow-workspace",
                    "description": "Allow OpenClaw workspace files.",
                    "actions": ["read_local_file"],
                    "paths": ["~/.openclaw/workspace/**"],
                }
            ],
        )
        result = evaluate_policy(
            {
                "actionType": "read_local_file",
                "path": "~/.openclaw/workspace/BOOTSTRAP.md",
            },
            policy,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "allow")

    def test_block_beats_confirm_beats_allow(self) -> None:
        policy = self._minimal_policy(
            allow=[
                {
                    "id": "allow-workspace",
                    "description": "Allow OpenClaw workspace.",
                    "actions": ["read_local_file"],
                    "paths": ["~/.openclaw/workspace/**"],
                }
            ],
            confirm=[
                {
                    "id": "confirm-reads",
                    "description": "Confirm all file reads.",
                    "actions": ["read_local_file"],
                }
            ],
            block=[
                {
                    "id": "block-env",
                    "description": "Block .env reads.",
                    "actions": ["read_local_file"],
                    "markers": [".env"],
                }
            ],
            sensitiveMarkers=[".env"],
        )
        result = evaluate_policy(
            {"actionType": "read_local_file", "path": "~/.openclaw/workspace/.env"},
            policy,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "block")

    def test_confirm_rule_skips_sensitive_markers(self) -> None:
        policy = self._minimal_policy(
            sensitiveMarkers=[".env", "token"],
            confirm=[
                {
                    "id": "confirm-network",
                    "description": "Confirm all network requests.",
                    "actions": ["open_external_link", "network_request"],
                }
            ],
        )
        result = evaluate_policy(
            {
                "actionType": "open_external_link",
                "url": "https://api.example.com/token/refresh",
            },
            policy,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["decision"], "require_confirmation")


class PolicyLoadTests(unittest.TestCase):
    """Tests for load_policy() and resolve_policy_path()."""

    def test_load_policy_returns_defaults_for_missing_file(self) -> None:
        with patch(
            "app.agent_defense.policy.resolve_policy_path",
            return_value=Path("/nonexistent/policy.json"),
        ):
            policy = load_policy()
        self.assertEqual(policy["schemaVersion"], "transpect.agent-defense.policy.v1")
        self.assertEqual(policy["allow"], [])
        self.assertEqual(policy["block"], [])
        self.assertEqual(policy["confirm"], [])
        self.assertNotIn("sensitiveMarkers", policy)

    def test_load_policy_falls_back_to_legacy_path(self) -> None:
        with patch(
            "app.agent_defense.policy._read_json",
            side_effect=lambda path: {
                "allow": [{"id": "legacy-rule", "actions": ["read_local_file"]}],
            },
        ), patch.object(
            Path,
            "exists",
            side_effect=lambda self: str(self).endswith("security-policy.json") or "Transpect" in str(self),
        ):
            with patch(
                "app.agent_defense.policy.resolve_policy_path",
                return_value=Path("/fake/config/security-policy.json"),
            ):
                policy = load_policy()
                self.assertEqual(len(policy["allow"]), 1)
                self.assertEqual(policy["allow"][0]["id"], "legacy-rule")

    def test_load_policy_fills_missing_defaults(self) -> None:
        partial = {"allow": [{"id": "test", "actions": ["execute_command"]}]}
        with patch("app.agent_defense.policy._read_json", return_value=partial), patch.object(
            Path, "exists", return_value=True
        ), patch(
            "app.agent_defense.policy.resolve_policy_path",
            return_value=Path("/fake/config/agent-defense-policy.json"),
        ):
            policy = load_policy()
        self.assertEqual(policy["allow"], partial["allow"])
        self.assertIsInstance(policy["block"], list)
        self.assertIsInstance(policy["confirm"], list)
        self.assertIsInstance(policy["sensitiveMarkers"], list)
        self.assertIsInstance(policy["bypassRules"], list)

    def test_resolve_policy_path_env_override(self) -> None:
        env_path = Path(tempfile.mkdtemp(prefix="policy-")) / "custom-policy.json"
        with patch.dict("os.environ", {"TRANSPECT_AGENT_DEFENSE_POLICY": str(env_path)}):
            resolved = resolve_policy_path()
        self.assertEqual(resolved, env_path.resolve())

    def test_resolve_policy_path_explicit_arg_wins(self) -> None:
        explicit = Path("/explicit/policy.json")
        with patch.dict("os.environ", {"TRANSPECT_AGENT_DEFENSE_POLICY": "/env/policy.json"}):
            resolved = resolve_policy_path(explicit)
        self.assertEqual(resolved, explicit.resolve())


if __name__ == "__main__":
    unittest.main()
