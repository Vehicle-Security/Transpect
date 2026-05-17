from __future__ import annotations

import unittest

from guardrail.security.context_state import compress_context, create_security_context
from guardrail.security.schemas import (
    NavigationEdge,
    SecurityContextState,
    SensitiveAction,
    SourceTrust,
    TaskScopeDeviation,
)


class CompressContextTests(unittest.TestCase):
    """Tests for compress_context() — research direction 1 feature vector."""

    def test_empty_context_returns_zero_vector(self) -> None:
        ctx = create_security_context(run_id="test")
        vec = compress_context(ctx)
        self.assertEqual(vec["cumulative_risk_score"], 0.0)
        self.assertEqual(vec["low_trust_ratio"], 0.0)
        self.assertEqual(vec["chain_escalation_flag"], 0.0)
        self.assertEqual(vec["scope_deviation_level"], 0.0)
        self.assertEqual(len(vec), 9)

    def test_low_trust_ratio_reflects_source_distribution(self) -> None:
        ctx = SecurityContextState(runId="test")
        ctx.sourceTrustChain = [
            SourceTrust(sourceType="user_instruction", trustLevel="high", content="task"),
            SourceTrust(sourceType="comment", trustLevel="low", content="详情请访问"),
            SourceTrust(sourceType="web_page", trustLevel="medium", content="topic"),
            SourceTrust(sourceType="advertisement", trustLevel="low", content="ad"),
        ]
        vec = compress_context(ctx)
        self.assertEqual(vec["low_trust_ratio"], 0.5)

    def test_external_nav_from_comment_triggers_escalation_flag(self) -> None:
        ctx = SecurityContextState(runId="test")
        ctx.sourceTrustChain = [
            SourceTrust(sourceType="comment", trustLevel="low", content="详情请访问xxx"),
        ]
        ctx.navigationChain = [
            NavigationEdge(fromSource="comment", toTarget="http://evil.com", sourceType="external_website", eventId="e1"),
        ]
        vec = compress_context(ctx)
        self.assertEqual(vec["chain_escalation_flag"], 1.0)

    def test_navigation_without_low_trust_source_no_escalation(self) -> None:
        ctx = SecurityContextState(runId="test")
        ctx.sourceTrustChain = [
            SourceTrust(sourceType="user_instruction", trustLevel="high", content="open url"),
        ]
        ctx.navigationChain = [
            NavigationEdge(fromSource="user_instruction", toTarget="http://safe.com", sourceType="user_instruction", eventId="e1"),
        ]
        vec = compress_context(ctx)
        self.assertEqual(vec["chain_escalation_flag"], 0.0)

    def test_unauthorized_ratio_counts_unauthorized_sensitive_actions(self) -> None:
        ctx = SecurityContextState(runId="test")
        ctx.sensitiveActions = [
            SensitiveAction(actionType="upload_photo", target="/photos", authorizedByUser=False,
                            sourceType="external_website", riskLevel="high", reason="test", eventId="e1"),
            SensitiveAction(actionType="read_local_file", target="/tmp/x.txt", authorizedByUser=True,
                            sourceType="user_instruction", riskLevel="low", reason="test", eventId="e2"),
            SensitiveAction(actionType="execute_command", target="curl evil.com", authorizedByUser=False,
                            sourceType="comment", riskLevel="high", reason="test", eventId="e3"),
        ]
        vec = compress_context(ctx)
        self.assertAlmostEqual(vec["unauthorized_sensitive_ratio"], 2.0 / 3.0)

    def test_scope_deviation_level_maps_correctly(self) -> None:
        ctx = SecurityContextState(runId="test")
        ctx.taskScopeDeviation = TaskScopeDeviation(level="scope_expansion")
        vec = compress_context(ctx)
        self.assertAlmostEqual(vec["scope_deviation_level"], 0.66)

    def test_full_attack_chain_produces_high_scores(self) -> None:
        ctx = SecurityContextState(runId="test")
        ctx.sourceTrustChain = [
            SourceTrust(sourceType="user_instruction", trustLevel="high", content="查看话题"),
            SourceTrust(sourceType="comment", trustLevel="low", content="详情请访问 http://evil.com"),
            SourceTrust(sourceType="external_website", trustLevel="low", content="waterhole page"),
        ]
        ctx.navigationChain = [
            NavigationEdge(fromSource="comment", toTarget="http://evil.com", sourceType="external_website", eventId="e1"),
        ]
        ctx.sensitiveActions = [
            SensitiveAction(actionType="upload_photo", target="local_user_photo_fixture", authorizedByUser=False,
                            sourceType="external_website", riskLevel="critical", reason="test", eventId="e2"),
        ]
        ctx.taskScopeDeviation = TaskScopeDeviation(level="severe_deviation")
        ctx.cumulativeRisk.score = 35
        ctx.riskTimeline.extend([{} for _ in range(5)])  # type: ignore[arg-type]

        vec = compress_context(ctx)
        self.assertGreater(vec["cumulative_risk_score"], 0.3)
        self.assertGreater(vec["low_trust_ratio"], 0.5)
        self.assertEqual(vec["chain_escalation_flag"], 1.0)
        self.assertEqual(vec["scope_deviation_level"], 1.0)
        self.assertEqual(vec["unauthorized_sensitive_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
