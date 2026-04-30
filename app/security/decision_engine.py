from __future__ import annotations

from .context_state import add_evidence
from .risk_scoring import decision_for_level, risk_level
from .schemas import SecurityContextState, SecurityDecision


USER_MESSAGES = {
    "allow": "安全检查通过，动作与当前任务范围一致。",
    "warn": "检测到低可信来源或轻微范围扩展，已记录风险并继续执行。",
    "require_confirmation": "该动作可能超出原始任务范围，需要用户确认后才能继续。",
    "block": "已阻断未授权的高风险动作，避免泄露隐私或执行危险操作。",
}


def decide(
    context: SecurityContextState,
    *,
    stage: str,
    score: int,
    reasons: list[str],
    evidence_event_id: str | None = None,
    hard_block_reason: str | None = None,
    force_decision: str | None = None,
) -> SecurityDecision:
    effective_score = max(score, 0)
    level = risk_level(score)
    decision = force_decision or decision_for_level(level)
    hard_block = hard_block_reason is not None
    if hard_block:
        decision = "block"
        level = "critical"
        effective_score = max(effective_score, 9)
        reasons = [hard_block_reason, *reasons]
    if decision == "allow" and not reasons:
        reasons = ["No material security risk detected."]
    if decision in {"block", "require_confirmation"} and not reasons:
        reasons = ["The action is too risky to continue without explicit user approval."]
    event_id = evidence_event_id or f"decision-{len(context.evidenceEvents) + 1}"
    security_decision = SecurityDecision(
        decision=decision,
        riskLevel=level,
        riskScore=effective_score,
        confidence=0.9 if hard_block else 0.7,
        hardBlockTriggered=hard_block,
        reasons=reasons,
        evidenceEvents=[event_id],
        suggestedUserMessage=USER_MESSAGES.get(decision, USER_MESSAGES["warn"]),
        lastStage=stage,
    )
    context.lastDecision = security_decision
    add_evidence(
        context,
        f"security.decision.{decision}",
        stage,
        {
            "eventId": event_id,
            "decision": decision,
            "riskLevel": level,
            "riskScore": effective_score,
            "reason": reasons[0],
            "evidence": {"hardBlockTriggered": hard_block},
        },
    )
    return security_decision
