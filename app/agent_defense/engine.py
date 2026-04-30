from __future__ import annotations

from pathlib import Path
from typing import Any

from app.security.action_guard import inspect_action as inspect_security_action
from app.security.context_state import add_risk_event, explicit_authorized
from app.security.decision_engine import decide
from app.security.schemas import SecurityContextState, SecurityDecision

from .context import detect_bypass_escalation, force_bypass_block
from .normalizers import normalize_action
from .policy import evaluate_policy, load_policy


def _apply_policy_decision(
    policy_decision: dict[str, Any],
    action: dict[str, Any],
    context: SecurityContextState,
) -> tuple[SecurityDecision, SecurityContextState]:
    decision_name = str(policy_decision.get("decision") or "warn")
    reason = str(policy_decision.get("reason") or "Agent Defense policy matched.")
    event_id = add_risk_event(
        context,
        stage="execution",
        action=str(action.get("actionType") or action.get("toolName") or "tool_call"),
        source_type=str(action.get("sourceType") or action.get("source") or "unknown"),
        target=str(action.get("target") or action.get("url") or action.get("path") or action.get("command") or ""),
        score=int(policy_decision.get("riskScore") or (10 if decision_name == "block" else 7)),
        reason=f"{policy_decision.get('ruleId')}: {reason}",
    )
    decision = decide(
        context,
        stage="execution",
        score=int(policy_decision.get("riskScore") or 7),
        reasons=[reason],
        evidence_event_id=event_id,
        hard_block_reason=reason if decision_name == "block" else None,
        force_decision=None if decision_name == "block" else decision_name,
    )
    return decision, context


def inspect_action(
    action: dict[str, Any],
    context: SecurityContextState,
    *,
    policy_path: str | Path | None = None,
) -> tuple[SecurityDecision, SecurityContextState, dict[str, Any]]:
    normalized_action = normalize_action(action)
    policy = load_policy(policy_path)

    bypass = detect_bypass_escalation(normalized_action, context)
    if bypass:
        decision, context = force_bypass_block(normalized_action, context, bypass)
        normalized_action["bypassDetected"] = True
        normalized_action["bypassEvidence"] = bypass
        return decision, context, normalized_action

    policy_decision = evaluate_policy(normalized_action, policy)
    if (
        policy_decision
        and policy_decision.get("decision") == "require_confirmation"
        and explicit_authorized(
            context,
            str(normalized_action.get("actionType") or normalized_action.get("toolName") or ""),
            str(normalized_action.get("target") or normalized_action.get("url") or ""),
        )
    ):
        policy_decision = None

    if policy_decision and policy_decision.get("decision") in {"block", "require_confirmation"}:
        decision, context = _apply_policy_decision(policy_decision, normalized_action, context)
        normalized_action["policyDecision"] = policy_decision
        return decision, context, normalized_action

    if explicit_authorized(
        context,
        str(normalized_action.get("actionType") or normalized_action.get("toolName") or ""),
        str(normalized_action.get("target") or normalized_action.get("url") or ""),
    ) and str(normalized_action.get("actionType") or "") in {"open_external_link", "network_request"}:
        normalized_action["sourceType"] = "user_instruction"
        normalized_action["authorizedByUserIntent"] = True

    decision, context = inspect_security_action(normalized_action, context)

    if policy_decision and policy_decision.get("decision") == "allow" and decision.decision == "warn":
        decision.reasons.append(str(policy_decision.get("reason") or "Policy allow rule matched."))

    return decision, context, normalized_action
