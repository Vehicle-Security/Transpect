from __future__ import annotations

from typing import Any

from .command_policy import analyze_command, analyze_file_read
from .context_state import add_risk_event, add_sensitive_action, explicit_authorized, set_scope_deviation
from .decision_engine import decide
from .risk_scoring import action_name, hard_block_reason, has_sensitive_target, score_action
from .schemas import NavigationEdge, SecurityContextState, SecurityDecision
from .trust_model import classify_source


def _target(action: dict[str, Any]) -> str:
    return str(
        action.get("target")
        or action.get("url")
        or action.get("path")
        or action.get("command")
        or action.get("cmd")
        or action.get("script")
        or action.get("toolName")
        or ""
    )


def inspect_action(action: dict[str, Any], context: SecurityContextState) -> tuple[SecurityDecision, SecurityContextState]:
    action_type = action_name(action)
    source_type = classify_source(action, default="unknown")
    target = _target(action)
    authorized = explicit_authorized(context, action_type, target) or source_type == "user_instruction"
    if action_type in {"execute_command", "read_local_file"}:
        policy = (
            analyze_command(target, source_type=source_type, user_goal=context.userIntent.originalGoal, authorized=authorized)
            if action_type == "execute_command"
            else analyze_file_read(target, source_type=source_type, user_goal=context.userIntent.originalGoal, authorized=authorized)
        )
        if policy.decision in {"block", "require_confirmation"}:
            set_scope_deviation(
                context,
                "severe_deviation" if policy.decision == "block" else "scope_expansion",
                context.userIntent.originalGoal,
                target,
                "Command/file policy identified a risky local capability.",
            )
        event_id = add_risk_event(
            context,
            stage="execution",
            action=action_type,
            source_type=source_type,
            target=target,
            score=policy.risk_score,
            reason=" ".join(policy.reasons),
        )
        if policy.decision == "block":
            add_sensitive_action(
                context,
                action_type=action_type,
                target=target,
                authorized=authorized,
                source_type=source_type,
                risk="critical",
                reason=policy.hard_block_reason or policy.reasons[0],
                event_id=event_id,
            )
        decision = decide(
            context,
            stage="execution",
            score=policy.risk_score,
            reasons=policy.reasons,
            evidence_event_id=event_id,
            hard_block_reason=policy.hard_block_reason,
            force_decision=None if policy.decision == "block" else policy.decision,
        )
        return decision, context
    chain_escalated = bool(context.navigationChain) or (
        source_type in {"comment", "advertisement", "popup", "external_website", "button"}
        and action_type not in {"view_page", "read_comment", "summarize"}
    )
    score, reasons = score_action(action, source_type=source_type, authorized=authorized, chain_escalated=chain_escalated)
    hard_reason = hard_block_reason(action_type, source_type, target, authorized)
    if action_type in {"open_external_link", "visit_unknown_domain", "network_request"}:
        context.navigationChain.append(
            NavigationEdge(
                fromSource=source_type,
                toTarget=target,
                sourceType=source_type,
                eventId=f"nav-{len(context.navigationChain) + 1}",
                reason="Navigation/action link inspected by execution guard.",
            )
        )
        set_scope_deviation(context, "scope_expansion", context.userIntent.originalGoal, target, "Execution moved to an external or unknown target.")
    if action_type == "click_unknown_button":
        set_scope_deviation(context, "scope_expansion", context.userIntent.originalGoal, target, "Unknown button click requires confirmation.")
    if has_sensitive_target(action_type, target):
        set_scope_deviation(context, "severe_deviation", context.userIntent.originalGoal, target, "Sensitive action deviates from original task.")
    event_id = add_risk_event(
        context,
        stage="execution",
        action=action_type,
        source_type=source_type,
        target=target,
        score=score,
        reason=" ".join(reasons),
    )
    if has_sensitive_target(action_type, target):
        add_sensitive_action(
            context,
            action_type=action_type,
            target=target,
            authorized=authorized,
            source_type=source_type,
            risk="critical" if hard_reason else "high",
            reason=hard_reason or "Sensitive action inspected.",
            event_id=event_id,
        )
    force_decision = None
    if action_type == "click_unknown_button" and not hard_reason:
        force_decision = "require_confirmation"
    if authorized and not hard_reason and action_type in {"upload_photo", "upload_file"}:
        force_decision = "require_confirmation"
        score = min(score, 8)
        reasons.append("User explicitly authorized upload, so this is not treated as an unauthorized attack.")
    decision = decide(
        context,
        stage="execution",
        score=score,
        reasons=reasons,
        evidence_event_id=event_id,
        hard_block_reason=hard_reason,
        force_decision=force_decision,
    )
    return decision, context
