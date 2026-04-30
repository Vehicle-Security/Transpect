from __future__ import annotations

from typing import Any

from .context_state import add_risk_event, explicit_authorized, set_scope_deviation
from .decision_engine import decide
from .risk_scoring import action_name
from .schemas import SecurityContextState, SecurityDecision
from .trust_model import classify_source


def _target(step: dict[str, Any]) -> str:
    return str(step.get("target") or step.get("url") or step.get("path") or step.get("content") or step.get("text") or "")


def inspect_plan_step(plan_step: dict[str, Any], context: SecurityContextState) -> tuple[SecurityDecision, SecurityContextState]:
    source_type = classify_source(plan_step, default="user_instruction")
    action = action_name(plan_step)
    target = _target(plan_step)
    authorized = explicit_authorized(context, action, target) or source_type == "user_instruction"
    score = 1
    reasons = [f"Plan step {action} inspected."]
    force_decision: str | None = None
    if action in {"view_page", "read_comment", "summarize"}:
        score = 1
        set_scope_deviation(context, "in_scope", context.userIntent.originalGoal, target, "Plan remains inside user browsing task.")
    elif action in {"open_external_link", "visit_unknown_domain"}:
        score = 4 if source_type == "user_instruction" or authorized else 5
        reasons.append("Plan opens an external link.")
        set_scope_deviation(context, "scope_expansion", context.userIntent.originalGoal, target, "Plan expands from browsing to external navigation.")
        force_decision = "warn"
    elif action == "click_unknown_button":
        score = 6
        reasons.append("Plan includes an unknown button click.")
        set_scope_deviation(context, "scope_expansion", context.userIntent.originalGoal, target, "Unknown button requires confirmation.")
        force_decision = "require_confirmation"
    elif action in {"upload_file", "upload_photo", "read_local_file", "execute_command", "submit_private_data", "access_token_or_cookie"}:
        score = 9
        reasons.append("Plan includes sensitive operation.")
        set_scope_deviation(context, "severe_deviation", context.userIntent.originalGoal, target, "Plan includes a severe sensitive operation.")
    event_id = add_risk_event(
        context,
        stage="planning",
        action=action,
        source_type=source_type,
        target=target,
        score=score,
        reason=" ".join(reasons),
    )
    decision = decide(context, stage="planning", score=score, reasons=reasons, evidence_event_id=event_id, force_decision=force_decision)
    return decision, context


def inspect_plan(plan: list[dict[str, Any]] | dict[str, Any] | str, context: SecurityContextState) -> tuple[SecurityDecision, SecurityContextState]:
    if isinstance(plan, str):
        text = plan
        inferred: list[dict[str, Any]] = []
        if "详情请访问" in text or "外部链接" in text or "http://" in text or "https://" in text:
            inferred.append({"action": "open_external_link", "sourceType": "comment", "target": text})
        if "按钮" in text or "button" in text.lower() or "点击" in text:
            inferred.append({"action": "click_unknown_button", "sourceType": "button", "target": text})
        if "上传" in text or "upload" in text.lower():
            inferred.append({"action": "upload_photo", "sourceType": "external_website", "target": text})
        plan_items = inferred or [{"action": "view_page", "sourceType": "user_instruction", "target": text}]
    elif isinstance(plan, dict):
        plan_items = [plan]
    else:
        plan_items = [item for item in plan if isinstance(item, dict)]
    decision = context.lastDecision
    for step in plan_items:
        decision, context = inspect_plan_step(step, context)
        if decision.decision == "block":
            break
    return decision, context
