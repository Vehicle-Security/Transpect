from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from guardrail.security.context_state import add_risk_event
from guardrail.security.decision_engine import decide
from guardrail.security.schemas import SecurityContextState, SecurityDecision

from .normalizers import extract_urls


INTERVENTION_DECISIONS = {"block", "require_confirmation"}


def _domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return parsed.netloc.lower()


def _same_target(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left in right or right in left:
        return True
    left_domain = _domain(left)
    right_domain = _domain(right)
    return bool(left_domain and right_domain and left_domain == right_domain)


def intervened_targets(context: SecurityContextState) -> list[str]:
    has_intervention = any(
        str(event.get("decision") or "").lower() in INTERVENTION_DECISIONS
        or str(event.get("eventType") or "").endswith((".block", ".require_confirmation"))
        for event in context.evidenceEvents
        if isinstance(event, dict)
    )
    if not has_intervention:
        return []
    targets = [str(item.target) for item in context.riskTimeline if str(item.target or "").strip()]
    for event in context.evidenceEvents:
        evidence = event.get("evidence") if isinstance(event, dict) else None
        if isinstance(evidence, dict):
            for value in (evidence.get("target"), evidence.get("url"), evidence.get("command")):
                if isinstance(value, str) and value.strip():
                    targets.append(value)
    return list(dict.fromkeys(targets))


def detect_bypass_escalation(action: dict[str, Any], context: SecurityContextState) -> dict[str, Any] | None:
    if str(action.get("actionType") or "") != "execute_command":
        return None
    command = str(action.get("command") or action.get("target") or "")
    lowered = command.lower()
    if "curl" not in lowered and "wget" not in lowered:
        return None
    urls = list(action.get("commandUrls") or []) or extract_urls(command)
    for url in urls:
        for previous_target in intervened_targets(context):
            if _same_target(url, previous_target):
                return {
                    "url": url,
                    "previousTarget": previous_target,
                    "command": command,
                    "reason": "Bypass escalation: command-line network access targets a URL already stopped by Agent Defense.",
                }
    return None


def force_bypass_block(
    action: dict[str, Any],
    context: SecurityContextState,
    bypass: dict[str, Any],
) -> tuple[SecurityDecision, SecurityContextState]:
    event_id = add_risk_event(
        context,
        stage="execution",
        action="bypass_escalation",
        source_type=str(action.get("sourceType") or action.get("source") or "unknown"),
        target=str(bypass.get("url") or action.get("target") or ""),
        score=10,
        reason=str(bypass.get("reason") or "Bypass escalation detected."),
    )
    decision = decide(
        context,
        stage="execution",
        score=10,
        reasons=[str(bypass.get("reason") or "Bypass escalation detected.")],
        evidence_event_id=event_id,
        hard_block_reason="Bypass escalation detected after a prior Agent Defense intervention.",
    )
    return decision, context
