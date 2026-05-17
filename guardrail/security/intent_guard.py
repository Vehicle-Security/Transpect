from __future__ import annotations

import re
from typing import Any

from .context_state import add_evidence, add_risk_event
from .decision_engine import decide
from .schemas import SecurityContextState, SourceTrust
from .trust_model import classify_source, trust_level


def _text(payload: dict[str, Any] | str) -> str:
    if isinstance(payload, str):
        return payload
    return " ".join(str(payload.get(key) or "") for key in ("message", "content", "text", "input", "output", "target", "url"))


def _extract_authorizations(message: str) -> list[str]:
    authorizations: list[str] = []
    lowered = message.lower()
    if "上传" in message or "upload" in lowered:
        authorizations.append(message)
    if "访问" in message or "打开" in message or "visit" in lowered or "open" in lowered:
        for url in re.findall(r"https?://[^\s，。；;]+", message):
            authorizations.append(url)
    return authorizations


def inspect_user_input(message: str, context: SecurityContextState) -> SecurityContextState:
    if not context.userIntent.originalGoal:
        context.userIntent.originalGoal = message
    context.userIntent.allowedActions.extend(item for item in ["view_page", "read_comment", "summarize"] if item not in context.userIntent.allowedActions)
    for authorization in _extract_authorizations(message):
        if authorization not in context.userIntent.explicitAuthorizations:
            context.userIntent.explicitAuthorizations.append(authorization)
    event_id = add_evidence(
        context,
        "security.input_inspected",
        "input",
        {
            "decision": "allow",
            "riskLevel": "low",
            "riskScore": 0,
            "reason": "User instruction captured as trusted original intent.",
            "evidence": {"message": message},
        },
    )
    context.sourceTrustChain.append(
        SourceTrust(
            sourceType="user_instruction",
            trustLevel="high",
            content=message,
            eventId=event_id,
            reason="Original user instruction is trusted.",
        )
    )
    decide(context, stage="input", score=0, reasons=["User instruction established the original task intent."], evidence_event_id=event_id)
    return context


def inspect_environment_input(event: dict[str, Any], context: SecurityContextState) -> SecurityContextState:
    source_type = classify_source(event)
    level = trust_level(source_type)
    content = _text(event)
    event_id = add_evidence(
        context,
        "security.low_trust_source_detected" if level in {"low", "unknown"} else "security.input_inspected",
        "input",
        {
            "decision": "warn" if level in {"low", "unknown"} else "allow",
            "riskLevel": "medium" if level in {"low", "unknown"} else "low",
            "riskScore": 3 if level in {"low", "unknown"} else 1,
            "reason": f"Environment input classified as {source_type}/{level}.",
            "evidence": event,
        },
    )
    context.sourceTrustChain.append(
        SourceTrust(
            sourceType=source_type,
            trustLevel=level,
            content=content,
            eventId=event_id,
            reason=f"Environment source classified as {source_type}.",
        )
    )
    if level in {"low", "unknown"}:
        add_risk_event(
            context,
            stage="input",
            action="environment_input",
            source_type=source_type,
            target=content[:200],
            score=3,
            reason=f"Low-trust environment input observed: {source_type}.",
            event_id=event_id,
        )
        decide(context, stage="input", score=3, reasons=[f"Low-trust environment input observed: {source_type}."], evidence_event_id=event_id)
    else:
        decide(context, stage="input", score=1, reasons=["Environment input is within expected trust bounds."], evidence_event_id=event_id)
    return context
