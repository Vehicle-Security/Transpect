from __future__ import annotations

from typing import Any

from .context_state import snapshot
from .schemas import SecurityContextState, SecurityDecision


def build_security_event(
    context: SecurityContextState,
    decision: SecurityDecision,
    *,
    event_type: str,
    stage: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "eventType": event_type,
        "stage": stage,
        "decision": decision.decision,
        "riskLevel": decision.riskLevel,
        "riskScore": decision.riskScore,
        "reason": decision.reasons[0] if decision.reasons else "",
        "evidence": evidence or {},
        "securityContextSnapshot": snapshot(context),
    }
