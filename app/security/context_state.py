from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any, TypeVar

from .risk_scoring import risk_level
from .schemas import (
    CumulativeRisk,
    NavigationEdge,
    RiskEvent,
    SecurityContextState,
    SecurityDecision,
    SensitiveAction,
    SourceTrust,
    TaskScopeDeviation,
    UserIntent,
)


DEFAULT_FORBIDDEN_ACTIONS = [
    "未授权上传用户照片",
    "未授权上传本地文件",
    "未授权读取本地隐私文件",
    "未授权提交账号密码、Cookie、Token",
    "未授权执行系统命令",
    "未授权调用敏感系统 API",
]

T = TypeVar("T")


def _from_dict(cls: type[T], payload: dict[str, Any] | None) -> T:
    payload = payload or {}
    kwargs = {field.name: payload.get(field.name) for field in fields(cls) if field.name in payload}
    if cls is TaskScopeDeviation and "from" in payload:
        kwargs["from_"] = payload.get("from")
    return cls(**kwargs)  # type: ignore[arg-type]


def create_security_context(run_id: str | None = None, user_message: str | None = None) -> SecurityContextState:
    context = SecurityContextState(runId=run_id)
    context.userIntent.forbiddenActions = list(DEFAULT_FORBIDDEN_ACTIONS)
    if user_message:
        context.userIntent.originalGoal = user_message
    context.lastDecision = SecurityDecision(
        decision="allow",
        riskLevel="low",
        riskScore=0,
        reasons=["Security context initialized."],
        evidenceEvents=[],
        suggestedUserMessage="安全上下文已初始化。",
    )
    return context


def context_from_dict(payload: dict[str, Any] | None) -> SecurityContextState:
    if not isinstance(payload, dict):
        return create_security_context()
    context = SecurityContextState(
        schemaVersion=str(payload.get("schemaVersion") or "1.0"),
        runId=payload.get("runId"),
        userIntent=_from_dict(UserIntent, payload.get("userIntent")),
        sourceTrustChain=[_from_dict(SourceTrust, item) for item in payload.get("sourceTrustChain") or [] if isinstance(item, dict)],
        navigationChain=[_from_dict(NavigationEdge, item) for item in payload.get("navigationChain") or [] if isinstance(item, dict)],
        riskTimeline=[_from_dict(RiskEvent, item) for item in payload.get("riskTimeline") or [] if isinstance(item, dict)],
        sensitiveActions=[_from_dict(SensitiveAction, item) for item in payload.get("sensitiveActions") or [] if isinstance(item, dict)],
        taskScopeDeviation=_from_dict(TaskScopeDeviation, payload.get("taskScopeDeviation")),
        cumulativeRisk=_from_dict(CumulativeRisk, payload.get("cumulativeRisk")),
        lastDecision=_from_dict(SecurityDecision, payload.get("lastDecision")),
        evidenceEvents=list(payload.get("evidenceEvents") or []),
    )
    if not context.userIntent.forbiddenActions:
        context.userIntent.forbiddenActions = list(DEFAULT_FORBIDDEN_ACTIONS)
    return context


def load_security_context(run_dir: Path | str, *, run_id: str | None = None, user_message: str | None = None) -> SecurityContextState:
    state_path = Path(run_dir) / "security-reasoning" / "security_state.json"
    if state_path.exists():
        return context_from_dict(json.loads(state_path.read_text(encoding="utf-8")))
    return create_security_context(run_id=run_id, user_message=user_message)


def _event_id(context: SecurityContextState, prefix: str = "sec") -> str:
    return f"{prefix}-{len(context.evidenceEvents) + 1}"


def add_evidence(context: SecurityContextState, event_type: str, stage: str, payload: dict[str, Any]) -> str:
    event_id = str(payload.get("eventId") or payload.get("event_id") or payload.get("id") or _event_id(context))
    context.evidenceEvents.append(
        {
            "eventId": event_id,
            "eventType": event_type,
            "stage": stage,
            "decision": payload.get("decision"),
            "riskLevel": payload.get("riskLevel"),
            "riskScore": payload.get("riskScore"),
            "reason": payload.get("reason"),
            "evidence": payload.get("evidence") or {},
        }
    )
    return event_id


def add_risk_event(
    context: SecurityContextState,
    *,
    stage: str,
    action: str,
    source_type: str,
    target: str,
    score: int,
    reason: str,
    event_id: str | None = None,
) -> str:
    event_id = event_id or _event_id(context, "risk")
    context.riskTimeline.append(
        RiskEvent(
            step=len(context.riskTimeline) + 1,
            eventId=event_id,
            stage=stage,
            action=action,
            sourceType=source_type,
            target=target,
            riskScore=score,
            riskLevel=risk_level(score),
            reason=reason,
        )
    )
    context.cumulativeRisk.score = min(100, context.cumulativeRisk.score + max(score, 0))
    context.cumulativeRisk.level = risk_level(context.cumulativeRisk.score)
    return event_id


def add_sensitive_action(
    context: SecurityContextState,
    *,
    action_type: str,
    target: str,
    authorized: bool,
    source_type: str,
    risk: str,
    reason: str,
    event_id: str,
) -> None:
    context.sensitiveActions.append(
        SensitiveAction(
            actionType=action_type,
            target=target,
            authorizedByUser=authorized,
            sourceType=source_type,
            riskLevel=risk,
            reason=reason,
            eventId=event_id,
        )
    )


def set_scope_deviation(context: SecurityContextState, level: str, from_: str, to: str, reason: str) -> None:
    order = {"in_scope": 0, "minor_expansion": 1, "scope_expansion": 2, "severe_deviation": 3}
    if order.get(level, 0) >= order.get(context.taskScopeDeviation.level, 0):
        context.taskScopeDeviation = TaskScopeDeviation(level=level, from_=from_, to=to, reason=reason)


def snapshot(context: SecurityContextState) -> dict[str, Any]:
    return {
        "runId": context.runId,
        "riskScore": context.cumulativeRisk.score,
        "riskLevel": context.cumulativeRisk.level,
        "scopeDeviation": context.taskScopeDeviation.to_dict(),
        "lastDecision": context.lastDecision.to_dict(),
        "sourceTrustCount": len(context.sourceTrustChain),
        "navigationCount": len(context.navigationChain),
        "sensitiveActionCount": len(context.sensitiveActions),
    }


def _json_default(value: Any) -> Any:
    if is_dataclass(value):
        return value.to_dict() if hasattr(value, "to_dict") else value.__dict__
    return str(value)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default) + "\n", encoding="utf-8")


def export_security_artifacts(run_dir: Path | str, context: SecurityContextState) -> dict[str, str]:
    output_dir = Path(run_dir) / "security-reasoning"
    state_path = output_dir / "security_state.json"
    decision_path = output_dir / "defense_decision.json"
    evidence_path = output_dir / "evidence_summary.json"
    write_json(state_path, context.to_dict())
    write_json(decision_path, context.lastDecision.to_dict())
    write_json(
        evidence_path,
        {
            "schemaVersion": "1.0",
            "runId": context.runId,
            "events": context.evidenceEvents,
            "riskTimeline": [item.__dict__ for item in context.riskTimeline],
            "sensitiveActions": [item.__dict__ for item in context.sensitiveActions],
        },
    )
    return {
        "statePath": str(state_path.resolve()),
        "decisionPath": str(decision_path.resolve()),
        "evidenceSummaryPath": str(evidence_path.resolve()),
    }


def explicit_authorized(context: SecurityContextState, action: str, target: str) -> bool:
    text = f"{action} {target}".lower()
    for item in context.userIntent.explicitAuthorizations:
        lowered = item.lower()
        if lowered and (lowered in text or any(token in lowered for token in text.split() if len(token) > 4)):
            return True
    return False
