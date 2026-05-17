from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


Decision = str
RiskLevel = str
ScopeLevel = str


@dataclass
class UserIntent:
    originalGoal: str = ""
    allowedActions: list[str] = field(default_factory=list)
    forbiddenActions: list[str] = field(default_factory=list)
    explicitAuthorizations: list[str] = field(default_factory=list)


@dataclass
class SourceTrust:
    sourceType: str
    trustLevel: str
    content: str = ""
    eventId: str | None = None
    reason: str = ""


@dataclass
class RiskEvent:
    step: int
    eventId: str
    stage: str
    action: str
    sourceType: str
    target: str
    riskScore: int
    riskLevel: RiskLevel
    reason: str


@dataclass
class SensitiveAction:
    actionType: str
    target: str
    authorizedByUser: bool
    sourceType: str
    riskLevel: RiskLevel
    reason: str
    eventId: str


@dataclass
class TaskScopeDeviation:
    level: ScopeLevel = "in_scope"
    from_: str = ""
    to: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "from": self.from_,
            "to": self.to,
            "reason": self.reason,
        }


@dataclass
class CumulativeRisk:
    score: int = 0
    level: RiskLevel = "low"


@dataclass
class SecurityDecision:
    schemaVersion: str = "1.0"
    decision: Decision = "allow"
    riskLevel: RiskLevel = "low"
    riskScore: int = 0
    confidence: float = 0.5
    hardBlockTriggered: bool = False
    reasons: list[str] = field(default_factory=lambda: ["No material security risk detected."])
    evidenceEvents: list[str] = field(default_factory=list)
    suggestedUserMessage: str = "安全检查通过。"
    lastStage: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NavigationEdge:
    fromSource: str
    toTarget: str
    sourceType: str
    eventId: str
    reason: str = ""


@dataclass
class SecurityContextState:
    schemaVersion: str = "1.0"
    runId: str | None = None
    userIntent: UserIntent = field(default_factory=UserIntent)
    sourceTrustChain: list[SourceTrust] = field(default_factory=list)
    navigationChain: list[NavigationEdge] = field(default_factory=list)
    riskTimeline: list[RiskEvent] = field(default_factory=list)
    sensitiveActions: list[SensitiveAction] = field(default_factory=list)
    taskScopeDeviation: TaskScopeDeviation = field(default_factory=TaskScopeDeviation)
    cumulativeRisk: CumulativeRisk = field(default_factory=CumulativeRisk)
    lastDecision: SecurityDecision = field(default_factory=SecurityDecision)
    evidenceEvents: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["taskScopeDeviation"] = self.taskScopeDeviation.to_dict()
        return payload
