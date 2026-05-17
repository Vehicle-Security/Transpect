from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class IntentConstraints:
    allowed_purpose: str
    disallowed_actions: list[str] = field(default_factory=list)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "IntentConstraints":
        allowed_purpose = str(payload.get("allowed_purpose") or "").strip()
        if not allowed_purpose:
            raise ValueError("scenario.intent_constraints.allowed_purpose is required")
        disallowed = [str(item).strip() for item in payload.get("disallowed_actions") or [] if str(item).strip()]
        return cls(allowed_purpose=allowed_purpose, disallowed_actions=disallowed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_purpose": self.allowed_purpose,
            "disallowed_actions": self.disallowed_actions,
        }


@dataclass(frozen=True)
class AgentScenario:
    id: str
    name: str
    mode: str
    description: str
    user_prompt: str
    allowed_domains: list[str]
    untrusted_content_sources: list[str]
    high_risk_actions: list[str]
    intent_constraints: IntentConstraints
    expected_chain: list[str]
    expected_decision: str
    timeout_seconds: int
    path: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any], *, path: Path | None = None) -> "AgentScenario":
        if not isinstance(payload, dict):
            raise ValueError("scenario payload must be a JSON object")
        scenario_id = str(payload.get("id") or "").strip()
        if not scenario_id:
            raise ValueError("scenario.id is required")
        mode = str(payload.get("mode") or "").strip()
        if mode != "agent_driven":
            raise ValueError("scenario.mode must be agent_driven")
        user_prompt = str(payload.get("user_prompt") or "").strip()
        if not user_prompt:
            raise ValueError("scenario.user_prompt is required")
        constraints = payload.get("intent_constraints")
        if not isinstance(constraints, dict) or not constraints:
            raise ValueError("scenario.intent_constraints is required")
        allowed_domains = [str(item).strip().lower() for item in payload.get("allowed_domains") or [] if str(item).strip()]
        return cls(
            id=scenario_id,
            name=str(payload.get("name") or scenario_id),
            mode=mode,
            description=str(payload.get("description") or ""),
            user_prompt=user_prompt,
            allowed_domains=allowed_domains,
            untrusted_content_sources=[
                str(item).strip() for item in payload.get("untrusted_content_sources") or [] if str(item).strip()
            ],
            high_risk_actions=[str(item).strip() for item in payload.get("high_risk_actions") or [] if str(item).strip()],
            intent_constraints=IntentConstraints.from_payload(constraints),
            expected_chain=[str(item).strip() for item in payload.get("expected_chain") or [] if str(item).strip()],
            expected_decision=str(payload.get("expected_decision") or "").strip(),
            timeout_seconds=max(int(payload.get("timeout_seconds") or 300), 1),
            path=str(path.resolve()) if path else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "mode": self.mode,
            "description": self.description,
            "user_prompt": self.user_prompt,
            "allowed_domains": self.allowed_domains,
            "untrusted_content_sources": self.untrusted_content_sources,
            "high_risk_actions": self.high_risk_actions,
            "intent_constraints": self.intent_constraints.to_dict(),
            "expected_chain": self.expected_chain,
            "expected_decision": self.expected_decision,
            "timeout_seconds": self.timeout_seconds,
            "path": self.path,
        }


def load_scenario(path: str | Path) -> AgentScenario:
    scenario_path = Path(path).expanduser().resolve()
    payload = json.loads(scenario_path.read_text(encoding="utf-8"))
    return AgentScenario.from_payload(payload, path=scenario_path)

