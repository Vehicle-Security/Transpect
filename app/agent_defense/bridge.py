from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.agent_defense.engine import inspect_action
from app.security.context_state import create_security_context, export_security_artifacts, load_security_context, snapshot
from app.security.evidence import build_security_event
from app.security.intent_guard import inspect_environment_input, inspect_user_input
from app.security.model_judge import judge_gray_zone
from app.security.plan_guard import inspect_plan


def _read_payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    return json.loads(raw)


def _maybe_apply_llm_judge(payload: dict[str, Any], action: dict[str, Any], context: Any, decision: Any) -> Any:
    llm_judge = payload.get("llmJudge") if isinstance(payload.get("llmJudge"), dict) else {}
    if decision.decision != "require_confirmation":
        return decision
    if llm_judge.get("enabled") is not True or llm_judge.get("mode", "gray_zone_only") != "gray_zone_only":
        return decision
    model_result = judge_gray_zone(
        {
            "action": action,
            "decision": decision.to_dict(),
            "snapshot": snapshot(context),
        }
    )
    if not model_result:
        return decision
    decision.decision = model_result["decision"]
    decision.riskLevel = model_result["riskLevel"]
    decision.reasons = [f"LLM gray-zone judge: {reason}" for reason in model_result["reasons"]]
    decision.confidence = float(model_result["confidence"])
    decision.hardBlockTriggered = model_result["decision"] == "block"
    context.lastDecision = decision
    return decision


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    operation = str(payload.get("operation") or "").strip()
    run_dir = Path(payload.get("runDir") or ".").resolve()
    run_id = payload.get("runId")
    context = load_security_context(run_dir, run_id=run_id, user_message=payload.get("message"))
    if run_id and not context.runId:
        context.runId = str(run_id)

    normalized_action: dict[str, Any] | None = None
    if operation == "inspect_user_input":
        context = inspect_user_input(str(payload.get("message") or ""), context)
        decision = context.lastDecision
        event_type = "security.input_inspected"
        stage = "input"
    elif operation == "inspect_environment_input":
        context = inspect_environment_input(payload.get("event") if isinstance(payload.get("event"), dict) else {}, context)
        decision = context.lastDecision
        event_type = "security.low_trust_source_detected" if decision.decision != "allow" else "security.input_inspected"
        stage = "input"
    elif operation == "inspect_plan":
        decision, context = inspect_plan(payload.get("plan") or payload.get("message") or "", context)
        event_type = "security.plan_inspected" if decision.decision not in {"block", "require_confirmation"} else f"security.decision.{decision.decision}"
        stage = "planning"
    elif operation == "inspect_action":
        action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
        decision, context, normalized_action = inspect_action(action, context, policy_path=payload.get("policyPath"))
        decision = _maybe_apply_llm_judge(payload, normalized_action, context, decision)
        event_type = "security.action_inspected" if decision.decision in {"allow", "warn"} else f"security.decision.{decision.decision}"
        stage = "execution"
    else:
        context = create_security_context(run_id=run_id)
        decision = context.lastDecision
        event_type = "security.bridge_warning"
        stage = "unknown"

    if os.environ.get("TRANSPECT_SECURITY_BYPASS", "").lower() in ("1", "true"):
        decision.decision = "allow"
        decision.riskLevel = "low"
        decision.riskScore = 0
        decision.reasons = ["Security bypassed by TRANSPECT_SECURITY_BYPASS."]
        decision.hardBlockTriggered = False
        event_type = "security.decision.allow"

    paths = export_security_artifacts(run_dir, context)
    evidence = dict(payload)
    if normalized_action is not None:
        evidence["normalizedAction"] = normalized_action

    return {
        "ok": True,
        "operation": operation,
        "decision": decision.to_dict(),
        "state": context.to_dict(),
        "snapshot": snapshot(context),
        "securityEvent": build_security_event(context, decision, event_type=event_type, stage=stage, evidence=evidence),
        "paths": paths,
        "shouldBlock": decision.decision in {"block", "require_confirmation"},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Transpect Agent Defense bridge.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    try:
        result = handle(_read_payload())
    except Exception as error:  # noqa: BLE001
        result = {
            "ok": False,
            "error": str(error),
            "decision": {
                "decision": "warn",
                "riskLevel": "medium",
                "riskScore": 3,
                "reasons": ["Agent Defense bridge failed; runtime should continue with warning unless another guard blocks."],
            },
            "shouldBlock": False,
        }
    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
