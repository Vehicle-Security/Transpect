from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from reasoner import reason_security_state  # noqa: E402
from state_builder import build_security_state  # noqa: E402
from trace_common import normalize_path, now_utc_iso, read_json, write_json, write_runs_index  # noqa: E402


def _update_run_manifest(run_dir: Path, decision: dict[str, Any]) -> None:
    manifest_path = run_dir / "manifest.json"
    manifest = read_json(manifest_path, default={})
    if not isinstance(manifest, dict):
        return
    manifest.setdefault("paths", {})["securityReasoning"] = "security-reasoning/defense_decision.json"
    manifest["securityReasoning"] = {
        "ready": True,
        "decision": decision.get("decision"),
        "riskLevel": decision.get("riskLevel"),
        "score": decision.get("score") if decision.get("score") is not None else decision.get("riskScore"),
        "riskScore": decision.get("riskScore") if decision.get("riskScore") is not None else decision.get("score"),
        "crossStepCorrelation": decision.get("crossStepCorrelation"),
        "decisionPointEventSeq": decision.get("decisionPointEventSeq"),
        "hardBlockTriggered": decision.get("hardBlockTriggered"),
        "lastStage": decision.get("lastStage"),
        "realInteraction": decision.get("realInteraction"),
        "lastRunAt": decision.get("generatedAt") or now_utc_iso(),
        "decisionPath": normalize_path((run_dir / "security-reasoning" / "defense_decision.json").resolve()),
        "statePath": normalize_path((run_dir / "security-reasoning" / "security_state.json").resolve()),
    }
    write_json(manifest_path, manifest)


def run_defense_reasoner(run_dir: Path | str, *, update_index: bool = True) -> dict[str, Any]:
    resolved_run_dir = Path(run_dir).resolve()
    existing_state = read_json(resolved_run_dir / "security-reasoning" / "security_state.json", default=None)
    existing_decision = read_json(resolved_run_dir / "security-reasoning" / "defense_decision.json", default=None)
    if isinstance(existing_state, dict) and isinstance(existing_decision, dict) and "userIntent" in existing_state:
        _update_run_manifest(resolved_run_dir, existing_decision)
        if update_index:
            write_runs_index(resolved_run_dir.parent)
        return {
            "ok": True,
            "status": "success",
            "state": existing_state,
            "decision": existing_decision,
            "statePath": normalize_path((resolved_run_dir / "security-reasoning" / "security_state.json").resolve()),
            "decisionPath": normalize_path((resolved_run_dir / "security-reasoning" / "defense_decision.json").resolve()),
        }
    state = build_security_state(resolved_run_dir)
    decision = reason_security_state(state)
    output_dir = resolved_run_dir / "security-reasoning"
    write_json(output_dir / "security_state.json", state)
    write_json(output_dir / "defense_decision.json", decision)
    _update_run_manifest(resolved_run_dir, decision)
    if update_index:
        write_runs_index(resolved_run_dir.parent)
    return {
        "ok": True,
        "status": "success",
        "state": state,
        "decision": decision,
        "statePath": normalize_path((output_dir / "security_state.json").resolve()),
        "decisionPath": normalize_path((output_dir / "defense_decision.json").resolve()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Layer 4 contextual security reasoning for one Transpect run.")
    parser.add_argument("--run-dir", required=True, help="Path to live/runs/<runId>.")
    parser.add_argument("--no-index", action="store_true", help="Do not rebuild live/runs/index.json after writing artifacts.")
    args = parser.parse_args()
    result = run_defense_reasoner(Path(args.run_dir), update_index=not args.no_index)
    print(json.dumps(result["decision"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
