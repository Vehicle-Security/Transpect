from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import WORKSPACE_ROOT, normalize_path, read_json  # noqa: E402
from freeze_showcase_run import DEFAULT_SHOWCASE_ROOT, SHOWCASE_SCHEMA, normalize_status  # noqa: E402


VALID_FRIDA_STATUSES = {"ok", "degraded", "unavailable", "failed"}
VALID_CODETRACER_STATUSES = {"ok", "available", "degraded", "unavailable", "failed"}


def resolve_run_dir(showcase_root: Path, value: Any) -> Path:
    text = str(value or "").strip()
    if not text:
        return showcase_root / "__missing__"
    candidate = Path(text).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    workspace_candidate = (WORKSPACE_ROOT / candidate).resolve()
    if workspace_candidate.exists():
        return workspace_candidate
    return (showcase_root / candidate).resolve()


def normalize_decision(payload: dict[str, Any]) -> str:
    return str(payload.get("finalDecision") or payload.get("decision") or "unknown").strip().lower()


def normalize_risk_level(payload: dict[str, Any]) -> str:
    return str(payload.get("riskLevel") or payload.get("risk_level") or "unknown").strip().lower()


def first_reason(payload: dict[str, Any]) -> str | None:
    reasons = payload.get("reasons")
    if isinstance(reasons, list) and reasons:
        return str(reasons[0])
    reason = payload.get("reason")
    return str(reason) if reason else None


def evidence(payload: dict[str, Any]) -> dict[str, Any]:
    return payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}


def frida_status(payload: dict[str, Any]) -> str:
    frida = evidence(payload).get("frida")
    if isinstance(frida, dict):
        return normalize_status(frida.get("status"), default="unavailable")
    return normalize_status(None, default="unavailable")


def codetracer_status(payload: dict[str, Any], run_dir: Path) -> str:
    code = evidence(payload).get("codeTracer")
    if isinstance(code, dict) and code.get("status"):
        return normalize_status(code.get("status"), default="unavailable")
    if (run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json").exists():
        return "ok"
    return "unavailable"


def has_risk_chain(payload: dict[str, Any], run_dir: Path) -> bool:
    chain = payload.get("riskChain")
    if isinstance(chain, dict) and isinstance(chain.get("nodes"), list) and chain.get("nodes"):
        return True
    state = read_json(run_dir / "security-reasoning" / "security_state.json", default={})
    if isinstance(state, dict):
        for key in ["causalTriggerChain", "riskTimeline"]:
            if isinstance(state.get(key), list) and state.get(key):
                return True
    task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
    return isinstance(task.get("stages"), list) and bool(task.get("stages"))


def validate_entry(
    showcase_root: Path,
    entry: dict[str, Any],
    *,
    strict: bool = False,
    require_report_model: bool = False,
) -> dict[str, Any]:
    showcase_id = str(entry.get("id") or "unknown")
    run_dir = resolve_run_dir(showcase_root, entry.get("runDir"))
    issues: list[str] = []
    warnings: list[str] = []
    final_path = run_dir / "security-reasoning" / "final_judgment.json"
    final_judgment = read_json(final_path, default=None)
    if not run_dir.exists():
        issues.append(f"runDir does not exist: {normalize_path(run_dir)}")
    if not isinstance(final_judgment, dict):
        issues.append(f"final_judgment.json missing or unreadable: {normalize_path(final_path)}")
        final_judgment = {}

    decision = normalize_decision(final_judgment)
    risk_level = normalize_risk_level(final_judgment)
    if decision == "unknown":
        issues.append("decision is missing or unknown")
    if risk_level == "unknown":
        issues.append("riskLevel is missing or unknown")
    if not first_reason(final_judgment):
        warnings.append("final judgment reason is missing")

    has_trace = (run_dir / "merged-trace.jsonl").exists() or (run_dir / "behavior-events.jsonl").exists()
    if not has_trace:
        issues.append("missing behavior-events.jsonl or merged-trace.jsonl")
    chain_ready = has_risk_chain(final_judgment, run_dir)
    if not chain_ready:
        warnings.append("risk chain nodes are unavailable")

    report_model_path = run_dir / "report_model.json"
    report_model = read_json(report_model_path, default=None)
    has_report_model = isinstance(report_model, dict)
    if require_report_model and not has_report_model:
        issues.append(f"report_model.json missing or unreadable: {normalize_path(report_model_path)}")

    normalized_frida = frida_status(final_judgment)
    normalized_code = codetracer_status(final_judgment, run_dir)
    if normalized_frida not in VALID_FRIDA_STATUSES:
        warnings.append(f"unexpected Frida status: {normalized_frida}")
    if normalized_code not in VALID_CODETRACER_STATUSES:
        warnings.append(f"unexpected CodeTracer status: {normalized_code}")

    return {
        "id": showcase_id,
        "title": entry.get("title"),
        "runDir": normalize_path(run_dir),
        "ok": not issues,
        "decision": decision,
        "riskLevel": risk_level,
        "fridaStatus": normalized_frida,
        "codeTracerStatus": normalized_code,
        "hasTrace": has_trace,
        "hasRiskChain": chain_ready,
        "hasReportModel": has_report_model,
        "reportModelPath": normalize_path(report_model_path),
        "finalJudgmentPath": normalize_path(final_path),
        "issues": issues,
        "warnings": warnings,
    }


def validate_showcase(
    *,
    showcase_root: Path | str = DEFAULT_SHOWCASE_ROOT,
    strict: bool = False,
    require_report_model: bool = False,
) -> dict[str, Any]:
    resolved_root = Path(showcase_root).expanduser().resolve()
    index_path = resolved_root / "index.json"
    index = read_json(index_path, default=None)
    if not isinstance(index, dict):
        return {
            "schemaVersion": SHOWCASE_SCHEMA,
            "ok": False,
            "showcaseRoot": normalize_path(resolved_root),
            "indexPath": normalize_path(index_path),
            "showcases": [],
            "issues": [f"showcase index missing or unreadable: {normalize_path(index_path)}"],
            "nextStep": "Generate one with scripts/demo/freeze_showcase_run.py --run-dir live/runs/<runId> --id staged_attack_block --title \"Cross-step Waterhole Attack\" --description \"...\"",
        }
    entries = index.get("showcases")
    if not isinstance(entries, list):
        entries = []
    reports = [
        validate_entry(
            resolved_root,
            entry if isinstance(entry, dict) else {},
            strict=strict,
            require_report_model=require_report_model,
        )
        for entry in entries
    ]
    issues: list[str] = []
    if not entries:
        issues.append("showcase index contains no showcases")
    if any(not item["ok"] for item in reports):
        issues.append("one or more showcase entries are not display-ready")
    return {
        "schemaVersion": SHOWCASE_SCHEMA,
        "ok": not issues,
        "showcaseRoot": normalize_path(resolved_root),
        "indexPath": normalize_path(index_path),
        "requireReportModel": require_report_model,
        "showcaseCount": len(reports),
        "showcases": reports,
        "issues": issues,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate frozen Transpect showcase data.")
    parser.add_argument("--showcase-root", default=str(DEFAULT_SHOWCASE_ROOT), help="Showcase root containing index.json.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when required display data is missing.")
    parser.add_argument("--require-report-model", action="store_true", help="Require each showcase to include report_model.json.")
    args = parser.parse_args()
    report = validate_showcase(
        showcase_root=args.showcase_root,
        strict=args.strict,
        require_report_model=args.require_report_model,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if (args.strict or args.require_report_model) and not report.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
