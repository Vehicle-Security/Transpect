#!/usr/bin/env python3
"""Layered deployment checks for replay, live, and full-evidence modes."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]


def evaluate_deployment(repo_root: str | Path = REPO_ROOT, *, mode: str = "replay") -> dict[str, Any]:
    root = Path(repo_root)
    if mode not in {"replay", "live", "full", "rjudge"}:
        raise ValueError(f"Unsupported mode: {mode}")

    components: list[dict[str, Any]] = []
    components.extend(_replay_components(root))

    if mode in {"live", "full"}:
        components.extend(_live_components(root))

    if mode == "full":
        components.extend(_full_evidence_components(root))

    if mode == "rjudge":
        components.extend(_rjudge_components(root, required=True))

    failed_required = [
        component
        for component in components
        if component.get("required") and component.get("status") not in {"ok", "warning"}
    ]
    return {
        "ok": not failed_required,
        "mode": mode,
        "components": components,
        "summary": {
            "requiredFailed": len(failed_required),
            "degraded": sum(1 for component in components if component.get("status") == "degraded"),
            "unavailable": sum(1 for component in components if component.get("status") == "unavailable"),
        },
        "recommendations": _recommendations(components),
    }


def _replay_components(root: Path) -> list[dict[str, Any]]:
    return [
        _component(
            "python",
            "ok",
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            required=True,
        ),
        _exists_component(
            "python_project",
            root / "pyproject.toml",
            required=True,
            suggestion="Clone the full repository; pyproject.toml is required for Python utilities.",
        ),
        _exists_component(
            "console_app",
            root / "dashboard" / "console" / "package.json",
            required=True,
            suggestion="Clone the dashboard/console directory and run npm ci inside it.",
        ),
        _exists_component(
            "console_dependencies",
            root / "dashboard" / "console" / "node_modules",
            required=True,
            suggestion="Run cd dashboard/console && npm ci.",
        ),
        _showcase_component(root),
    ]


def _live_components(root: Path) -> list[dict[str, Any]]:
    openclaw = shutil.which("openclaw")
    return [
        _component(
            "openclaw_gateway",
            "ok" if openclaw else "unavailable",
            openclaw or "openclaw executable not found",
            required=True,
            suggestion="Install/configure OpenClaw before running live Agent traces.",
        ),
        _exists_component(
            "behavior_mediator",
            root / "monitor" / "vendor" / "runtime-hooks" / "openclaw-behavior-mediator" / "index.js",
            required=True,
            suggestion="The repository-owned behavior mediator must be present for live trace capture.",
        ),
    ]


def _full_evidence_components(root: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    components.append(_frida_component())
    components.append(_codetracer_component(root))
    components.extend(_rjudge_components(root, required=False))
    return components


def _rjudge_components(root: Path, *, required: bool) -> list[dict[str, Any]]:
    env_root = os.environ.get("R_JUDGE_ROOT")
    candidates = [Path(env_root)] if env_root else []
    candidates.append((root / ".." / "R-Judge").resolve())
    found = next((path for path in candidates if path.exists()), None)
    return [
        _component(
            "rjudge_dataset",
            "ok" if found else "unavailable",
            str(found) if found else "R-Judge dataset not configured",
            required=required,
            suggestion="Set R_JUDGE_ROOT when running python tools/runtime/run_task_repo.py --repo rjudge.",
        )
    ]


def _showcase_component(root: Path) -> dict[str, Any]:
    index_path = root / "dashboard" / "state" / "showcase" / "index.json"
    if not index_path.exists():
        return _component(
            "showcase_data",
            "failed",
            "dashboard/state/showcase/index.json missing",
            required=True,
            suggestion="Commit frozen showcase data or generate it with tools/demo/freeze_showcase_run.py.",
        )
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _component(
            "showcase_data",
            "failed",
            f"index.json is not valid JSON: {exc}",
            required=True,
        )
    showcases = payload.get("showcases") or []
    missing_reports = []
    for entry in showcases:
        run_dir = root / str(entry.get("runDir", ""))
        if not (run_dir / "report_model.json").exists():
            missing_reports.append(str(entry.get("id", run_dir.name)))
    if missing_reports:
        return _component(
            "showcase_data",
            "failed",
            f"{len(missing_reports)} showcase report_model.json files missing",
            required=True,
            details={"missingReports": missing_reports},
            suggestion="Run python tools/demo/build_showcase_reports.py.",
        )
    return _component(
        "showcase_data",
        "ok",
        f"{len(showcases)} frozen showcases with report models",
        required=True,
    )


def _frida_component() -> dict[str, Any]:
    spec = importlib.util.find_spec("frida")
    if spec is None:
        return _component(
            "frida",
            "degraded",
            "Python frida package not installed",
            required=False,
            suggestion="Install frida/frida-tools only when OS-level evidence capture is required.",
        )
    return _component("frida", "ok", "Python frida package importable", required=False)


def _codetracer_component(root: Path) -> dict[str, Any]:
    env_src = os.environ.get("CODETRACER_SRC")
    env_root = os.environ.get("CODETRACER_ROOT")
    candidates = []
    if env_src:
        candidates.append(Path(env_src))
    if env_root:
        candidates.append(Path(env_root) / "src")
    candidates.append((root / ".." / "CodeTracer" / "src").resolve())
    found = next((path for path in candidates if path.exists()), None)
    if not found:
        return _component(
            "codetracer",
            "unavailable",
            "CodeTracer source not found",
            required=False,
            suggestion="Set CODETRACER_ROOT or CODETRACER_SRC if diagnosis bundles are required.",
        )
    return _component("codetracer", "ok", str(found), required=False)


def _exists_component(name: str, path: Path, *, required: bool, suggestion: str | None = None) -> dict[str, Any]:
    return _component(
        name,
        "ok" if path.exists() else "failed",
        str(path) if path.exists() else f"{path} missing",
        required=required,
        suggestion=suggestion,
    )


def _component(
    name: str,
    status: str,
    message: str,
    *,
    required: bool,
    suggestion: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "name": name,
        "status": status,
        "required": required,
        "message": message,
    }
    if suggestion:
        component["suggestion"] = suggestion
    if details:
        component["details"] = details
    return component


def _recommendations(components: list[dict[str, Any]]) -> list[str]:
    recommendations = []
    for component in components:
        if component.get("status") not in {"ok", "warning"} and component.get("suggestion"):
            recommendations.append(str(component["suggestion"]))
    return list(dict.fromkeys(recommendations))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Transpect deployment readiness by capability level.")
    parser.add_argument("--mode", choices=["replay", "live", "full", "rjudge"], default="replay")
    parser.add_argument("--root", default=str(REPO_ROOT))
    args = parser.parse_args()

    report = evaluate_deployment(args.root, mode=args.mode)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
