from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SCRIPTS_DIR / "common"))
sys.path.insert(0, str(_SCRIPTS_DIR / "export"))

from dotenv import load_dotenv

from export_codetracer_bundle import export_bundles
from trace_common import (
    TRACE_LIVE_RUNS_DIR,
    build_runs_index_payload,
    normalize_path,
    now_utc_iso,
    python_executable,
    read_json,
    run_command,
    write_json,
    write_runs_index,
)

# ── Load .env and map short names to CODETRACER_* env vars ──
_ENV_KEY_MAP = {
    "BASE_URL": "CODETRACER_API_BASE",
    "API_KEY": "CODETRACER_API_KEY",
    "MODEL_ID": "CODETRACER_MODEL",
}


def load_dotenv_config() -> None:
    """Load the project .env file and forward short key names to CODETRACER_* vars."""
    env_path = _SCRIPTS_DIR.parent / ".env"
    if not env_path.exists():
        return
    load_dotenv(env_path, override=False)
    for short, full in _ENV_KEY_MAP.items():
        value = os.environ.get(short, "").strip()
        if value and not os.environ.get(full):
            os.environ[full] = value


load_dotenv_config()


DIAGNOSIS_SCHEMA_VERSION = "openclaw.codetracer.analysisrun.v1"
REQUIRED_ANALYSIS_KEYS = {
    "root_cause_chain",
    "critical_decision_points",
    "correct_strategy",
    "stage_labels",
    "summary",
}


def redact_command_args(args: list[str]) -> list[str]:
    """Return a copy of *args* with values after sensitive flags replaced."""
    redacted = list(args)
    sensitive_flags = {"--api-key"}
    i = 0
    while i < len(redacted):
        if redacted[i] in sensitive_flags and i + 1 < len(redacted):
            redacted[i + 1] = "[REDACTED]"
            i += 2
        else:
            i += 1
    return redacted


def redact_sensitive_text(text: str | None, *, extra_values: list[str | None] | None = None) -> str:
    if not text:
        return ""
    redacted = text
    for value in extra_values or []:
        if value:
            redacted = redacted.replace(value, "[REDACTED]")
    redacted = re.sub(r"sk-[A-Za-z0-9_\-]{12,}", "sk-[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)(api[_-]?key['\"\s:=]+)([A-Za-z0-9_\-]{12,})",
        r"\1[REDACTED]",
        redacted,
    )
    return redacted


def detect_codetracer_src_dir() -> Path:
    candidates = [
        Path(os.environ.get("CODETRACER_ROOT", "")).expanduser() / "src" if os.environ.get("CODETRACER_ROOT") else None,
        Path(os.environ.get("CODETRACER_SRC", "")).expanduser() if os.environ.get("CODETRACER_SRC") else None,
        Path(__file__).resolve().parents[3] / "CodeTracer" / "src",
        Path(__file__).resolve().parents[2] / "CodeTracer" / "src",
        Path(__file__).resolve().parents[1] / "CodeTracer" / "src",
        Path.cwd() / "src",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate.resolve()
    raise FileNotFoundError("CodeTracer src directory not found. Set CODETRACER_ROOT or CODETRACER_SRC.")


def expected_output_name(profile: str | None) -> str:
    normalized = (profile or "detailed").strip().lower()
    if normalized == "tracebench":
        return "codetracer_labels.json"
    if normalized == "rl_feedback":
        return "codetracer_rl_feedback.json"
    return "codetracer_analysis.json"


def build_env(*, api_base: str | None, api_key: str | None) -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "").strip()
    segments = [str(detect_codetracer_src_dir())]
    if existing:
        segments.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(segments)
    if api_base:
        env["CODETRACER_API_BASE"] = api_base
    if api_key:
        env["CODETRACER_API_KEY"] = api_key
    return env


def load_analysis_validation(path: Path | None) -> tuple[bool, str | None]:
    if path is None:
        return False, "analysis_output_path_unknown"
    if not path.exists():
        return False, "analysis_output_missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return False, "analysis_output_not_json"
    if not isinstance(payload, dict):
        return False, "analysis_output_not_object"
    missing = sorted(REQUIRED_ANALYSIS_KEYS.difference(payload.keys()))
    if missing:
        return False, f"analysis_output_missing_keys:{','.join(missing)}"
    return True, None


def build_diagnosis_report(
    *,
    run_dir: Path,
    bundle_dir: Path,
    analysis_dir: Path,
    output_path: Path,
    traj_path: Path,
    diagnosis_run: dict[str, Any],
) -> dict[str, Any]:
    analysis_payload = read_json(output_path, default=None) if output_path.exists() else None
    bundle_manifest = read_json(bundle_dir / "manifest.json", default=None)
    trace_sources = {}
    if isinstance(bundle_manifest, dict) and isinstance(bundle_manifest.get("traceSources"), dict):
        trace_sources = bundle_manifest["traceSources"]
    input_trace_sources = [
        source.get("path")
        for source in trace_sources.values()
        if isinstance(source, dict) and source.get("status") == "ok" and source.get("path")
    ]
    frida_source = trace_sources.get("frida") if isinstance(trace_sources, dict) else None
    frida_included = bool(
        isinstance(frida_source, dict)
        and frida_source.get("status") == "ok"
        and int(frida_source.get("eventCount") or 0) > 0
    )
    return {
        "schemaVersion": "transpect.diagnosis-report.v1",
        "generatedAt": now_utc_iso(),
        "runId": diagnosis_run.get("runId") or run_dir.name,
        "diagnosisLayer": "codetracer",
        "role": "trajectory_diagnosis_not_benchmark_evaluation",
        "ok": diagnosis_run.get("ok"),
        "status": diagnosis_run.get("status"),
        "reason": diagnosis_run.get("reason"),
        "suggestion": diagnosis_run.get("suggestion"),
        "profile": diagnosis_run.get("profile"),
        "inputTraceSources": input_trace_sources,
        "fridaIncluded": frida_included,
        "paths": {
            "runDir": normalize_path(run_dir.resolve()),
            "bundleDir": normalize_path(bundle_dir.resolve()),
            "analysisDir": normalize_path(analysis_dir.resolve()),
            "analysis": normalize_path(output_path.resolve()),
            "analysisTrajectory": normalize_path(traj_path.resolve()) if traj_path.exists() else None,
            "diagnosisRun": diagnosis_run.get("diagnosisRunPath"),
        },
        "analysis": analysis_payload,
        "diagnosisRun": {
            "returncode": diagnosis_run.get("returncode"),
            "analysisExists": diagnosis_run.get("analysisExists"),
            "analysisValid": diagnosis_run.get("analysisValid"),
            "invalidAnalysisReason": diagnosis_run.get("invalidAnalysisReason"),
            "analysisRecovered": diagnosis_run.get("analysisRecovered"),
            "model": diagnosis_run.get("model"),
            "apiBase": diagnosis_run.get("apiBase"),
            "startedAt": diagnosis_run.get("startedAt"),
            "completedAt": diagnosis_run.get("completedAt"),
        },
    }


def resolve_run_dir(run_dir: Path | None) -> Path:
    if run_dir is not None:
        return run_dir.resolve()
    payload = build_runs_index_payload(TRACE_LIVE_RUNS_DIR)
    latest = payload.get("latestRun")
    run_path = latest.get("runPath") if isinstance(latest, dict) else None
    if not isinstance(run_path, str) or not run_path.strip():
        raise FileNotFoundError(f"no run directories found under {TRACE_LIVE_RUNS_DIR}")
    return Path(run_path).resolve()


def update_run_manifest(
    run_dir: Path,
    *,
    bundle_dir: Path,
    analysis_dir: Path,
    diagnosis_run: dict[str, Any],
) -> None:
    manifest_path = run_dir / "manifest.json"
    manifest = read_json(manifest_path, default={}) or {}
    if not isinstance(manifest, dict):
        manifest = {}
    paths = manifest.setdefault("paths", {})
    diagnosis = manifest.setdefault("diagnosis", {}).setdefault("codetracer", {})
    paths["codetracerBundle"] = normalize_path(bundle_dir.relative_to(run_dir))
    paths["codetracerAnalysis"] = normalize_path(analysis_dir.relative_to(run_dir))
    diagnosis["bundleReady"] = True
    diagnosis["analysisReady"] = bool(diagnosis_run.get("analysisExists"))
    diagnosis["analysisOk"] = diagnosis_run.get("ok")
    diagnosis["lastRunAt"] = diagnosis_run.get("completedAt")
    diagnosis["status"] = diagnosis_run.get("status")
    diagnosis["bundlePath"] = normalize_path(bundle_dir.resolve())
    diagnosis["analysisPath"] = diagnosis_run.get("analysisPath")
    diagnosis["analysisTracePath"] = diagnosis_run.get("trajPath")
    diagnosis["diagnosisRunPath"] = diagnosis_run.get("diagnosisRunPath")
    diagnosis["diagnosisReportPath"] = diagnosis_run.get("diagnosisReportPath")
    write_json(manifest_path, manifest)


def update_evaluation_inputs_seed(run_dir: Path, diagnosis_run: dict[str, Any]) -> None:
    seed_path = run_dir / "artifacts" / "task_repo" / "evaluation_inputs_seed.json"
    seed = read_json(seed_path, default=None)
    if not isinstance(seed, dict):
        return
    seed["diagnosis"] = {
        "tool": "CodeTracer",
        "role": "diagnosis_not_benchmark_judge",
        "diagnosisReportPath": diagnosis_run.get("diagnosisReportPath"),
        "diagnosisRunPath": diagnosis_run.get("diagnosisRunPath"),
        "analysisPath": diagnosis_run.get("analysisPath"),
        "bundleDir": diagnosis_run.get("bundlePath"),
        "ok": diagnosis_run.get("ok"),
        "status": diagnosis_run.get("status"),
        "invalidAnalysisReason": diagnosis_run.get("invalidAnalysisReason"),
    }
    seed["generatedAt"] = now_utc_iso()
    write_json(seed_path, seed)


def run_codetracer_diagnosis(
    *,
    run_dir: Path | None,
    model: str | None = None,
    api_base: str | None = None,
    api_key: str | None = None,
    profile: str | None = None,
    dry_run: bool = False,
    cost_limit: float = 3.0,
    config_path: Path | None = None,
    timeout_seconds: int = 1800,
) -> dict[str, Any]:
    resolved_run_dir = resolve_run_dir(run_dir)
    if not resolved_run_dir.exists():
        raise FileNotFoundError(f"run directory not found: {resolved_run_dir}")

    bundle_root = resolved_run_dir / "diagnosis" / "codetracer" / "bundle"
    analysis_root = resolved_run_dir / "diagnosis" / "codetracer" / "analysis"
    analysis_root.mkdir(parents=True, exist_ok=True)

    bundle_result = export_bundles(
        run_dir=resolved_run_dir,
        output_root=bundle_root,
        include_runtime_status=True,
    )
    bundles = bundle_result.get("bundles") or []
    if not bundles:
        raise RuntimeError(f"no bundle was exported for run dir: {resolved_run_dir}")

    bundle_dir = Path(bundles[0]["bundlePath"]).resolve()
    output_name = expected_output_name(profile)
    output_path = analysis_root / output_name
    started_at = now_utc_iso()

    args = [
        python_executable(),
        "-m",
        "codetracer",
        "analyze",
        str(bundle_dir),
        "--skip-discovery",
        "--cost-limit",
        str(cost_limit),
        "--output",
        str(output_path.resolve()),
    ]
    effective_model = model or os.environ.get("CODETRACER_MODEL")
    effective_api_base = api_base or os.environ.get("CODETRACER_API_BASE")
    effective_api_key = api_key or os.environ.get("CODETRACER_API_KEY")
    if effective_model:
        args.extend(["--model", effective_model])
    if effective_api_base:
        args.extend(["--api-base", effective_api_base])
    if effective_api_key:
        args.extend(["--api-key", effective_api_key])
    if profile:
        args.extend(["--profile", profile])
    if dry_run:
        args.append("--dry-run")
    if config_path:
        args.extend(["--config", str(config_path.resolve())])

    try:
        env = build_env(api_base=effective_api_base, api_key=effective_api_key)
    except FileNotFoundError as exc:
        finished_at = now_utc_iso()
        traj_path = output_path.parent / f"{output_path.stem}.traj.json"
        diagnosis_run = {
            "schemaVersion": DIAGNOSIS_SCHEMA_VERSION,
            "runId": resolved_run_dir.name,
            "bundlePath": normalize_path(bundle_dir.resolve()),
            "analysisPath": normalize_path(output_path.resolve()),
            "trajPath": None,
            "startedAt": started_at,
            "completedAt": finished_at,
            "command": redact_command_args(args),
            "model": effective_model,
            "apiBase": effective_api_base,
            "profile": profile or "detailed",
            "returncode": None,
            "analysisExists": False,
            "analysisValid": False,
            "invalidAnalysisReason": "codetracer_not_installed",
            "analysisRecovered": False,
            "ok": False,
            "status": "unavailable",
            "reason": "codetracer_not_installed",
            "suggestion": "Set CODETRACER_ROOT or CODETRACER_SRC, or install CodeTracer if diagnosis is required.",
            "stdout": "",
            "stderr": redact_sensitive_text(str(exc), extra_values=[effective_api_key]),
        }
        diagnosis_run_path = analysis_root / "diagnosis_run.json"
        diagnosis_report_path = analysis_root / "diagnosis_report.json"
        diagnosis_run["diagnosisRunPath"] = normalize_path(diagnosis_run_path.resolve())
        diagnosis_run["diagnosisReportPath"] = normalize_path(diagnosis_report_path.resolve())
        write_json(diagnosis_run_path, diagnosis_run)
        diagnosis_report = build_diagnosis_report(
            run_dir=resolved_run_dir,
            bundle_dir=bundle_dir,
            analysis_dir=analysis_root,
            output_path=output_path,
            traj_path=traj_path,
            diagnosis_run=diagnosis_run,
        )
        write_json(diagnosis_report_path, diagnosis_report)
        update_run_manifest(
            resolved_run_dir,
            bundle_dir=bundle_dir,
            analysis_dir=analysis_root,
            diagnosis_run=diagnosis_run,
        )
        update_evaluation_inputs_seed(resolved_run_dir, diagnosis_run)
        write_runs_index(resolved_run_dir.parent)
        return {
            "ok": False,
            "status": "unavailable",
            "reason": "codetracer_not_installed",
            "suggestion": diagnosis_run["suggestion"],
            "runDir": normalize_path(resolved_run_dir.resolve()),
            "bundleDir": normalize_path(bundle_dir.resolve()),
            "analysisDir": normalize_path(analysis_root.resolve()),
            "analysisPath": diagnosis_run["analysisPath"],
            "analysisTrajPath": None,
            "diagnosisRunPath": diagnosis_run["diagnosisRunPath"],
            "diagnosisReportPath": diagnosis_run["diagnosisReportPath"],
            "returncode": None,
            "analysisExists": False,
            "analysisValid": False,
            "invalidAnalysisReason": "codetracer_not_installed",
            "stdout": "",
            "stderr": diagnosis_run["stderr"],
        }

    result = run_command(
        args,
        cwd=resolved_run_dir,
        timeout=timeout_seconds,
        check=False,
        env=env,
    )

    # ── Fix 1: recover misplaced analysis output from bundle/ ──
    analysis_recovered = False
    if not output_path.exists():
        misplaced = bundle_dir / output_name
        if misplaced.exists():
            shutil.move(str(misplaced), str(output_path))
            misplaced_traj = bundle_dir / f"{output_path.stem}.traj.json"
            if misplaced_traj.exists():
                shutil.move(str(misplaced_traj), str(analysis_root / misplaced_traj.name))
            analysis_recovered = True

    traj_path = output_path.parent / f"{output_path.stem}.traj.json"
    analysis_exists = output_path.exists()
    analysis_valid = True if dry_run else False
    invalid_reason = None
    if not dry_run:
        analysis_valid, invalid_reason = load_analysis_validation(output_path)

    finished_at = now_utc_iso()
    redacted_stdout = redact_sensitive_text(result.stdout, extra_values=[effective_api_key])
    redacted_stderr = redact_sensitive_text(result.stderr, extra_values=[effective_api_key])
    diagnosis_run = {
        "schemaVersion": DIAGNOSIS_SCHEMA_VERSION,
        "runId": resolved_run_dir.name,
        "bundlePath": normalize_path(bundle_dir.resolve()),
        "analysisPath": normalize_path(output_path.resolve()) if output_path.exists() else normalize_path(output_path.resolve()),
        "trajPath": normalize_path(traj_path.resolve()) if traj_path.exists() else None,
        "startedAt": started_at,
        "completedAt": finished_at,
        "command": redact_command_args(args),
        "model": effective_model,
        "apiBase": effective_api_base,
        "profile": profile or "detailed",
        "returncode": result.returncode,
        "analysisExists": analysis_exists,
        "analysisValid": None if dry_run else analysis_valid,
        "invalidAnalysisReason": invalid_reason,
        "analysisRecovered": analysis_recovered,
        "ok": result.returncode == 0 and (dry_run or analysis_valid),
        "status": "success" if result.returncode == 0 and (dry_run or analysis_valid) else "failed",
        "stdout": redacted_stdout,
        "stderr": redacted_stderr,
    }
    diagnosis_run_path = analysis_root / "diagnosis_run.json"
    write_json(diagnosis_run_path, diagnosis_run)
    diagnosis_run["diagnosisRunPath"] = normalize_path(diagnosis_run_path.resolve())
    diagnosis_report_path = analysis_root / "diagnosis_report.json"
    diagnosis_run["diagnosisReportPath"] = normalize_path(diagnosis_report_path.resolve())
    write_json(diagnosis_run_path, diagnosis_run)
    diagnosis_report = build_diagnosis_report(
        run_dir=resolved_run_dir,
        bundle_dir=bundle_dir,
        analysis_dir=analysis_root,
        output_path=output_path,
        traj_path=traj_path,
        diagnosis_run=diagnosis_run,
    )
    write_json(diagnosis_report_path, diagnosis_report)
    update_run_manifest(
        resolved_run_dir,
        bundle_dir=bundle_dir,
        analysis_dir=analysis_root,
        diagnosis_run=diagnosis_run,
    )
    update_evaluation_inputs_seed(resolved_run_dir, diagnosis_run)
    write_runs_index(resolved_run_dir.parent)
    return {
        "ok": diagnosis_run["ok"],
        "runDir": normalize_path(resolved_run_dir.resolve()),
        "bundleDir": normalize_path(bundle_dir.resolve()),
        "analysisDir": normalize_path(analysis_root.resolve()),
        "analysisPath": diagnosis_run["analysisPath"],
        "analysisTrajPath": diagnosis_run["trajPath"],
        "diagnosisRunPath": diagnosis_run["diagnosisRunPath"],
        "diagnosisReportPath": diagnosis_run["diagnosisReportPath"],
        "status": diagnosis_run["status"],
        "returncode": diagnosis_run["returncode"],
        "analysisExists": diagnosis_run["analysisExists"],
        "analysisValid": diagnosis_run["analysisValid"],
        "invalidAnalysisReason": diagnosis_run["invalidAnalysisReason"],
        "stdout": diagnosis_run["stdout"],
        "stderr": diagnosis_run["stderr"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a CodeTracer bundle for one run directory and execute diagnosis.")
    parser.add_argument("--run-dir", default=None, help="Path to a run directory. Defaults to the latest run.")
    parser.add_argument("--model", help="OpenAI-compatible model name for CodeTracer.")
    parser.add_argument("--api-base", help="OpenAI-compatible API base URL.")
    parser.add_argument("--api-key", help="API key for the selected model backend.")
    parser.add_argument("--profile", default="detailed", help="CodeTracer output profile.")
    parser.add_argument("--dry-run", action="store_true", help="Normalize + tree only, skip LLM analysis.")
    parser.add_argument("--cost-limit", type=float, default=3.0, help="CodeTracer max LLM spend in USD.")
    parser.add_argument("--config", help="Optional CodeTracer YAML config override.")
    parser.add_argument("--timeout-seconds", type=int, default=1800, help="Subprocess timeout in seconds.")
    args = parser.parse_args()

    payload = run_codetracer_diagnosis(
        run_dir=Path(args.run_dir).resolve() if args.run_dir else None,
        model=args.model,
        api_base=args.api_base,
        api_key=args.api_key,
        profile=args.profile,
        dry_run=args.dry_run,
        cost_limit=args.cost_limit,
        config_path=Path(args.config).resolve() if args.config else None,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
