from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any

from jsonschema import validate

from repo_roots import resolve_manifest_repo_root
from trace_common import (
    TRACE_LIVE_RUNS_DIR,
    TRACE_ROOT,
    build_run_dir_name,
    ensure_dir,
    ensure_trace_layout,
    normalize_path,
    now_utc_iso,
    python_executable,
    read_json,
    run_command,
    safe_slug,
    write_json,
    write_runs_index,
)


TASK_REPOS_ROOT = TRACE_ROOT / "monitor" / "task_repos"
TASK_REPO_MANIFEST_SCHEMA = TASK_REPOS_ROOT / "manifest.schema.json"
SENSITIVE_ENV_TOKENS = ("key", "token", "secret", "password")
DEFAULT_ARTIFACT_MAX_COPY_FILES = 50
DEFAULT_ARTIFACT_MAX_COPY_BYTES = 10 * 1024 * 1024
RAW_ENV_KEYS = ("BASE_URL", "API_KEY", "MODEL_ID")
NORMALIZED_ENV_KEYS = ("MODEL_BASE_URL", "MODEL_API_KEY", "MODEL_NAME")
ENVIRONMENT_FAILURE_REASONS = {
    "python_version_unsupported",
    "expected_env_missing",
    "expected_env_mismatch",
    "missing_required_env",
    "model_service_env_missing",
    "model_service_unreachable",
    "model_auth_failed",
    "model_quota_failed",
    "model_name_unavailable",
}
REPOSITORY_FAILURE_REASONS = {
    "required_file_missing",
    "required_file_unreadable",
    "required_file_blocked",
    "command_failed",
    "repo_outputs_missing",
    "source_adapter_missing",
    "task_not_found",
}
AGENT_TRACE_FAILURE_REASONS = {
    "agent_launch_failed",
    "agent_run_timeout",
}


def load_task_repo_manifest(repo_name: str) -> dict[str, Any]:
    manifest_path = TASK_REPOS_ROOT / repo_name / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"task repo manifest not found: {manifest_path}")
    manifest = read_json(manifest_path, default=None)
    if not isinstance(manifest, dict):
        raise ValueError(f"task repo manifest is not a JSON object: {manifest_path}")
    schema = read_json(TASK_REPO_MANIFEST_SCHEMA, default=None)
    if not isinstance(schema, dict):
        raise ValueError(f"task repo manifest schema is not available: {TASK_REPO_MANIFEST_SCHEMA}")
    validate(instance=manifest, schema=schema)
    manifest["_manifestPath"] = str(manifest_path.resolve())
    return manifest


def load_task_repo_adapter(repo_name: str) -> ModuleType | None:
    adapter_path = TASK_REPOS_ROOT / repo_name / "adapter.py"
    if not adapter_path.exists():
        return None
    module_name = f"transpect_task_repo_{safe_slug(repo_name, 'repo')}"
    spec = importlib.util.spec_from_file_location(module_name, adapter_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load adapter module from {adapter_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_task_repo_source_preflight(repo_name: str) -> ModuleType | None:
    preflight_path = TASK_REPOS_ROOT / repo_name / "source_preflight.py"
    if not preflight_path.exists():
        return None
    module_name = f"transpect_task_repo_{safe_slug(repo_name, 'repo')}_source_preflight"
    spec = importlib.util.spec_from_file_location(module_name, preflight_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load source preflight module from {preflight_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def has_source_capabilities(adapter: ModuleType | None) -> bool:
    return bool(
        adapter
        and callable(getattr(adapter, "list_tasks", None))
        and callable(getattr(adapter, "load_task", None))
        and callable(getattr(adapter, "build_agent_input", None))
    )


def resolve_repo_root(manifest: dict[str, Any]) -> Path:
    return resolve_manifest_repo_root(manifest)


def read_dotenv_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def load_env_file_layers(base_env: dict[str, str], env_paths: list[Path]) -> tuple[dict[str, str], list[str]]:
    merged = dict(base_env)
    loaded_paths: list[str] = []
    for env_path in env_paths:
        env_values = read_dotenv_values(env_path)
        if not env_values:
            continue
        loaded_paths.append(normalize_path(env_path.resolve()) or str(env_path))
        for key, value in env_values.items():
            merged.setdefault(key, value)
    return merged, loaded_paths


def present_env_keys(values: dict[str, str], keys: tuple[str, ...]) -> dict[str, bool]:
    return {key: bool(str(values.get(key) or "").strip()) for key in keys}


def apply_env_aliases(values: dict[str, str]) -> dict[str, str]:
    normalized = dict(values)
    alias_map = {
        "MODEL_BASE_URL": "BASE_URL",
        "MODEL_API_KEY": "API_KEY",
        "MODEL_NAME": "MODEL_ID",
    }
    for normalized_key, raw_key in alias_map.items():
        raw_value = str(normalized.get(raw_key) or "").strip()
        if raw_value and not str(normalized.get(normalized_key) or "").strip():
            normalized[normalized_key] = raw_value
    return normalized


def prepare_environment(manifest: dict[str, Any]) -> dict[str, Any]:
    repo_root = resolve_repo_root(manifest)
    workspace_root = Path(__file__).resolve().parents[2]
    common_env, loaded_env_files = load_env_file_layers(
        os.environ.copy(),
        [
            workspace_root / ".env",
            repo_root / ".env",
        ],
    )
    common_env.setdefault("TRANSPECT_ROOT", str(workspace_root))
    common_env.setdefault("TASK_REPO_ROOT", str(repo_root))
    raw_env_keys_present = present_env_keys(common_env, RAW_ENV_KEYS)
    common_env = apply_env_aliases(common_env)
    for key, value in (manifest.get("env_defaults") or {}).items():
        if isinstance(key, str) and isinstance(value, str) and key not in common_env:
            common_env[key] = value
    normalized_env_keys_present = present_env_keys(common_env, NORMALIZED_ENV_KEYS)
    repo_env = dict(common_env)
    env_map_status: list[dict[str, Any]] = []
    for repo_key, common_key in (manifest.get("env_map") or {}).items():
        source_value = common_env.get(common_key)
        if source_value is not None:
            repo_env[repo_key] = source_value
        env_map_status.append(
            {
                "targetEnv": repo_key,
                "sourceEnv": common_key,
                "present": source_value is not None,
            }
        )
    template_env = dict(common_env)
    template_env.update(repo_env)
    return {
        "commonEnv": common_env,
        "repoEnv": repo_env,
        "templateEnv": template_env,
        "envMapStatus": env_map_status,
        "rawEnvKeysPresent": raw_env_keys_present,
        "normalizedEnvKeysPresent": normalized_env_keys_present,
        "loadedEnvFiles": loaded_env_files,
    }


def sanitize_env_snapshot(values: dict[str, str], keys: list[str]) -> dict[str, str | None]:
    output: dict[str, str | None] = {}
    for key in keys:
        raw = values.get(key)
        lowered = key.lower()
        if raw is None:
            output[key] = None
        elif any(token in lowered for token in SENSITIVE_ENV_TOKENS):
            output[key] = "[REDACTED]"
        else:
            output[key] = raw
    return output


def render_template(value: str, env: dict[str, str]) -> str:
    pattern = re.compile(r"\$\{([^}]+)\}")

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return env.get(key, "")

    return pattern.sub(replace, value)


def tokenize_command(command_text: str) -> list[str]:
    return shlex.split(command_text, posix=os.name != "nt")


def create_task_repo_run(repo_name: str, manifest: dict[str, Any], *, mode: str, selected_commands: list[str]) -> dict[str, Any]:
    ensure_trace_layout()
    created_at = now_utc_iso()
    run_id = build_run_dir_name(
        run_id=f"taskrepo-{safe_slug(repo_name, 'repo')}-{created_at.replace(':', '').replace('-', '').lower()}",
        trace_id=None,
    )
    run_dir = TRACE_LIVE_RUNS_DIR / run_id
    ensure_dir(run_dir / "adapter")
    ensure_dir(run_dir / "artifacts")
    task_input = {
        "schemaVersion": "transpect.task-repo.task-input.v1",
        "taskType": "task_repo_adapter",
        "repository": {
            "name": manifest.get("name"),
            "slug": repo_name,
            "repoRoot": normalize_path(resolve_repo_root(manifest)),
            "manifestPath": normalize_path(manifest.get("_manifestPath")),
        },
        "request": {
            "mode": mode,
            "selectedCommands": selected_commands,
        },
    }
    runtime_status = {
        "schemaVersion": "transpect.task-repo.runtime.v1",
        "status": "running",
        "phase": "starting",
        "startedAt": created_at,
        "updatedAt": created_at,
        "pythonExecutable": python_executable(),
    }
    manifest_payload = {
        "schemaVersion": "openclaw.run.v1",
        "runId": run_id,
        "traceId": f"taskrepo_{safe_slug(repo_name, 'repo')}_{run_id}",
        "sessionKey": f"taskrepo:{safe_slug(repo_name, 'repo')}",
        "scenarioId": repo_name,
        "createdAt": created_at,
        "completedAt": None,
        "status": "running",
        "eventCount": 0,
        "artifactCount": 0,
        "hasRuntimeStatus": True,
        "hasTaskInput": True,
        "paths": {
            "events": None,
            "runtimeStatus": "runtime_status.json",
            "taskInput": "task_input.json",
            "artifacts": "artifacts",
            "codetracerBundle": None,
            "codetracerAnalysis": None,
            "adapter": "adapter",
        },
        "diagnosis": {
            "codetracer": {
                "bundleReady": False,
                "analysisReady": False,
                "analysisOk": None,
                "lastRunAt": None,
            }
        },
        "taskRepo": {
            "name": manifest.get("name"),
            "slug": repo_name,
            "repoRoot": normalize_path(resolve_repo_root(manifest)),
            "mode": mode,
            "selectedCommands": selected_commands,
        },
    }
    write_json(run_dir / "task_input.json", task_input)
    write_json(run_dir / "runtime_status.json", runtime_status)
    write_json(run_dir / "manifest.json", manifest_payload)
    write_runs_index(run_dir.parent)
    return {
        "runId": run_id,
        "runDir": run_dir,
    }


def inject_runtime_context(prepared_env: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    adapter_dir = run_dir / "adapter"
    artifact_root = run_dir / "artifacts" / "task_repo"
    for env_name in ("commonEnv", "repoEnv", "templateEnv"):
        env_map = prepared_env.get(env_name)
        if not isinstance(env_map, dict):
            continue
        env_map["RUN_DIR"] = str(run_dir.resolve())
        env_map["ADAPTER_DIR"] = str(adapter_dir.resolve())
        env_map["TASK_REPO_ARTIFACT_ROOT"] = str(artifact_root.resolve())
    return prepared_env


def update_task_repo_run_state(
    run_dir: Path,
    *,
    status: str,
    phase: str,
    summary: dict[str, Any],
    artifact_count: int,
) -> None:
    manifest = read_json(run_dir / "manifest.json", default={}) or {}
    runtime_status = read_json(run_dir / "runtime_status.json", default={}) or {}
    completed_at = now_utc_iso()
    if isinstance(manifest, dict):
        manifest["status"] = status
        manifest["completedAt"] = completed_at
        manifest["artifactCount"] = artifact_count
        manifest.setdefault("taskRepo", {})["summary"] = summary
        write_json(run_dir / "manifest.json", manifest)
    if isinstance(runtime_status, dict):
        runtime_status["status"] = status
        runtime_status["phase"] = phase
        runtime_status["updatedAt"] = completed_at
        runtime_status["completedAt"] = completed_at
        runtime_status["summary"] = summary
        write_json(run_dir / "runtime_status.json", runtime_status)
    write_runs_index(run_dir.parent)


def normalize_task_repo_metadata(repo_name: str, task_metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "sourceRepo": repo_name,
        "taskId": task_metadata.get("taskId"),
        "sourcePath": task_metadata.get("sourcePath"),
        "scenario": task_metadata.get("scenario"),
        "attackType": task_metadata.get("attackType"),
        "expectedLabel": task_metadata.get("label"),
        "harnessMode": "agent-trace",
    }


def create_agent_trace_run(repo_name: str, manifest: dict[str, Any], task_metadata: dict[str, Any]) -> dict[str, Any]:
    run_record = create_task_repo_run(
        repo_name,
        manifest,
        mode="agent-trace",
        selected_commands=[],
    )
    run_dir = Path(run_record["runDir"])
    task_input = read_json(run_dir / "task_input.json", default={}) or {}
    task_input["taskType"] = "agent_trace"
    task_input["taskRepo"] = normalize_task_repo_metadata(repo_name, task_metadata)
    write_json(run_dir / "task_input.json", task_input)
    return run_record


def resolve_agent_trace_run_dir(run_id: str | None) -> Path | None:
    if not run_id:
        return None
    candidate = TRACE_LIVE_RUNS_DIR / build_run_dir_name(run_id=run_id, trace_id=None)
    if candidate.exists():
        return candidate
    if TRACE_LIVE_RUNS_DIR.exists():
        for directory in sorted(path for path in TRACE_LIVE_RUNS_DIR.iterdir() if path.is_dir()):
            manifest = read_json(directory / "manifest.json", default=None)
            if isinstance(manifest, dict) and manifest.get("runId") == run_id:
                return directory
    return None


def read_behavior_events(run_dir: Path | None) -> list[dict[str, Any]]:
    if run_dir is None:
        return []
    events_path = run_dir / "behavior-events.jsonl"
    if not events_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with events_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def has_terminal_agent_request(rows: list[dict[str, Any]]) -> bool:
    return any(row.get("kind") == "request" and row.get("status") in {"ok", "error"} for row in rows)


def find_security_intervention(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    for row in rows:
        status = str(row.get("status") or "")
        name = str(row.get("name") or "")
        kind = str(row.get("kind") or "")
        if kind == "security" and status in {"block", "blocked", "require_confirmation"}:
            return row
        if name == "security_intervention":
            return row
        if kind == "tool" and status in {"blocked", "would_block"}:
            return row
    return None


def wait_for_agent_trace_run(
    run_id: str | None,
    *,
    timeout_seconds: int = 300,
    poll_interval_seconds: int = 2,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(int(timeout_seconds), 1)
    attempts = 0
    run_dir: Path | None = None
    latest_rows: list[dict[str, Any]] = []
    while time.monotonic() <= deadline:
        attempts += 1
        run_dir = resolve_agent_trace_run_dir(run_id)
        latest_rows = read_behavior_events(run_dir)
        intervention = find_security_intervention(latest_rows)
        if run_dir and latest_rows and intervention is not None:
            return {
                "ok": True,
                "timedOut": False,
                "attempts": attempts,
                "runDir": run_dir,
                "eventCount": len(latest_rows),
                "terminalSeen": False,
                "securityIntervention": True,
                "securityInterventionEvent": intervention,
            }
        if run_dir and latest_rows and has_terminal_agent_request(latest_rows):
            return {
                "ok": True,
                "timedOut": False,
                "attempts": attempts,
                "runDir": run_dir,
                "eventCount": len(latest_rows),
                "terminalSeen": True,
                "securityIntervention": False,
            }
        time.sleep(max(int(poll_interval_seconds), 1))
    return {
        "ok": False,
        "timedOut": True,
        "attempts": attempts,
        "runDir": run_dir,
        "eventCount": len(latest_rows),
        "terminalSeen": False,
        "securityIntervention": False,
    }


def run_source_preflight_checks(
    repo_name: str,
    manifest: dict[str, Any],
    adapter: ModuleType | None,
    prepared_env: dict[str, Any],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    if not has_source_capabilities(adapter):
        checks.append(
            {
                "name": "source_adapter",
                "ok": False,
                "reason": "source_adapter_missing",
                "details": {"repo": repo_name},
            }
        )
    source_preflight = load_task_repo_source_preflight(repo_name)
    if source_preflight and callable(getattr(source_preflight, "run_checks", None)):
        checks.extend(source_preflight.run_checks(manifest, prepared_env, adapter=adapter))
    elif has_source_capabilities(adapter):
        checks.append(
            {
                "name": "source_preflight",
                "ok": True,
                "reason": None,
                "details": {"skipped": True},
            }
        )
    reason, details = choose_primary_failure(checks)
    return {
        "ok": all(check.get("ok", False) for check in checks),
        "phase": "source_preflight",
        "reason": reason,
        "details": details,
        "checks": checks,
        "summary": {
            "repoRoot": normalize_path(resolve_repo_root(manifest)),
            "sourceCapable": has_source_capabilities(adapter),
        },
    }


def attach_source_metadata_to_run(
    run_dir: Path,
    source_metadata: dict[str, Any],
    *,
    source_task: dict[str, Any] | None = None,
    harness_report: dict[str, Any] | None = None,
    evaluation_inputs_seed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    artifact_root = ensure_dir(run_dir / "artifacts" / "task_repo")
    written_artifacts: list[dict[str, Any]] = []

    task_input = read_json(run_dir / "task_input.json", default={}) or {}
    if isinstance(task_input, dict):
        task_input.setdefault("taskRepo", {}).update(source_metadata)
        write_json(run_dir / "task_input.json", task_input)

    manifest = read_json(run_dir / "manifest.json", default={}) or {}
    if isinstance(manifest, dict):
        manifest.setdefault("taskRepo", {}).update(
            {
                "slug": source_metadata.get("sourceRepo"),
                "taskId": source_metadata.get("taskId"),
                "harnessMode": "agent-trace",
            }
        )
        write_json(run_dir / "manifest.json", manifest)

    if source_task is not None:
        source_task_path = write_json(artifact_root / "source_task.json", source_task)
        written_artifacts.append(
            build_extra_artifact(
                logical_name="source:task",
                source_kind="source",
                collected_path=source_task_path,
                declared_path="artifacts/task_repo/source_task.json",
            )
        )
    if harness_report is not None:
        harness_report_path = write_json(artifact_root / "harness_report.json", harness_report)
        written_artifacts.append(
            build_extra_artifact(
                logical_name="framework:harness_report",
                source_kind="framework",
                collected_path=harness_report_path,
                declared_path="artifacts/task_repo/harness_report.json",
            )
        )
    if evaluation_inputs_seed is not None:
        evaluation_seed_path = write_json(artifact_root / "evaluation_inputs_seed.json", evaluation_inputs_seed)
        written_artifacts.append(
            build_extra_artifact(
                logical_name="evaluation:inputs_seed",
                source_kind="evaluation_seed",
                collected_path=evaluation_seed_path,
                declared_path="artifacts/task_repo/evaluation_inputs_seed.json",
            )
        )

    artifact_manifest_path = write_artifact_manifest(
        artifact_root,
        build_artifact_manifest(command_results=[], declared_artifacts=[], extra_artifacts=written_artifacts),
    )
    if harness_report is not None:
        harness_report["artifactManifestPath"] = normalize_path(artifact_manifest_path.resolve())
        write_json(artifact_root / "harness_report.json", harness_report)
    written_artifacts.append(
        build_extra_artifact(
            logical_name="framework:artifact_manifest",
            source_kind="framework",
            collected_path=artifact_manifest_path,
            declared_path="artifacts/task_repo/artifact_manifest.json",
        )
    )
    write_runs_index(run_dir.parent)
    return {
        "artifactManifestPath": normalize_path(artifact_manifest_path.resolve()),
        "artifacts": written_artifacts,
    }


def _preview_text(preview: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = preview.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def collect_final_answer_candidates(run_dir: Path, *, max_candidates: int = 5) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    rows = read_behavior_events(run_dir)
    for row in rows:
        if row.get("kind") not in {"turn", "request"} or row.get("status") != "ok":
            continue
        preview = row.get("preview")
        if not isinstance(preview, dict):
            continue
        text = _preview_text(preview, ("assistant", "response", "result", "message"))
        if not text:
            continue
        candidates.append(
            {
                "source": f"behavior-events.jsonl:{row.get('kind')}.{row.get('status')}.preview",
                "seq": row.get("seq"),
                "spanId": row.get("spanId"),
                "kind": row.get("kind"),
                "status": row.get("status"),
                "text": text,
            }
        )
    return candidates[-max_candidates:]


def collect_policy_evidence(run_dir: Path, *, max_items: int = 20) -> dict[str, Any]:
    task_input = read_json(run_dir / "task_input.json", default={}) or {}
    policy_observations = []
    if isinstance(task_input, dict):
        raw_observations = task_input.get("policyObservations")
        if isinstance(raw_observations, list):
            policy_observations = raw_observations
    event_evidence: list[dict[str, Any]] = []
    for row in read_behavior_events(run_dir):
        has_policy_shape = any(key in row for key in ("policy", "policyDecision", "policyObservation", "ruleId"))
        status = str(row.get("status") or "")
        if status not in {"blocked", "would_block"} and not has_policy_shape:
            continue
        event_evidence.append(
            {
                "seq": row.get("seq"),
                "kind": row.get("kind"),
                "status": row.get("status"),
                "spanId": row.get("spanId"),
                "name": row.get("name"),
                "preview": row.get("preview") if isinstance(row.get("preview"), dict) else None,
                "policy": row.get("policy") or row.get("policyDecision") or row.get("policyObservation"),
                "ruleId": row.get("ruleId"),
            }
        )
    return {
        "taskInputPolicyObservations": policy_observations,
        "eventPolicyEvidence": event_evidence[:max_items],
    }


def build_evaluation_inputs_seed(
    run_dir: Path,
    *,
    repo_name: str,
    source_task: dict[str, Any],
    source_metadata: dict[str, Any],
    diagnosis_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_manifest = read_json(run_dir / "manifest.json", default={}) or {}
    event_count = len(read_behavior_events(run_dir))
    diagnosis_result = diagnosis_result or {}
    diagnosis_report_path = diagnosis_result.get("diagnosisReportPath")
    return {
        "schemaVersion": "transpect.evaluation-inputs-seed.v1",
        "generatedAt": now_utc_iso(),
        "evaluationLayerStatus": "prepared_only",
        "benchmarkEvaluationImplemented": False,
        "futureTaxonomy": {
            "safeUnsafe": None,
            "riskSource": None,
            "failureMode": None,
            "realWorldHarm": None,
            "benchmarkAlignment": None,
        },
        "source": {
            "repoSlug": repo_name,
            "taskId": source_metadata.get("taskId"),
            "sourcePath": source_metadata.get("sourcePath"),
            "scenario": source_metadata.get("scenario"),
            "attackType": source_metadata.get("attackType"),
            "benchmarkReference": {
                "label": source_task.get("label"),
                "riskDescription": source_task.get("risk_description"),
                "sampleId": source_task.get("id"),
            },
        },
        "run": {
            "runId": run_manifest.get("runId") if isinstance(run_manifest, dict) else run_dir.name,
            "runDir": normalize_path(run_dir.resolve()),
            "status": run_manifest.get("status") if isinstance(run_manifest, dict) else None,
            "paths": {
                "manifest": normalize_path((run_dir / "manifest.json").resolve()),
                "taskInput": normalize_path((run_dir / "task_input.json").resolve()),
                "runtimeStatus": normalize_path((run_dir / "runtime_status.json").resolve()),
                "behaviorEvents": normalize_path((run_dir / "behavior-events.jsonl").resolve()),
                "fridaEvents": normalize_path((run_dir / "frida-events.jsonl").resolve()),
                "traceIndex": normalize_path((run_dir / "trace_index.json").resolve()),
                "mergedTrace": normalize_path((run_dir / "merged-trace.jsonl").resolve()),
                "finalJudgment": normalize_path((run_dir / "security-reasoning" / "final_judgment.json").resolve()),
            },
            "eventCount": event_count,
        },
        "trajectoryEvidence": {
            "evaluationUnit": "full_trajectory",
            "finalAnswerCandidates": collect_final_answer_candidates(run_dir),
            "policyEvidence": collect_policy_evidence(run_dir),
        },
        "diagnosis": {
            "tool": "CodeTracer",
            "role": "diagnosis_not_benchmark_judge",
            "diagnosisReportPath": diagnosis_report_path,
            "diagnosisRunPath": diagnosis_result.get("diagnosisRunPath"),
            "analysisPath": diagnosis_result.get("analysisPath"),
            "bundleDir": diagnosis_result.get("bundleDir"),
            "ok": diagnosis_result.get("ok"),
        },
        "layer4Notes": {
            "status": "deferred",
            "intendedInputs": [
                "source benchmark metadata",
                "full behavior-events trajectory",
                "run-local merged trace with Frida evidence",
                "final answer candidates",
                "policy evidence",
                "CodeTracer diagnosis report",
                "Agent Defense final judgment",
            ],
            "nonGoalsInThisStep": [
                "safe/unsafe scoring",
                "risk source classification",
                "failure mode classification",
                "real-world harm classification",
            ],
        },
    }


def build_harness_report(
    *,
    repo_name: str,
    manifest: dict[str, Any],
    mode: str,
    task_metadata: dict[str, Any] | None,
    preflight: dict[str, Any] | None,
    framework_success: bool,
    agent_run_success: bool,
    agent_payload: dict[str, Any] | None,
    resolved_run_dir: Path | None,
    phase: str,
    reason: str | None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_id = None
    if isinstance(agent_payload, dict):
        run_id = agent_payload.get("runId")
    return {
        "repo": manifest.get("name") or repo_name,
        "repoSlug": repo_name,
        "mode": mode,
        "taskId": (task_metadata or {}).get("taskId"),
        "sourcePath": (task_metadata or {}).get("sourcePath"),
        "scenario": (task_metadata or {}).get("scenario"),
        "attackType": (task_metadata or {}).get("attackType"),
        "expectedLabel": (task_metadata or {}).get("label"),
        "ok": framework_success and agent_run_success,
        "frameworkSuccess": framework_success,
        "agentRunSuccess": agent_run_success,
        "agentRunId": run_id,
        "resolvedRunDir": normalize_path(resolved_run_dir.resolve()) if resolved_run_dir else None,
        "agentLaunched": isinstance(agent_payload, dict) and bool(agent_payload.get("ok")),
        "runIdObtained": bool(run_id),
        "phase": phase,
        "reason": reason,
        "details": details,
        "generatedAt": now_utc_iso(),
        "preflight": preflight,
    }


def choose_primary_failure(checks: list[dict[str, Any]]) -> tuple[str | None, dict[str, Any] | None]:
    for check in checks:
        if not check.get("ok", False):
            return check.get("reason"), check.get("details")
    return None, None


def _copy_preflight_config(preflight: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(preflight, dict):
        return {}
    copied: dict[str, Any] = {}
    for key in ("required_files", "required_env"):
        value = preflight.get(key)
        if isinstance(value, list):
            copied[key] = [str(item) for item in value]
    for key in ("model_probe_url_env", "model_probe_path"):
        value = preflight.get(key)
        if isinstance(value, str):
            copied[key] = value
    return copied


def resolve_effective_preflight(manifest: dict[str, Any], selected_commands: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    effective = _copy_preflight_config(manifest.get("preflight"))
    if len(selected_commands or []) != 1:
        return effective
    command_preflight = (selected_commands or [])[0].get("preflight")
    if not isinstance(command_preflight, dict):
        return effective
    if bool(command_preflight.get("replace_global")):
        return _copy_preflight_config(command_preflight)
    merged = dict(effective)
    for key in ("required_files", "required_env"):
        combined = list(merged.get(key) or [])
        for item in command_preflight.get(key) or []:
            rendered = str(item)
            if rendered not in combined:
                combined.append(rendered)
        if combined:
            merged[key] = combined
    for key in ("model_probe_url_env", "model_probe_path"):
        if isinstance(command_preflight.get(key), str):
            merged[key] = command_preflight[key]
    return merged


def classify_failure_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    if reason in ENVIRONMENT_FAILURE_REASONS:
        return "machine_environment"
    if reason in REPOSITORY_FAILURE_REASONS:
        return "repository_input"
    if reason in AGENT_TRACE_FAILURE_REASONS:
        return "repository_runtime"
    return "repository_runtime"


def check_python_compatibility(manifest: dict[str, Any]) -> dict[str, Any]:
    python_info = manifest.get("python") or {}
    supported = [str(item) for item in (python_info.get("supported") or [])]
    current_version = f"{sys_version_tuple()[0]}.{sys_version_tuple()[1]}"
    ok = current_version in supported if supported else True
    return {
        "name": "python_version",
        "ok": ok,
        "reason": None if ok else "python_version_unsupported",
        "details": {
            "current": current_version,
            "preferred": python_info.get("preferred"),
            "supported": supported,
            "pythonExecutable": python_executable(),
        },
    }


def sys_version_tuple() -> tuple[int, int, int]:
    return (os.sys.version_info.major, os.sys.version_info.minor, os.sys.version_info.micro)


def detect_current_environment() -> dict[str, Any]:
    venv_path = os.environ.get("VIRTUAL_ENV")
    conda_name = os.environ.get("CONDA_DEFAULT_ENV")
    conda_prefix = os.environ.get("CONDA_PREFIX")
    current_venv = None
    if venv_path:
        current_venv = Path(venv_path).name
    elif getattr(os.sys, "base_prefix", os.sys.prefix) != os.sys.prefix:
        current_venv = Path(os.sys.prefix).name
    inferred_conda_name = None
    inferred_conda_prefix = None
    prefix_path = Path(os.sys.prefix)
    parts = [part.lower() for part in prefix_path.parts]
    if "envs" in parts:
        env_index = parts.index("envs")
        if env_index + 1 < len(prefix_path.parts):
            inferred_conda_name = prefix_path.parts[env_index + 1]
            inferred_conda_prefix = str(prefix_path)
    current_conda = None
    if inferred_conda_name:
        current_conda = inferred_conda_name
        conda_prefix = inferred_conda_prefix
    elif conda_name:
        current_conda = conda_name
    elif conda_prefix:
        current_conda = Path(conda_prefix).name
    return {
        "venv": {
            "name": current_venv,
            "prefix": venv_path or (os.sys.prefix if current_venv else None),
            "active": current_venv is not None,
        },
        "conda": {
            "name": current_conda,
            "prefix": conda_prefix,
            "active": current_conda is not None,
        },
    }


def get_expected_environments(manifest: dict[str, Any]) -> list[dict[str, str]]:
    python_info = manifest.get("python") or {}
    expected: list[dict[str, str]] = []
    explicit = python_info.get("expected_envs") or []
    for item in explicit:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").strip()
        name = str(item.get("name") or "").strip()
        if kind and name:
            expected.append({"kind": kind, "name": name})
    legacy_venv = str(python_info.get("venv_name") or "").strip()
    if legacy_venv and not any(item["kind"] == "venv" and item["name"] == legacy_venv for item in expected):
        expected.append({"kind": "venv", "name": legacy_venv})
    legacy_conda = str(python_info.get("conda_env_name") or "").strip()
    if legacy_conda and not any(item["kind"] == "conda" and item["name"] == legacy_conda for item in expected):
        expected.append({"kind": "conda", "name": legacy_conda})
    return expected


def check_expected_environment(manifest: dict[str, Any]) -> dict[str, Any]:
    expected = get_expected_environments(manifest)
    detected = detect_current_environment()
    if not expected:
        return {
            "name": "expected_environment",
            "ok": True,
            "reason": None,
            "details": {
                "skipped": True,
                "detected": detected,
            },
        }
    active_names = {
        "venv": detected["venv"]["name"],
        "conda": detected["conda"]["name"],
    }
    matched = [
        item
        for item in expected
        if item["kind"] in active_names and active_names[item["kind"]] == item["name"]
    ]
    if matched:
        return {
            "name": "expected_environment",
            "ok": True,
            "reason": None,
            "details": {
                "expected": expected,
                "matched": matched,
                "detected": detected,
            },
        }
    active_any = any(info["active"] for info in detected.values())
    return {
        "name": "expected_environment",
        "ok": False,
        "reason": "expected_env_mismatch" if active_any else "expected_env_missing",
        "details": {
            "expected": expected,
            "detected": detected,
        },
    }


def _windows_file_probe(path: Path) -> tuple[str | None, str | None]:
    if os.name != "nt":
        return None, None
    escaped_path = str(path).replace("'", "''")
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        f"Get-Content -LiteralPath '{escaped_path}' -TotalCount 1",
    ]
    try:
        result = run_command(command, timeout=10, check=False)
    except Exception as error:  # noqa: BLE001
        return None, str(error)
    combined = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    lowered = combined.lower()
    if "virus" in lowered or "potentially unwanted software" in lowered:
        return "required_file_blocked", combined
    return None, combined or None


def build_artifact_inventory(
    command_results: list[dict[str, Any]],
    declared_artifacts: list[dict[str, Any]],
    extra_artifacts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for command in command_results:
        for artifact_path in command.get("artifactPaths", []):
            inventory.append(
                {
                    "source": "command",
                    "command": command.get("name"),
                    "status": "collected",
                    "artifactPath": artifact_path,
                }
            )
    for declaration in declared_artifacts:
        artifact_paths = declaration.get("artifactPaths", [])
        if artifact_paths:
            for artifact_path in artifact_paths:
                inventory.append(
                    {
                        "source": "declared_result",
                        "declaredPath": declaration.get("declaredPath"),
                        "status": declaration.get("status"),
                        "artifactPath": artifact_path,
                    }
                )
        else:
            inventory.append(
                {
                    "source": "declared_result",
                    "declaredPath": declaration.get("declaredPath"),
                    "status": declaration.get("status"),
                    "artifactPath": None,
                }
            )
    for artifact in extra_artifacts or []:
        inventory.append(
            {
                "source": artifact.get("sourceKind"),
                "declaredPath": artifact.get("declaredPath"),
                "status": artifact.get("status"),
                "artifactPath": artifact.get("collectedPath"),
                "logicalName": artifact.get("logicalName"),
            }
        )
    return inventory


def count_artifacts(
    command_results: list[dict[str, Any]],
    declared_artifacts: list[dict[str, Any]],
    extra_artifacts: list[dict[str, Any]] | None = None,
) -> int:
    count = 0
    for command in command_results:
        count += len(command.get("artifactPaths", []))
    for declaration in declared_artifacts:
        count += len(declaration.get("artifactPaths", []))
    for artifact in extra_artifacts or []:
        if artifact.get("status") == "collected" and artifact.get("collectedPath"):
            count += 1
    return count


def build_extra_artifact(
    *,
    logical_name: str,
    source_kind: str,
    collected_path: Path | None,
    declared_path: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    normalized_collected = normalize_path(collected_path.resolve()) if collected_path and collected_path.exists() else None
    size_bytes = collected_path.stat().st_size if collected_path and collected_path.exists() and collected_path.is_file() else None
    return {
        "logicalName": logical_name,
        "sourceKind": source_kind,
        "declaredPath": declared_path,
        "collectedPath": normalized_collected,
        "status": status or ("collected" if normalized_collected else "missing"),
        "sizeBytes": size_bytes,
    }


def build_artifact_manifest(
    *,
    command_results: list[dict[str, Any]],
    declared_artifacts: list[dict[str, Any]],
    extra_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    framework_artifacts: list[dict[str, Any]] = []
    repo_artifacts: list[dict[str, Any]] = []
    missing_artifacts: list[dict[str, Any]] = []
    for command in command_results:
        for label, path_key in (("stdout", "stdoutPath"), ("stderr", "stderrPath")):
            collected_path = command.get(path_key)
            entry = {
                "logicalName": f"command:{command.get('name')}:{label}",
                "sourceKind": "command",
                "declaredPath": command.get("command"),
                "collectedPath": collected_path,
                "status": "collected" if collected_path else "missing",
                "sizeBytes": Path(str(collected_path)).stat().st_size if collected_path and Path(str(collected_path)).exists() else None,
            }
            if collected_path:
                framework_artifacts.append(entry)
            else:
                missing_artifacts.append(entry)
    for declaration in declared_artifacts:
        artifact_paths = declaration.get("artifactPaths", [])
        if artifact_paths:
            for index, artifact_path in enumerate(artifact_paths):
                path_obj = Path(str(artifact_path))
                repo_artifacts.append(
                    {
                        "logicalName": f"declared:{declaration.get('declaredPath')}:{index}",
                        "sourceKind": "declared_result",
                        "declaredPath": declaration.get("declaredPath"),
                        "collectedPath": artifact_path,
                        "status": declaration.get("status"),
                        "sizeBytes": path_obj.stat().st_size if path_obj.exists() else None,
                    }
                )
        else:
            missing_artifacts.append(
                {
                    "logicalName": f"declared:{declaration.get('declaredPath')}",
                    "sourceKind": "declared_result",
                    "declaredPath": declaration.get("declaredPath"),
                    "collectedPath": None,
                    "status": declaration.get("status"),
                    "sizeBytes": None,
                }
            )
    for artifact in extra_artifacts or []:
        destination = framework_artifacts if artifact.get("status") == "collected" else missing_artifacts
        destination.append(artifact)
    return {
        "generatedAt": now_utc_iso(),
        "frameworkArtifacts": framework_artifacts,
        "repoArtifacts": repo_artifacts,
        "missingArtifacts": missing_artifacts,
    }


def write_artifact_manifest(artifact_root: Path, payload: dict[str, Any]) -> Path:
    manifest_path = ensure_dir(artifact_root) / "artifact_manifest.json"
    write_json(manifest_path, payload)
    return manifest_path


def check_required_files(manifest: dict[str, Any], preflight_config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    repo_root = resolve_repo_root(manifest)
    effective_preflight = preflight_config or {}
    checks: list[dict[str, Any]] = []
    for relative in effective_preflight.get("required_files", []):
        path = (repo_root / relative).resolve()
        if not path.exists():
            checks.append(
                {
                    "name": f"required_file:{relative}",
                    "ok": False,
                    "reason": "required_file_missing",
                    "details": {
                        "path": normalize_path(path),
                    },
                }
            )
            continue
        try:
            with path.open("rb") as handle:
                handle.read(1024)
        except Exception as error:  # noqa: BLE001
            reason = "required_file_unreadable"
            windows_reason, windows_details = _windows_file_probe(path)
            if windows_reason:
                reason = windows_reason
            checks.append(
                {
                    "name": f"required_file:{relative}",
                    "ok": False,
                    "reason": reason,
                    "details": {
                        "path": normalize_path(path),
                        "error": str(error),
                        "windowsProbe": windows_details,
                    },
                }
            )
            continue
        checks.append(
            {
                "name": f"required_file:{relative}",
                "ok": True,
                "reason": None,
                "details": {
                    "path": normalize_path(path),
                },
            }
        )
    return checks


def check_required_env(preflight_config: dict[str, Any], prepared_env: dict[str, Any]) -> dict[str, Any]:
    common_env = prepared_env["commonEnv"]
    required = [str(item) for item in (preflight_config.get("required_env") or [])]
    missing = [name for name in required if not common_env.get(name)]
    return {
        "name": "required_env",
        "ok": not missing,
        "reason": None if not missing else "missing_required_env",
        "details": {
            "required": required,
            "missing": missing,
            "snapshot": sanitize_env_snapshot(common_env, required),
        },
    }


def build_model_probe_url(preflight: dict[str, Any], prepared_env: dict[str, Any]) -> str | None:
    env_name = preflight.get("model_probe_url_env")
    if not env_name:
        return None
    base = str(prepared_env["commonEnv"].get(env_name) or "").strip()
    if not base:
        return None
    path = str(preflight.get("model_probe_path") or "/models").strip() or "/models"
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def check_model_probe(preflight: dict[str, Any], prepared_env: dict[str, Any]) -> dict[str, Any]:
    env_name = preflight.get("model_probe_url_env")
    if not env_name:
        return {
            "name": "model_probe",
            "ok": True,
            "reason": None,
            "details": {"skipped": True},
        }
    probe_url = build_model_probe_url(preflight, prepared_env)
    if not probe_url:
        return {
            "name": "model_probe",
            "ok": False,
            "reason": "model_service_env_missing",
            "details": {
                "env": env_name,
                "probeUrl": None,
            },
        }
    try:
        with urllib.request.urlopen(probe_url, timeout=5) as response:
            ok = int(response.status) < 400
            return {
                "name": "model_probe",
                "ok": ok,
                "reason": None if ok else "model_service_unreachable",
                "details": {
                    "env": env_name,
                    "probeUrl": probe_url,
                    "status": response.status,
                },
            }
    except urllib.error.HTTPError as error:
        return {
            "name": "model_probe",
            "ok": False,
            "reason": "model_service_unreachable",
            "details": {
                "env": env_name,
                "probeUrl": probe_url,
                "status": error.code,
                "error": str(error),
            },
        }
    except Exception as error:  # noqa: BLE001
        return {
            "name": "model_probe",
            "ok": False,
            "reason": "model_service_unreachable",
            "details": {
                "env": env_name,
                "probeUrl": probe_url,
                "error": str(error),
            },
        }


def run_preflight_checks(
    manifest: dict[str, Any],
    adapter: ModuleType | None,
    prepared_env: dict[str, Any],
    *,
    selected_commands: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    effective_preflight = resolve_effective_preflight(manifest, selected_commands)
    checks = [
        check_python_compatibility(manifest),
        check_expected_environment(manifest),
        check_required_env(effective_preflight, prepared_env),
        *check_required_files(manifest, effective_preflight),
        check_model_probe(effective_preflight, prepared_env),
    ]
    if adapter and hasattr(adapter, "additional_preflight_checks"):
        try:
            extra = adapter.additional_preflight_checks(
                manifest,
                prepared_env,
                selected_commands=selected_commands,
            )
        except TypeError:
            extra = adapter.additional_preflight_checks(manifest, prepared_env)
        if isinstance(extra, list):
            checks.extend(extra)
    reason, details = choose_primary_failure(checks)
    return {
        "ok": all(check.get("ok", False) for check in checks),
        "phase": "preflight",
        "reason": reason,
        "details": details,
        "checks": checks,
        "summary": {
            "pythonVersion": f"{sys_version_tuple()[0]}.{sys_version_tuple()[1]}.{sys_version_tuple()[2]}",
            "pythonExecutable": python_executable(),
            "repoRoot": normalize_path(resolve_repo_root(manifest)),
            "rawEnvKeysPresent": prepared_env.get("rawEnvKeysPresent") or {},
            "normalizedEnvKeysPresent": prepared_env.get("normalizedEnvKeysPresent") or {},
            "loadedEnvFiles": prepared_env.get("loadedEnvFiles") or [],
            "expectedEnvironmentOk": not any(
                check.get("reason") in {"expected_env_missing", "expected_env_mismatch"} for check in checks
            ),
            "requiredEnvPresent": not any(check.get("reason") == "missing_required_env" for check in checks),
            "modelReachable": not any(check.get("reason") in {"model_service_unreachable", "model_service_env_missing"} for check in checks),
            "requiredFilesOk": not any(
                check.get("reason") in {"required_file_missing", "required_file_unreadable", "required_file_blocked"} for check in checks
            ),
            "selectedCommands": [str(command.get("name")) for command in (selected_commands or [])],
        },
    }


def execute_command_spec(
    *,
    repo_root: Path,
    command_spec: dict[str, Any],
    template_env: dict[str, str],
    repo_env: dict[str, str],
    artifact_root: Path,
) -> dict[str, Any]:
    name = str(command_spec["name"])
    rendered = render_template(str(command_spec["cmd"]), template_env)
    args = tokenize_command(rendered)
    timeout_seconds = int(command_spec.get("timeout_seconds") or 3600)
    command_dir = ensure_dir(artifact_root / "commands" / safe_slug(name, "command"))
    result = run_command(args, cwd=repo_root, timeout=timeout_seconds, check=False, env=repo_env)
    stdout_path = command_dir / "stdout.log"
    stderr_path = command_dir / "stderr.log"
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    return {
        "name": name,
        "ok": result.returncode == 0,
        "command": rendered,
        "args": args,
        "returncode": result.returncode,
        "stdoutPath": normalize_path(stdout_path.resolve()),
        "stderrPath": normalize_path(stderr_path.resolve()),
        "artifactPaths": [
            normalize_path(stdout_path.resolve()),
            normalize_path(stderr_path.resolve()),
        ],
        "stdoutPreview": result.stdout[:2000],
        "stderrPreview": result.stderr[:2000],
    }


def _safe_relative_artifact_path(repo_root: Path, candidate: Path, fallback_stem: str) -> Path:
    try:
        return candidate.relative_to(repo_root)
    except ValueError:
        suffix = candidate.suffix or ""
        return Path("external") / f"{safe_slug(fallback_stem, 'artifact')}{suffix}"


def _is_within_path(parent: Path, candidate: Path) -> bool:
    parent = parent.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _copy_declared_artifact_file(
    *,
    repo_root: Path,
    source: Path,
    artifact_root: Path,
    fallback_stem: str,
) -> dict[str, Any]:
    relative_dest = _safe_relative_artifact_path(repo_root, source, fallback_stem)
    destination = artifact_root / "repo_outputs" / relative_dest
    ensure_dir(destination.parent)
    shutil.copy2(source, destination)
    return {
        "sourcePath": normalize_path(source.resolve()),
        "artifactPath": normalize_path(destination.resolve()),
        "sizeBytes": source.stat().st_size,
    }


def collect_result_paths(
    manifest: dict[str, Any],
    repo_root: Path,
    template_env: dict[str, str],
    run_dir: Path,
) -> list[dict[str, Any]]:
    import glob

    repo_root = repo_root.resolve()
    artifact_config = manifest.get("artifacts", {}) or {}
    max_copy_files = int(artifact_config.get("max_copy_files") or DEFAULT_ARTIFACT_MAX_COPY_FILES)
    max_copy_bytes = int(artifact_config.get("max_copy_bytes") or DEFAULT_ARTIFACT_MAX_COPY_BYTES)
    paths: list[dict[str, Any]] = []
    repo_artifact_root = ensure_dir(run_dir / "artifacts" / "task_repo")
    for raw_pattern in artifact_config.get("result_paths", []):
        rendered = render_template(str(raw_pattern), template_env)
        rendered_path = Path(rendered)
        absolute_pattern = str((repo_root / rendered).resolve())
        declaration: dict[str, Any] = {
            "declaredPath": str(raw_pattern),
            "resolvedPattern": normalize_path(absolute_pattern),
            "matches": [],
        }
        if rendered_path.is_absolute() or not _is_within_path(repo_root, Path(absolute_pattern)):
            declaration["status"] = "rejected"
            declaration["reason"] = "absolute_path" if rendered_path.is_absolute() else "outside_repo_root"
            declaration["copiedFileCount"] = 0
            declaration["copiedBytes"] = 0
            declaration["artifactPaths"] = []
            paths.append(declaration)
            continue
        matches = glob.glob(absolute_pattern)
        if not matches and Path(absolute_pattern).exists():
            matches = [absolute_pattern]
        if not matches:
            declaration["status"] = "missing"
            paths.append(declaration)
            continue
        copied_files: list[dict[str, Any]] = []
        total_bytes = 0
        total_files = 0
        status = "collected"
        for match in matches:
            candidate = Path(match).resolve()
            if not _is_within_path(repo_root, candidate):
                status = "rejected"
                match_entry = {
                    "sourcePath": normalize_path(candidate),
                    "kind": "directory" if candidate.is_dir() else "file",
                    "copiedFiles": [],
                    "status": "rejected",
                    "reason": "outside_repo_root",
                }
                declaration["matches"].append(match_entry)
                continue
            match_entry: dict[str, Any] = {
                "sourcePath": normalize_path(candidate),
                "kind": "directory" if candidate.is_dir() else "file",
                "copiedFiles": [],
            }
            if candidate.is_file():
                copied = _copy_declared_artifact_file(
                    repo_root=repo_root,
                    source=candidate,
                    artifact_root=repo_artifact_root,
                    fallback_stem=candidate.name,
                )
                copied_files.append(copied)
                match_entry["copiedFiles"].append(copied)
                total_files += 1
                total_bytes += int(copied["sizeBytes"])
            elif candidate.is_dir():
                for source_file in sorted(path for path in candidate.rglob("*") if path.is_file()):
                    source_file = source_file.resolve()
                    if not _is_within_path(repo_root, source_file):
                        status = "partial"
                        match_entry["copiedFiles"].append(
                            {
                                "sourcePath": normalize_path(source_file),
                                "status": "rejected",
                                "reason": "outside_repo_root",
                            }
                        )
                        continue
                    file_size = source_file.stat().st_size
                    if total_files >= max_copy_files or total_bytes + file_size > max_copy_bytes:
                        status = "partial"
                        break
                    copied = _copy_declared_artifact_file(
                        repo_root=repo_root,
                        source=source_file,
                        artifact_root=repo_artifact_root,
                        fallback_stem=str(source_file.relative_to(candidate)),
                    )
                    copied_files.append(copied)
                    match_entry["copiedFiles"].append(copied)
                    total_files += 1
                    total_bytes += int(copied["sizeBytes"])
            declaration["matches"].append(match_entry)
            if status == "partial":
                break
        declaration["status"] = status
        declaration["copiedFileCount"] = total_files
        declaration["copiedBytes"] = total_bytes
        declaration["limits"] = {
            "maxCopyFiles": max_copy_files,
            "maxCopyBytes": max_copy_bytes,
        }
        declaration["artifactPaths"] = [item["artifactPath"] for item in copied_files]
        paths.append(declaration)
    return paths
