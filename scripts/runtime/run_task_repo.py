from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "diagnosis"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "security_context"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from task_repo_common import (
    attach_source_metadata_to_run,
    build_evaluation_inputs_seed,
    build_artifact_manifest,
    build_artifact_inventory,
    build_extra_artifact,
    build_harness_report,
    classify_failure_reason,
    count_artifacts,
    collect_result_paths,
    create_task_repo_run,
    execute_command_spec,
    inject_runtime_context,
    load_task_repo_adapter,
    load_task_repo_manifest,
    prepare_environment,
    resolve_agent_trace_run_dir,
    resolve_repo_root,
    run_source_preflight_checks,
    run_preflight_checks,
    update_task_repo_run_state,
    wait_for_agent_trace_run,
    write_artifact_manifest,
)
from run_codetracer_diagnosis import run_codetracer_diagnosis
from run_context_judge import run_context_judge
from trace_common import normalize_path, now_utc_iso, run_openclaw_agent, write_json
from app.agent_defense.final_judge import run_final_judgment
from app.agent_defense.trace_merge import merge_run_traces
from app.instrumentation.frida import FridaTraceConfig, FridaTraceManager
from app.security.context_state import create_security_context
from app.security.intent_guard import inspect_user_input
from app.security.plan_guard import inspect_plan


def select_command_specs(manifest: dict[str, Any], command_name: str | None) -> list[dict[str, Any]]:
    if "run" not in manifest or not isinstance(manifest.get("run"), dict):
        raise ValueError("manifest run.commands is required for repo-native mode")
    commands = list((manifest.get("run") or {}).get("commands") or [])
    if not commands:
        raise ValueError("manifest run.commands is required for repo-native mode")
    if not command_name:
        return commands
    selected = [command for command in commands if command.get("name") == command_name]
    if selected:
        return selected
    raise ValueError(f"command not found in manifest: {command_name}")


def build_final_report(
    *,
    repo_name: str,
    manifest: dict[str, Any],
    prepared_env: dict[str, Any],
    run_dir: Path,
    preflight: dict[str, Any],
    command_results: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    extra_artifacts: list[dict[str, Any]],
    framework_success: bool,
    repo_success: bool,
    phase: str,
    reason: str | None,
    details: dict[str, Any] | None,
    repo_evaluation: dict[str, Any] | None,
    artifact_manifest_path: Path | None,
) -> dict[str, Any]:
    artifact_inventory = build_artifact_inventory(command_results, artifacts, extra_artifacts)
    adapter_state = prepared_env.get("adapterState") or {}
    model_resolution = adapter_state.get("modelResolution") or {}
    return {
        "repo": manifest.get("name") or repo_name,
        "repoSlug": repo_name,
        "ok": framework_success and repo_success,
        "phase": phase,
        "reason": reason,
        "details": details,
        "runDir": normalize_path(run_dir.resolve()),
        "manifestPath": normalize_path(manifest.get("_manifestPath")),
        "frameworkSuccess": framework_success,
        "repoSuccess": repo_success,
        "generatedAt": now_utc_iso(),
        "preflight": preflight,
        "commands": command_results,
        "artifacts": artifacts,
        "artifactInventory": artifact_inventory,
        "artifactManifestPath": normalize_path(artifact_manifest_path.resolve()) if artifact_manifest_path else None,
        "requestedModel": model_resolution.get("requestedModel"),
        "effectiveModel": model_resolution.get("effectiveModel") or prepared_env.get("templateEnv", {}).get("MODEL_NAME"),
        "fallbackUsed": bool(model_resolution.get("fallbackUsed")),
        "rawEnvKeysPresent": prepared_env.get("rawEnvKeysPresent") or {},
        "normalizedEnvKeysPresent": prepared_env.get("normalizedEnvKeysPresent") or {},
        "repoEvaluation": repo_evaluation or {},
        "summary": {
            "failureClass": classify_failure_reason(reason),
            "pythonVersion": preflight.get("summary", {}).get("pythonVersion"),
            "repoRoot": preflight.get("summary", {}).get("repoRoot"),
            "frameworkSuccess": framework_success,
            "repoSuccess": repo_success,
            "expectedEnvironmentOk": preflight.get("summary", {}).get("expectedEnvironmentOk"),
            "modelReachable": preflight.get("summary", {}).get("modelReachable"),
            "requiredEnvPresent": preflight.get("summary", {}).get("requiredEnvPresent"),
            "requiredFilesOk": preflight.get("summary", {}).get("requiredFilesOk"),
            "requestedModel": model_resolution.get("requestedModel"),
            "effectiveModel": model_resolution.get("effectiveModel") or prepared_env.get("templateEnv", {}).get("MODEL_NAME"),
            "fallbackUsed": bool(model_resolution.get("fallbackUsed")),
            "rawEnvKeysPresent": prepared_env.get("rawEnvKeysPresent") or {},
            "normalizedEnvKeysPresent": prepared_env.get("normalizedEnvKeysPresent") or {},
            "commandCount": len(command_results),
            "artifactCount": len(artifact_inventory),
        },
    }


def _source_task_metadata(repo_name: str, task: dict[str, Any]) -> dict[str, Any]:
    return {
        "sourceRepo": repo_name,
        "taskId": task.get("taskId"),
        "sourcePath": task.get("sourcePath"),
        "scenario": task.get("scenario"),
        "attackType": task.get("attackType") or task.get("attack_type"),
        "expectedLabel": task.get("label"),
        "harnessMode": "agent-trace",
    }


def _task_report_metadata(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "taskId": task.get("taskId"),
        "sourcePath": task.get("sourcePath"),
        "scenario": task.get("scenario"),
        "attackType": task.get("attackType") or task.get("attack_type"),
        "label": task.get("label"),
    }


def _wait_for_run_dir(run_id: str, *, timeout_seconds: int = 3) -> Path | None:
    import time

    deadline = time.monotonic() + max(timeout_seconds, 1)
    while time.monotonic() <= deadline:
        run_dir = resolve_agent_trace_run_dir(run_id)
        if run_dir is not None:
            return run_dir
        time.sleep(0.5)
    return None


def _start_frida(args: argparse.Namespace, run_id: str, run_dir: Path | None) -> tuple[FridaTraceManager | None, dict[str, Any]]:
    if getattr(args, "frida", "auto") == "off":
        return None, {"status": "disabled", "ok": False, "reason": "frida_disabled"}
    if run_dir is None:
        return None, {"status": "unavailable", "ok": False, "reason": "run_dir_not_available_before_poll"}
    manager = FridaTraceManager(
        FridaTraceConfig(
            enabled=True,
            target=getattr(args, "frida_target", "auto") or "auto",
            output=str((run_dir / "frida-events.jsonl").resolve()),
        )
    )
    result = manager.start(run_id=run_id, session_id=None, started_at=now_utc_iso())
    payload = result.to_dict()
    if result.ok:
        payload["status"] = "ok"
    elif any("permission" in warning or "attach_failed" in warning for warning in result.warnings):
        payload["status"] = "attach_failed"
    else:
        payload["status"] = "unavailable"
    if not result.ok:
        (run_dir / "frida-events.jsonl").parent.mkdir(parents=True, exist_ok=True)
        (run_dir / "frida-events.jsonl").touch(exist_ok=True)
    return manager if result.ok else None, payload


def _stop_frida(manager: FridaTraceManager | None, status: dict[str, Any]) -> dict[str, Any]:
    if manager is None:
        return status
    stop_result = manager.stop().to_dict()
    merged = dict(status)
    merged["stop"] = stop_result
    merged["eventCount"] = stop_result.get("event_count")
    return merged


def _sanitize_task_for_dry_run(task: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(task)
    contents = sanitized.get("contents")
    if isinstance(contents, str) and len(contents) > 500:
        sanitized["contents"] = f"[CONTENT_TRUNCATED: {len(contents)} chars] {contents[:200]}..."
    return sanitized


def _build_dry_run_report(
    *,
    repo_name: str,
    manifest: dict[str, Any],
    task: dict[str, Any],
    message: str,
    security_decision: Any,
    security_context: Any,
) -> dict[str, Any]:
    sanitized_task = _sanitize_task_for_dry_run(task)
    decision_dict = security_decision.to_dict() if hasattr(security_decision, "to_dict") else {}
    return {
        "ok": True,
        "mode": "agent-trace",
        "dryRun": True,
        "repo": manifest.get("name") or repo_name,
        "taskId": task.get("taskId") or task.get("id"),
        "task": sanitized_task,
        "message": message,
        "inputSecurity": {
            "decision": decision_dict.get("decision"),
            "riskLevel": decision_dict.get("riskLevel"),
            "reasons": decision_dict.get("reasons", []),
        },
        "willLaunchAgent": False,
        "willCreateRun": False,
        "generatedAt": now_utc_iso(),
    }


def _source_preflight_report(
    *,
    args: argparse.Namespace,
    manifest: dict[str, Any],
    adapter: Any,
    prepared_env: dict[str, Any],
) -> dict[str, Any]:
    preflight = run_source_preflight_checks(args.repo, manifest, adapter, prepared_env)
    return {
        "repo": manifest.get("name") or args.repo,
        "repoSlug": args.repo,
        "mode": args.mode,
        "ok": bool(preflight.get("ok")),
        "phase": "source_preflight",
        "reason": preflight.get("reason"),
        "details": preflight.get("details"),
        "generatedAt": now_utc_iso(),
        "preflight": preflight,
    }


def _run_list_tasks(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    adapter: Any,
    prepared_env: dict[str, Any],
) -> dict[str, Any]:
    preflight_report = _source_preflight_report(args=args, manifest=manifest, adapter=adapter, prepared_env=prepared_env)
    if args.preflight_only or not preflight_report["ok"]:
        return preflight_report
    tasks = adapter.list_tasks(manifest, prepared_env)
    return {
        "repo": manifest.get("name") or args.repo,
        "repoSlug": args.repo,
        "mode": "list-tasks",
        "ok": True,
        "taskCount": len(tasks),
        "tasks": tasks,
        "generatedAt": now_utc_iso(),
        "preflight": preflight_report["preflight"],
    }


def _run_show_task(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    adapter: Any,
    prepared_env: dict[str, Any],
) -> dict[str, Any]:
    preflight_report = _source_preflight_report(args=args, manifest=manifest, adapter=adapter, prepared_env=prepared_env)
    if args.preflight_only or not preflight_report["ok"]:
        return preflight_report
    try:
        task = adapter.load_task(manifest, prepared_env, args.task_id)
    except LookupError as error:
        return {
            "repo": manifest.get("name") or args.repo,
            "repoSlug": args.repo,
            "mode": "show-task",
            "ok": False,
            "phase": "load_task",
            "reason": "task_not_found",
            "details": {"taskId": args.task_id, "error": str(error)},
            "generatedAt": now_utc_iso(),
            "preflight": preflight_report["preflight"],
        }
    return {
        "repo": manifest.get("name") or args.repo,
        "repoSlug": args.repo,
        "mode": "show-task",
        "ok": True,
        "taskId": args.task_id,
        "task": task,
        "generatedAt": now_utc_iso(),
        "preflight": preflight_report["preflight"],
    }


def _run_agent_trace(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    adapter: Any,
    prepared_env: dict[str, Any],
) -> dict[str, Any]:
    preflight_report = _source_preflight_report(args=args, manifest=manifest, adapter=adapter, prepared_env=prepared_env)
    preflight = preflight_report["preflight"]
    if args.preflight_only:
        return preflight_report
    if not preflight_report["ok"]:
        return build_harness_report(
            repo_name=args.repo,
            manifest=manifest,
            mode="agent-trace",
            task_metadata={"taskId": args.task_id},
            preflight=preflight,
            framework_success=bool(preflight_report["ok"]),
            agent_run_success=False,
            agent_payload=None,
            resolved_run_dir=None,
            phase="source_preflight",
            reason=None if preflight_report["ok"] else preflight_report.get("reason"),
            details=preflight_report.get("details"),
        )
    try:
        task = adapter.load_task(manifest, prepared_env, args.task_id)
    except LookupError as error:
        return build_harness_report(
            repo_name=args.repo,
            manifest=manifest,
            mode="agent-trace",
            task_metadata={"taskId": args.task_id},
            preflight=preflight,
            framework_success=False,
            agent_run_success=False,
            agent_payload=None,
            resolved_run_dir=None,
            phase="load_task",
            reason="task_not_found",
            details={"taskId": args.task_id, "error": str(error)},
        )

    task_metadata = _task_report_metadata(task)
    message = adapter.build_agent_input(manifest, prepared_env, task)
    security_context = create_security_context(run_id=None)
    security_context = inspect_user_input(message, security_context)
    security_decision, security_context = inspect_plan(message, security_context)
    if args.dry_run:
        return _build_dry_run_report(
            repo_name=args.repo,
            manifest=manifest,
            task=task,
            message=message,
            security_decision=security_decision,
            security_context=security_context,
        )
    if security_decision.decision == "block":
        return build_harness_report(
            repo_name=args.repo,
            manifest=manifest,
            mode="agent-trace",
            task_metadata=task_metadata,
            preflight=preflight,
            framework_success=True,
            agent_run_success=False,
            agent_payload=None,
            resolved_run_dir=None,
            phase="input_security",
            reason="security_input_blocked",
            details={"decision": security_decision.to_dict()},
        )
    try:
        agent_payload = run_openclaw_agent(
            message=message,
            timeout_seconds=int(args.timeout),
            no_wait=True,
        )
    except (TimeoutError, subprocess.TimeoutExpired) as error:
        return build_harness_report(
            repo_name=args.repo,
            manifest=manifest,
            mode="agent-trace",
            task_metadata=task_metadata,
            preflight=preflight,
            framework_success=True,
            agent_run_success=False,
            agent_payload=None,
            resolved_run_dir=None,
            phase="agent_launch",
            reason="agent_run_timeout",
            details={"error": str(error)},
        )
    except Exception as error:  # noqa: BLE001
        return build_harness_report(
            repo_name=args.repo,
            manifest=manifest,
            mode="agent-trace",
            task_metadata=task_metadata,
            preflight=preflight,
            framework_success=True,
            agent_run_success=False,
            agent_payload=None,
            resolved_run_dir=None,
            phase="agent_launch",
            reason="agent_launch_failed",
            details={"error": str(error)},
        )
    run_id = agent_payload.get("runId") if isinstance(agent_payload, dict) else None
    if not isinstance(agent_payload, dict) or not agent_payload.get("ok") or not run_id:
        return build_harness_report(
            repo_name=args.repo,
            manifest=manifest,
            mode="agent-trace",
            task_metadata=task_metadata,
            preflight=preflight,
            framework_success=True,
            agent_run_success=False,
            agent_payload=agent_payload if isinstance(agent_payload, dict) else None,
            resolved_run_dir=None,
            phase="agent_launch",
            reason="agent_launch_failed",
            details={"agentPayload": agent_payload},
        )

    pre_poll_run_dir = _wait_for_run_dir(str(run_id), timeout_seconds=3)
    frida_manager, frida_status = _start_frida(args, str(run_id), pre_poll_run_dir)
    try:
        poll = wait_for_agent_trace_run(run_id, timeout_seconds=int(args.timeout), poll_interval_seconds=2)
    finally:
        frida_status = _stop_frida(frida_manager, frida_status)
    resolved_run_dir = poll.get("runDir") if isinstance(poll.get("runDir"), Path) else None
    if resolved_run_dir is None:
        resolved_run_dir = pre_poll_run_dir
    timed_out = bool(poll.get("timedOut"))
    trace_observed = bool(resolved_run_dir is not None and int(poll.get("eventCount") or 0) > 0)
    security_intervened = bool(poll.get("securityIntervention"))
    phase = "security_intervened" if security_intervened else (
        "completed" if not timed_out and resolved_run_dir is not None else ("timeout_with_trace" if timed_out and trace_observed else "polling")
    )
    agent_run_success = bool(resolved_run_dir is not None and (not timed_out or security_intervened))
    harness_report = build_harness_report(
        repo_name=args.repo,
        manifest=manifest,
        mode="agent-trace",
        task_metadata=task_metadata,
        preflight=preflight,
        framework_success=True,
        agent_run_success=agent_run_success,
        agent_payload=agent_payload,
        resolved_run_dir=resolved_run_dir,
        phase=phase,
        reason=None if agent_run_success else ("agent_run_timeout" if timed_out else "agent_trace_missing"),
        details={
            "polling": {key: value for key, value in poll.items() if key != "runDir"},
            "frida": frida_status,
        },
    )
    if resolved_run_dir is not None:
        try:
            trace_merge_result = merge_run_traces(resolved_run_dir, frida_status=frida_status)
        except Exception as error:  # noqa: BLE001
            trace_merge_result = {
                "ok": False,
                "status": "failed",
                "reason": "trace_merge_failed",
                "error": str(error),
            }
        harness_report["traceMerge"] = trace_merge_result
        diagnosis_result: dict[str, Any] | None = None
        if args.skip_diagnosis:
            diagnosis_result = {
                "ok": None,
                "status": "skipped",
                "reason": "skip_diagnosis_requested",
            }
        else:
            try:
                diagnosis_result = run_codetracer_diagnosis(
                    run_dir=resolved_run_dir,
                    model=args.diagnosis_model,
                    profile=args.diagnosis_profile,
                    cost_limit=float(args.diagnosis_cost_limit),
                    timeout_seconds=int(args.diagnosis_timeout_seconds),
                )
                diagnosis_result["status"] = "success" if diagnosis_result.get("ok") else "failed"
            except Exception as error:  # noqa: BLE001
                diagnosis_report_path = resolved_run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json"
                write_json(
                    diagnosis_report_path,
                    {
                        "schemaVersion": "transpect.diagnosis-report.v1",
                        "generatedAt": now_utc_iso(),
                        "runId": resolved_run_dir.name,
                        "diagnosisLayer": "codetracer",
                        "role": "trajectory_diagnosis_not_benchmark_evaluation",
                        "ok": False,
                        "status": "failed",
                        "reason": "diagnosis_failed",
                        "error": str(error),
                    },
                )
                diagnosis_result = {
                    "ok": False,
                    "status": "failed",
                    "reason": "diagnosis_failed",
                    "error": str(error),
                    "diagnosisReportPath": normalize_path(diagnosis_report_path.resolve()),
                }
        harness_report["diagnosis"] = diagnosis_result
        evaluation_inputs_seed = build_evaluation_inputs_seed(
            resolved_run_dir,
            repo_name=args.repo,
            source_task=task,
            source_metadata=_source_task_metadata(args.repo, task),
            diagnosis_result=diagnosis_result,
        )
        attachment = attach_source_metadata_to_run(
            resolved_run_dir,
            _source_task_metadata(args.repo, task),
            source_task=task,
            harness_report=harness_report,
            evaluation_inputs_seed=evaluation_inputs_seed,
        )
        harness_report["artifactManifestPath"] = attachment["artifactManifestPath"]
        if args.skip_context_judge:
            context_result = {
                "ok": None,
                "status": "skipped",
                "reason": "skip_context_judge_requested",
            }
        else:
            try:
                context_result = run_context_judge(resolved_run_dir)
                context_result["status"] = "success" if context_result.get("ok") else "failed"
            except Exception as error:  # noqa: BLE001
                context_report_path = resolved_run_dir / "security-context" / "context_report.json"
                context_result = {
                    "schemaVersion": "transpect.security-context-report.v1",
                    "generatedAt": now_utc_iso(),
                    "runId": resolved_run_dir.name,
                    "ok": False,
                    "status": "failed",
                    "reason": "context_judge_failed",
                    "error": str(error),
                    "decision": None,
                    "riskLevel": None,
                    "score": None,
                }
                write_json(context_report_path, context_result)
                context_result["reportPath"] = normalize_path(context_report_path.resolve())
        harness_report["securityContext"] = context_result
        if isinstance(context_result, dict) and isinstance(context_result.get("securityReasoning"), dict):
            harness_report["securityReasoning"] = context_result["securityReasoning"]
        try:
            final_judgment = run_final_judgment(resolved_run_dir)
            harness_report["finalJudgment"] = {
                "ok": True,
                "decision": final_judgment.get("finalDecision"),
                "riskLevel": final_judgment.get("riskLevel"),
                "path": normalize_path((resolved_run_dir / "security-reasoning" / "final_judgment.json").resolve()),
            }
        except Exception as error:  # noqa: BLE001
            final_judgment_path = resolved_run_dir / "security-reasoning" / "final_judgment.json"
            write_json(
                final_judgment_path,
                {
                    "schemaVersion": "transpect.agent-defense.final-judgment.v1",
                    "generatedAt": now_utc_iso(),
                    "runId": resolved_run_dir.name,
                    "ok": False,
                    "status": "failed",
                    "reason": "final_judgment_failed",
                    "error": str(error),
                },
            )
            harness_report["finalJudgment"] = {
                "ok": False,
                "status": "failed",
                "reason": "final_judgment_failed",
                "error": str(error),
                "path": normalize_path(final_judgment_path.resolve()),
            }
        write_json(resolved_run_dir / "artifacts" / "task_repo" / "harness_report.json", harness_report)
    return harness_report


def _run_repo_native(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    adapter: Any,
    prepared_env: dict[str, Any],
) -> dict[str, Any]:
    selected_commands = select_command_specs(manifest, args.command)
    selected_names = [str(command.get("name")) for command in selected_commands]
    run_record = create_task_repo_run(
        args.repo,
        manifest,
        mode="preflight" if args.preflight_only else "run",
        selected_commands=selected_names,
    )
    run_dir = Path(run_record["runDir"])
    prepared_env = inject_runtime_context(prepared_env, run_dir)
    adapter_dir = run_dir / "adapter"
    write_json(adapter_dir / "repo_manifest.json", manifest)

    preflight = run_preflight_checks(
        manifest,
        adapter,
        prepared_env,
        selected_commands=selected_commands,
    )
    write_json(adapter_dir / "preflight_report.json", preflight)
    extra_artifacts: list[dict[str, Any]] = []
    model_resolution = ((prepared_env.get("adapterState") or {}).get("modelResolution") or None)
    if isinstance(model_resolution, dict):
        model_resolution_path = adapter_dir / "model_resolution.json"
        write_json(
            model_resolution_path,
            {
                "requestedModel": model_resolution.get("requestedModel"),
                "effectiveModel": model_resolution.get("effectiveModel"),
                "fallbackUsed": bool(model_resolution.get("fallbackUsed")),
                "resolutionStatus": model_resolution.get("resolutionStatus"),
                "failureReason": model_resolution.get("failureReason"),
                "attempts": model_resolution.get("attempts") or [],
            },
        )
        extra_artifacts.append(
            build_extra_artifact(
                logical_name="adapter:model_resolution",
                source_kind="adapter",
                collected_path=model_resolution_path,
                declared_path="adapter/model_resolution.json",
            )
        )

    if args.preflight_only or not preflight.get("ok"):
        artifact_manifest_path = write_artifact_manifest(
            run_dir / "artifacts" / "task_repo",
            build_artifact_manifest(command_results=[], declared_artifacts=[], extra_artifacts=extra_artifacts),
        )
        extra_artifacts.append(
            build_extra_artifact(
                logical_name="framework:artifact_manifest",
                source_kind="framework",
                collected_path=artifact_manifest_path,
                declared_path="artifacts/task_repo/artifact_manifest.json",
            )
        )
        final_report = build_final_report(
            repo_name=args.repo,
            manifest=manifest,
            prepared_env=prepared_env,
            run_dir=run_dir,
            preflight=preflight,
            command_results=[],
            artifacts=[],
            extra_artifacts=extra_artifacts,
            framework_success=True,
            repo_success=bool(preflight.get("ok")),
            phase="preflight",
            reason=preflight.get("reason"),
            details=preflight.get("details"),
            repo_evaluation={"repoSuccess": bool(preflight.get("ok")), "phase": "preflight"},
            artifact_manifest_path=artifact_manifest_path,
        )
        write_json(adapter_dir / "run_report.json", final_report)
        update_task_repo_run_state(
            run_dir,
            status="completed" if preflight.get("ok") else "preflight_failed",
            phase="preflight",
            summary=final_report["summary"],
            artifact_count=count_artifacts([], [], extra_artifacts),
        )
        return final_report

    repo_root = resolve_repo_root(manifest)
    task_repo_artifact_root = run_dir / "artifacts" / "task_repo"
    command_results = [
        execute_command_spec(
            repo_root=repo_root,
            command_spec=command,
            template_env=prepared_env["templateEnv"],
            repo_env=prepared_env["repoEnv"],
            artifact_root=task_repo_artifact_root,
        )
        for command in selected_commands
    ]
    failed_command = next((command for command in command_results if not command.get("ok")), None)
    artifacts = collect_result_paths(manifest, repo_root, prepared_env["templateEnv"], run_dir)
    repo_evaluation = None
    if adapter and hasattr(adapter, "evaluate_repo_result"):
        repo_evaluation = adapter.evaluate_repo_result(
            manifest,
            prepared_env,
            command_results,
            artifacts,
            selected_commands=selected_commands,
        )
    if not isinstance(repo_evaluation, dict):
        repo_evaluation = {"repoSuccess": failed_command is None}
    repo_success = bool(repo_evaluation.get("repoSuccess")) and failed_command is None
    artifact_manifest_path = write_artifact_manifest(
        run_dir / "artifacts" / "task_repo",
        build_artifact_manifest(command_results=command_results, declared_artifacts=artifacts, extra_artifacts=extra_artifacts),
    )
    extra_artifacts.append(
        build_extra_artifact(
            logical_name="framework:artifact_manifest",
            source_kind="framework",
            collected_path=artifact_manifest_path,
            declared_path="artifacts/task_repo/artifact_manifest.json",
        )
    )
    artifact_count = count_artifacts(command_results, artifacts, extra_artifacts)
    final_report = build_final_report(
        repo_name=args.repo,
        manifest=manifest,
        prepared_env=prepared_env,
        run_dir=run_dir,
        preflight=preflight,
        command_results=command_results,
        artifacts=artifacts,
        extra_artifacts=extra_artifacts,
        framework_success=True,
        repo_success=repo_success,
        phase="run" if not repo_success else "completed",
        reason="command_failed" if failed_command else ("repo_outputs_missing" if not repo_success else None),
        details={"command": failed_command} if failed_command else repo_evaluation,
        repo_evaluation=repo_evaluation,
        artifact_manifest_path=artifact_manifest_path,
    )
    write_json(adapter_dir / "run_report.json", final_report)
    update_task_repo_run_state(
        run_dir,
        status="failed" if not repo_success else "completed",
        phase="run",
        summary=final_report["summary"],
        artifact_count=artifact_count,
    )
    return final_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a manifest-driven external task repository adapter.")
    parser.add_argument("--repo", required=True, help="Task repository slug under task_repos/.")
    parser.add_argument(
        "--mode",
        choices=["repo-native", "list-tasks", "show-task", "agent-trace"],
        default="repo-native",
        help="Runner mode. Defaults to repo-native for backward compatibility.",
    )
    parser.add_argument("--preflight-only", action="store_true", help="Only run preflight checks for the selected mode.")
    parser.add_argument("--dry-run", action="store_true", help="Build agent input and run security checks without launching the agent. Valid only in agent-trace mode.")
    parser.add_argument("--command", help="Run one named command from the manifest. Valid only in repo-native mode.")
    parser.add_argument("--task-id", help="Source task ID for show-task and agent-trace modes.")
    parser.add_argument("--timeout", type=int, default=300, help="Agent execution timeout for agent-trace mode.")
    parser.add_argument("--skip-diagnosis", action="store_true", help="Skip Layer 3 CodeTracer diagnosis for agent-trace mode.")
    parser.add_argument("--diagnosis-profile", default="detailed", help="CodeTracer diagnosis profile for agent-trace mode.")
    parser.add_argument("--diagnosis-model", help="Optional model name for CodeTracer diagnosis.")
    parser.add_argument("--diagnosis-timeout-seconds", type=int, default=1800, help="CodeTracer diagnosis timeout.")
    parser.add_argument("--diagnosis-cost-limit", type=float, default=3.0, help="CodeTracer max LLM spend in USD.")
    parser.add_argument("--skip-context-judge", action="store_true", help="Skip Layer 4 security context judgment for agent-trace mode.")
    parser.add_argument("--frida", choices=["auto", "off", "on"], default="auto", help="Best-effort Frida runtime trace capture for agent-trace mode.")
    parser.add_argument("--frida-target", default="auto", help="Frida target selector: auto, node, chrome, pid:<PID>, or name:<NAME>.")
    args = parser.parse_args()

    if args.command and args.mode != "repo-native":
        parser.error("--command is only valid with --mode repo-native")
    if args.dry_run and args.mode != "agent-trace":
        parser.error("--dry-run is only valid with --mode agent-trace")
    if args.mode in {"show-task", "agent-trace"} and not args.task_id:
        parser.error("--task-id is required for show-task and agent-trace modes")

    manifest = load_task_repo_manifest(args.repo)
    adapter = load_task_repo_adapter(args.repo)
    prepared_env = prepare_environment(manifest)

    if args.mode == "repo-native":
        report = _run_repo_native(args, manifest, adapter, prepared_env)
    elif args.mode == "list-tasks":
        report = _run_list_tasks(args, manifest, adapter, prepared_env)
    elif args.mode == "show-task":
        report = _run_show_task(args, manifest, adapter, prepared_env)
    else:
        report = _run_agent_trace(args, manifest, adapter, prepared_env)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
