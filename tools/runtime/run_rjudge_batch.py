from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import TRACE_LIVE_DIR, now_utc_iso, safe_slug, write_json  # noqa: E402


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = TRACE_LIVE_DIR / "reports"


def now_iso_precise() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_command(args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(WORKSPACE_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def parse_json_stdout(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"command did not emit JSON: {completed.args}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"command emitted non-object JSON: {completed.args}")
    return payload


def list_rjudge_tasks(repo: str) -> list[dict[str, Any]]:
    completed = run_command(
        [
            sys.executable,
            "tools/runtime/run_task_repo.py",
            "--repo",
            repo,
            "--mode",
            "list-tasks",
        ],
        timeout=300,
    )
    payload = parse_json_stdout(completed)
    if completed.returncode != 0 or not payload.get("ok"):
        raise RuntimeError(f"list-tasks failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}")
    tasks = payload.get("tasks")
    if not isinstance(tasks, list):
        raise RuntimeError("list-tasks response missing tasks[]")
    return [task for task in tasks if isinstance(task, dict)]


def source_matches(task_source: str | None, filters: list[str]) -> bool:
    if not filters:
        return True
    source = str(task_source or "").strip().replace("\\", "/")
    for raw_filter in filters:
        prefix = str(raw_filter or "").strip().replace("\\", "/").rstrip("/")
        if not prefix:
            continue
        if source == prefix or source.startswith(f"{prefix}/"):
            return True
    return False


def filter_tasks(
    tasks: list[dict[str, Any]],
    *,
    task_ids: list[str],
    source_paths: list[str],
    labels: list[int],
    attack_types: list[str],
    scenario: str | None,
) -> list[dict[str, Any]]:
    task_id_set = {item.strip() for item in task_ids if item.strip()}
    attack_type_set = {item.strip().lower() for item in attack_types if item.strip()}
    scenario_text = str(scenario or "").strip().lower()
    output: list[dict[str, Any]] = []
    for task in tasks:
        task_id = str(task.get("taskId") or "")
        if task_id_set and task_id not in task_id_set:
            continue
        if not source_matches(task.get("sourcePath"), source_paths):
            continue
        if labels and task.get("label") not in labels:
            continue
        attack_type = str(task.get("attackType") or "").strip().lower()
        if attack_type_set and attack_type not in attack_type_set:
            continue
        if scenario_text and scenario_text not in str(task.get("scenario") or "").strip().lower():
            continue
        output.append(task)
    return output


def select_tasks(tasks: list[dict[str, Any]], *, count: int | None, shuffle: bool, seed: int) -> list[dict[str, Any]]:
    selected = list(tasks)
    if shuffle:
        random.Random(seed).shuffle(selected)
    if count is not None:
        selected = selected[: max(count, 0)]
    return selected


def make_batch_id(repo: str, count: int, requested_name: str | None) -> str:
    if requested_name:
        return safe_slug(requested_name, "rjudge-batch")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return safe_slug(f"{repo}-batch-{count}-{stamp}", "rjudge-batch")


def extract_run_id(payload: dict[str, Any]) -> str | None:
    value = payload.get("agentRunId") or payload.get("runId")
    if isinstance(value, str) and value.strip():
        return value.strip()
    resolved = payload.get("resolvedRunDir")
    if isinstance(resolved, str) and resolved.strip():
        return Path(resolved).name
    return None


def extract_predicted_label(run_dir: Path | None) -> int | None:
    if not run_dir:
        return None
    steps_path = run_dir / "diagnosis" / "codetracer" / "bundle" / "steps.json"
    if not steps_path.exists():
        return None
    try:
        steps = json.loads(steps_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(steps, list):
        return None
    finals = [
        step
        for step in steps
        if isinstance(step, dict) and (step.get("openclaw_meta") or {}).get("syntheticReason") == "final_assistant_answer"
    ]
    if not finals:
        return None
    observation_ref = finals[-1].get("observation_ref") or {}
    text = ""
    if isinstance(observation_ref, dict) and isinstance(observation_ref.get("content"), str):
        try:
            content = json.loads(observation_ref["content"])
            text = str((((content.get("payload") or {}).get("preview") or {}).get("assistant")) or "")
        except json.JSONDecodeError:
            text = observation_ref["content"]
    if not text:
        text = str(finals[-1].get("observation") or "")
    patterns = [
        r"^\s*([01])\b",
        r"\b([01])\s*\n\n\*\*Reason:\*\*",
        r"\brated as\s*([01])\b",
        r"\bshould be rated as\s*([01])\b",
        r"\.([01])\s*\n\n\*\*Reason:\*\*",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return int(match.group(1))
    lowered = text.lower()
    if "rated as 1" in lowered:
        return 1
    if "rated as 0" in lowered:
        return 0
    return None


def agent_trace_command(args: argparse.Namespace, task_id: str) -> list[str]:
    command = [
        sys.executable,
        "tools/runtime/run_task_repo.py",
        "--repo",
        args.repo,
        "--mode",
        "agent-trace",
        "--task-id",
        task_id,
        "--timeout",
        str(args.timeout),
        "--diagnosis-profile",
        args.diagnosis_profile,
        "--diagnosis-timeout-seconds",
        str(args.diagnosis_timeout_seconds),
        "--diagnosis-cost-limit",
        str(args.diagnosis_cost_limit),
    ]
    if args.skip_diagnosis:
        command.append("--skip-diagnosis")
    if getattr(args, "skip_context_judge", False):
        command.append("--skip-context-judge")
    if args.diagnosis_model:
        command.extend(["--diagnosis-model", args.diagnosis_model])
    return command


def run_one_task(args: argparse.Namespace, task: dict[str, Any]) -> dict[str, Any]:
    task_id = str(task.get("taskId") or "")
    started_at = now_iso_precise()
    completed = run_command(agent_trace_command(args, task_id), timeout=args.command_timeout_seconds)
    completed_at = now_iso_precise()
    payload: dict[str, Any] | None = None
    parse_error = None
    try:
        parsed = json.loads(completed.stdout)
        payload = parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError as error:
        parse_error = str(error)
    run_id = extract_run_id(payload or {})
    run_dir = Path(payload["resolvedRunDir"]) if payload and isinstance(payload.get("resolvedRunDir"), str) else None
    predicted_label = extract_predicted_label(run_dir)
    expected_label = task.get("label")
    label_matched = predicted_label == expected_label if predicted_label is not None and expected_label is not None else None
    return {
        "taskId": task_id,
        "sourcePath": task.get("sourcePath"),
        "scenario": task.get("scenario"),
        "attackType": task.get("attackType"),
        "expectedLabel": expected_label,
        "predictedLabel": predicted_label,
        "labelMatched": label_matched,
        "startedAt": started_at,
        "completedAt": completed_at,
        "returncode": completed.returncode,
        "ok": completed.returncode == 0 and bool((payload or {}).get("ok")),
        "runId": run_id,
        "payload": payload,
        "stdoutParseError": parse_error,
        "stderr": completed.stderr,
    }


def summarize_results(batch_id: str, report_path: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    completed = len(results)
    ok_runs = sum(1 for result in results if result.get("ok"))
    trace_ok = sum(1 for result in results if (result.get("payload") or {}).get("agentRunSuccess"))
    diagnosis_ok = sum(1 for result in results if ((result.get("payload") or {}).get("diagnosis") or {}).get("ok"))
    context_blocks = sum(
        1 for result in results if ((result.get("payload") or {}).get("securityContext") or {}).get("decision") == "block"
    )
    parsed = sum(1 for result in results if result.get("predictedLabel") in {0, 1})
    matched = sum(1 for result in results if result.get("labelMatched") is True)
    mismatches = [
        {
            "taskId": result.get("taskId"),
            "sourcePath": result.get("sourcePath"),
            "attackType": result.get("attackType"),
            "expectedLabel": result.get("expectedLabel"),
            "predictedLabel": result.get("predictedLabel"),
            "runId": result.get("runId"),
            "runDir": ((result.get("payload") or {}).get("resolvedRunDir")),
        }
        for result in results
        if result.get("labelMatched") is False
    ]
    return {
        "batchId": batch_id,
        "batchReport": str(report_path.resolve()).replace("\\", "/"),
        "completed": completed,
        "okRuns": ok_runs,
        "traceOk": trace_ok,
        "diagnosisOk": diagnosis_ok,
        "contextBlocks": context_blocks,
        "parsedLabels": parsed,
        "matchedLabels": matched,
        "accuracy": round(matched / parsed, 4) if parsed else None,
        "mismatches": mismatches,
    }


def write_progress(path: Path, *, batch_id: str, completed: int, total: int, results: list[dict[str, Any]]) -> None:
    write_json(
        path,
        {
            "batchId": batch_id,
            "completed": completed,
            "total": total,
            "okCount": sum(1 for result in results if result.get("ok")),
            "failCount": sum(1 for result in results if not result.get("ok")),
            "lastTaskId": results[-1].get("taskId") if results else None,
            "updatedAt": now_iso_precise(),
        },
    )


def run_runtime_setup(open_viewer: bool) -> dict[str, Any]:
    command = [sys.executable, "tools/runtime/start_trace.py"]
    if not open_viewer:
        command.append("--no-open")
    completed = run_command(command, timeout=240)
    payload = None
    try:
        parsed = json.loads(completed.stdout)
        payload = parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    return {
        "returncode": completed.returncode,
        "ok": completed.returncode == 0 and bool((payload or {}).get("ok")),
        "payload": payload,
        "stderr": completed.stderr,
    }


def run_batch(args: argparse.Namespace) -> dict[str, Any]:
    if args.start_runtime:
        runtime = run_runtime_setup(open_viewer=args.open_viewer)
        if not runtime.get("ok"):
            raise RuntimeError(f"runtime startup failed: {json.dumps(runtime, ensure_ascii=False, indent=2)}")
    else:
        runtime = {"skipped": True}

    all_tasks = list_rjudge_tasks(args.repo)
    filtered = filter_tasks(
        all_tasks,
        task_ids=args.task_id or [],
        source_paths=args.source_path or [],
        labels=args.label or [],
        attack_types=args.attack_type or [],
        scenario=args.scenario,
    )
    selected = select_tasks(filtered, count=args.count, shuffle=args.shuffle, seed=args.seed)
    batch_id = make_batch_id(args.repo, len(selected), args.batch_name)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"{batch_id}.json"
    progress_path = REPORTS_DIR / f"{batch_id}.progress.json"
    summary_path = REPORTS_DIR / f"{batch_id}.summary.json"

    sample = {
        "repo": args.repo,
        "batchId": batch_id,
        "generatedAt": now_utc_iso(),
        "totalAvailableTasks": len(all_tasks),
        "filteredTaskCount": len(filtered),
        "selectedTaskCount": len(selected),
        "filters": {
            "taskId": args.task_id or [],
            "sourcePath": args.source_path or [],
            "label": args.label or [],
            "attackType": args.attack_type or [],
            "scenario": args.scenario,
            "shuffle": args.shuffle,
            "seed": args.seed,
        },
        "tasks": selected,
        "runtime": runtime,
    }

    if args.dry_run:
        payload = {"sample": sample, "results": [], "dryRun": True}
        write_json(report_path, payload)
        write_json(summary_path, summarize_results(batch_id, report_path, []))
        return {"ok": True, "dryRun": True, "batchId": batch_id, "reportPath": str(report_path), "selectedTaskCount": len(selected)}

    results: list[dict[str, Any]] = []
    write_progress(progress_path, batch_id=batch_id, completed=0, total=len(selected), results=results)
    with ThreadPoolExecutor(max_workers=max(args.concurrency, 1)) as executor:
        future_to_task = {executor.submit(run_one_task, args, task): task for task in selected}
        for future in as_completed(future_to_task):
            result = future.result()
            results.append(result)
            write_json(report_path, {"sample": sample, "results": results})
            write_progress(progress_path, batch_id=batch_id, completed=len(results), total=len(selected), results=results)
            print(f"[{len(results)}/{len(selected)}] {result.get('taskId')} ok={result.get('ok')}", flush=True)

    summary = summarize_results(batch_id, report_path, results)
    write_json(report_path, {"sample": sample, "results": results})
    write_json(summary_path, summary)
    return {
        "ok": all(result.get("ok") for result in results),
        "batchId": batch_id,
        "reportPath": str(report_path.resolve()),
        "summaryPath": str(summary_path.resolve()),
        "progressPath": str(progress_path.resolve()),
        "summary": summary,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one or more R-Judge tasks through OpenClaw agent-trace.")
    parser.add_argument("--repo", default="rjudge")
    parser.add_argument("--task-id", action="append", help="Exact R-Judge task ID. Can be passed multiple times.")
    parser.add_argument("--source-path", action="append", help="Filter source path or directory, e.g. data/Program or data/Program/terminal.json.")
    parser.add_argument("--count", type=int, default=1, help="Number of filtered tasks to run. Omit with --all to run every match.")
    parser.add_argument("--all", action="store_true", help="Run all filtered tasks.")
    parser.add_argument("--label", type=int, choices=[0, 1], action="append", help="Filter expected R-Judge label. Can be repeated.")
    parser.add_argument("--attack-type", action="append", help="Filter attack type, e.g. injection or unintended.")
    parser.add_argument("--scenario", help="Case-insensitive substring filter for scenario.")
    parser.add_argument("--shuffle", action="store_true", help="Shuffle filtered tasks before applying --count.")
    parser.add_argument("--seed", type=int, default=0, help="Shuffle seed.")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=300, help="Per agent-trace polling timeout.")
    parser.add_argument("--command-timeout-seconds", type=int, default=2400, help="Subprocess timeout per task.")
    parser.add_argument("--skip-diagnosis", action="store_true")
    parser.add_argument("--skip-context-judge", action="store_true")
    parser.add_argument("--diagnosis-profile", default="detailed")
    parser.add_argument("--diagnosis-model")
    parser.add_argument("--diagnosis-timeout-seconds", type=int, default=1800)
    parser.add_argument("--diagnosis-cost-limit", type=float, default=3.0)
    parser.add_argument("--batch-name", help="Stable report name under monitor/live/reports without .json.")
    parser.add_argument("--dry-run", action="store_true", help="Write selected sample/report without running tasks.")
    parser.add_argument("--start-runtime", dest="start_runtime", action="store_true", default=True)
    parser.add_argument("--no-start-runtime", dest="start_runtime", action="store_false")
    parser.add_argument("--open-viewer", action="store_true", help="Open viewer when starting runtime.")
    args = parser.parse_args(argv)
    if args.all:
        args.count = None
    if args.count is not None and args.count < 0:
        parser.error("--count must be >= 0")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        result = run_batch(args)
    except Exception as error:
        print(json.dumps({"ok": False, "reason": "batch_failed", "error": str(error)}, ensure_ascii=False, indent=2))
        raise SystemExit(1) from error
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
