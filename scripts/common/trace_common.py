from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from uuid import uuid4
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def resolve_workspace_root() -> Path:
    override = os.environ.get("TRANSPECT_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    current = Path(__file__).resolve()
    if current.parent.name == "common" and current.parent.parent.name == "scripts":
        return current.parents[2]
    return current.parents[1]


WORKSPACE_ROOT = resolve_workspace_root()
TRACE_ROOT = WORKSPACE_ROOT
TRACE_CONFIG_DIR = TRACE_ROOT / "config"
TRACE_CAPTURES_DIR = TRACE_ROOT / "captures"
TRACE_FIXTURE_DIR = TRACE_ROOT / "tests" / "fixtures"
TRACE_FRIDA_DIR = TRACE_ROOT / "frida"
TRACE_LIVE_DIR = TRACE_ROOT / "live"
TRACE_LIVE_LOGS_DIR = TRACE_LIVE_DIR / "logs"
TRACE_LIVE_ARCHIVE_DIR = TRACE_LIVE_DIR / "archive"
TRACE_LIVE_OTEL_DIR = TRACE_LIVE_DIR / "otel"
TRACE_LIVE_FRIDA_DIR = TRACE_LIVE_DIR / "frida"
TRACE_LIVE_HARVEST_DIR = TRACE_LIVE_DIR / "harvest"  # LEGACY – not part of canonical architecture
TRACE_LIVE_RUNS_DIR = TRACE_LIVE_DIR / "runs"
TRACE_LIVE_RUNS_INDEX_PATH = TRACE_LIVE_RUNS_DIR / "index.json"
TRACE_LIVE_PLUGIN_DIR = TRACE_LIVE_DIR / "openclaw"
TRACE_LIVE_PORTS_DIR = TRACE_LIVE_DIR / "ports"
TRACE_SCRIPTS_DIR = TRACE_ROOT / "scripts"
TRACE_VENDOR_DIR = TRACE_ROOT / "vendor"
TRACE_BIN_DIR = TRACE_ROOT / "bin"

OPENCLAW_HOME = Path.home() / ".openclaw"
OPENCLAW_CONFIG_PATH = OPENCLAW_HOME / "openclaw.json"
OPENCLAW_TASKS_DIR = OPENCLAW_HOME / "tasks"
OPENCLAW_TASKS_DB = OPENCLAW_TASKS_DIR / "runs.sqlite"
OPENCLAW_LOGS_DIR = OPENCLAW_HOME / "logs"
OPENCLAW_AGENTS_DIR = OPENCLAW_HOME / "agents"
OBSERVABILITY_PLUGIN_VENDOR_PATH = TRACE_VENDOR_DIR / "external" / "openclaw-observability-plugin"
BEHAVIOR_PLUGIN_VENDOR_PATH = TRACE_VENDOR_DIR / "runtime-hooks" / "openclaw-behavior-mediator"
PLUGIN_VENDOR_PATH = OBSERVABILITY_PLUGIN_VENDOR_PATH
OTEL_COLLECTOR_TEMPLATE_PATH = TRACE_CONFIG_DIR / "otel-collector.template.yaml"
OTEL_COLLECTOR_CONFIG_PATH = TRACE_CONFIG_DIR / "otel-collector.local.yaml"

DEFAULT_PATH_PREFIXES = [
    str(WORKSPACE_ROOT),
    str(OPENCLAW_HOME),
    str(Path(os.environ.get("LOCALAPPDATA", "")) / "Temp" / "openclaw"),
]
DEFAULT_PROCESS_TOKENS = ["openclaw", "node", "powershell", "cmd"]


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_utc_iso() -> str:
    return now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_trace_layout() -> None:
    for directory in [
        TRACE_ROOT,
        TRACE_CONFIG_DIR,
        TRACE_CAPTURES_DIR,
        TRACE_FIXTURE_DIR,
        TRACE_FRIDA_DIR,
        TRACE_LIVE_DIR,
        TRACE_LIVE_LOGS_DIR,
        TRACE_LIVE_ARCHIVE_DIR,
        TRACE_LIVE_OTEL_DIR,
        TRACE_LIVE_FRIDA_DIR,
        TRACE_LIVE_RUNS_DIR,
        TRACE_LIVE_PLUGIN_DIR,
        TRACE_LIVE_PORTS_DIR,
        TRACE_SCRIPTS_DIR,
        TRACE_VENDOR_DIR,
        TRACE_BIN_DIR,
    ]:
        ensure_dir(directory)


def read_json(path: Path, default: Any | None = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> Path:
    ensure_dir(path.parent)
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if not text.endswith("\n"):
        text += "\n"
    path.write_bytes(text.encode("utf-8"))
    return path


def write_text(path: Path, content: str) -> Path:
    ensure_dir(path.parent)
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    path.write_bytes(normalized.encode("utf-8"))
    return path


def append_jsonl(path: Path, payload: Any) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[Any]:
    if not path.exists():
        return []
    rows: list[Any] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line})
    return rows


def normalize_path(path: Path | str | None) -> str | None:
    if path is None:
        return None
    return str(path).replace("\\", "/")


def safe_slug(value: str | None, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip(".-")
    return text or fallback


def build_run_dir_name(*, run_id: str | None, trace_id: str | None, session_key: str | None = None) -> str:
    if isinstance(run_id, str) and run_id.strip():
        return safe_slug(run_id, "run")
    if isinstance(trace_id, str) and trace_id.strip():
        return safe_slug(trace_id, "trace")
    if isinstance(session_key, str) and session_key.strip():
        return safe_slug(session_key, "session")
    return safe_slug(f"run-{uuid4().hex[:12]}", "run")


def list_run_dirs(root: Path | None = None) -> list[Path]:
    base = (root or TRACE_LIVE_RUNS_DIR).resolve()
    if not base.exists():
        return []
    return sorted(path for path in base.iterdir() if path.is_dir())


TASK_REPO_KEYS = ["sourceRepo", "taskId", "sourcePath", "scenario", "attackType", "expectedLabel", "harnessMode"]


def normalize_task_repo_metadata(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    metadata = {key: payload.get(key) for key in TASK_REPO_KEYS if key in payload}
    return metadata if any(value is not None for value in metadata.values()) else None


def read_task_repo_metadata(run_dir: Path) -> dict[str, Any] | None:
    task_input = read_json(run_dir / "task_input.json", default=None)
    if isinstance(task_input, dict):
        metadata = normalize_task_repo_metadata(task_input.get("taskRepo"))
        if metadata:
            return metadata

    harness_report = read_json(run_dir / "artifacts" / "task_repo" / "harness_report.json", default=None)
    if isinstance(harness_report, dict):
        return normalize_task_repo_metadata(
            {
                "sourceRepo": harness_report.get("repoSlug") or harness_report.get("repo"),
                "taskId": harness_report.get("taskId"),
                "sourcePath": harness_report.get("sourcePath"),
                "scenario": harness_report.get("scenario"),
                "attackType": harness_report.get("attackType"),
                "expectedLabel": harness_report.get("expectedLabel"),
                "harnessMode": harness_report.get("mode"),
            }
        )
    return None


def read_security_context_metadata(run_dir: Path) -> dict[str, Any] | None:
    report = read_json(run_dir / "security-context" / "context_report.json", default=None)
    if not isinstance(report, dict):
        manifest = read_json(run_dir / "manifest.json", default=None)
        security_context = manifest.get("securityContext") if isinstance(manifest, dict) else None
        if not isinstance(security_context, dict):
            return None
        return {
            "ready": security_context.get("ready"),
            "decision": security_context.get("decision"),
            "riskLevel": security_context.get("riskLevel"),
            "score": security_context.get("score"),
            "lastRunAt": security_context.get("lastRunAt"),
            "reportPath": security_context.get("reportPath"),
            "timelinePath": security_context.get("timelinePath"),
        }
    return {
        "ready": True,
        "decision": report.get("decision"),
        "riskLevel": report.get("riskLevel"),
        "score": report.get("score"),
        "scenario": report.get("scenario"),
        "attackType": report.get("attackType"),
        "evidenceCount": (report.get("summary") or {}).get("evidenceCount") if isinstance(report.get("summary"), dict) else None,
        "summary": (report.get("summary") or {}).get("why") if isinstance(report.get("summary"), dict) else None,
        "reportPath": normalize_path((run_dir / "security-context" / "context_report.json").resolve()),
        "timelinePath": normalize_path((run_dir / "security-context" / "security_context_timeline.json").resolve()),
    }


def read_security_reasoning_metadata(run_dir: Path) -> dict[str, Any] | None:
    final_judgment = read_json(run_dir / "security-reasoning" / "final_judgment.json", default=None)
    decision = read_json(run_dir / "security-reasoning" / "defense_decision.json", default=None)
    if isinstance(final_judgment, dict):
        evidence = final_judgment.get("evidence") if isinstance(final_judgment.get("evidence"), dict) else {}
        return {
            "ready": True,
            "decision": final_judgment.get("finalDecision"),
            "riskLevel": final_judgment.get("riskLevel"),
            "score": decision.get("score") if isinstance(decision, dict) else None,
            "riskScore": decision.get("riskScore") if isinstance(decision, dict) else None,
            "scenario": decision.get("scenario") if isinstance(decision, dict) else None,
            "attackType": decision.get("attackType") if isinstance(decision, dict) else None,
            "crossStepCorrelation": decision.get("crossStepCorrelation") if isinstance(decision, dict) else None,
            "decisionPointEventSeq": decision.get("decisionPointEventSeq") if isinstance(decision, dict) else None,
            "bypassDetected": evidence.get("bypassDetected") if evidence.get("bypassDetected") is not None else (decision.get("bypassDetected") if isinstance(decision, dict) else None),
            "fridaIncluded": evidence.get("fridaIncluded"),
            "codeTracerIncluded": evidence.get("codeTracerIncluded"),
            "fridaCriticalEvidenceCount": evidence.get("fridaCriticalEvidenceCount"),
            "reasons": final_judgment.get("reasons"),
            "summary": " | ".join(final_judgment.get("reasons") or []),
            "decisionPath": normalize_path((run_dir / "security-reasoning" / "defense_decision.json").resolve()) if isinstance(decision, dict) else None,
            "statePath": normalize_path((run_dir / "security-reasoning" / "security_state.json").resolve()),
            "finalJudgmentPath": normalize_path((run_dir / "security-reasoning" / "final_judgment.json").resolve()),
        }
    if not isinstance(decision, dict):
        manifest = read_json(run_dir / "manifest.json", default=None)
        security_reasoning = manifest.get("securityReasoning") if isinstance(manifest, dict) else None
        if not isinstance(security_reasoning, dict):
            return None
        return {
            "ready": security_reasoning.get("ready"),
            "decision": security_reasoning.get("decision"),
            "riskLevel": security_reasoning.get("riskLevel"),
            "score": security_reasoning.get("score") if security_reasoning.get("score") is not None else security_reasoning.get("riskScore"),
            "riskScore": security_reasoning.get("riskScore") if security_reasoning.get("riskScore") is not None else security_reasoning.get("score"),
            "crossStepCorrelation": security_reasoning.get("crossStepCorrelation"),
            "decisionPointEventSeq": security_reasoning.get("decisionPointEventSeq"),
            "hardBlockTriggered": security_reasoning.get("hardBlockTriggered"),
            "lastStage": security_reasoning.get("lastStage"),
            "realInteraction": security_reasoning.get("realInteraction"),
            "lastRunAt": security_reasoning.get("lastRunAt"),
            "decisionPath": security_reasoning.get("decisionPath"),
            "statePath": security_reasoning.get("statePath"),
        }
    return {
        "ready": True,
        "decision": decision.get("decision"),
        "riskLevel": decision.get("riskLevel"),
        "score": decision.get("score") if decision.get("score") is not None else decision.get("riskScore"),
        "riskScore": decision.get("riskScore") if decision.get("riskScore") is not None else decision.get("score"),
        "scenario": decision.get("scenario"),
        "attackType": decision.get("attackType"),
        "crossStepCorrelation": decision.get("crossStepCorrelation"),
        "decisionPointEventSeq": decision.get("decisionPointEventSeq"),
        "hardBlockTriggered": decision.get("hardBlockTriggered"),
        "lastStage": decision.get("lastStage"),
        "realInteraction": decision.get("realInteraction"),
        "matchedRules": decision.get("matchedRules"),
        "reasons": decision.get("reasons"),
        "summary": " -> ".join(decision.get("matchedRules") or []),
        "decisionPath": normalize_path((run_dir / "security-reasoning" / "defense_decision.json").resolve()),
        "statePath": normalize_path((run_dir / "security-reasoning" / "security_state.json").resolve()),
    }


def batch_id_from_summary_path(path: Path) -> str:
    name = path.name
    suffix = ".summary.json"
    return name[: -len(suffix)] if name.endswith(suffix) else path.stem


def run_id_from_batch_result(result: dict[str, Any]) -> str | None:
    payload = result.get("payload")
    if isinstance(payload, dict):
        for key in ["agentRunId", "runId"]:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        run_dir = payload.get("resolvedRunDir")
        if isinstance(run_dir, str) and run_dir.strip():
            return Path(run_dir).name
    value = result.get("runId")
    return value.strip() if isinstance(value, str) and value.strip() else None


def batch_result_task_repo(result: dict[str, Any]) -> dict[str, Any] | None:
    payload = result.get("payload") if isinstance(result.get("payload"), dict) else {}
    return normalize_task_repo_metadata(
        {
            "sourceRepo": payload.get("repoSlug") or payload.get("repo"),
            "taskId": result.get("taskId") or payload.get("taskId"),
            "sourcePath": result.get("sourcePath") or payload.get("sourcePath"),
            "scenario": result.get("scenario") or payload.get("scenario"),
            "attackType": result.get("attackType") or payload.get("attackType"),
            "expectedLabel": result.get("expectedLabel") if result.get("expectedLabel") is not None else payload.get("expectedLabel"),
            "harnessMode": payload.get("mode"),
        }
    )


def scan_batch_report_links(reports_root: Path) -> dict[str, dict[str, Any]]:
    if not reports_root.exists():
        return {}

    summaries: dict[str, dict[str, Any]] = {}
    for summary_path in sorted(reports_root.glob("*.summary.json")):
        summary = read_json(summary_path, default=None)
        if isinstance(summary, dict):
            summaries[batch_id_from_summary_path(summary_path)] = summary

    links: dict[str, dict[str, Any]] = {}
    for report_path in sorted(reports_root.glob("*.json")):
        if report_path.name.endswith(".summary.json") or report_path.name.endswith(".progress.json"):
            continue
        report = read_json(report_path, default=None)
        if not isinstance(report, dict):
            continue
        results = report.get("results")
        if not isinstance(results, list):
            continue

        batch_id = report_path.stem
        summary = summaries.get(batch_id)
        mismatch_by_run: dict[str, dict[str, Any]] = {}
        if isinstance(summary, dict):
            for mismatch in summary.get("mismatches") or []:
                if not isinstance(mismatch, dict):
                    continue
                run_id = mismatch.get("runId")
                if not isinstance(run_id, str) or not run_id.strip():
                    run_dir = mismatch.get("runDir")
                    run_id = Path(run_dir).name if isinstance(run_dir, str) and run_dir.strip() else None
                if isinstance(run_id, str) and run_id.strip():
                    mismatch_by_run[run_id.strip()] = mismatch

        started_values = [
            result.get("startedAt")
            for result in results
            if isinstance(result, dict) and isinstance(result.get("startedAt"), str) and result.get("startedAt")
        ]
        batch_started_at = min(started_values) if started_values else None

        for result in results:
            if not isinstance(result, dict):
                continue
            run_id = run_id_from_batch_result(result)
            if not run_id:
                continue
            task_repo = batch_result_task_repo(result)
            expected_label = task_repo.get("expectedLabel") if task_repo else None
            mismatch = mismatch_by_run.get(run_id)
            predicted_label = None
            label_matched = None
            if mismatch:
                predicted_label = mismatch.get("predictedLabel")
                label_matched = False
            elif isinstance(summary, dict) and expected_label is not None:
                predicted_label = expected_label
                label_matched = True
            links[run_id] = {
                "batchId": batch_id,
                "batchName": batch_id,
                "batchStartedAt": batch_started_at,
                "batchReportPath": normalize_path(report_path.resolve()),
                "taskRepo": task_repo,
                "predictedLabel": predicted_label,
                "labelMatched": label_matched,
            }
    return links


def scan_run_summaries(root: Path | None = None) -> list[dict[str, Any]]:
    runs_root = (root or TRACE_LIVE_RUNS_DIR).resolve()
    batch_links = scan_batch_report_links(runs_root.parent / "reports")
    summaries: list[dict[str, Any]] = []
    for run_dir in list_run_dirs(runs_root):
        manifest_path = run_dir / "manifest.json"
        manifest = read_json(manifest_path, default=None)
        if not isinstance(manifest, dict):
            continue
        run_id = manifest.get("runId")
        batch_link = batch_links.get(str(run_id)) if run_id else None
        task_repo = read_task_repo_metadata(run_dir) or ((batch_link or {}).get("taskRepo"))
        security_context = read_security_context_metadata(run_dir)
        security_reasoning = read_security_reasoning_metadata(run_dir)
        summary = {
            "runId": run_id,
            "traceId": manifest.get("traceId"),
            "sessionKey": manifest.get("sessionKey"),
            "scenarioId": manifest.get("scenarioId"),
            "createdAt": manifest.get("createdAt"),
            "completedAt": manifest.get("completedAt"),
            "status": manifest.get("status"),
            "analysisReady": bool((((manifest.get("diagnosis") or {}).get("codetracer") or {}).get("analysisReady"))),
            "analysisOk": (((manifest.get("diagnosis") or {}).get("codetracer") or {}).get("analysisOk")),
            "eventCount": manifest.get("eventCount"),
            "artifactCount": manifest.get("artifactCount"),
            "dirName": run_dir.name,
            "runPath": normalize_path(run_dir.resolve()),
            "manifestPath": normalize_path(manifest_path.resolve()),
            "eventsPath": f"/live/runs/{run_dir.name}/behavior-events.jsonl",
            "taskRepo": task_repo,
            "batchId": (batch_link or {}).get("batchId"),
            "batchName": (batch_link or {}).get("batchName"),
            "batchStartedAt": (batch_link or {}).get("batchStartedAt"),
            "batchReportPath": (batch_link or {}).get("batchReportPath"),
            "predictedLabel": (batch_link or {}).get("predictedLabel"),
            "labelMatched": (batch_link or {}).get("labelMatched"),
            "securityContext": security_context,
            "securityReasoning": security_reasoning,
        }
        summaries.append(summary)
    summaries.sort(
        key=lambda item: (
            str(item.get("completedAt") or ""),
            str(item.get("createdAt") or ""),
            str(item.get("runId") or item.get("traceId") or item.get("dirName") or ""),
        ),
        reverse=True,
    )
    return summaries


def build_runs_index_payload(root: Path | None = None) -> dict[str, Any]:
    runs_root = (root or TRACE_LIVE_RUNS_DIR).resolve()
    runs = scan_run_summaries(runs_root)
    latest = runs[0] if runs else None
    return {
        "schemaVersion": "openclaw.runs.index.v1",
        "generatedAt": now_utc_iso(),
        "runsRoot": normalize_path(runs_root),
        "runCount": len(runs),
        "latestRun": latest,
        "runs": runs,
    }


def write_runs_index(root: Path | None = None) -> Path:
    runs_root = (root or TRACE_LIVE_RUNS_DIR).resolve()
    ensure_dir(runs_root)
    payload = build_runs_index_payload(runs_root)
    return write_json(runs_root / "index.json", payload)


def extract_json_from_text(text: str) -> Any:
    text = text.strip()
    if not text:
        raise ValueError("command produced no stdout")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    matches = re.findall(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    for candidate in reversed(matches):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ValueError(f"unable to parse JSON from stdout: {text[:200]}")


def run_command(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
    check: bool = False,
    env: dict[str, str] | None = None,
) -> CommandResult:
    merged_env = os.environ.copy()
    merged_env.setdefault("PYTHONUTF8", "1")
    merged_env.setdefault("PYTHONIOENCODING", "utf-8")
    if env:
        merged_env.update(env)
    completed = subprocess.run(
        args,
        cwd=str(cwd or WORKSPACE_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=merged_env,
    )
    result = CommandResult(
        args=args,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return result


def run_command_json(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 120,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> Any:
    result = run_command(args, cwd=cwd, timeout=timeout, check=check, env=env)
    return extract_json_from_text(result.stdout)


def parse_json_command_output(result: CommandResult) -> tuple[Any | None, str | None]:
    last_error: str | None = None
    for raw in [result.stdout, result.stderr]:
        if not raw.strip():
            continue
        try:
            return extract_json_from_text(raw), None
        except ValueError as error:
            last_error = str(error)
    return None, last_error


def openclaw_executable() -> str:
    resolved = shutil.which("openclaw")
    if resolved:
        return resolved
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidate = Path(appdata) / "npm" / "openclaw.cmd"
        if candidate.exists():
            return str(candidate)
    return "openclaw"


def node_executable() -> str:
    resolved = shutil.which("node")
    if resolved:
        return resolved
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    candidate = program_files / "nodejs" / "node.exe"
    if candidate.exists():
        return str(candidate)
    return "node"


def get_gateway_status(include_probe: bool = False, timeout_seconds: int = 180) -> dict[str, Any]:
    cmd = find_openclaw_cmd() or "openclaw"
    args = [cmd, "gateway", "status", "--json"]
    if not include_probe:
        args.append("--no-probe")
    return run_command_json(args, timeout=max(int(timeout_seconds) + 2, 5))


def get_gateway_pid(status: dict[str, Any] | None = None) -> int | None:
    status = status or get_gateway_status()
    listeners = status.get("port", {}).get("listeners") or []
    for listener in listeners:
        pid = listener.get("pid")
        command = str(listener.get("command") or "").lower()
        if pid and ("node" in command or not command):
            return int(pid)
    return None


def get_gateway_log_path(status: dict[str, Any] | None = None) -> Path | None:
    status = status or get_gateway_status()
    raw = status.get("logFile")
    return Path(raw) if raw else None


def get_trace_runtime_log_paths(name: str) -> dict[str, Path]:
    stem = re.sub(r"[^a-z0-9._-]+", "-", str(name or "").strip().lower()).strip("-") or "process"
    return {
        "stdout": TRACE_LIVE_LOGS_DIR / f"{stem}.out.log",
        "stderr": TRACE_LIVE_LOGS_DIR / f"{stem}.err.log",
    }


def make_trace_archive_dir(label: str = "runtime-cleanup") -> Path:
    stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
    stem = re.sub(r"[^a-z0-9._-]+", "-", str(label or "").strip().lower()).strip("-") or "archive"
    candidate = TRACE_LIVE_ARCHIVE_DIR / f"{stamp}-{stem}"
    counter = 1
    while candidate.exists():
        counter += 1
        candidate = TRACE_LIVE_ARCHIVE_DIR / f"{stamp}-{stem}-{counter}"
    ensure_dir(candidate)
    return candidate


def copy_file_if_exists(source: Path, target: Path) -> Path | None:
    if not source.exists():
        return None
    ensure_dir(target.parent)
    shutil.copy2(source, target)
    return target


def copy_sqlite_family(source: Path, target_dir: Path) -> list[Path]:
    ensure_dir(target_dir)
    copied: list[Path] = []
    for suffix in ["", "-wal", "-shm"]:
        candidate = Path(str(source) + suffix)
        if candidate.exists():
            destination = target_dir / candidate.name
            shutil.copy2(candidate, destination)
            copied.append(destination)
    return copied


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_files(root: Path, pattern: str) -> list[Path]:
    return sorted(root.rglob(pattern)) if root.exists() else []


def resolve_otelcol_binary() -> Path | None:
    candidates = list(TRACE_BIN_DIR.rglob("otelcol-contrib.exe"))
    return candidates[0] if candidates else None


def find_openclaw_cmd() -> str | None:
    try:
        from app.runtime.agent_scenarios.openclaw_resolver import OpenClawResolver
        res = OpenClawResolver().resolve()
        if res.selected_candidate:
            return res.selected_candidate.path
    except ImportError:
        pass
        
    resolved = shutil.which("openclaw")
    if resolved:
        return resolved
    try:
        cmd = ["where", "openclaw"] if sys.platform == "win32" else ["which", "openclaw"]
        result = run_command(cmd, timeout=30, check=False)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                return line
    except Exception:
        pass
    candidate = openclaw_executable()
    return candidate if candidate != "openclaw" else None


def get_openclaw_install_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "version": None,
        "installSource": None,
        "cliPath": find_openclaw_cmd(),
        "packagePath": None,
    }
    version_result = run_command([openclaw_executable(), "--version"], timeout=60, check=False)
    version_match = re.search(r"OpenClaw\s+([0-9][^\s(]+)", version_result.stdout + version_result.stderr)
    if version_match:
        info["version"] = version_match.group(1)

    cli_path = info["cliPath"]
    if cli_path:
        cli = Path(cli_path)
        npm_root = cli.parent / "node_modules" / "openclaw"
        if npm_root.exists():
            info["installSource"] = "npm-global"
            info["packagePath"] = str(npm_root)
            package_json = npm_root / "package.json"
            package = read_json(package_json, default={}) or {}
            info["version"] = package.get("version", info["version"])
    return info


def find_recent_gateway_log_lines(
    log_path: Path,
    start_time: datetime | None = None,
    max_lines: int = 5000,
) -> list[str]:
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def collect_session_files() -> list[Path]:
    if not OPENCLAW_AGENTS_DIR.exists():
        return []
    return sorted(OPENCLAW_AGENTS_DIR.rglob("sessions/*.jsonl"))


def normalize_session_key(raw: str | None) -> str | None:
    if raw is None:
        return None
    return str(raw)


def list_command_logger_candidates() -> list[Path]:
    candidates = []
    for name in ["commands.log", "command-logger.log"]:
        candidate = OPENCLAW_LOGS_DIR / name
        if candidate.exists():
            candidates.append(candidate)
    return candidates


def utc_from_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def python_executable() -> str:
    return sys.executable


def extract_run_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    candidates = [
        payload.get("runId"),
        (payload.get("result") or {}).get("runId") if isinstance(payload.get("result"), dict) else None,
        (payload.get("data") or {}).get("runId") if isinstance(payload.get("data"), dict) else None,
        (payload.get("started") or {}).get("runId") if isinstance(payload.get("started"), dict) else None,
        ((payload.get("started") or {}).get("result") or {}).get("runId")
        if isinstance((payload.get("started") or {}).get("result"), dict)
        else None,
    ]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def run_openclaw_gateway_call(
    method: str,
    *,
    params: dict[str, Any] | None = None,
    timeout_seconds: int = 90,
    url: str | None = None,
    token: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    timeout_ms = max(int(timeout_seconds * 1000), 1_000)
    # Keep the subprocess budget slightly above the gateway timeout without
    # turning short health probes into multi-minute hangs.
    timeout_budget_seconds = max(int(timeout_seconds) + 2, 5)
    args = [
        openclaw_executable(),
        "gateway",
        "call",
        method,
        "--json",
        "--timeout",
        str(timeout_ms),
        "--params",
        json.dumps(params or {}, ensure_ascii=False),
    ]
    if url:
        args.extend(["--url", url])
    if token:
        args.extend(["--token", token])
    if password:
        args.extend(["--password", password])

    try:
        result = run_command(args, cwd=WORKSPACE_ROOT, timeout=timeout_budget_seconds, check=False)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "timeout",
            "result": None,
            "error": {
                "message": f"openclaw gateway call timed out after {timeout_budget_seconds} seconds",
                "exitCode": None,
                "parseError": None,
            },
            "attempts": 1,
            "successfulAttempts": 0,
            "raw": {
                "command": args,
                "stdout": "",
                "stderr": "",
                "returncode": None,
                "parsed": None,
            },
        }
    parsed, parse_error = parse_json_command_output(result)
    ok_from_payload = isinstance(parsed, dict) and parsed.get("ok") is not False
    ok = result.returncode == 0 and isinstance(parsed, dict) and ok_from_payload

    return {
        "ok": ok,
        "status": "ok" if ok else "handler_error",
        "result": parsed if ok else None,
        "error": None
        if ok
        else {
            "message": result.stderr.strip()
            or result.stdout.strip()
            or (parse_error or f"openclaw gateway call failed with exit code {result.returncode}"),
            "exitCode": result.returncode,
            "parseError": parse_error,
        },
        "attempts": 1,
        "successfulAttempts": 1 if ok else 0,
        "raw": {
            "command": args,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "parsed": parsed,
        },
    }


def run_openclaw_agent(
    *,
    message: str,
    timeout_seconds: int = 180,
    agent_id: str = "main",
    session_id: str | None = None,
    thinking: str | None = None,
    target: str | None = None,
    no_wait: bool = False,
) -> dict[str, Any]:
    resolved_session_id = (session_id or str(uuid4())).strip()
    args = [
        openclaw_executable(),
        "agent",
        "--json",
        "--agent",
        agent_id,
        "--session-id",
        resolved_session_id,
        "--message",
        message,
        "--timeout",
        str(timeout_seconds),
    ]
    if thinking:
        args.extend(["--thinking", thinking])
    if target:
        args.extend(["--to", target])

    command_timed_out = False
    timeout_budget = max(timeout_seconds + 30, 60)
    try:
        result = run_command(args, cwd=WORKSPACE_ROOT, timeout=timeout_budget, check=False)
    except subprocess.TimeoutExpired as error:
        # OpenClaw may create and complete the canonical run before the CLI
        # process exits, especially when post-run diagnosis hooks keep working.
        # In no-wait harness mode, keep the real run as the source of truth and
        # let the caller poll live/runs/<sessionId>/.
        command_timed_out = True
        result = CommandResult(
            args=args,
            returncode=-1,
            stdout=(error.stdout or "") if isinstance(error.stdout, str) else "",
            stderr=(error.stderr or "") if isinstance(error.stderr, str) else "",
        )
    parsed, parse_error = parse_json_command_output(result)
    parsed_run_id = extract_run_id(parsed)
    inferred_run_id = resolved_session_id if (TRACE_LIVE_RUNS_DIR / resolved_session_id).exists() or no_wait else None
    run_id = parsed_run_id or inferred_run_id
    ok = (result.returncode == 0 and parsed is not None) or (no_wait and run_id is not None)

    payload: dict[str, Any] = {
        "command": "agent",
        "agentId": agent_id,
        "sessionId": resolved_session_id,
        "runId": run_id,
        "ok": ok,
        "started": {
            "result": {"runId": run_id},
            "raw": parsed,
        }
        if parsed is not None
        else None,
        "waited": None if no_wait else parsed,
        "raw": {
            "command": args,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "parseError": parse_error,
            "timedOut": command_timed_out,
            "timeoutBudgetSeconds": timeout_budget,
        },
    }
    if not ok:
        payload["error"] = result.stderr.strip() or result.stdout.strip() or parse_error or "openclaw agent failed"
    elif command_timed_out:
        payload["warning"] = "openclaw agent subprocess timed out after run launch; using sessionId as runId"
    return payload
