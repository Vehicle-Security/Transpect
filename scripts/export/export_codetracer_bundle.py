from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import (
    TRACE_LIVE_RUNS_DIR,
    ensure_dir,
    now_utc_iso,
    normalize_path,
    read_json,
    run_openclaw_gateway_call,
    safe_slug,
    write_runs_index,
    write_json,
    write_text,
)


EXPORTER_SCHEMA_VERSION = "openclaw.codetracer.bundle.v1"
SOURCE_TRACE_RELATIVE_PATH = "source/merged-trace.jsonl"
BEHAVIOR_TRACE_RELATIVE_PATH = "source/behavior-events.jsonl"
FRIDA_TRACE_RELATIVE_PATH = "source/frida-events.jsonl"
TRACE_INDEX_RELATIVE_PATH = "source/trace_index.json"
LINE_MAP_RELATIVE_PATH = "source/line-map.json"
OPENCLAW_RUNTIME_RELATIVE_PATH = "openclaw_runtime.json"
MANIFEST_RELATIVE_PATH = "manifest.json"
TASK_RELATIVE_PATH = "task.md"
STAGE_RANGES_RELATIVE_PATH = "stage_ranges.json"
STEPS_RELATIVE_PATH = "steps.json"
RUN_EVENTS_NAME = "behavior-events.jsonl"
RUN_MERGED_TRACE_NAME = "merged-trace.jsonl"
RUN_MANIFEST_NAME = "manifest.json"

POLICY_STATUSES = {"blocked", "would_block"}
EXECUTION_STATUSES = {"ok", "error"}
TOOL_LIFECYCLE_STATUSES = {"started", "ok", "error"}
STEP_KIND_VALUES = {"explore", "state_change", "verify", "synthetic"}
POLICY_FIELDS = [
    "status",
    "ruleId",
    "code",
    "severity",
    "category",
    "reason",
    "description",
    "decision",
    "outcome",
    "matches",
    "linkedToolCallId",
    "linkedObservationSpanId",
    "observedExecution",
    "linkedObservationStatus",
    "linkedObservationOutcome",
    "pathSecurity",
    "mode",
    "observation",
]
LONG_TEXT_LIMIT = 1200
MAX_COLLECTION_ITEMS = 40
MAX_DEPTH = 6

EXPLORE_TOOL_NAMES = {
    "read",
    "find",
    "search",
    "glob",
    "list",
    "ls",
    "dir",
    "stat",
    "inspect",
    "open",
    "fetch",
    "search_query",
    "image_query",
    "finance",
    "weather",
    "time",
    "sports",
    "view_image",
}
STATE_CHANGE_TOOL_NAMES = {
    "write",
    "edit",
    "apply_patch",
    "move",
    "rename",
    "delete",
    "remove",
    "create",
    "mkdir",
    "install",
}
VERIFY_TOOL_NAMES = {
    "test",
    "verify",
    "assert",
    "status",
    "diff",
}
EXEC_EXPLORE_PREFIXES = {
    "pwd",
    "cd",
    "ls",
    "dir",
    "tree",
    "rg",
    "grep",
    "find",
    "sed",
    "cat",
    "type",
    "get-content",
    "get-childitem",
    "select-string",
    "git",
}
EXEC_STATE_CHANGE_TOKENS = {
    "apply_patch",
    "move-item",
    "copy-item",
    "remove-item",
    "new-item",
    "mkdir",
    "touch",
    "git apply",
    "pip install",
    "npm install",
    "pnpm install",
    "yarn install",
    "uv pip install",
    "cargo build",
    "npm run build",
    "pnpm build",
    "yarn build",
}
EXEC_VERIFY_TOKENS = {
    "pytest",
    "npm test",
    "pnpm test",
    "yarn test",
    "python -m pytest",
    "go test",
    "cargo test",
    "ruff",
    "mypy",
    "eslint",
    "tsc",
    "git diff",
    "git status",
}
SETUP_CONTEXT_HINTS = {
    "readme",
    "task.md",
    "requirements",
    "package.json",
    "pyproject.toml",
    "workspace",
    "commands.txt",
    "pre-agent",
    "post-agent",
    "pwd",
    "get-location",
    "get-childitem",
}


@dataclass(frozen=True)
class TraceRow:
    line_number: int
    payload: dict[str, Any]

    @property
    def seq(self) -> int:
        value = self.payload.get("seq")
        return int(value) if isinstance(value, (int, float)) else 0

    @property
    def kind(self) -> str:
        return str(self.payload.get("kind") or "")

    @property
    def status(self) -> str:
        return str(self.payload.get("status") or "")

    @property
    def span_id(self) -> str:
        return str(self.payload.get("spanId") or "")

    @property
    def parent_span_id(self) -> str:
        return str(self.payload.get("parentSpanId") or "")

    @property
    def trace_id(self) -> str:
        return str(self.payload.get("traceId") or "")

    @property
    def run_id(self) -> str:
        return str(self.payload.get("runId") or "")

    @property
    def session_key(self) -> str:
        return str(self.payload.get("sessionKey") or "")

    @property
    def tool_call_id(self) -> str:
        return str(self.payload.get("toolCallId") or "")


@dataclass
class StepDraft:
    step_id: int
    step_kind: str
    step_kind_reason: str
    tool_type: str
    action: str
    observation: str
    action_payload: Any
    observation_payload: Any
    source_kind: str
    source_status: str
    trace_id: str | None
    span_id: str | None
    parent_span_id: str | None
    run_id: str | None
    session_key: str | None
    tool_call_id: str | None
    policy_observation: dict[str, Any] | None
    security_scenario: dict[str, Any] | None
    mode: str | None
    effective_mode: str | None
    path_security: dict[str, Any] | None
    expected_mode: str | None
    expected_outcome: str | None
    observed_outcome: str | None
    expectation_matched: bool | None
    synthetic_reason: str | None
    source_rows: list[TraceRow]
    runtime_input_artifact: Path | None
    runtime_output_artifact: Path | None
    runtime_input_wrapper: dict[str, Any] | None
    runtime_output_wrapper: dict[str, Any] | None
    bundle_action_path: str | None = None
    bundle_observation_path: str | None = None


def load_trace_rows(path: Path) -> list[TraceRow]:
    rows: list[TraceRow] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(TraceRow(line_number=line_number, payload=payload))
    rows.sort(key=lambda row: (row.seq, row.line_number))
    return rows


def latest_run_dir(root: Path) -> Path | None:
    manifests = []
    for candidate in sorted(path for path in root.iterdir() if path.is_dir()) if root.exists() else []:
        manifest_path = candidate / RUN_MANIFEST_NAME
        manifest = read_json(manifest_path, default=None)
        if not isinstance(manifest, dict):
            continue
        manifests.append(
            (
                str(manifest.get("completedAt") or ""),
                str(manifest.get("createdAt") or ""),
                candidate,
            )
        )
    if not manifests:
        return None
    manifests.sort(reverse=True)
    return manifests[0][2]


def resolve_input_run_path(path: Path | None) -> tuple[Path, Path]:
    if path is None:
        latest_dir = latest_run_dir(TRACE_LIVE_RUNS_DIR)
        if latest_dir is None:
            raise FileNotFoundError(f"no run directories found under {TRACE_LIVE_RUNS_DIR}")
        candidate = latest_dir / RUN_MERGED_TRACE_NAME
        if candidate.exists():
            return candidate, latest_dir
        candidate = latest_dir / RUN_EVENTS_NAME
        if candidate.exists():
            return candidate, latest_dir
        raise FileNotFoundError(f"run directory missing {RUN_EVENTS_NAME}: {latest_dir}")
    resolved = path.resolve()
    if resolved.is_dir():
        candidate = resolved / RUN_MERGED_TRACE_NAME
        if candidate.exists():
            return candidate, resolved
        candidate = resolved / RUN_EVENTS_NAME
        if not candidate.exists():
            raise FileNotFoundError(f"run directory missing {RUN_EVENTS_NAME}: {resolved}")
        return candidate, resolved
    return resolved, resolved.parent


def update_run_manifest_link(
    run_dir: Path,
    *,
    bundle_path: Path,
    bundle_id: str,
) -> None:
    manifest_path = run_dir / RUN_MANIFEST_NAME
    manifest = read_json(manifest_path, default=None)
    if not isinstance(manifest, dict):
        return
    paths = manifest.setdefault("paths", {})
    paths["codetracerBundle"] = "diagnosis/codetracer/bundle"
    diagnosis = manifest.setdefault("diagnosis", {}).setdefault("codetracer", {})
    diagnosis["bundleReady"] = True
    diagnosis.setdefault("analysisReady", False)
    diagnosis.setdefault("analysisOk", None)
    diagnosis["bundlePath"] = normalize_path(bundle_path.resolve())
    diagnosis["bundleManifestPath"] = normalize_path((bundle_path / MANIFEST_RELATIVE_PATH).resolve())
    manifest["bundleId"] = bundle_id
    write_json(manifest_path, manifest)
    write_runs_index(run_dir.parent)


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def compact_for_text(value: Any, *, depth: int = 0) -> Any:
    if depth >= MAX_DEPTH:
        if isinstance(value, dict):
            return f"<object keys={len(value)}>"
        if isinstance(value, list):
            return f"<array items={len(value)}>"
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) <= LONG_TEXT_LIMIT:
            return value
        return f"{value[:LONG_TEXT_LIMIT]}...[{len(value)} chars total]"
    if isinstance(value, list):
        output = [compact_for_text(item, depth=depth + 1) for item in value[:MAX_COLLECTION_ITEMS]]
        if len(value) > MAX_COLLECTION_ITEMS:
            output.append({"_truncated_items": len(value) - MAX_COLLECTION_ITEMS})
        return output
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_COLLECTION_ITEMS:
                output["_truncated_keys"] = len(value) - MAX_COLLECTION_ITEMS
                break
            output[str(key)] = compact_for_text(item, depth=depth + 1)
        return output
    return str(value)


def stringify_payload(label: str, payload: Any, *, status: str | None = None) -> str:
    compacted = compact_for_text(payload)
    lines = [label]
    if status:
        lines.append(f"Status: {status}")
    lines.append(json_dumps(compacted))
    return "\n".join(lines)

def safe_bundle_dir_name(bundle_id: str) -> str:
    return safe_slug(bundle_id, "bundle")


def normalize_policy_observation(payload: Any, *, status: str | None = None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    normalized: dict[str, Any] = {}
    effective_status = status or payload.get("status") or payload.get("outcome")
    if effective_status:
        normalized["status"] = effective_status
    for field in POLICY_FIELDS:
        if field == "status":
            continue
        value = payload.get(field)
        if value is not None:
            normalized[field] = value
    return normalized or None


def extract_policy_observation(*rows: TraceRow | None) -> dict[str, Any] | None:
    for row in rows:
        if row is None:
            continue
        payload = row.payload.get("evidence") if isinstance(row.payload.get("evidence"), dict) else {}
        policy = payload.get("policy") if isinstance(payload, dict) else None
        normalized = normalize_policy_observation(policy, status=row.status if row.status in POLICY_STATUSES else None)
        if normalized:
            return normalized
    return None


def extract_security_scenario(*rows: TraceRow | None) -> dict[str, Any] | None:
    for row in rows:
        if row is None:
            continue
        evidence = row.payload.get("evidence") if isinstance(row.payload.get("evidence"), dict) else {}
        security = evidence.get("securityScenario") if isinstance(evidence, dict) else None
        if isinstance(security, dict):
            return security
    return None


def extract_artifact_relative_path(row: TraceRow | None, key: str) -> str | None:
    if row is None:
        return None
    evidence = row.payload.get("evidence")
    if not isinstance(evidence, dict):
        return None
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    value = artifacts.get(key)
    return str(value).strip() if isinstance(value, str) and value.strip() else None


def resolve_runtime_artifact_path(row: TraceRow | None, input_file: Path, key: str) -> Path | None:
    if row is None:
        return None
    relative = extract_artifact_relative_path(row, key)
    if relative:
        candidate = (input_file.parent / relative).resolve()
        if candidate.exists():
            return candidate
    if row.kind == "tool":
        default_path = (
            input_file.parent
            / "artifacts"
            / (row.tool_call_id or row.span_id or "tool-unknown")
            / ("input.json" if key == "input" else "output.json")
        )
        if default_path.exists():
            return default_path
    return None


def load_runtime_artifact(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def pick_tool_name(start_row: TraceRow | None, fallback_row: TraceRow | None = None) -> str:
    for row in (start_row, fallback_row):
        if row is None:
            continue
        target = row.payload.get("target")
        if isinstance(target, dict) and isinstance(target.get("toolName"), str) and target.get("toolName"):
            return str(target["toolName"])
        name = row.payload.get("name")
        if isinstance(name, str) and name.startswith("tool."):
            return name.split(".", 1)[1]
    return "unknown"


def build_action_payload(start_row: TraceRow | None, runtime_wrapper: dict[str, Any] | None) -> Any:
    if isinstance(runtime_wrapper, dict) and "payload" in runtime_wrapper:
        return runtime_wrapper.get("payload")
    if start_row is None:
        return {}
    target = start_row.payload.get("target")
    preview = start_row.payload.get("preview")
    return {
        "target": target if isinstance(target, dict) else None,
        "preview": preview if isinstance(preview, dict) else None,
    }


def build_observation_payload(finish_row: TraceRow | None, runtime_wrapper: dict[str, Any] | None) -> Any:
    if isinstance(runtime_wrapper, dict) and "payload" in runtime_wrapper:
        return runtime_wrapper.get("payload")
    if finish_row is None:
        return {}
    preview = finish_row.payload.get("preview")
    metrics = finish_row.payload.get("metrics")
    evidence = finish_row.payload.get("evidence")
    return {
        "preview": preview if isinstance(preview, dict) else None,
        "metrics": metrics if isinstance(metrics, dict) else None,
        "evidence": evidence if isinstance(evidence, dict) else None,
    }


def classify_exec_command(command: str) -> tuple[str, str]:
    normalized = " ".join(str(command or "").strip().lower().split())
    if not normalized:
        return "explore", "empty exec command treated as exploration"
    if any(token in normalized for token in EXEC_VERIFY_TOKENS):
        return "verify", f"exec command matched verify token in '{normalized}'"
    if any(token in normalized for token in EXEC_STATE_CHANGE_TOKENS):
        return "state_change", f"exec command matched state-change token in '{normalized}'"
    first_token = normalized.split(" ", 1)[0]
    if first_token in EXEC_EXPLORE_PREFIXES:
        if normalized.startswith("git diff") or normalized.startswith("git status"):
            return "verify", f"exec command '{normalized}' treated as verification"
        return "explore", f"exec command '{normalized}' treated as exploration"
    return "explore", f"exec command '{normalized}' defaulted to exploration"


def classify_step_kind(tool_name: str, action_payload: Any, observation_payload: Any) -> tuple[str, str]:
    normalized_name = str(tool_name or "").strip().lower()
    if normalized_name in STATE_CHANGE_TOOL_NAMES:
        return "state_change", f"tool '{tool_name}' is in the state-change allowlist"
    if normalized_name in VERIFY_TOOL_NAMES:
        return "verify", f"tool '{tool_name}' is in the verify allowlist"
    if normalized_name in EXPLORE_TOOL_NAMES:
        return "explore", f"tool '{tool_name}' is in the explore allowlist"
    if normalized_name in {"exec", "bash", "shell_command"}:
        command = None
        if isinstance(action_payload, dict):
            command = (
                action_payload.get("command")
                or action_payload.get("cmd")
                or action_payload.get("script")
                or action_payload.get("commandLine")
            )
        return classify_exec_command(str(command or ""))
    if isinstance(observation_payload, dict):
        preview = observation_payload.get("preview")
        if isinstance(preview, dict):
            result_text = str(preview.get("result") or preview.get("response") or "")
            if any(token in result_text.lower() for token in ("test", "passed", "failed", "diff")):
                return "verify", f"observation preview hinted verification semantics for '{tool_name}'"
    return "explore", f"tool '{tool_name}' defaulted to exploration"


def looks_like_setup_context(step: StepDraft) -> bool:
    if step.step_kind == "synthetic":
        if step.synthetic_reason == "final_assistant_answer":
            return False
        return True
    if step.step_kind != "explore":
        return False
    action_text = step.action.lower()
    tool_name = str(step.tool_type or "").lower()
    if tool_name in {"read", "find", "search", "glob", "list", "ls", "dir"}:
        return any(hint in action_text for hint in SETUP_CONTEXT_HINTS)
    return any(hint in action_text for hint in SETUP_CONTEXT_HINTS)


def build_stage_ranges(steps: list[StepDraft]) -> list[dict[str, Any]]:
    if not steps:
        return []
    first_state_change = next((index for index, step in enumerate(steps) if step.step_kind == "state_change"), None)
    last_state_change = next((index for index in range(len(steps) - 1, -1, -1) if steps[index].step_kind == "state_change"), None)

    setup_end = 0
    while setup_end < len(steps):
        if not looks_like_setup_context(steps[setup_end]):
            break
        if first_state_change is not None and setup_end >= first_state_change:
            break
        setup_end += 1

    ranges: list[dict[str, Any]] = []

    def append_range(stage: str, start_index: int, end_index: int) -> None:
        if start_index > end_index:
            return
        ranges.append(
            {
                "stage": stage,
                "start_step_id": steps[start_index].step_id,
                "end_step_id": steps[end_index].step_id,
            }
        )

    if setup_end > 0:
        append_range("setup_context", 0, setup_end - 1)

    if first_state_change is not None and last_state_change is not None:
        if setup_end <= first_state_change - 1:
            append_range("exploration", setup_end, first_state_change - 1)
        append_range("state_change", first_state_change, last_state_change)
        if last_state_change + 1 <= len(steps) - 1:
            append_range("verification_completion", last_state_change + 1, len(steps) - 1)
        return ranges

    trailing_verify_start = len(steps)
    while trailing_verify_start > setup_end and (
        steps[trailing_verify_start - 1].step_kind == "verify"
        or steps[trailing_verify_start - 1].synthetic_reason == "final_assistant_answer"
    ):
        trailing_verify_start -= 1

    if setup_end <= trailing_verify_start - 1:
        append_range("exploration", setup_end, trailing_verify_start - 1)
    if trailing_verify_start < len(steps):
        append_range("verification_completion", trailing_verify_start, len(steps) - 1)
    return ranges


def sort_rows(rows: Iterable[TraceRow]) -> list[TraceRow]:
    return sorted(rows, key=lambda row: (row.seq, row.line_number))


def group_bundle_ids(rows: list[TraceRow]) -> list[str]:
    primary_run_ids = [
        row.run_id
        for row in rows
        if row.run_id and row.kind in {"request", "turn"}
    ]
    if primary_run_ids:
        return sorted(dict.fromkeys(primary_run_ids))
    any_run_ids = [row.run_id for row in rows if row.run_id]
    if any_run_ids:
        return sorted(dict.fromkeys(any_run_ids))
    trace_ids = [row.trace_id for row in rows if row.trace_id]
    return sorted(dict.fromkeys(trace_ids))


def select_rows_for_bundle(rows: list[TraceRow], *, run_id: str | None = None, trace_id: str | None = None) -> list[TraceRow]:
    if run_id:
        direct_rows = [row for row in rows if row.run_id == run_id]
        if not direct_rows:
            return []
        trace_ids = {row.trace_id for row in direct_rows if row.trace_id}
        return [
            row
            for row in rows
            if row.run_id == run_id or (row.trace_id in trace_ids if trace_ids else False)
        ]
    if trace_id:
        return [row for row in rows if row.trace_id == trace_id]
    return []


def pick_primary_trace_id(rows: list[TraceRow]) -> str | None:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        if row.trace_id:
            counts[row.trace_id] += 1
    if not counts:
        return None
    return max(counts, key=counts.get)


def pick_primary_run_id(rows: list[TraceRow]) -> str | None:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        if row.run_id:
            counts[row.run_id] += 1
    if not counts:
        return None
    return max(counts, key=counts.get)


def extract_task_description(rows: list[TraceRow], bundle_id: str) -> str:
    preview_keys = ["message", "prompt", "user", "task"]
    for kind in ("request", "turn"):
        for status in ("started", "ok", "error"):
            for row in rows:
                if row.kind != kind or row.status != status:
                    continue
                preview = row.payload.get("preview")
                if not isinstance(preview, dict):
                    continue
                for key in preview_keys:
                    value = preview.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip().replace("\r", "")
    return f"OpenClaw trace export for {bundle_id}"


def normalize_security_fields(security_scenario: dict[str, Any] | None) -> tuple[str | None, str | None, str | None, bool | None]:
    if not isinstance(security_scenario, dict):
        return None, None, None, None
    return (
        security_scenario.get("expectedMode"),
        security_scenario.get("expectedOutcome"),
        security_scenario.get("observedOutcome"),
        security_scenario.get("expectationMatched"),
    )


def build_span_children(rows: list[TraceRow]) -> dict[str, set[str]]:
    children: dict[str, set[str]] = defaultdict(set)
    seen_pairs: set[tuple[str, str]] = set()
    for row in rows:
        if row.parent_span_id and row.span_id and (row.parent_span_id, row.span_id) not in seen_pairs:
            children[row.parent_span_id].add(row.span_id)
            seen_pairs.add((row.parent_span_id, row.span_id))
    return children


def descendant_contains_tool(span_id: str, tool_span_ids: set[str], children: dict[str, set[str]]) -> bool:
    stack = [span_id]
    visited: set[str] = set()
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        for child in children.get(current, set()):
            if child in tool_span_ids:
                return True
            stack.append(child)
    return False


def terminal_preview_payload(row: TraceRow) -> dict[str, Any] | None:
    preview = row.payload.get("preview")
    if not isinstance(preview, dict):
        return None
    meaningful = {}
    for key in ("assistant", "result", "error", "response", "message", "prompt", "user"):
        value = preview.get(key)
        if isinstance(value, str) and value.strip():
            meaningful[key] = value.strip()
    return meaningful or None


def build_synthetic_turn_steps(
    rows: list[TraceRow],
    *,
    existing_count: int,
    runtime_snapshot: dict[str, Any],
    primary_run_id: str | None,
    primary_trace_id: str | None,
) -> list[StepDraft]:
    started_by_span: dict[str, TraceRow] = {}
    executed_tool_span_ids: set[str] = set()
    for row in rows:
        if row.kind == "tool" and row.status == "started":
            executed_tool_span_ids.add(row.span_id)
        if row.status == "started" and row.span_id:
            started_by_span[row.span_id] = row
    children = build_span_children(rows)

    synthetic_steps: list[StepDraft] = []
    seen_terminal_spans: set[str] = set()

    for kind in ("turn", "request"):
        for row in rows:
            if row.kind != kind or row.status not in EXECUTION_STATUSES:
                continue
            if row.span_id in seen_terminal_spans:
                continue
            if descendant_contains_tool(row.span_id, executed_tool_span_ids, children):
                continue
            preview_payload = terminal_preview_payload(row)
            security = extract_security_scenario(row, started_by_span.get(row.span_id))
            expected_mode, expected_outcome, observed_outcome, expectation_matched = normalize_security_fields(security)
            meaningful = bool(preview_payload)
            if expectation_matched is False or observed_outcome:
                meaningful = True
            if not meaningful:
                continue
            source_start = started_by_span.get(row.span_id)
            action_payload = {
                "prompt": terminal_preview_payload(source_start) if source_start else None,
                "name": row.payload.get("name"),
            }
            observation_payload = {
                "status": row.status,
                "preview": preview_payload,
            }
            step_id = existing_count + len(synthetic_steps) + 1
            synthetic_steps.append(
                StepDraft(
                    step_id=step_id,
                    step_kind="synthetic",
                    step_kind_reason=f"tool-less {kind} retained for diagnostic state",
                    tool_type="synthetic",
                    action=stringify_payload(f"Synthetic {kind} diagnostic", action_payload, status="synthetic"),
                    observation=stringify_payload(f"{kind.capitalize()} completion", observation_payload, status=row.status),
                    action_payload=action_payload,
                    observation_payload=observation_payload,
                    source_kind=kind,
                    source_status=row.status,
                    trace_id=row.trace_id or primary_trace_id,
                    span_id=row.span_id or None,
                    parent_span_id=row.parent_span_id or None,
                    run_id=row.run_id or primary_run_id,
                    session_key=row.session_key or None,
                    tool_call_id=None,
                    policy_observation=None,
                    security_scenario=security,
                    mode=runtime_snapshot.get("mode"),
                    effective_mode=runtime_snapshot.get("effectiveMode"),
                    path_security=runtime_snapshot.get("pathSecurity"),
                    expected_mode=expected_mode,
                    expected_outcome=expected_outcome,
                    observed_outcome=observed_outcome,
                    expectation_matched=expectation_matched,
                    synthetic_reason=f"toolless_{kind}_diagnostic",
                    source_rows=[source_start] if source_start else [],
                    runtime_input_artifact=None,
                    runtime_output_artifact=None,
                    runtime_input_wrapper=None,
                    runtime_output_wrapper=None,
                )
            )
            synthetic_steps[-1].source_rows.append(row)
            seen_terminal_spans.add(row.span_id)
        if synthetic_steps:
            break

    return synthetic_steps


def build_final_answer_step(
    rows: list[TraceRow],
    *,
    existing_count: int,
    runtime_snapshot: dict[str, Any],
    primary_run_id: str | None,
    primary_trace_id: str | None,
    existing_span_ids: set[str],
) -> StepDraft | None:
    """Create a synthetic step for the final assistant answer.

    This captures the assistant's response from the last ``turn.ok`` or
    ``request.ok`` event that carries a ``preview.assistant`` value,
    regardless of whether the turn had tool calls.  Returns *None* if
    the answer's span is already represented in existing steps.
    """
    started_by_span: dict[str, TraceRow] = {}
    for row in rows:
        if row.status == "started" and row.span_id:
            started_by_span[row.span_id] = row

    for row in reversed(sort_rows(rows)):
        if row.kind not in ("turn", "request"):
            continue
        if row.status != "ok":
            continue
        if row.span_id in existing_span_ids:
            continue
        preview = row.payload.get("preview")
        if not isinstance(preview, dict):
            continue
        assistant_text = preview.get("assistant")
        if not isinstance(assistant_text, str) or not assistant_text.strip():
            continue

        source_start = started_by_span.get(row.span_id)
        action_payload = {
            "prompt": terminal_preview_payload(source_start) if source_start else None,
            "name": row.payload.get("name"),
        }
        observation_payload = {
            "status": row.status,
            "preview": {"assistant": assistant_text.strip()},
        }
        step_id = existing_count + 1
        return StepDraft(
            step_id=step_id,
            step_kind="synthetic",
            step_kind_reason="final assistant answer captured for diagnosis visibility",
            tool_type="synthetic",
            action=stringify_payload("Final assistant answer", action_payload, status="synthetic"),
            observation=stringify_payload("Assistant answer", observation_payload, status=row.status),
            action_payload=action_payload,
            observation_payload=observation_payload,
            source_kind=row.kind,
            source_status=row.status,
            trace_id=row.trace_id or primary_trace_id,
            span_id=row.span_id or None,
            parent_span_id=row.parent_span_id or None,
            run_id=row.run_id or primary_run_id,
            session_key=row.session_key or None,
            tool_call_id=None,
            policy_observation=None,
            security_scenario=None,
            mode=runtime_snapshot.get("mode"),
            effective_mode=runtime_snapshot.get("effectiveMode"),
            path_security=runtime_snapshot.get("pathSecurity"),
            expected_mode=None,
            expected_outcome=None,
            observed_outcome=None,
            expectation_matched=None,
            synthetic_reason="final_assistant_answer",
            source_rows=[source_start, row] if source_start else [row],
            runtime_input_artifact=None,
            runtime_output_artifact=None,
            runtime_input_wrapper=None,
            runtime_output_wrapper=None,
        )
    return None


def build_zero_step_policy_fallback(
    rows: list[TraceRow],
    *,
    runtime_snapshot: dict[str, Any],
    primary_run_id: str | None,
    primary_trace_id: str | None,
) -> StepDraft | None:
    policy_rows = [row for row in rows if row.kind == "tool" and row.status in POLICY_STATUSES]
    if not policy_rows:
        return None
    chosen = sort_rows(policy_rows)[0]
    tool_name = pick_tool_name(None, chosen)
    policy_observation = extract_policy_observation(chosen)
    security = extract_security_scenario(chosen)
    expected_mode, expected_outcome, observed_outcome, expectation_matched = normalize_security_fields(security)
    preview = chosen.payload.get("preview") if isinstance(chosen.payload.get("preview"), dict) else {}
    action_payload = {
        "toolName": tool_name,
        "paramsPreview": preview.get("params"),
        "target": chosen.payload.get("target") if isinstance(chosen.payload.get("target"), dict) else None,
    }
    observation_payload = {
        "status": chosen.status,
        "reason": preview.get("reason"),
        "matchValue": preview.get("matchValue"),
        "policy": policy_observation,
    }
    return StepDraft(
        step_id=1,
        step_kind="synthetic",
        step_kind_reason="policy row preserved because the run had no executable tool spans",
        tool_type=tool_name,
        action=stringify_payload(f"Synthetic tool policy diagnostic: {tool_name}", action_payload, status="synthetic"),
        observation=stringify_payload("Policy observation", observation_payload, status=chosen.status),
        action_payload=action_payload,
        observation_payload=observation_payload,
        source_kind="tool_policy",
        source_status=chosen.status,
        trace_id=chosen.trace_id or primary_trace_id,
        span_id=chosen.span_id or None,
        parent_span_id=chosen.parent_span_id or None,
        run_id=chosen.run_id or primary_run_id,
        session_key=chosen.session_key or None,
        tool_call_id=chosen.tool_call_id or None,
        policy_observation=policy_observation,
        security_scenario=security,
        mode=runtime_snapshot.get("mode"),
        effective_mode=runtime_snapshot.get("effectiveMode"),
        path_security=policy_observation.get("pathSecurity") if policy_observation else runtime_snapshot.get("pathSecurity"),
        expected_mode=expected_mode,
        expected_outcome=expected_outcome,
        observed_outcome=observed_outcome,
        expectation_matched=expectation_matched,
        synthetic_reason="no_executable_tool_steps_policy_row",
        source_rows=[chosen],
        runtime_input_artifact=None,
        runtime_output_artifact=None,
        runtime_input_wrapper=None,
        runtime_output_wrapper=None,
    )


def build_runtime_snapshot(
    behavior_status_call: dict[str, Any] | None,
    rule_guard_status_call: dict[str, Any] | None,
) -> dict[str, Any]:
    rule_result = (rule_guard_status_call or {}).get("result") if isinstance(rule_guard_status_call, dict) else None
    snapshot = {
        "mode": rule_result.get("mode") if isinstance(rule_result, dict) else None,
        "effectiveMode": rule_result.get("effectiveMode") if isinstance(rule_result, dict) else None,
        "policyLoadHealthy": rule_result.get("policyLoadHealthy") if isinstance(rule_result, dict) else None,
        "effectiveEnabled": rule_result.get("effectiveEnabled") if isinstance(rule_result, dict) else None,
        "effectiveEnforcement": rule_result.get("effectiveEnforcement") if isinstance(rule_result, dict) else None,
        "degradedReason": rule_result.get("degradedReason") if isinstance(rule_result, dict) else None,
        "ruleCounters": rule_result.get("ruleCounters") if isinstance(rule_result, dict) else None,
        "pathSecurity": rule_result.get("pathSecurity") if isinstance(rule_result, dict) else None,
    }
    return {
        "schemaVersion": EXPORTER_SCHEMA_VERSION,
        "exportedAt": now_utc_iso(),
        "behaviorMediatorStatus": behavior_status_call,
        "ruleGuardStatus": rule_guard_status_call,
        "snapshot": snapshot,
    }


def write_source_trace_copy(bundle_dir: Path, rows: list[TraceRow]) -> dict[int, int]:
    source_path = bundle_dir / SOURCE_TRACE_RELATIVE_PATH
    ensure_dir(source_path.parent)
    line_map: list[dict[str, int]] = []
    with source_path.open("w", encoding="utf-8") as handle:
        for copy_line_number, row in enumerate(rows, start=1):
            handle.write(json.dumps(row.payload, ensure_ascii=False) + "\n")
            line_map.append({"copyLine": copy_line_number, "originalLine": row.line_number, "seq": row.seq})
    write_json(bundle_dir / LINE_MAP_RELATIVE_PATH, line_map)
    return {entry["originalLine"]: entry["copyLine"] for entry in line_map}


def copy_run_trace_sources(bundle_dir: Path, run_dir: Path) -> dict[str, dict[str, Any]]:
    ensure_dir(bundle_dir / "source")
    mapping = {
        "behavior": (run_dir / "behavior-events.jsonl", BEHAVIOR_TRACE_RELATIVE_PATH),
        "frida": (run_dir / "frida-events.jsonl", FRIDA_TRACE_RELATIVE_PATH),
        "merged": (run_dir / "merged-trace.jsonl", SOURCE_TRACE_RELATIVE_PATH),
        "traceIndex": (run_dir / "trace_index.json", TRACE_INDEX_RELATIVE_PATH),
    }
    sources: dict[str, dict[str, Any]] = {}
    for name, (source, relative) in mapping.items():
        target = bundle_dir / relative
        if source.exists():
            if source.resolve() != target.resolve():
                ensure_dir(target.parent)
                shutil.copy2(source, target)
            event_count = None
            if source.suffix == ".jsonl":
                event_count = sum(1 for line in target.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
            sources[name] = {
                "path": relative,
                "status": "ok",
                "eventCount": event_count,
            }
        else:
            sources[name] = {
                "path": relative,
                "status": "missing",
                "eventCount": 0 if source.suffix == ".jsonl" else None,
            }
    return sources


def build_file_ref(path: str, content: Any) -> dict[str, Any]:
    if isinstance(content, str):
        text = content
    else:
        text = json_dumps(content)
    line_count = max(text.count("\n") + 1, 1)
    return {
        "path": path,
        "line_start": 1,
        "line_end": line_count,
        "content": text,
    }


def write_step_sidecars(bundle_dir: Path, step: StepDraft, source_line_map: dict[int, int]) -> None:
    step_dir = bundle_dir / "sidecars" / f"step-{step.step_id:04d}"
    ensure_dir(step_dir)
    action_sidecar = {
        "schemaVersion": EXPORTER_SCHEMA_VERSION,
        "kind": "action",
        "stepId": step.step_id,
        "stepKind": step.step_kind,
        "toolType": step.tool_type,
        "payload": step.action_payload,
        "runtimeArtifact": normalize_path(step.runtime_input_artifact) if step.runtime_input_artifact else None,
        "sourceRows": [
            {
                "originalLine": row.line_number,
                "copiedLine": source_line_map.get(row.line_number),
                "seq": row.seq,
                "kind": row.kind,
                "status": row.status,
            }
            for row in step.source_rows
        ],
    }
    observation_sidecar = {
        "schemaVersion": EXPORTER_SCHEMA_VERSION,
        "kind": "observation",
        "stepId": step.step_id,
        "stepKind": step.step_kind,
        "toolType": step.tool_type,
        "payload": step.observation_payload,
        "runtimeArtifact": normalize_path(step.runtime_output_artifact) if step.runtime_output_artifact else None,
        "sourceRows": action_sidecar["sourceRows"],
    }
    action_path = step_dir / "action.json"
    observation_path = step_dir / "observation.json"
    write_json(action_path, action_sidecar)
    write_json(observation_path, observation_sidecar)
    step.bundle_action_path = normalize_path(action_path.relative_to(bundle_dir))
    step.bundle_observation_path = normalize_path(observation_path.relative_to(bundle_dir))


def find_policy_row(
    start_row: TraceRow,
    finish_row: TraceRow,
    policy_rows_by_span: dict[str, TraceRow],
    policy_rows_by_tool_call: dict[str, list[TraceRow]],
) -> TraceRow | None:
    if start_row.parent_span_id and start_row.parent_span_id in policy_rows_by_span:
        return policy_rows_by_span[start_row.parent_span_id]
    tool_call_id = start_row.tool_call_id or finish_row.tool_call_id
    if tool_call_id:
        rows = policy_rows_by_tool_call.get(tool_call_id, [])
        preceding = [row for row in rows if row.seq <= start_row.seq]
        if preceding:
            return preceding[-1]
        if rows:
            return rows[0]
    return None


def draft_execution_steps(
    rows: list[TraceRow],
    *,
    input_file: Path,
    runtime_snapshot: dict[str, Any],
    primary_run_id: str | None,
    primary_trace_id: str | None,
) -> list[StepDraft]:
    started_by_span = {
        row.span_id: row
        for row in rows
        if row.kind == "tool" and row.status == "started" and row.span_id
    }
    terminal_by_span = {
        row.span_id: row
        for row in rows
        if row.kind == "tool" and row.status in EXECUTION_STATUSES and row.span_id
    }
    policy_rows_by_span = {
        row.span_id: row
        for row in rows
        if row.kind == "tool" and row.status in POLICY_STATUSES and row.span_id
    }
    policy_rows_by_tool_call: dict[str, list[TraceRow]] = defaultdict(list)
    for row in rows:
        if row.kind == "tool" and row.status in POLICY_STATUSES and row.tool_call_id:
            policy_rows_by_tool_call[row.tool_call_id].append(row)
    for tool_call_id in list(policy_rows_by_tool_call):
        policy_rows_by_tool_call[tool_call_id] = sort_rows(policy_rows_by_tool_call[tool_call_id])

    ordered_starts = sort_rows(started_by_span.values())
    steps: list[StepDraft] = []
    for step_index, start_row in enumerate(ordered_starts, start=1):
        finish_row = terminal_by_span.get(start_row.span_id)
        if finish_row is None:
            continue
        policy_row = find_policy_row(start_row, finish_row, policy_rows_by_span, policy_rows_by_tool_call)
        tool_name = pick_tool_name(start_row, finish_row)

        runtime_input_artifact = resolve_runtime_artifact_path(start_row, input_file, "input")
        runtime_output_artifact = resolve_runtime_artifact_path(finish_row, input_file, "output")
        runtime_input_wrapper = load_runtime_artifact(runtime_input_artifact)
        runtime_output_wrapper = load_runtime_artifact(runtime_output_artifact)

        action_payload = build_action_payload(start_row, runtime_input_wrapper)
        observation_payload = build_observation_payload(finish_row, runtime_output_wrapper)
        step_kind, step_kind_reason = classify_step_kind(tool_name, action_payload, observation_payload)
        policy_observation = extract_policy_observation(policy_row, finish_row, start_row)
        security_scenario = extract_security_scenario(finish_row, start_row, policy_row)
        expected_mode, expected_outcome, observed_outcome, expectation_matched = normalize_security_fields(security_scenario)
        path_security = (
            policy_observation.get("pathSecurity")
            if isinstance(policy_observation, dict) and policy_observation.get("pathSecurity") is not None
            else runtime_snapshot.get("pathSecurity")
        )
        mode = (
            policy_observation.get("mode")
            if isinstance(policy_observation, dict) and policy_observation.get("mode") is not None
            else runtime_snapshot.get("mode")
        )

        action = stringify_payload(f"Tool: {tool_name}", action_payload, status="started")
        observation = stringify_payload("Tool result", observation_payload, status=finish_row.status)
        source_rows = [row for row in [policy_row, start_row, finish_row] if row is not None]

        steps.append(
            StepDraft(
                step_id=step_index,
                step_kind=step_kind,
                step_kind_reason=step_kind_reason,
                tool_type=tool_name,
                action=action,
                observation=observation,
                action_payload=action_payload,
                observation_payload=observation_payload,
                source_kind="tool",
                source_status=finish_row.status,
                trace_id=start_row.trace_id or primary_trace_id,
                span_id=start_row.span_id or None,
                parent_span_id=start_row.parent_span_id or None,
                run_id=start_row.run_id or primary_run_id,
                session_key=start_row.session_key or None,
                tool_call_id=start_row.tool_call_id or finish_row.tool_call_id or None,
                policy_observation=policy_observation,
                security_scenario=security_scenario,
                mode=mode,
                effective_mode=runtime_snapshot.get("effectiveMode"),
                path_security=path_security,
                expected_mode=expected_mode,
                expected_outcome=expected_outcome,
                observed_outcome=observed_outcome,
                expectation_matched=expectation_matched,
                synthetic_reason=None,
                source_rows=source_rows,
                runtime_input_artifact=runtime_input_artifact,
                runtime_output_artifact=runtime_output_artifact,
                runtime_input_wrapper=runtime_input_wrapper,
                runtime_output_wrapper=runtime_output_wrapper,
            )
        )
    return steps


def bundle_step_to_dict(step: StepDraft, bundle_dir: Path, source_line_map: dict[int, int]) -> dict[str, Any]:
    openclaw_meta = {
        "traceId": step.trace_id,
        "spanId": step.span_id,
        "parentSpanId": step.parent_span_id,
        "runId": step.run_id,
        "sessionKey": step.session_key,
        "toolCallId": step.tool_call_id,
        "step_kind_reason": step.step_kind_reason,
        "source_kind": step.source_kind,
        "source_status": step.source_status,
        "policyMatched": step.policy_observation is not None,
        "policyObservation": step.policy_observation,
        "securityScenario": step.security_scenario,
        "mode": step.mode,
        "effectiveMode": step.effective_mode,
        "pathSecurity": step.path_security,
        "expectedMode": step.expected_mode,
        "expectedOutcome": step.expected_outcome,
        "observedOutcome": step.observed_outcome,
        "expectationMatched": step.expectation_matched,
        "syntheticReason": step.synthetic_reason,
        "sourceRows": [
            {
                "originalLine": row.line_number,
                "copiedLine": source_line_map.get(row.line_number),
                "seq": row.seq,
                "kind": row.kind,
                "status": row.status,
                "path": SOURCE_TRACE_RELATIVE_PATH,
            }
            for row in step.source_rows
        ],
    }
    return {
        "step_id": step.step_id,
        "action": step.action,
        "observation": step.observation,
        "tool_type": step.tool_type,
        "step_kind": step.step_kind,
        "openclaw_meta": openclaw_meta,
        "action_ref": build_file_ref(step.bundle_action_path or "", json.loads((bundle_dir / (step.bundle_action_path or "")).read_text(encoding="utf-8")) if step.bundle_action_path else step.action_payload),
        "observation_ref": build_file_ref(step.bundle_observation_path or "", json.loads((bundle_dir / (step.bundle_observation_path or "")).read_text(encoding="utf-8")) if step.bundle_observation_path else step.observation_payload),
    }


def export_single_bundle(
    *,
    bundle_id: str,
    rows: list[TraceRow],
    input_file: Path,
    run_dir: Path,
    output_root: Path,
    behavior_status_call: dict[str, Any] | None,
    rule_guard_status_call: dict[str, Any] | None,
) -> dict[str, Any]:
    bundle_dir_name = safe_bundle_dir_name(bundle_id)
    bundle_dir = output_root
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    ensure_dir(bundle_dir)

    primary_run_id = pick_primary_run_id(rows)
    primary_trace_id = pick_primary_trace_id(rows)
    runtime_record = build_runtime_snapshot(behavior_status_call, rule_guard_status_call)
    existing_runtime = read_json(run_dir / "runtime_status.json", default=None)
    if isinstance(existing_runtime, dict):
        runtime_record = existing_runtime
    if isinstance(runtime_record, dict) and isinstance(runtime_record.get("snapshot"), dict):
        runtime_snapshot = runtime_record["snapshot"]
    elif isinstance(((runtime_record.get("ruleGuard") or {}).get("result")) if isinstance(runtime_record, dict) else None, dict):
        rule_result = (runtime_record.get("ruleGuard") or {}).get("result")
        runtime_snapshot = {
            "mode": rule_result.get("mode"),
            "effectiveMode": rule_result.get("effectiveMode"),
            "policyLoadHealthy": rule_result.get("policyLoadHealthy"),
            "effectiveEnabled": rule_result.get("effectiveEnabled"),
            "effectiveEnforcement": rule_result.get("effectiveEnforcement"),
            "degradedReason": rule_result.get("degradedReason"),
            "ruleCounters": rule_result.get("ruleCounters"),
            "pathSecurity": rule_result.get("pathSecurity"),
        }
    else:
        runtime_snapshot = {}

    source_line_map = write_source_trace_copy(bundle_dir, rows)
    trace_sources = copy_run_trace_sources(bundle_dir, run_dir)
    write_json(bundle_dir / OPENCLAW_RUNTIME_RELATIVE_PATH, runtime_record)
    task_description = extract_task_description(rows, bundle_id)
    write_text(bundle_dir / TASK_RELATIVE_PATH, task_description)

    steps = draft_execution_steps(
        rows,
        input_file=input_file,
        runtime_snapshot=runtime_snapshot,
        primary_run_id=primary_run_id,
        primary_trace_id=primary_trace_id,
    )

    if steps:
        synthetic_turn_steps = build_synthetic_turn_steps(
            rows,
            existing_count=len(steps),
            runtime_snapshot=runtime_snapshot,
            primary_run_id=primary_run_id,
            primary_trace_id=primary_trace_id,
        )
        steps.extend(synthetic_turn_steps)

    if not steps:
        policy_fallback = build_zero_step_policy_fallback(
            rows,
            runtime_snapshot=runtime_snapshot,
            primary_run_id=primary_run_id,
            primary_trace_id=primary_trace_id,
        )
        if policy_fallback:
            steps = [policy_fallback]
        else:
            steps = build_synthetic_turn_steps(
                rows,
                existing_count=0,
                runtime_snapshot=runtime_snapshot,
                primary_run_id=primary_run_id,
                primary_trace_id=primary_trace_id,
            )

    # Fix 3: append final assistant answer as a diagnosis-visible step
    existing_span_ids = {step.span_id for step in steps if step.span_id}
    final_answer_step = build_final_answer_step(
        rows,
        existing_count=len(steps),
        runtime_snapshot=runtime_snapshot,
        primary_run_id=primary_run_id,
        primary_trace_id=primary_trace_id,
        existing_span_ids=existing_span_ids,
    )
    if final_answer_step:
        steps.append(final_answer_step)

    for index, step in enumerate(steps, start=1):
        step.step_id = index
        write_step_sidecars(bundle_dir, step, source_line_map)

    stage_ranges = build_stage_ranges(steps)
    write_json(bundle_dir / STAGE_RANGES_RELATIVE_PATH, stage_ranges)

    steps_json = [bundle_step_to_dict(step, bundle_dir, source_line_map) for step in steps]
    write_json(bundle_dir / STEPS_RELATIVE_PATH, steps_json)

    manifest = {
        "schemaVersion": EXPORTER_SCHEMA_VERSION,
        "exportedAt": now_utc_iso(),
        "bundleId": bundle_id,
        "bundleDirName": bundle_dir_name,
        "bundlePath": normalize_path(bundle_dir),
        "sourceTracePath": normalize_path(input_file),
        "inputTraceSources": trace_sources,
        "sourceKind": "run",
        "sourceRunPath": normalize_path(run_dir.resolve()),
        "sourceRunManifestPath": normalize_path((run_dir / RUN_MANIFEST_NAME).resolve()),
        "primaryRunId": primary_run_id,
        "primaryTraceId": primary_trace_id,
        "rowCount": len(rows),
        "stepCount": len(steps),
        "syntheticStepCount": sum(1 for step in steps if step.step_kind == "synthetic"),
        "policyMatchedStepCount": sum(1 for step in steps if step.policy_observation is not None),
        "files": {
            "steps": STEPS_RELATIVE_PATH,
            "task": TASK_RELATIVE_PATH,
            "stageRanges": STAGE_RANGES_RELATIVE_PATH,
            "runtime": OPENCLAW_RUNTIME_RELATIVE_PATH,
            "sourceTrace": SOURCE_TRACE_RELATIVE_PATH,
            "behaviorTrace": BEHAVIOR_TRACE_RELATIVE_PATH,
            "fridaTrace": FRIDA_TRACE_RELATIVE_PATH,
            "mergedTrace": SOURCE_TRACE_RELATIVE_PATH,
            "traceIndex": TRACE_INDEX_RELATIVE_PATH,
            "lineMap": LINE_MAP_RELATIVE_PATH,
        },
        "traceSources": trace_sources,
        "stages": stage_ranges,
    }
    write_json(bundle_dir / MANIFEST_RELATIVE_PATH, manifest)
    update_run_manifest_link(run_dir, bundle_path=bundle_dir, bundle_id=bundle_id)
    return {
        "bundleId": bundle_id,
        "bundleDirName": bundle_dir_name,
        "bundlePath": str(bundle_dir.resolve()),
        "sourceKind": manifest["sourceKind"],
        "sourceRunPath": manifest["sourceRunPath"],
        "stepCount": len(steps),
        "rowCount": len(rows),
        "stageCount": len(stage_ranges),
        "syntheticStepCount": manifest["syntheticStepCount"],
    }


def call_runtime_statuses(timeout_seconds: int) -> tuple[dict[str, Any], dict[str, Any]]:
    behavior = run_openclaw_gateway_call("behavior-mediator.status", timeout_seconds=timeout_seconds)
    rule_guard = run_openclaw_gateway_call("rule-guard.status", timeout_seconds=timeout_seconds)
    return behavior, rule_guard


def export_bundles(
    *,
    input_file: Path | None = None,
    run_dir: Path | None = None,
    output_root: Path | None = None,
    run_id: str | None = None,
    trace_id: str | None = None,
    include_runtime_status: bool = True,
    timeout_seconds: int = 8,
) -> dict[str, Any]:
    resolved_input_file, resolved_run_dir = resolve_input_run_path(run_dir or input_file)
    rows = load_trace_rows(resolved_input_file)
    effective_output_root = (output_root or (resolved_run_dir / "diagnosis" / "codetracer" / "bundle")).resolve()
    ensure_dir(effective_output_root)

    behavior_status_call: dict[str, Any] | None = None
    rule_guard_status_call: dict[str, Any] | None = None
    if include_runtime_status:
        behavior_status_call, rule_guard_status_call = call_runtime_statuses(timeout_seconds)

    bundle_ids: list[str]
    if run_id:
        bundle_ids = [run_id]
    elif trace_id:
        bundle_ids = [trace_id]
    else:
        bundle_ids = group_bundle_ids(rows)

    exported: list[dict[str, Any]] = []
    known_run_ids = {row.run_id for row in rows if row.run_id}
    for bundle_id in bundle_ids:
        selected_rows = select_rows_for_bundle(
            rows,
            run_id=run_id or (bundle_id if bundle_id in known_run_ids else None),
            trace_id=trace_id or (bundle_id if bundle_id not in known_run_ids else None),
        )
        if not selected_rows:
            continue
        exported.append(
            export_single_bundle(
                bundle_id=bundle_id,
                rows=selected_rows,
                input_file=resolved_input_file,
                run_dir=resolved_run_dir,
                output_root=effective_output_root,
                behavior_status_call=behavior_status_call,
                rule_guard_status_call=rule_guard_status_call,
            )
        )

    return {
        "ok": True,
        "generatedAt": now_utc_iso(),
        "inputFile": str(resolved_input_file.resolve()),
        "inputKind": "run",
        "runDir": str(resolved_run_dir.resolve()),
        "outputRoot": str(effective_output_root.resolve()),
        "bundleCount": len(exported),
        "bundles": exported,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export one Transpect run directory into a CodeTracer-compatible bundle.")
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Path to a run directory that contains behavior-events.jsonl. Defaults to the most recent run.",
    )
    parser.add_argument(
        "--output-root",
        default=None,
        help="Optional explicit bundle output directory. Defaults to <run-dir>/diagnosis/codetracer/bundle.",
    )
    parser.add_argument("--run-id", help="Export one bundle for a specific runId.")
    parser.add_argument("--trace-id", help="Export one bundle for a specific traceId.")
    parser.add_argument(
        "--skip-runtime-status",
        action="store_true",
        help="Skip behavior-mediator.status and rule-guard.status capture.",
    )
    parser.add_argument(
        "--gateway-timeout",
        type=int,
        default=8,
        help="Timeout in seconds for gateway status snapshots.",
    )
    args = parser.parse_args()

    payload = export_bundles(
        run_dir=Path(args.run_dir).resolve() if args.run_dir else None,
        output_root=Path(args.output_root).resolve() if args.output_root else None,
        run_id=args.run_id,
        trace_id=args.trace_id,
        include_runtime_status=not args.skip_runtime_status,
        timeout_seconds=args.gateway_timeout,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
