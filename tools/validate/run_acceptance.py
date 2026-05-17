from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import (
    TRACE_FIXTURE_DIR,
    TRACE_LIVE_DIR,
    TRACE_LIVE_RUNS_DIR,
    WORKSPACE_ROOT,
    build_run_dir_name,
    extract_run_id,
    python_executable,
    read_json,
    read_jsonl,
    run_command,
    run_openclaw_agent,
)


CASES = {
    "a": {
        "label": "A",
        "fixture": TRACE_FIXTURE_DIR / "smoke-prompt.txt",
        "description": "single request without tools",
    },
    "b": {
        "label": "B",
        "fixture": TRACE_FIXTURE_DIR / "single-tool-prompt.txt",
        "description": "single request with exactly one read tool",
    },
    "c": {
        "label": "C",
        "fixture": TRACE_FIXTURE_DIR / "failure-prompt.txt",
        "description": "controlled failure request",
    },
}


def resolve_run_dir(run_id: str | None, *, trace_ids: list[str] | None = None) -> Path | None:
    if run_id:
        candidate = TRACE_LIVE_RUNS_DIR / build_run_dir_name(run_id=run_id, trace_id=None)
        if candidate.exists():
            return candidate
    for directory in sorted(path for path in TRACE_LIVE_RUNS_DIR.iterdir() if path.is_dir()) if TRACE_LIVE_RUNS_DIR.exists() else []:
        manifest = read_json(directory / "manifest.json", default=None)
        if not isinstance(manifest, dict):
            continue
        if run_id and manifest.get("runId") == run_id:
            return directory
        if trace_ids and manifest.get("traceId") in trace_ids:
            return directory
    return None


def load_run_rows(run_dir: Path | None) -> list[dict[str, Any]]:
    if run_dir is None:
        return []
    rows = read_jsonl(run_dir / "behavior-events.jsonl")
    return [row for row in rows if isinstance(row, dict)]


def run_gateway_agent(fixture: Path, timeout_seconds: int, output_path: Path) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    payload = run_openclaw_agent(
        message=fixture.read_text(encoding="utf-8").strip(),
        timeout_seconds=timeout_seconds,
        no_wait=True,
    )
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return {
        "returncode": 0 if payload.get("ok") else 1,
        "stdout": payload.get("raw", {}).get("stdout", ""),
        "stderr": payload.get("raw", {}).get("stderr", ""),
        "payload": payload,
    }


def has_terminal_request(rows: list[dict[str, Any]]) -> bool:
    return any(row.get("kind") == "request" and row.get("status") in {"ok", "error"} for row in rows)


def wait_for_case_rows(run_id: str | None, timeout_seconds: int) -> tuple[list[dict[str, Any]], bool, int]:
    deadline = time.monotonic() + max(timeout_seconds, 1)
    attempts = 0
    latest_rows: list[dict[str, Any]] = []
    while time.monotonic() <= deadline:
        attempts += 1
        run_dir = resolve_run_dir(run_id)
        latest_rows = load_run_rows(run_dir)
        if latest_rows and has_terminal_request(latest_rows):
            return latest_rows, True, attempts
        time.sleep(2)
    return latest_rows, False, attempts


def summarize_delta(rows: list[dict[str, Any]]) -> dict[str, Any]:
    trace_ids = sorted({row.get("traceId") for row in rows if row.get("traceId")})
    run_ids = sorted({row.get("runId") for row in rows if row.get("runId")})
    kind_counts = Counter(str(row.get("kind")) for row in rows if row.get("kind"))
    status_counts = Counter(str(row.get("status")) for row in rows if row.get("status"))
    return {
        "eventCount": len(rows),
        "traceIds": trace_ids,
        "runIds": run_ids,
        "kindCounts": dict(kind_counts),
        "statusCounts": dict(status_counts),
    }


def evaluate_case(case_id: str, delta_summary: dict[str, Any]) -> dict[str, Any]:
    kind_counts = delta_summary["kindCounts"]
    status_counts = delta_summary["statusCounts"]
    has_request = kind_counts.get("request", 0) > 0
    has_turn = kind_counts.get("turn", 0) > 0
    has_tool = kind_counts.get("tool", 0) > 0
    has_error = status_counts.get("error", 0) > 0

    if case_id == "a":
        passed = has_request and has_turn and not has_tool
        expectation = "request/turn present and no tool events"
    elif case_id == "b":
        passed = has_request and has_turn and has_tool
        expectation = "request/turn/tool present"
    else:
        passed = has_request and has_turn and has_error
        expectation = "request/turn present and at least one error status"
    return {
        "passed": passed,
        "expectation": expectation,
    }


def run_doctor(viewer_port: int) -> dict[str, Any]:
    result = run_command(
        [
            python_executable(),
            str(WORKSPACE_ROOT / "tools" / "validate" / "doctor.py"),
            "--port",
            str(viewer_port),
        ],
        cwd=WORKSPACE_ROOT,
        timeout=180,
        check=False,
    )
    parsed = json.loads(result.stdout)
    return {
        "returncode": result.returncode,
        "report": parsed,
    }


def run_case(case_id: str, timeout_seconds: int, viewer_port: int, out_dir: Path) -> dict[str, Any]:
    case = CASES[case_id]
    fixture = case["fixture"]
    if not fixture.exists():
        raise FileNotFoundError(f"fixture missing: {fixture}")

    gateway_output = out_dir / f"{case_id}-gateway.json"
    gateway = run_gateway_agent(fixture, timeout_seconds, gateway_output)
    run_id = extract_run_id(gateway.get("payload"))
    delta_rows, terminal_seen, poll_attempts = wait_for_case_rows(run_id, timeout_seconds)
    delta_summary = summarize_delta(delta_rows)
    evaluation = evaluate_case(case_id, delta_summary)
    doctor = run_doctor(viewer_port)

    report = {
        "caseId": case_id,
        "label": case["label"],
        "description": case["description"],
        "fixture": str(fixture.resolve()),
        "runId": run_id,
        "gateway": gateway,
        "polling": {
            "terminalSeen": terminal_seen,
            "attempts": poll_attempts,
        },
        "delta": delta_summary,
        "evaluation": evaluation,
        "doctor": doctor,
    }
    (out_dir / f"{case_id}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Transpect acceptance checks.")
    parser.add_argument("--case", choices=["a", "b", "c", "all"], default="all")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--viewer-port", type=int, default=8711)
    parser.add_argument(
        "--out-dir",
        default=str(TRACE_LIVE_DIR / "acceptance"),
        help="Directory to store acceptance JSON reports.",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = ["a", "b", "c"] if args.case == "all" else [args.case]
    reports = [run_case(case_id, args.timeout_seconds, args.viewer_port, out_dir) for case_id in selected]

    summary = {
        "ok": all(report["evaluation"]["passed"] for report in reports),
        "cases": [
            {
                "caseId": report["caseId"],
                "passed": report["evaluation"]["passed"],
                "eventCount": report["delta"]["eventCount"],
                "traceIds": report["delta"]["traceIds"],
            }
            for report in reports
        ],
        "outputDir": str(out_dir),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
