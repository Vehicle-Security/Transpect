from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "common"))
sys.path.insert(0, str(ROOT / "scripts" / "diagnosis"))
sys.path.insert(0, str(ROOT / "scripts" / "security_reasoning"))
sys.path.insert(0, str(ROOT / "scripts" / "export"))
sys.path.insert(0, str(ROOT))

from app.agent_defense.final_judge import run_final_judgment  # noqa: E402
from app.agent_defense.trace_merge import merge_run_traces  # noqa: E402
from app.trace_model.build_canonical_trace import build_canonical_trace  # noqa: E402
from scripts.export.export_openinference_trace import export_openinference_trace  # noqa: E402
from scripts.validate.evaluate_trace_quality import evaluate_trace_quality  # noqa: E402
from mark_showcase_run import mark_showcase_run  # noqa: E402
from run_codetracer_diagnosis import run_codetracer_diagnosis  # noqa: E402
from run_defense_reasoner import run_defense_reasoner  # noqa: E402
from trace_common import (  # noqa: E402
    TRACE_LIVE_LOGS_DIR,
    TRACE_LIVE_RUNS_DIR,
    build_runs_index_payload,
    get_gateway_status,
    normalize_path,
    python_executable,
    read_json,
    run_openclaw_gateway_call,
    run_command,
    write_runs_index,
)


DEFAULT_TASK_ID = "data/xiaohongshu_waterhole_photo_upload.json#xhs-waterhole-photo-upload-001"
VIEWER_URL_TEMPLATE = "http://{host}:{port}/viewer/index.html?view=traces&run={run_id}"


@dataclass
class ShowcaseStep:
    label: str
    status: str
    detail: str = ""


def _probe(url: str, *, timeout_seconds: int = 2) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            return 200 <= int(response.status) < 500
    except (OSError, urllib.error.URLError):
        return False


def _start_background(name: str, args: list[str]) -> None:
    TRACE_LIVE_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = TRACE_LIVE_LOGS_DIR / f"showcase-{name}.out.log"
    err_path = TRACE_LIVE_LOGS_DIR / f"showcase-{name}.err.log"
    with out_path.open("ab") as stdout, err_path.open("ab") as stderr:
        subprocess.Popen(
            args,
            cwd=str(ROOT),
            stdout=stdout,
            stderr=stderr,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )


def ensure_demo_site(*, host: str = "127.0.0.1", port: int = 8765, auto_start: bool = True) -> dict[str, Any]:
    url = f"http://{host}:{port}/xhs/topic/camping"
    if _probe(f"http://{host}:{port}/health"):
        return {"status": "ok", "detail": url}
    if not auto_start:
        return {"status": "failed", "detail": f"not running: {url}"}
    _start_background(
        "staged-attack-site",
        [python_executable(), str(ROOT / "scripts" / "demo" / "run_staged_attack_site.py"), "--host", host, "--port", str(port)],
    )
    for _ in range(20):
        if _probe(f"http://{host}:{port}/health"):
            return {"status": "ok", "detail": url}
        time.sleep(0.25)
    return {"status": "failed", "detail": f"could not start: {url}"}


def ensure_viewer(*, host: str = "127.0.0.1", port: int = 8711, auto_start: bool = True) -> dict[str, Any]:
    base = f"http://{host}:{port}"
    if _probe(f"{base}/health"):
        return {"status": "ok", "detail": base}
    if not auto_start:
        return {"status": "not_running", "detail": base}
    _start_background(
        "viewer",
        [python_executable(), str(ROOT / "scripts" / "runtime" / "serve_viewer.py"), "--host", host, "--port", str(port)],
    )
    for _ in range(20):
        if _probe(f"{base}/health"):
            return {"status": "ok", "detail": base}
        time.sleep(0.25)
    return {"status": "not_running", "detail": base}


def find_showcase_run() -> Path | None:
    payload = build_runs_index_payload(TRACE_LIVE_RUNS_DIR)
    runs = payload.get("runs") if isinstance(payload, dict) else []
    if not isinstance(runs, list):
        return None
    for run in runs:
        if isinstance(run, dict) and run.get("showcase") and run.get("runPath"):
            return Path(str(run["runPath"])).resolve()
    latest = payload.get("latestRun") if isinstance(payload, dict) else None
    if isinstance(latest, dict) and latest.get("runPath"):
        return Path(str(latest["runPath"])).resolve()
    return None


def check_runtime_guard(*, timeout_seconds: int = 4) -> dict[str, Any]:
    gateway_ok = False
    behavior_active = False
    details: list[str] = []
    try:
        get_gateway_status(include_probe=False, timeout_seconds=timeout_seconds)
        gateway_ok = True
        details.append("gateway ok")
    except Exception as error:  # noqa: BLE001
        details.append(f"gateway unknown: {error}")

    try:
        payload = run_openclaw_gateway_call("behavior-mediator.status", timeout_seconds=timeout_seconds)
        result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        behavior_active = bool(payload.get("ok") and (result.get("active") is not False))
        details.append("behavior mediator active" if behavior_active else f"behavior mediator {payload.get('status') or 'unknown'}")
    except Exception as error:  # noqa: BLE001
        details.append(f"behavior mediator unknown: {error}")

    return {
        "status": "ok" if gateway_ok and behavior_active else "degraded",
        "detail": ", ".join(details),
    }


def _parse_json_output(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else {}
    except json.JSONDecodeError:
        return {}


def check_frida_smoke(*, timeout_seconds: int = 75, verbose: bool = False) -> dict[str, Any]:
    report_path = ROOT / "live" / "frida" / "smoke" / "frida-smoke-report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if report_path.exists():
        report_path.unlink()
    command = [
        python_executable(),
        str(ROOT / "scripts" / "validate" / "frida_smoke.py"),
        "--report",
        str(report_path),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None if verbose else subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception as error:  # noqa: BLE001
        return {
            "ok": False,
            "status": "failed",
            "detail": f"frida smoke command failed: {error}",
        }
    payload = read_json(report_path, default={})
    if not payload:
        return {
            "ok": False,
            "status": "failed",
            "detail": f"frida smoke did not write JSON report (exit={result.returncode})",
        }
    return payload


def _final_frida_summary(final_judgment: dict[str, Any]) -> dict[str, Any]:
    evidence = final_judgment.get("evidence") if isinstance(final_judgment, dict) else {}
    frida = evidence.get("frida") if isinstance(evidence, dict) else {}
    return frida if isinstance(frida, dict) else {}


def require_real_frida_evidence(run_dir: Path, final_judgment: dict[str, Any]) -> None:
    frida = _final_frida_summary(final_judgment)
    status = str(frida.get("status") or "").lower()
    try:
        event_count = int(frida.get("eventCount") or 0)
    except (TypeError, ValueError):
        event_count = 0
    frida_path = run_dir / "frida-events.jsonl"
    if status != "ok" or event_count <= 0 or not frida_path.exists() or frida_path.stat().st_size <= 0:
        raise RuntimeError(
            "Frida evidence is required but not available: "
            f"status={status or 'unknown'}, eventCount={event_count}, path={frida_path}"
        )


def run_agent_trace(*, task_id: str = DEFAULT_TASK_ID, timeout_seconds: int, verbose: bool) -> Path:
    command = [
        python_executable(),
        str(ROOT / "scripts" / "runtime" / "run_task_repo.py"),
        "--repo",
        "staged_attack",
        "--mode",
        "agent-trace",
        "--task-id",
        task_id,
        "--timeout",
        str(timeout_seconds),
        "--frida",
        "auto",
        "--skip-diagnosis",
        "--diagnosis-timeout-seconds",
        "180",
    ]
    TRACE_LIVE_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = str(int(time.time()))
    stdout_path = TRACE_LIVE_LOGS_DIR / f"showcase-agent-trace-{stamp}.out.json"
    stderr_path = TRACE_LIVE_LOGS_DIR / f"showcase-agent-trace-{stamp}.err.log"
    try:
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            result = subprocess.run(
                command,
                cwd=str(ROOT),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout_seconds + 120,
                check=False,
            )
    except Exception as error:  # noqa: BLE001
        raise RuntimeError(f"agent trace command failed: {error}; stdout={stdout_path}; stderr={stderr_path}") from error
    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    payload = _parse_json_output(stdout_text)
    if verbose and stderr_text.strip():
        print(stderr_text.strip())
    run_dir = payload.get("resolvedRunDir")
    if isinstance(run_dir, str) and run_dir.strip():
        return Path(run_dir).resolve()
    run_id = payload.get("agentRunId")
    if isinstance(run_id, str) and run_id.strip():
        candidate = TRACE_LIVE_RUNS_DIR / run_id
        if candidate.exists():
            return candidate.resolve()
    detail = payload.get("reason") or stderr_text.strip() or f"agent trace did not produce a run directory; stdout={stdout_path}; stderr={stderr_path}"
    if result.returncode != 0:
        detail = f"agent trace failed ({result.returncode}): {detail}"
    raise RuntimeError(str(detail))


def _existing_codetracer_diagnosis(run_dir: Path) -> dict[str, Any] | None:
    report_path = run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json"
    report = read_json(report_path, default=None)
    if not isinstance(report, dict):
        return None
    run = report.get("run") if isinstance(report.get("run"), dict) else {}
    ok = bool(report.get("ok") or run.get("ok"))
    analysis_exists = bool(run.get("analysisExists") or (run_dir / "diagnosis" / "codetracer" / "analysis" / "codetracer_analysis.json").exists())
    if not ok or not analysis_exists:
        return None
    paths = report.get("paths") if isinstance(report.get("paths"), dict) else {}
    return {
        "ok": True,
        "status": "success",
        "reason": "existing_diagnosis_reused",
        "diagnosisReportPath": normalize_path(report_path.resolve()),
        "analysisPath": paths.get("analysis") or normalize_path((run_dir / "diagnosis" / "codetracer" / "analysis" / "codetracer_analysis.json").resolve()),
        "bundleDir": paths.get("bundleDir") or normalize_path((run_dir / "diagnosis" / "codetracer" / "bundle").resolve()),
    }


def complete_artifacts(run_dir: Path, *, verbose: bool) -> dict[str, Any]:
    trace_index = read_json(run_dir / "trace_index.json", default={})
    frida_status = ((trace_index or {}).get("sources") or {}).get("frida") if isinstance(trace_index, dict) else {}
    merge_result = merge_run_traces(run_dir, frida_status=frida_status if isinstance(frida_status, dict) else None)
    defense_result = run_defense_reasoner(run_dir)
    diagnosis_result = _existing_codetracer_diagnosis(run_dir)
    if diagnosis_result is None:
        try:
            diagnosis_result = run_codetracer_diagnosis(run_dir=run_dir, timeout_seconds=180)
        except Exception as error:  # noqa: BLE001
            diagnosis_result = {"ok": False, "status": "failed", "reason": str(error)}
            if verbose:
                print(f"CodeTracer failed: {error}")
    final_judgment = run_final_judgment(run_dir)
    canonical_trace = build_canonical_trace(run_dir)
    trace_quality = evaluate_trace_quality(run_dir, write=True)
    openinference_export = export_openinference_trace(run_dir)
    mark_showcase_run(run_dir, reason="Generated by scripts/demo/run_showcase.py")
    write_runs_index(run_dir.parent)
    return {
        "merge": merge_result,
        "defense": defense_result,
        "diagnosis": diagnosis_result,
        "finalJudgment": final_judgment,
        "canonicalTrace": {
            "path": canonical_trace.get("path"),
            "spanCount": len(canonical_trace.get("spans") or []),
            "eventCount": len(canonical_trace.get("events") or []),
        },
        "traceQuality": {
            "path": normalize_path((run_dir / "trace_quality.json").resolve()),
            "traceDepth": trace_quality.get("traceDepth"),
            "score": trace_quality.get("score"),
        },
        "openInference": openinference_export,
    }


def _status_word(status: str) -> str:
    normalized = str(status or "unknown").lower()
    if normalized in {"ok", "success", "active"}:
        return "OK"
    if normalized in {"degraded", "not_running", "unavailable", "attach_failed", "disabled", "empty"}:
        return "DEGRADED"
    if normalized in {"failed", "error", "broken"}:
        return "FAILED"
    return normalized.upper()


def _frida_detail(final_judgment: dict[str, Any]) -> tuple[str, str]:
    frida = ((final_judgment.get("evidence") or {}).get("frida") or {}) if isinstance(final_judgment, dict) else {}
    status = str(frida.get("status") or ("ok" if final_judgment.get("evidence", {}).get("fridaIncluded") else "degraded"))
    detail = str(frida.get("summary") or f"{frida.get('eventCount', 0)} events")
    return status, detail


def _codetracer_detail(final_judgment: dict[str, Any]) -> tuple[str, str]:
    code = ((final_judgment.get("evidence") or {}).get("codeTracer") or {}) if isinstance(final_judgment, dict) else {}
    status = str(code.get("status") or ("ok" if final_judgment.get("evidence", {}).get("codeTracerIncluded") else "failed"))
    detail = str(code.get("summary") or code.get("analysisPath") or "diagnosis unavailable")
    return status, detail


def print_summary(steps: list[ShowcaseStep], *, run_dir: Path, final_judgment: dict[str, Any], host: str, viewer_port: int) -> None:
    run_id = run_dir.name
    decision = str(final_judgment.get("finalDecision") or "unknown").upper()
    risk = str(final_judgment.get("riskLevel") or "unknown")
    frida_status, frida_detail = _frida_detail(final_judgment)
    code_status, code_detail = _codetracer_detail(final_judgment)
    rows = [
        *steps,
        ShowcaseStep("Frida evidence", _status_word(frida_status), frida_detail),
        ShowcaseStep("CodeTracer", _status_word(code_status), code_detail),
        ShowcaseStep("Final judgment", "OK" if decision != "UNKNOWN" else "DEGRADED", f"{decision} / {risk}"),
    ]
    print("Transpect Showcase\n")
    for index, row in enumerate(rows, start=1):
        print(f"{index}. {row.label:<16} {row.status:<9} {row.detail}")
    print("\nOpen:")
    print(VIEWER_URL_TEMPLATE.format(host=host, port=viewer_port, run_id=run_id))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Transpect staged attack product showcase.")
    parser.add_argument("--reuse-latest", action="store_true", help="Reuse the latest showcase run and only print the viewer URL.")
    parser.add_argument("--verbose", action="store_true", help="Print internal failure details.")
    parser.add_argument("--no-openclaw-run", action="store_true", help="Use --run-dir and rebuild artifacts without launching a new agent.")
    parser.add_argument("--run-dir", help="Existing run directory for --no-openclaw-run.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--site-port", type=int, default=8765)
    parser.add_argument("--viewer-port", type=int, default=8711)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--task-id", default=DEFAULT_TASK_ID, help="staged_attack task id to run.")
    parser.add_argument(
        "--require-frida-ok",
        action="store_true",
        help="Fail unless a real Frida smoke check passes and the run records non-empty Frida evidence.",
    )
    args = parser.parse_args()

    steps: list[ShowcaseStep] = []
    try:
        site = ensure_demo_site(host=args.host, port=args.site_port)
        viewer = ensure_viewer(host=args.host, port=args.viewer_port)
        steps.extend(
            [
                ShowcaseStep("Demo site", _status_word(site["status"]), str(site["detail"])),
                ShowcaseStep("Viewer", _status_word(viewer["status"]), str(viewer["detail"])),
            ]
        )

        if args.reuse_latest:
            run_dir = find_showcase_run()
            if run_dir is None:
                raise RuntimeError("no showcase run found; run without --reuse-latest first")
            final_judgment = read_json(run_dir / "security-reasoning" / "final_judgment.json", default={})
            if not isinstance(final_judgment, dict):
                final_judgment = {}
            steps.append(ShowcaseStep("Runtime trace", "OK", f"runId={run_dir.name}"))
            print_summary(steps, run_dir=run_dir, final_judgment=final_judgment, host=args.host, viewer_port=args.viewer_port)
            return

        if args.no_openclaw_run:
            if not args.run_dir:
                raise RuntimeError("--no-openclaw-run requires --run-dir")
            run_dir = Path(args.run_dir).resolve()
        else:
            if args.require_frida_ok:
                smoke = check_frida_smoke(timeout_seconds=75, verbose=args.verbose)
                smoke_status = str(smoke.get("status") or ("ok" if smoke.get("ok") else "failed"))
                smoke_events = int(smoke.get("evidenceEventCount") or smoke.get("eventCount") or 0)
                steps.append(ShowcaseStep("Frida smoke", _status_word(smoke_status), f"{smoke_events} evidence event(s)"))
                if not smoke.get("ok"):
                    raise RuntimeError(smoke.get("detail") or smoke.get("status") or "Frida smoke check failed")
            guard = check_runtime_guard()
            steps.append(ShowcaseStep("Runtime guard", _status_word(guard["status"]), str(guard["detail"])))
            run_dir = run_agent_trace(task_id=args.task_id, timeout_seconds=args.timeout, verbose=args.verbose)
        steps.append(ShowcaseStep("Runtime trace", "OK", f"runId={run_dir.name}"))

        artifacts = complete_artifacts(run_dir, verbose=args.verbose)
        final_judgment = artifacts["finalJudgment"]
        if args.require_frida_ok:
            require_real_frida_evidence(run_dir, final_judgment)
        print_summary(steps, run_dir=run_dir, final_judgment=final_judgment, host=args.host, viewer_port=args.viewer_port)
    except Exception as error:  # noqa: BLE001
        print("Transpect Showcase\n")
        for index, row in enumerate(steps, start=1):
            print(f"{index}. {row.label:<16} {row.status:<9} {row.detail}")
        print(f"\nFAILED: {error}")
        if args.verbose:
            raise
        print("Next step: rerun with --verbose, or use --reuse-latest to replay an existing showcase run.")
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
