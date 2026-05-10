from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import extract_json_from_text, node_executable, python_executable, run_command


def token(*parts: str) -> str:
    return "".join(parts)


REPO_ROOT = Path(__file__).resolve().parents[2]
STABLE_SCREENSHOTS = [
    "runtime-traces.png",
    "runtime-timeline.png",
    "runtime-timeline-detail.png",
    "runtime-timeline-evidence.png",
    "console-overview-dashboard.png",
    "console-staged-attack-report.png",
    "console-artifact-viewer.png",
]
REQUIRED_PATHS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "requirements.txt",
    REPO_ROOT / "docs" / "architecture" / "canonical-layout.md",
    REPO_ROOT / "docs" / "architecture" / "overview.md",
    REPO_ROOT / "docs" / "directory-layout.md",
    REPO_ROOT / "docs" / "observability.md",
    REPO_ROOT / "docs" / "frida.md",
    REPO_ROOT / "docs" / "runtime-storage-plan.md",
    REPO_ROOT / "config" / "agent-defense-policy.json",
    REPO_ROOT / "app" / "agent_defense" / "bridge.py",
    REPO_ROOT / "app" / "agent_defense" / "trace_merge.py",
    REPO_ROOT / "app" / "agent_defense" / "final_judge.py",
    REPO_ROOT / "viewer" / "index.html",
    REPO_ROOT / "viewer" / "app.js",
    REPO_ROOT / "viewer" / "app.css",
    REPO_ROOT / "viewer" / "shared.js",
    REPO_ROOT / "scripts" / "compat" / "entrypoint.py",
    REPO_ROOT / "scripts" / "common" / "trace_common.py",
    REPO_ROOT / "scripts" / "runtime" / "start_trace.py",
    REPO_ROOT / "scripts" / "runtime" / "setup_runtime.py",
    REPO_ROOT / "scripts" / "validate" / "doctor.py",
    REPO_ROOT / "scripts" / "validate" / "run_acceptance.py",
    REPO_ROOT / "scripts" / "export" / "export_codetracer_bundle.py",
    REPO_ROOT / "scripts" / "diagnosis" / "run_codetracer_diagnosis.py",
    REPO_ROOT / "tests" / "validate" / "test_codetracer_export.py",
    REPO_ROOT / "tests" / "validate" / "test_trace_pipeline.py",
    REPO_ROOT / "scripts" / "validate" / "trace_topology.py",
    REPO_ROOT / "scripts" / "diagnosis" / "segment_behavior_events.py",
    REPO_ROOT / "vendor" / "runtime-hooks" / "openclaw-behavior-mediator" / "tests" / "behavior-mediator.test.mjs",
]
REMOVED_LEGACY_ENTRYPOINTS = [
    REPO_ROOT / "scripts" / "start_trace.py",
    REPO_ROOT / "scripts" / "setup_runtime.py",
    REPO_ROOT / "scripts" / "export_codetracer_bundle.py",
    REPO_ROOT / "scripts" / "run_codetracer_diagnosis.py",
    REPO_ROOT / "scripts" / "check_repo.py",
]
REQUIRED_GITIGNORE_PATTERNS = [
    ".venv*/",
    ".conda*/",
    "live/**",
    "!live/.gitkeep",
    "!live/otel/.gitkeep",
    "captures/**",
    "!captures/.gitkeep",
    "vendor/external/openclaw-observability-plugin/node_modules/",
    "config/*.local.yaml",
    "docs/images/*.png",
    "!docs/images/runtime-traces.png",
    "!docs/images/runtime-timeline.png",
    "!docs/images/runtime-timeline-detail.png",
    "!docs/images/runtime-timeline-evidence.png",
    "!docs/images/console-overview-dashboard.png",
    "!docs/images/console-staged-attack-report.png",
    "!docs/images/console-artifact-viewer.png",
]
HARD_CODED_PATTERNS = [
    token("D", ":/"),
    token("C", ":/Users"),
    "/".join(["state", "trace"]),
    token("start_trace", "_", "de", "mo"),
    token("de", "mo", ".js"),
    token("de", "mo", ".css"),
    token("Trace ", "De", "mo"),
]
SCAN_SUFFIXES = {".md", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".mjs", ".txt", ".css", ".html", ".sh", ".cmd"}
EXCLUDED_SCAN_PARTS = {".git", "node_modules", "__pycache__", "live", "captures", ".venv-frida-arm64", ".conda-frida-arm64"}


def check_python_syntax() -> dict[str, Any]:
    roots = [REPO_ROOT / "app", REPO_ROOT / "scripts", REPO_ROOT / "task_repos", REPO_ROOT / "tests"]
    files = sorted(path for root in roots for path in root.rglob("*.py") if path.is_file())
    entries: list[dict[str, Any]] = []
    ok = True
    for path in files:
        result = run_command([python_executable(), "-m", "py_compile", str(path)], timeout=60, check=False)
        passed = result.returncode == 0
        ok = ok and passed
        entries.append(
            {
                "path": str(path.relative_to(REPO_ROOT)),
                "ok": passed,
                "stderr": result.stderr.strip(),
            }
        )
    return {"ok": ok, "files": entries}


def check_js_syntax() -> dict[str, Any]:
    files = [
        REPO_ROOT / "viewer" / "app.js",
        REPO_ROOT / "viewer" / "shared.js",
        REPO_ROOT / "vendor" / "runtime-hooks" / "openclaw-behavior-mediator" / "index.js",
    ]
    entries: list[dict[str, Any]] = []
    ok = True
    for path in files:
        result = run_command([node_executable(), "--check", str(path)], timeout=60, check=False)
        passed = result.returncode == 0
        ok = ok and passed
        entries.append(
            {
                "path": str(path.relative_to(REPO_ROOT)),
                "ok": passed,
                "stderr": result.stderr.strip(),
            }
        )
    return {"ok": ok, "files": entries}


def check_required_paths() -> dict[str, Any]:
    missing = [str(path.relative_to(REPO_ROOT)) for path in REQUIRED_PATHS if not path.exists()]
    screenshot_dir = REPO_ROOT / "docs" / "images"
    extra_screenshots = sorted(
        path.name for path in screenshot_dir.glob("*.png") if path.name not in set(STABLE_SCREENSHOTS)
    )
    return {
        "ok": not missing and not extra_screenshots,
        "missing": missing,
        "stableScreenshots": STABLE_SCREENSHOTS,
        "extraScreenshots": extra_screenshots,
    }


def check_gitignore() -> dict[str, Any]:
    path = REPO_ROOT / ".gitignore"
    if not path.exists():
        return {"ok": False, "missingPatterns": REQUIRED_GITIGNORE_PATTERNS, "error": ".gitignore missing"}
    text = path.read_text(encoding="utf-8")
    missing = [pattern for pattern in REQUIRED_GITIGNORE_PATTERNS if pattern not in text]
    tracked_vendor = run_command(
        ["git", "ls-files", "vendor/external/openclaw-observability-plugin/node_modules"],
        cwd=REPO_ROOT,
        timeout=30,
        check=False,
    )
    return {
        "ok": not missing and not tracked_vendor.stdout.strip(),
        "missingPatterns": missing,
        "vendorNodeModulesTracked": bool(tracked_vendor.stdout.strip()),
    }


def scan_hardcoded_paths() -> dict[str, Any]:
    matches: list[dict[str, str]] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if any(part in EXCLUDED_SCAN_PARTS for part in path.parts):
            continue
        if path.name.endswith(".local.yaml"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in HARD_CODED_PATTERNS:
            if pattern in text:
                matches.append({"path": str(path.relative_to(REPO_ROOT)), "pattern": pattern})
    return {
        "ok": not matches,
        "matches": matches,
    }


def check_compat_entrypoints() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    ok = True
    for path in REMOVED_LEGACY_ENTRYPOINTS:
        passed = not path.exists()
        ok = ok and passed
        entries.append(
            {
                "path": str(path.relative_to(REPO_ROOT)),
                "ok": passed,
                "removed": passed,
            }
        )
    return {"ok": ok, "entries": entries}


def run_start(host: str, port: int) -> dict[str, Any]:
    result = run_command(
        [
            python_executable(),
            str(REPO_ROOT / "scripts" / "runtime" / "start_trace.py"),
            "--viewer-host",
            host,
            "--viewer-port",
            str(port),
            "--no-open",
        ],
        cwd=REPO_ROOT,
        timeout=180,
        check=False,
    )
    parsed = None
    parse_error = None
    if result.stdout.strip():
        try:
            parsed = extract_json_from_text(result.stdout)
        except ValueError as error:
            parse_error = str(error)
    ok = result.returncode == 0 and isinstance(parsed, dict) and bool(parsed.get("ok"))
    return {
        "ok": ok,
        "returncode": result.returncode,
        "parsed": parsed,
        "parseError": parse_error,
        "stderr": result.stderr.strip(),
    }


def run_doctor(host: str, port: int) -> dict[str, Any]:
    result = run_command(
        [
            python_executable(),
            str(REPO_ROOT / "scripts" / "validate" / "doctor.py"),
            "--host",
            host,
            "--port",
            str(port),
        ],
        cwd=REPO_ROOT,
        timeout=180,
        check=False,
    )
    parsed = None
    parse_error = None
    if result.stdout.strip():
        try:
            parsed = extract_json_from_text(result.stdout)
        except ValueError as error:
            parse_error = str(error)
    summary = parsed.get("summary") if isinstance(parsed, dict) else {}
    ok = result.returncode == 0 and isinstance(summary, dict) and summary.get("verdict") in {"ok", "degraded"}
    return {
        "ok": ok,
        "returncode": result.returncode,
        "summary": summary,
        "parseError": parse_error,
        "stderr": result.stderr.strip(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Sanity check the repository before publishing.")
    parser.add_argument("--viewer-host", default="127.0.0.1")
    parser.add_argument("--viewer-port", type=int, default=8711)
    parser.add_argument("--skip-start", action="store_true", help="Skip runtime startup checks.")
    args = parser.parse_args()

    report: dict[str, Any] = {
        "pythonSyntax": check_python_syntax(),
        "jsSyntax": check_js_syntax(),
        "requiredPaths": check_required_paths(),
        "gitignore": check_gitignore(),
        "hardcodedPaths": scan_hardcoded_paths(),
        "compatEntryPoints": check_compat_entrypoints(),
    }

    if args.skip_start:
        report["startRuntime"] = {"ok": True, "skipped": True}
        report["doctor"] = {"ok": True, "skipped": True}
    else:
        report["startRuntime"] = run_start(args.viewer_host, args.viewer_port)
        report["doctor"] = run_doctor(args.viewer_host, args.viewer_port)

    report["ok"] = all(
        bool(section.get("ok"))
        for section in [
            report["pythonSyntax"],
            report["jsSyntax"],
            report["requiredPaths"],
            report["gitignore"],
            report["hardcodedPaths"],
            report["compatEntryPoints"],
            report["startRuntime"],
            report["doctor"],
        ]
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
