from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from trace_common import extract_json_from_text, node_executable, python_executable, run_command


def token(*parts: str) -> str:
    return "".join(parts)


REPO_ROOT = Path(__file__).resolve().parents[1]
STABLE_SCREENSHOTS = [
    "runtime-traces.png",
    "runtime-timeline.png",
]
REQUIRED_PATHS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "requirements.txt",
    REPO_ROOT / "docs" / "architecture.md",
    REPO_ROOT / "docs" / "observability.md",
    REPO_ROOT / "docs" / "frida.md",
    REPO_ROOT / "viewer" / "index.html",
    REPO_ROOT / "viewer" / "app.js",
    REPO_ROOT / "viewer" / "app.css",
    REPO_ROOT / "viewer" / "shared.js",
    REPO_ROOT / "scripts" / "start_trace.py",
    REPO_ROOT / "scripts" / "setup_runtime.py",
    REPO_ROOT / "scripts" / "doctor.py",
    REPO_ROOT / "scripts" / "run_acceptance.py",
]
REQUIRED_GITIGNORE_PATTERNS = [
    "live/**",
    "!live/.gitkeep",
    "!live/otel/.gitkeep",
    "captures/**",
    "!captures/.gitkeep",
    "vendor/openclaw-observability-plugin/node_modules/",
    "config/*.local.yaml",
    "docs/images/*.png",
    "!docs/images/runtime-traces.png",
    "!docs/images/runtime-timeline.png",
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
EXCLUDED_SCAN_PARTS = {".git", "node_modules", "__pycache__", "live", "captures"}


def check_python_syntax() -> dict[str, Any]:
    files = sorted((REPO_ROOT / "scripts").glob("*.py"))
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
        ["git", "ls-files", "vendor/openclaw-observability-plugin/node_modules"],
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


def run_start(host: str, port: int) -> dict[str, Any]:
    result = run_command(
        [
            python_executable(),
            str(REPO_ROOT / "scripts" / "start_trace.py"),
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
            str(REPO_ROOT / "scripts" / "doctor.py"),
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
            report["startRuntime"],
            report["doctor"],
        ]
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
