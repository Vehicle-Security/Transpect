#!/usr/bin/env python3
"""Check tracked deployment artifacts for machine-local absolute paths."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGETS = [
    "README.md",
    "docs",
    "dashboard/state/showcase",
    "dashboard/console",
    "dashboard/viewer",
    "tools/demo",
    "tools/validate",
]
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".jsonl",
    ".md",
    ".mjs",
    ".py",
    ".ts",
    ".tsx",
    ".txt",
    ".yml",
    ".yaml",
}
SKIP_PARTS = {
    ".git",
    ".next",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
}
ALLOWLIST_RELATIVE_PATHS = {
    "tools/demo/sanitize_showcase_paths.py",
    "tools/validate/check_portability.py",
    "tools/validate/check_repo.py",
}
FORBIDDEN_PATTERNS = [
    re.compile(r"/Users/qwer\b"),
    re.compile(r"/Users/qwer/"),
    re.compile(r"Documents/code/Transpect"),
    re.compile(r"/opt/anaconda3\b"),
    re.compile(r"\.venv-frida-arm64"),
    re.compile(r"\.conda-frida-arm64"),
]


def iter_candidate_files(root: Path, targets: list[str] | None = None) -> list[Path]:
    selected = targets or DEFAULT_TARGETS
    files: list[Path] = []
    for target in selected:
        path = root / target
        if not path.exists():
            continue
        if path.is_file():
            if _is_text_candidate(path, root):
                files.append(path)
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file() and _is_text_candidate(child, root):
                files.append(child)
    return files


def check_portability(
    repo_root: str | Path = REPO_ROOT,
    *,
    targets: list[str] | None = None,
) -> dict[str, Any]:
    root = Path(repo_root)
    matches: list[dict[str, Any]] = []
    scanned = 0
    for path in iter_candidate_files(root, targets):
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in FORBIDDEN_PATTERNS:
                match = pattern.search(line)
                if match:
                    matches.append(
                        {
                            "path": _display_path(path, root),
                            "line": line_no,
                            "pattern": pattern.pattern,
                            "preview": _preview(line),
                        }
                    )
                    break
    return {
        "ok": not matches,
        "filesScanned": scanned,
        "matches": matches,
        "recommendations": _recommendations(matches),
    }


def _is_text_candidate(path: Path, root: Path) -> bool:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        relative = path.as_posix()
    if relative in ALLOWLIST_RELATIVE_PATHS:
        return False
    if any(part in SKIP_PARTS for part in path.parts):
        return False
    return path.suffix in TEXT_SUFFIXES


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _preview(line: str) -> str:
    line = line.strip()
    if len(line) <= 180:
        return line
    return line[:177] + "..."


def _recommendations(matches: list[dict[str, Any]]) -> list[str]:
    if not matches:
        return []
    return [
        "Replace local absolute paths with repo-relative paths or placeholders such as <transpect_root>, <user_home>, <openclaw_home>, and <python_env>.",
        "Run python tools/demo/sanitize_showcase_paths.py before committing frozen showcase artifacts.",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check docs and frozen showcase artifacts for local paths.")
    parser.add_argument("--root", default=str(REPO_ROOT))
    parser.add_argument(
        "--target",
        action="append",
        dest="targets",
        help="Relative path to scan. Can be passed multiple times.",
    )
    args = parser.parse_args()

    report = check_portability(args.root, targets=args.targets)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
