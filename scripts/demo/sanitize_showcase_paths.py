#!/usr/bin/env python3
"""Remove machine-local absolute paths from frozen showcase artifacts."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SHOWCASE_ROOT = REPO_ROOT / "state" / "showcase"
TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".txt", ".log", ".csv", ".html"}


def replacement_pairs(repo_root: Path = REPO_ROOT) -> list[tuple[str, str]]:
    root = repo_root.resolve().as_posix()
    home = Path.home().resolve().as_posix()
    return [
        (f"{root}/.venv-frida-arm64", "<python_env>"),
        (f"{root}/.conda-frida-arm64", "<python_env>"),
        (root, "<transpect_root>"),
        (f"{home}/.openclaw", "<openclaw_home>"),
        (home, "<user_home>"),
        ("/opt/anaconda3", "<python_env>"),
        ("/opt/homebrew", "<homebrew_prefix>"),
        (".venv-frida-arm64", "<python_env>"),
        (".conda-frida-arm64", "<python_env>"),
    ]


def sanitize_text(text: str, repo_root: Path = REPO_ROOT) -> tuple[str, int]:
    count = 0
    sanitized = text
    for needle, replacement in replacement_pairs(repo_root):
        occurrences = sanitized.count(needle)
        if occurrences:
            sanitized = sanitized.replace(needle, replacement)
            count += occurrences
    sanitized, temp_count = re.subn(r"/private/var/folders/[^\s\"'<>]+", "<system_temp>", sanitized)
    count += temp_count
    return sanitized, count


def iter_text_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    if root.is_file():
        return [root] if root.suffix in TEXT_SUFFIXES else []
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            files.append(path)
    return files


def sanitize_showcase_paths(
    showcase_root: str | Path = DEFAULT_SHOWCASE_ROOT,
    *,
    check: bool = False,
    repo_root: str | Path = REPO_ROOT,
) -> dict[str, Any]:
    root = Path(showcase_root)
    repo = Path(repo_root)
    files = iter_text_files(root)
    changed: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    total_replacements = 0

    for path in files:
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue

        sanitized, replacement_count = sanitize_text(original, repo)
        if replacement_count:
            total_replacements += replacement_count
            changed.append(
                {
                    "path": _display_path(path, repo),
                    "replacementCount": replacement_count,
                }
            )
            if not check:
                path.write_text(sanitized, encoding="utf-8")

    ok = not errors and (not check or total_replacements == 0)
    return {
        "ok": ok,
        "mode": "check" if check else "rewrite",
        "showcaseRoot": _display_path(root, repo),
        "filesScanned": len(files),
        "filesChanged": len(changed),
        "replacementCount": total_replacements,
        "changed": changed,
        "errors": errors,
    }


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description="Sanitize local absolute paths in frozen showcase files.")
    parser.add_argument("--showcase-root", default=str(DEFAULT_SHOWCASE_ROOT))
    parser.add_argument("--check", action="store_true", help="Report local paths without rewriting files.")
    args = parser.parse_args()

    report = sanitize_showcase_paths(args.showcase_root, check=args.check)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
