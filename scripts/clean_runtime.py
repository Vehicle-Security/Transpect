from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from trace_common import (
    TRACE_LIVE_ARCHIVE_DIR,
    TRACE_LIVE_DIR,
    TRACE_LIVE_LOGS_DIR,
    TRACE_LIVE_OTEL_DIR,
    TRACE_LIVE_PLUGIN_DIR,
    TRACE_ROOT,
    WORKSPACE_ROOT,
    ensure_dir,
    ensure_trace_layout,
    make_trace_archive_dir,
    now_utc_iso,
    write_json,
)


def relative_to_workspace(path: Path) -> str:
    return str(path.resolve().relative_to(WORKSPACE_ROOT)).replace("\\", "/")


def collect_candidates() -> dict[str, list[Path]]:
    tmp_artifacts = sorted(TRACE_ROOT.glob("tmp-*.log")) + sorted(TRACE_ROOT.glob("tmp-*.jsonl"))
    legacy_root_logs = sorted(TRACE_LIVE_DIR.glob("*.out.log")) + sorted(TRACE_LIVE_DIR.glob("*.err.log"))
    legacy_openclaw_files = sorted(path for path in TRACE_LIVE_PLUGIN_DIR.rglob("*") if path.is_file())
    return {
        "tmpArtifacts": sorted({path.resolve() for path in tmp_artifacts}),
        "legacyRootLogs": sorted({path.resolve() for path in legacy_root_logs}),
        "legacyOpenclawFiles": sorted({path.resolve() for path in legacy_openclaw_files}),
    }


def build_preview() -> dict[str, Any]:
    ensure_trace_layout()
    candidates = collect_candidates()
    archive_root = TRACE_LIVE_ARCHIVE_DIR.resolve()
    total_files = sum(len(items) for items in candidates.values())
    return {
        "ok": True,
        "mode": "dry-run",
        "generatedAt": now_utc_iso(),
        "archiveRoot": str(archive_root),
        "preserved": {
            "behaviorEvents": str((TRACE_LIVE_DIR / "behavior-events.jsonl").resolve()),
            "runtimeLogs": str(TRACE_LIVE_LOGS_DIR.resolve()),
            "acceptance": str((TRACE_LIVE_DIR / "acceptance").resolve()),
            "otel": str(TRACE_LIVE_OTEL_DIR.resolve()),
        },
        "counts": {key: len(value) for key, value in candidates.items()},
        "totalFiles": total_files,
        "files": {key: [relative_to_workspace(path) for path in value] for key, value in candidates.items()},
    }


def archive_candidates() -> dict[str, Any]:
    ensure_trace_layout()
    candidates = collect_candidates()
    total_files = sum(len(items) for items in candidates.values())
    if total_files == 0:
        return {
            "ok": True,
            "mode": "archive",
            "generatedAt": now_utc_iso(),
            "archivePath": None,
            "counts": {key: 0 for key in candidates},
            "totalFiles": 0,
            "moved": [],
            "manifestPath": None,
        }

    archive_dir = make_trace_archive_dir()
    moved: list[dict[str, Any]] = []
    category_roots = {
        "tmpArtifacts": archive_dir / "state-trace-root",
        "legacyRootLogs": archive_dir / "live-root",
        "legacyOpenclawFiles": archive_dir / "live-openclaw",
    }

    for category, files in candidates.items():
        destination_root = ensure_dir(category_roots[category])
        for source in files:
            source_path = Path(source)
            if not source_path.exists():
                continue
            if category == "legacyOpenclawFiles":
                relative = source_path.relative_to(TRACE_LIVE_PLUGIN_DIR)
            else:
                relative = Path(source_path.name)
            destination = destination_root / relative
            ensure_dir(destination.parent)
            shutil.move(str(source_path), str(destination))
            moved.append(
                {
                    "category": category,
                    "source": relative_to_workspace(source_path),
                    "archivedTo": relative_to_workspace(destination),
                    "bytes": destination.stat().st_size,
                }
            )

    if TRACE_LIVE_PLUGIN_DIR.exists() and not any(TRACE_LIVE_PLUGIN_DIR.iterdir()):
        TRACE_LIVE_PLUGIN_DIR.rmdir()

    manifest = {
        "generatedAt": now_utc_iso(),
        "archivePath": relative_to_workspace(archive_dir),
        "counts": {key: len(value) for key, value in candidates.items()},
        "totalFiles": total_files,
        "moved": moved,
    }
    manifest_path = write_json(archive_dir / "manifest.json", manifest)
    return {
        "ok": True,
        "mode": "archive",
        "generatedAt": manifest["generatedAt"],
        "archivePath": str(archive_dir.resolve()),
        "counts": manifest["counts"],
        "totalFiles": total_files,
        "moved": moved,
        "manifestPath": str(manifest_path.resolve()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Archive legacy trace runtime residue into a timestamped folder.")
    parser.add_argument("--dry-run", action="store_true", help="Preview files that would be archived.")
    args = parser.parse_args()

    payload = build_preview() if args.dry_run else archive_candidates()
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
