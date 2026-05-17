from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools" / "common"))

from repo_roots import resolve_manifest_repo_root  # noqa: E402


def _repo_root(manifest: dict[str, Any]) -> Path:
    return resolve_manifest_repo_root(manifest)


def _data_root(manifest: dict[str, Any]) -> Path:
    source = manifest.get("source") or {}
    configured = str(source.get("data_root") or "data")
    path = Path(configured)
    return path if path.is_absolute() else _repo_root(manifest) / path


def _data_pattern(manifest: dict[str, Any]) -> str:
    source = manifest.get("source") or {}
    return str(source.get("data_pattern") or "**/*.json")


def run_checks(manifest: dict[str, Any], prepared_env: dict[str, Any], *, adapter: Any | None = None) -> list[dict[str, Any]]:
    repo_root = _repo_root(manifest)
    data_root = _data_root(manifest)
    checks: list[dict[str, Any]] = [
        {
            "name": "source_repo_root",
            "ok": repo_root.exists(),
            "reason": None if repo_root.exists() else "required_file_missing",
            "details": {"path": str(repo_root).replace("\\", "/")},
        },
        {
            "name": "source_data_dir",
            "ok": data_root.exists() and data_root.is_dir(),
            "reason": None if data_root.exists() and data_root.is_dir() else "required_file_missing",
            "details": {"path": str(data_root).replace("\\", "/")},
        },
    ]
    json_files = sorted(data_root.glob(_data_pattern(manifest))) if data_root.exists() else []
    checks.append(
        {
            "name": "source_data_files",
            "ok": bool(json_files),
            "reason": None if json_files else "required_file_missing",
            "details": {
                "dataRoot": str(data_root).replace("\\", "/"),
                "pattern": _data_pattern(manifest),
                "jsonFileCount": len(json_files),
            },
        }
    )
    can_load = False
    error = None
    if adapter is not None and hasattr(adapter, "list_tasks") and hasattr(adapter, "load_task"):
        try:
            tasks = adapter.list_tasks(manifest, prepared_env)
            if tasks:
                adapter.load_task(manifest, prepared_env, tasks[0]["taskId"])
                can_load = True
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
    checks.append(
        {
            "name": "source_sample_load",
            "ok": can_load,
            "reason": None if can_load else "task_not_found",
            "details": {"error": error},
        }
    )
    return checks
