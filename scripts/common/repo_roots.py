from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


def is_windows_absolute_path(raw_path: str) -> bool:
    return bool(WINDOWS_ABSOLUTE_PATH_RE.match(str(raw_path or "").strip()))


def _manifest_dir(manifest: dict[str, Any]) -> Path | None:
    manifest_path = str(manifest.get("_manifestPath") or "").strip()
    if not manifest_path:
        return None
    return Path(manifest_path).expanduser().resolve().parent


def _repo_root_override(manifest: dict[str, Any]) -> str | None:
    env_name = str(manifest.get("repo_root_env") or "").strip()
    if not env_name:
        return None
    value = str(os.environ.get(env_name) or "").strip()
    return value or None


def resolve_manifest_repo_root(manifest: dict[str, Any]) -> Path:
    raw_repo_root = _repo_root_override(manifest) or str(manifest["repo_root"]).strip()
    if not raw_repo_root:
        raise ValueError("manifest repo_root must not be empty")

    path = Path(raw_repo_root).expanduser()
    if path.is_absolute():
        return path.resolve()

    if os.name != "nt" and is_windows_absolute_path(raw_repo_root):
        return Path("/" + raw_repo_root.replace("\\", "/").lstrip("/"))

    manifest_dir = _manifest_dir(manifest)
    if manifest_dir is not None:
        return (manifest_dir / path).resolve()
    return path.resolve()
