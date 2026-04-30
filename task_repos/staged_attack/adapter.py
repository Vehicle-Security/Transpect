from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "common"))

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
    return str(source.get("data_pattern") or "*.json")


def _source_path_for_task(data_root: Path, file_path: Path) -> str:
    relative = file_path.resolve().relative_to(data_root.resolve())
    return str(Path("data") / relative).replace("\\", "/")


def _load_tasks(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("tasks"), list):
        return [item for item in payload["tasks"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _task_entry(source_path: str, task: dict[str, Any]) -> dict[str, Any]:
    task_id = str(task.get("id") or "").strip()
    return {
        "taskId": f"{source_path}#{task_id}",
        "sampleId": task_id,
        "sourcePath": source_path,
        "scenario": task.get("scenario"),
        "attackType": task.get("attackType") or task.get("attack_type"),
        "expectedLabel": task.get("expectedDecision"),
        "label": task.get("expectedDecision"),
    }


def list_tasks(manifest: dict[str, Any], prepared_env: dict[str, Any]) -> list[dict[str, Any]]:
    data_root = _data_root(manifest)
    tasks: list[dict[str, Any]] = []
    for path in sorted(data_root.glob(_data_pattern(manifest))):
        if not path.is_file():
            continue
        source_path = _source_path_for_task(data_root, path)
        for task in _load_tasks(path):
            tasks.append(_task_entry(source_path, task))
    return tasks


def load_task(manifest: dict[str, Any], prepared_env: dict[str, Any], task_id: str) -> dict[str, Any]:
    source_part, separator, sample_part = str(task_id).partition("#")
    if not separator or not source_part.startswith("data/"):
        raise LookupError(f"task not found: {task_id}")
    data_root = _data_root(manifest)
    source_file = (data_root / source_part.removeprefix("data/")).resolve()
    try:
        source_file.relative_to(data_root.resolve())
    except ValueError as error:
        raise LookupError(f"task not found: {task_id}") from error
    if not source_file.exists():
        raise LookupError(f"task not found: {task_id}")
    for task in _load_tasks(source_file):
        if str(task.get("id")) == sample_part:
            loaded = dict(task)
            loaded["taskId"] = task_id
            loaded["sourcePath"] = source_part
            loaded["label"] = task.get("expectedDecision")
            return loaded
    raise LookupError(f"task not found: {task_id}")


def build_agent_input(manifest: dict[str, Any], prepared_env: dict[str, Any], task: dict[str, Any]) -> str:
    prompt = str(task.get("prompt") or "").strip()
    if prompt:
        return prompt
    environment = task.get("environment") if isinstance(task.get("environment"), dict) else {}
    topic_url = str(environment.get("topicUrl") or "").strip()
    user_intent = str(task.get("userIntent") or "").strip()
    if topic_url:
        return f"请打开 {topic_url}，{user_intent or '查看页面内容并总结要点'}。"
    return user_intent
