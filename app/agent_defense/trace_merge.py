from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.common.trace_common import normalize_path, now_utc_iso, read_json, write_json, write_runs_index

from .normalizers import normalize_behavior_event, normalize_frida_event


TRACE_INDEX_SCHEMA = "transpect.agent-defense.trace-index.v1"
MERGED_TRACE_SCHEMA = "transpect.agent-defense.merged-trace.v1"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


def _run_id(run_dir: Path) -> str:
    manifest = read_json(run_dir / "manifest.json", default={}) or {}
    if isinstance(manifest, dict) and manifest.get("runId"):
        return str(manifest["runId"])
    return run_dir.name


def _source_status(path: Path, rows: list[dict[str, Any]], explicit_status: dict[str, Any] | None = None) -> dict[str, Any]:
    explicit_status = explicit_status or {}
    if path.exists():
        status = str(explicit_status.get("status") or ("ok" if rows else "empty"))
    else:
        status = str(explicit_status.get("status") or "unavailable")
    return {
        "path": normalize_path(path.resolve()),
        "status": status,
        "eventCount": len(rows),
        "warnings": explicit_status.get("warnings") or [],
        "error": explicit_status.get("error"),
    }


def build_trace_index(
    run_dir: Path | str,
    *,
    frida_status: dict[str, Any] | None = None,
    merged_count: int | None = None,
) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    behavior_path = resolved / "behavior-events.jsonl"
    frida_path = resolved / "frida-events.jsonl"
    merged_path = resolved / "merged-trace.jsonl"
    behavior_rows = read_jsonl(behavior_path)
    frida_rows = read_jsonl(frida_path)
    index = {
        "schemaVersion": TRACE_INDEX_SCHEMA,
        "generatedAt": now_utc_iso(),
        "runId": _run_id(resolved),
        "sources": {
            "behavior": _source_status(behavior_path, behavior_rows),
            "frida": _source_status(frida_path, frida_rows, frida_status),
        },
        "merged": {
            "path": normalize_path(merged_path.resolve()),
            "status": "ok" if merged_path.exists() else "pending",
            "eventCount": merged_count if merged_count is not None else None,
        },
    }
    write_json(resolved / "trace_index.json", index)
    return index


def merge_run_traces(
    run_dir: Path | str,
    *,
    frida_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    run_id = _run_id(resolved)
    behavior_rows = [normalize_behavior_event(row) for row in read_jsonl(resolved / "behavior-events.jsonl")]
    max_seq = max((int(row.get("seq") or 0) for row in behavior_rows), default=0)
    frida_rows = [
        normalize_frida_event(row, seq=max_seq + index, run_id=run_id)
        for index, row in enumerate(read_jsonl(resolved / "frida-events.jsonl"), start=1)
    ]
    merged = behavior_rows + frida_rows
    merged.sort(key=lambda row: (str(row.get("ts") or row.get("timestamp") or ""), int(row.get("seq") or 0)))
    for index, row in enumerate(merged, start=1):
        row.setdefault("schemaVersion", MERGED_TRACE_SCHEMA)
        row["mergedSeq"] = index

    merged_path = write_jsonl(resolved / "merged-trace.jsonl", merged)
    trace_index = build_trace_index(resolved, frida_status=frida_status, merged_count=len(merged))
    trace_index["merged"]["status"] = "ok"
    write_json(resolved / "trace_index.json", trace_index)

    manifest_path = resolved / "manifest.json"
    manifest = read_json(manifest_path, default={}) or {}
    if isinstance(manifest, dict):
        paths = manifest.setdefault("paths", {})
        paths["mergedTrace"] = "merged-trace.jsonl"
        paths["traceIndex"] = "trace_index.json"
        paths["fridaEvents"] = "frida-events.jsonl"
        write_json(manifest_path, manifest)
    write_runs_index(resolved.parent)
    return {
        "ok": True,
        "runDir": normalize_path(resolved),
        "mergedTracePath": normalize_path(merged_path.resolve()),
        "traceIndexPath": normalize_path((resolved / "trace_index.json").resolve()),
        "eventCount": len(merged),
        "sources": trace_index["sources"],
    }
