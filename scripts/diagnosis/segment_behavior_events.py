from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import TRACE_LIVE_ARCHIVE_DIR, TRACE_LIVE_DIR, ensure_dir, now_utc_iso, normalize_path, write_runs_index


SEGMENT_SCHEMA_VERSION = "openclaw.run.v1"
SEGMENT_MANIFEST_NAME = "manifest.json"
SEGMENT_EVENTS_NAME = "behavior-events.jsonl"


@dataclass(frozen=True)
class TraceRow:
    line_number: int
    payload: dict[str, Any]

    @property
    def run_id(self) -> str:
        return str(self.payload.get("runId") or "").strip()

    @property
    def trace_id(self) -> str:
        return str(self.payload.get("traceId") or "").strip()

    @property
    def session_key(self) -> str:
        return str(self.payload.get("sessionKey") or "").strip()

    @property
    def ts(self) -> str:
        return str(self.payload.get("ts") or "").strip()

    @property
    def kind(self) -> str:
        return str(self.payload.get("kind") or "").strip()

    @property
    def status(self) -> str:
        return str(self.payload.get("status") or "").strip()


def safe_name(value: str | None, fallback: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in str(value or "").strip()).strip(".-")
    return text or fallback


def parse_ts(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def load_rows(path: Path) -> list[TraceRow]:
    rows: list[TraceRow] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(TraceRow(line_number=line_number, payload=payload))
    return rows


def choose_segment_key(row: TraceRow, group_by: str) -> str:
    if group_by == "run":
        return row.run_id or row.trace_id or f"line-{row.line_number}"
    if group_by == "trace":
        return row.trace_id or row.run_id or f"line-{row.line_number}"
    return row.run_id or row.trace_id or f"line-{row.line_number}"


def group_rows(rows: list[TraceRow], group_by: str) -> dict[str, list[TraceRow]]:
    if group_by == "auto":
        grouped: dict[str, list[TraceRow]] = defaultdict(list)
        trace_to_run: dict[str, str] = {}
        for row in rows:
            if row.run_id:
                grouped[row.run_id].append(row)
                if row.trace_id:
                    trace_to_run.setdefault(row.trace_id, row.run_id)
        for row in rows:
            if row.run_id:
                continue
            if row.trace_id and row.trace_id in trace_to_run:
                grouped[trace_to_run[row.trace_id]].append(row)
                continue
            grouped[row.trace_id or f"line-{row.line_number}"].append(row)
        for bucket in grouped.values():
            bucket.sort(key=lambda item: item.line_number)
        return dict(grouped)
    grouped: dict[str, list[TraceRow]] = defaultdict(list)
    for row in rows:
        grouped[choose_segment_key(row, group_by)].append(row)
    for bucket in grouped.values():
        bucket.sort(key=lambda item: item.line_number)
    return dict(grouped)


def segment_directory(output_root: Path, rows: list[TraceRow], segment_id: str) -> Path:
    return output_root / safe_name(segment_id, "segment")


def write_json(path: Path, payload: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: list[TraceRow]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row.payload, ensure_ascii=False) + "\n")


def archive_source(input_file: Path, archive_root: Path, *, dry_run: bool) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dated = archive_root / datetime.now(timezone.utc).strftime("%Y") / datetime.now(timezone.utc).strftime("%m") / datetime.now(timezone.utc).strftime("%d")
    target = dated / f"behavior-events.{stamp}.jsonl"
    if not dry_run:
        ensure_dir(target.parent)
        shutil.copy2(input_file, target)
    return target


def truncate_input_file(input_file: Path, *, dry_run: bool) -> None:
    if dry_run:
        return
    input_file.write_text("", encoding="utf-8")


def build_manifest(segment_id: str, rows: list[TraceRow], source_path: Path, output_dir: Path) -> dict[str, Any]:
    trace_ids = sorted({row.trace_id for row in rows if row.trace_id})
    session_keys = sorted({row.session_key for row in rows if row.session_key})
    kind_counts = Counter(row.kind for row in rows if row.kind)
    status_counts = Counter(row.status for row in rows if row.status)
    timestamps = [parse_ts(row.ts) for row in rows if parse_ts(row.ts) is not None]
    first_ts = min(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None
    last_ts = max(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None
    run_id = next((row.run_id for row in rows if row.run_id), None)
    trace_id = trace_ids[0] if trace_ids else None
    return {
        "schemaVersion": SEGMENT_SCHEMA_VERSION,
        "createdAt": first_ts,
        "completedAt": last_ts,
        "runId": run_id,
        "traceId": trace_id,
        "sessionKey": session_keys[0] if session_keys else None,
        "scenarioId": None,
        "status": "completed" if status_counts.get("ok", 0) or status_counts.get("error", 0) else "running",
        "eventCount": len(rows),
        "artifactCount": 0,
        "hasRuntimeStatus": False,
        "hasTaskInput": False,
        "sourcePath": normalize_path(source_path.resolve()),
        "runPath": normalize_path(output_dir.resolve()),
        "paths": {
            "events": SEGMENT_EVENTS_NAME,
            "manifest": SEGMENT_MANIFEST_NAME,
            "runtimeStatus": None,
            "taskInput": None,
            "artifacts": None,
            "codetracerBundle": None,
            "codetracerAnalysis": None,
        },
        "diagnosis": {
            "codetracer": {
                "bundleReady": False,
                "analysisReady": False,
                "analysisOk": None,
                "lastRunAt": None,
            }
        },
        "stats": {
            "rowCount": len(rows),
            "kindCounts": dict(kind_counts),
            "statusCounts": dict(status_counts),
            "firstTs": first_ts,
            "lastTs": last_ts,
            "sourceLines": [rows[0].line_number, rows[-1].line_number] if rows else None,
        },
    }


def segment_behavior_events(
    *,
    input_file: Path,
    output_root: Path,
    group_by: str,
    archive_source_file: bool,
    truncate_input: bool,
    dry_run: bool,
) -> dict[str, Any]:
    rows = load_rows(input_file)
    grouped = group_rows(rows, group_by)
    segments: list[dict[str, Any]] = []
    for segment_id, segment_rows in grouped.items():
        output_dir = segment_directory(output_root, segment_rows, segment_id)
        manifest = build_manifest(segment_id, segment_rows, input_file, output_dir)
        if not dry_run:
            write_jsonl(output_dir / SEGMENT_EVENTS_NAME, segment_rows)
            write_json(output_dir / SEGMENT_MANIFEST_NAME, manifest)
        segments.append(
            {
                "segmentId": segment_id,
                "outputPath": normalize_path(output_dir.resolve()),
                "rowCount": manifest["stats"]["rowCount"],
                "runId": manifest["runId"],
                "traceId": manifest["traceId"],
                "firstTs": manifest["stats"]["firstTs"],
                "lastTs": manifest["stats"]["lastTs"],
            }
        )

    archive_path = None
    if archive_source_file:
        archive_path = archive_source(input_file, TRACE_LIVE_ARCHIVE_DIR / "raw", dry_run=dry_run)

    if truncate_input:
        truncate_input_file(input_file, dry_run=dry_run)

    if not dry_run:
        write_runs_index(output_root)

    return {
        "ok": True,
        "schemaVersion": SEGMENT_SCHEMA_VERSION,
        "generatedAt": now_utc_iso(),
        "inputFile": normalize_path(input_file.resolve()),
        "outputRoot": normalize_path(output_root.resolve()),
        "groupBy": group_by,
        "dryRun": dry_run,
        "archiveSource": archive_source_file,
        "archivePath": normalize_path(archive_path.resolve()) if archive_path else None,
        "truncatedInput": truncate_input,
        "segmentCount": len(segments),
        "segments": segments,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Split the monolithic hot behavior-events.jsonl into per-run or per-trace raw files.")
    parser.add_argument(
        "--input-file",
        default=str((TRACE_LIVE_DIR / SEGMENT_EVENTS_NAME).resolve()),
        help="Hot behavior-events.jsonl to segment.",
    )
    parser.add_argument(
        "--output-root",
        default=str((TRACE_LIVE_DIR / "runs").resolve()),
        help="Directory that will receive per-run/per-trace raw files.",
    )
    parser.add_argument(
        "--group-by",
        choices=["auto", "run", "trace"],
        default="auto",
        help="How to group rows into stable raw segments.",
    )
    parser.add_argument(
        "--archive-source",
        action="store_true",
        help="Copy the source behavior-events.jsonl into live/archive/raw/YYYY/MM/DD/ before any truncation.",
    )
    parser.add_argument(
        "--truncate-input",
        action="store_true",
        help="Empty the hot input file after segmentation. Use only during a quiescent window or after restarting gateway.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the segmentation plan without writing files.",
    )
    args = parser.parse_args()

    payload = segment_behavior_events(
        input_file=Path(args.input_file).resolve(),
        output_root=Path(args.output_root).resolve(),
        group_by=args.group_by,
        archive_source_file=args.archive_source,
        truncate_input=args.truncate_input,
        dry_run=args.dry_run,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
