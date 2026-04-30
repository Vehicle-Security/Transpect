from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LIVE_ROOT = ROOT / "live"


@dataclass
class TraceBundle:
    status: str
    run_id: str | None = None
    run_dir: str | None = None
    trace_source: str = "none"
    reason: str | None = None
    raw_events: list[dict[str, Any]] = field(default_factory=list)
    manifest: dict[str, Any] | None = None
    task_input: dict[str, Any] | None = None
    sidecars: dict[str, Any] = field(default_factory=dict)
    missing_artifacts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    final_answer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "run_id": self.run_id,
            "run_dir": self.run_dir,
            "trace_source": self.trace_source,
            "reason": self.reason,
            "event_count": len(self.raw_events),
            "raw_events": self.raw_events,
            "manifest": self.manifest,
            "task_input": self.task_input,
            "sidecars": self.sidecars,
            "missing_artifacts": self.missing_artifacts,
            "warnings": self.warnings,
            "final_answer": self.final_answer,
        }


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return default


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    rows.append(parsed)
            except json.JSONDecodeError:
                rows.append({"raw": line})
    return rows


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _has_terminal_request(rows: list[dict[str, Any]]) -> bool:
    return any(row.get("kind") == "request" and row.get("status") in {"ok", "error"} for row in rows)


def _final_answer(rows: list[dict[str, Any]]) -> str | None:
    for row in reversed(rows):
        preview = row.get("preview") if isinstance(row.get("preview"), dict) else {}
        for key in ("assistant", "response", "result"):
            value = preview.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


class TraceCollector:
    def __init__(self, live_root: str | Path | None = None) -> None:
        self.live_root = Path(live_root or DEFAULT_LIVE_ROOT).expanduser().resolve()
        self.runs_root = self.live_root / "runs"

    @staticmethod
    def empty_bundle(*, status: str = "failed", reason: str = "no_trace_found") -> TraceBundle:
        return TraceBundle(status=status, reason=reason, trace_source="none", warnings=[reason])

    def collect_frida_events(
        self,
        path: Path | str,
        *,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Read ``frida_events.jsonl`` and return (events within window, total_events_in_file).

        Each returned dict in the list is a serialised :class:`FridaEvent`.
        """
        rows = _read_jsonl(Path(path))
        if not rows:
            return [], 0
        cutoff_start = _parse_ts(started_at) if started_at else datetime.min.replace(tzinfo=timezone.utc)
        cutoff_end = _parse_ts(ended_at) if ended_at else datetime.max.replace(tzinfo=timezone.utc)
        filtered: list[dict[str, Any]] = []
        for row in rows:
            ts = _parse_ts(row.get("timestamp") or row.get("ts"))
            if cutoff_start <= ts <= cutoff_end:
                filtered.append(row)
        return sorted(filtered, key=lambda r: r.get("timestamp") or r.get("ts") or ""), len(rows)

    def collect_by_run_id(self, run_id: str | None, timeout_seconds: int = 300) -> TraceBundle:
        if not run_id:
            return self._fallback_or_missing(None)
        deadline = time.monotonic() + max(int(timeout_seconds), 0)
        while True:
            run_dir = self.runs_root / str(run_id)
            if run_dir.exists():
                bundle = self._collect_run_dir(run_dir)
                if bundle.raw_events and (_has_terminal_request(bundle.raw_events) or timeout_seconds <= 0):
                    return bundle
            if time.monotonic() >= deadline:
                return self._collect_run_dir(run_dir) if run_dir.exists() else self._fallback_or_missing(run_id)
            time.sleep(1)

    def collect_latest_after(
        self,
        started_at: str,
        scenario_id: str,
        timeout_seconds: int = 300,
        fallback_global_path: str | Path | None = None,
    ) -> TraceBundle:
        deadline = time.monotonic() + max(int(timeout_seconds), 0)
        while True:
            run_dir = self._latest_run_after(started_at, scenario_id)
            if run_dir is not None:
                bundle = self._collect_run_dir(run_dir)
                if bundle.raw_events and (_has_terminal_request(bundle.raw_events) or timeout_seconds <= 0):
                    return bundle
            if time.monotonic() >= deadline:
                if run_dir is not None:
                    return self._collect_run_dir(run_dir)
                return self._fallback_or_missing(None, fallback_global_path=fallback_global_path)
            time.sleep(1)

    def _latest_run_after(self, started_at: str, scenario_id: str) -> Path | None:
        del scenario_id  # current run manifests do not consistently carry scenario IDs.
        cutoff = _parse_ts(started_at)
        index = _read_json(self.runs_root / "index.json", default={})
        candidates: list[tuple[datetime, Path]] = []
        for item in index.get("runs") or []:
            if not isinstance(item, dict):
                continue
            created = _parse_ts(item.get("createdAt") or item.get("completedAt"))
            if created < cutoff:
                continue
            dir_name = item.get("dirName") or item.get("runId")
            if isinstance(dir_name, str) and dir_name.strip():
                candidates.append((created, self.runs_root / dir_name))
        if not candidates and self.runs_root.exists():
            for run_dir in self.runs_root.iterdir():
                manifest = _read_json(run_dir / "manifest.json", default={})
                created = _parse_ts(manifest.get("createdAt") or manifest.get("completedAt"))
                if created >= cutoff:
                    candidates.append((created, run_dir))
        if not candidates:
            return None
        return sorted(candidates, key=lambda item: item[0], reverse=True)[0][1]

    def _collect_run_dir(self, run_dir: Path) -> TraceBundle:
        events_path = run_dir / "behavior-events.jsonl"
        events = _read_jsonl(events_path)
        missing: list[str] = []
        if not events_path.exists():
            missing.append(str(events_path))
        manifest = _read_json(run_dir / "manifest.json", default=None)
        task_input = _read_json(run_dir / "task_input.json", default=None)
        sidecars = self._read_sidecars(run_dir)
        status = "completed" if _has_terminal_request(events) else ("failed_with_trace" if events else "failed")
        reason = None if events else "no_trace_found"
        warnings = [] if _has_terminal_request(events) else ["terminal request event not observed"] if events else ["no_trace_found"]
        return TraceBundle(
            status=status,
            run_id=(manifest or {}).get("runId") if isinstance(manifest, dict) else run_dir.name,
            run_dir=str(run_dir.resolve()),
            trace_source="per_run",
            reason=reason,
            raw_events=events,
            manifest=manifest if isinstance(manifest, dict) else None,
            task_input=task_input if isinstance(task_input, dict) else None,
            sidecars=sidecars,
            missing_artifacts=missing,
            warnings=warnings,
            final_answer=_final_answer(events),
        )

    def _read_sidecars(self, run_dir: Path) -> dict[str, Any]:
        sidecars: dict[str, Any] = {}
        artifacts = run_dir / "artifacts"
        if not artifacts.exists():
            return sidecars
        for path in artifacts.rglob("*.json"):
            relative = path.relative_to(run_dir).as_posix()
            sidecars[relative] = _read_json(path, default=None)
        return sidecars

    def _fallback_or_missing(self, run_id: str | None, fallback_global_path: str | Path | None = None) -> TraceBundle:
        global_path = Path(fallback_global_path) if fallback_global_path else self.live_root / "behavior-events.jsonl"
        events = _read_jsonl(global_path)
        if events:
            return TraceBundle(
                status="failed_with_trace" if not _has_terminal_request(events) else "completed",
                run_id=run_id,
                trace_source="global",
                raw_events=events,
                warnings=["using global behavior-events fallback"],
                final_answer=_final_answer(events),
            )
        return TraceBundle(status="failed", run_id=run_id, trace_source="none", reason="no_trace_found", warnings=["no_trace_found"])

