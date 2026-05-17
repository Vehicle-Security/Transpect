from __future__ import annotations

from pathlib import Path
from typing import Any

from .normalizers import normalize_openclaw_native_sources


def ingest_openclaw_native_trace(run_dir: Path | str, root_span_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    return normalize_openclaw_native_sources(Path(run_dir).resolve(), root_span_id)
