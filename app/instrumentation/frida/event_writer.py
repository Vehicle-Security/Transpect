"""Thread-safe JSONL writer with automatic payload redaction."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from app.instrumentation.frida.config import REDACTED_FIELD_TOKENS, REDACTED_HEADER_KEYS


class FridaEventWriter:
    """Append-only, thread-safe JSONL writer with privacy redaction."""

    def __init__(self, output_path: str | Path, *, body_preview_max_chars: int = 2048) -> None:
        self._path = Path(output_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._count = 0
        self._body_max = body_preview_max_chars

    @property
    def event_count(self) -> int:
        return self._count

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, record: dict[str, Any]) -> None:
        """Write a single event record to disk, redacting sensitive fields."""
        sanitised = self._redact(record)
        line = json.dumps(sanitised, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            self._count += 1

    def flush(self) -> None:
        """No-op — writes are already flushed per call."""

    # ------------------------------------------------------------------
    # Privacy redaction
    # ------------------------------------------------------------------

    def _redact(self, obj: Any, *, depth: int = 0) -> Any:
        if depth > 12:
            return "<redacted:depth>"
        if isinstance(obj, dict):
            return {k: self._redact_value(k, v, depth=depth + 1) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._redact(item, depth=depth + 1) for item in obj]
        return obj

    def _redact_value(self, key: str, value: Any, *, depth: int) -> Any:
        key_lower = key.lower()
        # Completely scrub known-secret header / field values.
        if key_lower in REDACTED_HEADER_KEYS or any(tok in key_lower for tok in REDACTED_FIELD_TOKENS):
            return "<redacted>"
        # Truncate body previews.
        if key_lower in ("body", "request_body_preview", "response_body_preview", "body_preview"):
            if isinstance(value, str) and len(value) > self._body_max:
                return value[: self._body_max] + f"... (truncated at {self._body_max} chars)"
        return self._redact(value, depth=depth)
