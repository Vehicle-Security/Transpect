"""Data models for Frida runtime events, targets and session results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Target description
# ---------------------------------------------------------------------------

@dataclass
class FridaTarget:
    """Describes a resolved OS process that Frida will (or did) attach to."""
    pid: int
    name: str
    cmdline: str = ""
    role: str = "unknown"  # openclaw_gateway | chrome_browser | unknown
    platform: str = ""
    experimental: bool = False
    attach_recommended: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Session lifecycle results
# ---------------------------------------------------------------------------

@dataclass
class FridaStartResult:
    ok: bool
    targets: list[FridaTarget] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    started_at: str | None = None
    resolution: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "targets": [t.to_dict() for t in self.targets],
            "warnings": self.warnings,
            "error": self.error,
            "started_at": self.started_at,
            "resolution": self.resolution,
        }


@dataclass
class FridaStopResult:
    ok: bool
    event_count: int = 0
    stopped_at: str | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Core event model
# ---------------------------------------------------------------------------

@dataclass
class FridaEvent:
    """A single normalised event emitted by a Frida hook script."""

    event_id: str
    timestamp: str
    source: str = "frida"
    run_id: str | None = None
    session_id: str | None = None
    pid: int | None = None
    process_name: str = ""
    process_role: str = "unknown"
    event_type: str = ""  # process_event | network_event | file_access_event | command_execution_event | browser_runtime_event
    raw: dict[str, Any] = field(default_factory=dict)
    normalized: dict[str, Any] = field(default_factory=dict)
    risk_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
