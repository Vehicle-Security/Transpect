"""Configuration constants and dataclass for Frida runtime tracing."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_FRIDA_TIMEOUT_SECONDS: int = 300
DEFAULT_BODY_PREVIEW_MAX_CHARS: int = 2048
DEFAULT_OUTPUT_FILENAME: str = "frida_events.jsonl"

# Sensitive header keys whose *values* must never be recorded.
REDACTED_HEADER_KEYS: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
})

# Tokens that trigger value redaction in arbitrary payload fields.
REDACTED_FIELD_TOKENS: frozenset[str] = frozenset({
    "token",
    "password",
    "secret",
    "key",
    "cookie",
    "credential",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
})

# Sensitive path fragments used by risk-tagging heuristics.
SENSITIVE_PATH_FRAGMENTS: tuple[str, ...] = (
    ".ssh",
    ".env",
    "id_rsa",
    "id_ed25519",
    "token",
    "credential",
    "key",
    ".openclaw",
    "/tmp/openclaw/uploads",
)

TargetMode = Literal["auto", "node", "chrome"]


@dataclass
class FridaTraceConfig:
    """All tunables for a single Frida trace session."""

    enabled: bool = False
    target: str = "auto"  # auto | node | chrome | pid:<PID> | name:<NAME>
    output: str = DEFAULT_OUTPUT_FILENAME
    timeout_seconds: int = DEFAULT_FRIDA_TIMEOUT_SECONDS
    attach_best_effort: bool = True
    body_preview_max_chars: int = DEFAULT_BODY_PREVIEW_MAX_CHARS
    scripts_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "scripts")
