"""Frida-based runtime trace enhancement layer.

This module provides optional Frida instrumentation for observing low-level
process behaviour (network, file-system, child-process spawns) during
OpenClaw Agent-driven browser security experiments.

Frida is purely observational — it never changes Agent behaviour and
gracefully degrades when the ``frida`` package is not installed or when
the target process cannot be attached.
"""

from .config import FridaTraceConfig
from .event_models import FridaEvent, FridaStartResult, FridaStopResult, FridaTarget
from .event_normalizer import FridaEventNormalizer
from .event_writer import FridaEventWriter
from .frida_manager import FridaTraceManager
from .frida_resolver import FridaResolution, FridaResolver
from .target_resolver import TargetResolver

__all__ = [
    "FridaEvent",
    "FridaEventNormalizer",
    "FridaEventWriter",
    "FridaResolution",
    "FridaResolver",
    "FridaStartResult",
    "FridaStopResult",
    "FridaTarget",
    "FridaTraceConfig",
    "FridaTraceManager",
    "TargetResolver",
]
