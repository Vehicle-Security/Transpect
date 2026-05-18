"""FridaTraceManager — orchestrates attach, hook-script loading, event collection and detach.

All interactions with the ``frida`` package are import-guarded so that the
rest of the project never fails when Frida is not installed.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from monitor.instrumentation.frida.config import FridaTraceConfig
from monitor.instrumentation.frida.event_models import FridaEvent, FridaStartResult, FridaStopResult, FridaTarget
from monitor.instrumentation.frida.event_normalizer import FridaEventNormalizer
from monitor.instrumentation.frida.event_writer import FridaEventWriter
from monitor.instrumentation.frida.target_resolver import TargetResolver

logger = logging.getLogger(__name__)

_FRIDA_AVAILABLE: bool | None = None


def _check_frida() -> bool:
    global _FRIDA_AVAILABLE  # noqa: PLW0603
    if _FRIDA_AVAILABLE is None:
        try:
            import frida  # noqa: F401
            _FRIDA_AVAILABLE = True
        except ImportError:
            _FRIDA_AVAILABLE = False
    return _FRIDA_AVAILABLE


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class FridaTraceManager:
    """Best-effort Frida runtime trace session manager.

    If Frida is unavailable or attachment fails, all public methods return
    graceful failure objects rather than raising exceptions.
    """

    def __init__(self, config: FridaTraceConfig) -> None:
        self._config = config
        self._resolver = TargetResolver()
        self._writer: FridaEventWriter | None = None
        self._normalizer: FridaEventNormalizer | None = None
        self._sessions: list[Any] = []  # list of frida.core.Session
        self._scripts: list[Any] = []   # list of frida.core.Script
        self._targets: list[FridaTarget] = []
        self._started_at: str | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return ``True`` if the frida package can be imported."""
        return _check_frida()

    def resolved_targets(self) -> list[FridaTarget]:
        return list(self._targets)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(
        self,
        run_id: str | None = None,
        session_id: str | None = None,
        started_at: str | None = None,
    ) -> FridaStartResult:
        """Attach to target processes and begin collecting events.

        Returns a :class:`FridaStartResult` describing what happened.
        Never raises — all errors are captured in the result.
        """
        self._started_at = started_at or _now_iso()
        warnings: list[str] = []

        # Resolve capabilities
        from .frida_resolver import FridaResolver
        res = FridaResolver().resolve()
        
        if not res.package_available:
            return FridaStartResult(
                ok=False,
                warnings=res.warnings,
                error="Frida package is not available or shadowed.",
                started_at=self._started_at,
                resolution=res.to_dict(),
            )
            
        if not res.attach_ready:
            warnings.extend(res.warnings)
            return FridaStartResult(
                ok=False,
                warnings=warnings,
                error="Frida attach capabilities missing (check macOS permissions).",
                started_at=self._started_at,
                resolution=res.to_dict(),
            )

        # Resolve targets
        targets = self._resolver.resolve(self._config.target)
        if not targets:
            msg = f"No processes matched target spec '{self._config.target}'."
            return FridaStartResult(ok=False, warnings=["frida_no_target_found"], error=msg, started_at=self._started_at, resolution=res.to_dict())

        self._targets = targets
        self._writer = FridaEventWriter(self._config.output, body_preview_max_chars=self._config.body_preview_max_chars)
        self._normalizer = FridaEventNormalizer(run_id=run_id, session_id=session_id)

        import frida  # type: ignore[import-untyped]

        for target in targets:
            if not target.attach_recommended:
                warnings.append(f"frida_attach_skipped:pid={target.pid}:role={target.role}")
                continue
                
            try:
                session = frida.attach(target.pid)
                self._sessions.append(session)
                scripts_loaded = self._load_scripts(session, target)
                if not scripts_loaded and self._config.attach_best_effort:
                    warnings.append(f"frida_no_scripts_loaded:pid={target.pid}")
            except Exception as exc:  # Catch all first, then match types since exceptions might be dynamic
                err_str = str(exc).lower()
                name = type(exc).__name__
                if "processnotfound" in name.lower():
                    warnings.append(f"frida_attach_failed:pid={target.pid}:process_not_found")
                elif "permission" in err_str or "task_for_pid" in err_str or "denied" in err_str:
                    warnings.append(f"frida_permission_denied:pid={target.pid}")
                elif "unable to bind" in err_str and "libsystem" in err_str:
                    warnings.append(f"frida_darwin_symbol_bind_failed:pid={target.pid}:{exc!r}")
                    if "frida_python_arch_mismatch" in res.warnings:
                        warnings.append("frida_use_arm64_python_on_apple_silicon")
                else:
                    warnings.append(f"frida_attach_failed:pid={target.pid}:{exc!r}")

        ok = bool(self._sessions)
        if not ok:
            warnings.append("frida_attach_failed")

        return FridaStartResult(ok=ok, targets=targets, warnings=warnings, started_at=self._started_at, resolution=res.to_dict())

    def stop(self) -> FridaStopResult:
        """Detach from all sessions and return a summary."""
        warnings: list[str] = []
        for script in self._scripts:
            try:
                script.unload()
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"frida_script_unload_error:{exc!r}")
        for session in self._sessions:
            try:
                session.detach()
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"frida_detach_error:{exc!r}")
        self._scripts.clear()
        self._sessions.clear()

        event_count = self._writer.event_count if self._writer else 0
        return FridaStopResult(
            ok=True,
            event_count=event_count,
            stopped_at=_now_iso(),
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Script loading
    # ------------------------------------------------------------------

    def _load_scripts(self, session: Any, target: FridaTarget) -> bool:
        """Load the appropriate JS hook scripts for *target*'s role."""
        scripts_dir = self._config.scripts_dir
        loaded = False

        if target.role == "openclaw_gateway" or target.role == "unknown":
            # Always try the Node trace for gateway / unknown targets
            node_script_path = scripts_dir / "node_trace.js"
            if node_script_path.exists():
                loaded |= self._inject_script(session, node_script_path, target)

            file_script_path = scripts_dir / "file_access_trace.js"
            if file_script_path.exists():
                loaded |= self._inject_script(session, file_script_path, target)

        if target.role == "chrome_browser":
            chrome_script_path = scripts_dir / "chrome_network_trace.js"
            if chrome_script_path.exists():
                loaded |= self._inject_script(session, chrome_script_path, target)

        return loaded

    def _inject_script(self, session: Any, script_path: Path, target: FridaTarget) -> bool:
        """Create, wire the message handler, and load a single JS script."""
        try:
            source = script_path.read_text(encoding="utf-8")
            script = session.create_script(source)
            script.on("message", lambda msg, data, _t=target: self._on_message(msg, data, _t))
            script.load()
            self._scripts.append(script)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to inject %s into pid %s: %s", script_path.name, target.pid, exc)
            return False

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    def _on_message(self, message: dict[str, Any], data: Any, target: FridaTarget) -> None:
        """Handle a single Frida *send()* message from a hook script."""
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        # Enrich with target metadata
        payload.setdefault("process_name", target.name)
        payload.setdefault("process_role", target.role)

        # Normalise
        if self._normalizer is not None:
            event = self._normalizer.normalize(payload)
            if event is not None and self._writer is not None:
                self._writer.write(event.to_dict())
