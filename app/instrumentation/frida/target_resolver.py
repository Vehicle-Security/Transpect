"""Resolve target processes for Frida attachment.

Supports: auto | node | chrome | pid:<PID> | name:<PROCESS_NAME>
"""

from __future__ import annotations

import platform
import re
import subprocess
from typing import Any

from app.instrumentation.frida.event_models import FridaTarget

# Tokens used to identify OpenClaw gateway processes in command lines.
_OPENCLAW_TOKENS = ("openclaw", "openclaw-gateway", "oc-gateway")
# CDP / debug ports commonly used by OpenClaw-launched Chrome.
_CHROME_PORTS = ("18800", "9222")
_CHROME_NAMES = ("google chrome", "chromium", "chrome")


def _ps_list() -> list[dict[str, Any]]:
    """Return a list of running processes with pid, name, cmdline (macOS/Linux)."""
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,comm,args"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:  # noqa: BLE001
        return []
    rows: list[dict[str, Any]] = []
    for line in result.stdout.strip().splitlines()[1:]:
        parts = line.strip().split(None, 2)
        if len(parts) < 2:
            continue
        pid_str, name = parts[0], parts[1]
        cmdline = parts[2] if len(parts) > 2 else name
        try:
            pid = int(pid_str)
            if pid <= 1:
                continue
            rows.append({"pid": pid, "name": name, "cmdline": cmdline})
        except ValueError:
            continue
    return rows


def _is_system_process(proc: dict[str, Any]) -> bool:
    name = proc.get("name", "").lower()
    if name in ("launchd", "kernel_task", "sysmond", "logd", "usbd"):
        return True
    return False

def _classify(proc: dict[str, Any]) -> str:
    """Classify a process as openclaw_gateway, chrome_browser, or unknown."""
    if _is_system_process(proc):
        return "system_process"
    cmdline_lower = proc.get("cmdline", "").lower()
    name_lower = proc.get("name", "").lower()
    if any(token in cmdline_lower for token in _OPENCLAW_TOKENS):
        return "openclaw_gateway"
    if any(token in name_lower for token in _CHROME_NAMES):
        return "chrome_browser"
    return "unknown"


class TargetResolver:
    """Resolve which OS processes to attach Frida to."""

    def resolve(self, target_spec: str) -> list[FridaTarget]:
        """Return a list of ``FridaTarget`` matching *target_spec*.

        Supported formats:
        - ``auto``            – heuristic: OpenClaw node + Chrome
        - ``node``            – only OpenClaw gateway node process
        - ``chrome``          – only Chrome / Chromium processes
        - ``pid:<PID>``       – single PID
        - ``name:<NAME>``     – match process name substring
        """
        spec = (target_spec or "auto").strip().lower()

        if spec.startswith("pid:"):
            return self._resolve_pid(spec)
        if spec.startswith("name:"):
            return self._resolve_name(spec)
        if spec == "node":
            return self._resolve_node()
        if spec == "chrome":
            return self._resolve_chrome()
        return self._resolve_auto()

    # ------------------------------------------------------------------

    def _resolve_pid(self, spec: str) -> list[FridaTarget]:
        match = re.match(r"pid:(\d+)", spec)
        if not match:
            return []
        pid = int(match.group(1))
        for proc in _ps_list():
            if proc["pid"] == pid:
                role = _classify(proc)
                return [FridaTarget(pid=pid, name=proc["name"], cmdline=proc["cmdline"], role=role, platform=platform.system(), experimental=(role == "chrome_browser"), attach_recommended=(role not in ("system_process", "unknown")))]
        return [FridaTarget(pid=pid, name="<unknown>", cmdline="", role="unknown", platform=platform.system(), experimental=False, attach_recommended=False)]

    def _resolve_name(self, spec: str) -> list[FridaTarget]:
        name_query = spec.removeprefix("name:").strip()
        targets: list[FridaTarget] = []
        for proc in _ps_list():
            if name_query in proc["name"].lower() or name_query in proc.get("cmdline", "").lower():
                role = _classify(proc)
                targets.append(FridaTarget(pid=proc["pid"], name=proc["name"], cmdline=proc["cmdline"], role=role, platform=platform.system(), experimental=(role == "chrome_browser"), attach_recommended=(role not in ("system_process", "unknown"))))
        return targets

    def _resolve_node(self) -> list[FridaTarget]:
        targets: list[FridaTarget] = []
        for proc in _ps_list():
            if _classify(proc) == "openclaw_gateway":
                targets.append(FridaTarget(pid=proc["pid"], name=proc["name"], cmdline=proc["cmdline"], role="openclaw_gateway", platform=platform.system(), experimental=False, attach_recommended=True))
        return targets

    def _resolve_chrome(self) -> list[FridaTarget]:
        targets: list[FridaTarget] = []
        for proc in _ps_list():
            if _classify(proc) != "chrome_browser":
                continue
            cmdline_lower = proc.get("cmdline", "").lower()
            # Prefer Chrome instances launched with OpenClaw profile or debug port.
            has_openclaw_profile = any(token in cmdline_lower for token in _OPENCLAW_TOKENS)
            has_debug_port = any(port in cmdline_lower for port in _CHROME_PORTS)
            role = "chrome_browser"
            if has_openclaw_profile or has_debug_port:
                # Insert at front so callers attach more relevant processes first.
                targets.insert(0, FridaTarget(pid=proc["pid"], name=proc["name"], cmdline=proc["cmdline"], role=role, platform=platform.system(), experimental=True, attach_recommended=True))
            else:
                targets.append(FridaTarget(pid=proc["pid"], name=proc["name"], cmdline=proc["cmdline"], role=role, platform=platform.system(), experimental=True, attach_recommended=True))
        return targets

    def _resolve_auto(self) -> list[FridaTarget]:
        return self._resolve_node() + self._resolve_chrome()
