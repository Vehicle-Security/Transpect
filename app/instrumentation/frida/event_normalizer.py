"""Normalise raw Frida hook payloads into structured FridaEvents with risk tags."""

from __future__ import annotations

import uuid
from typing import Any

from app.instrumentation.frida.config import SENSITIVE_PATH_FRAGMENTS
from app.instrumentation.frida.event_models import FridaEvent


def _ts(payload: dict[str, Any]) -> str:
    return str(payload.get("ts") or payload.get("timestamp") or "")


class FridaEventNormalizer:
    """Convert raw Frida messages into :class:`FridaEvent` instances.

    Risk-tagging heuristics are intentionally conservative — false positives
    are preferable to missed indicators in a security-analysis pipeline.
    """

    def __init__(self, *, run_id: str | None = None, session_id: str | None = None) -> None:
        self._run_id = run_id
        self._session_id = session_id

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def normalize(self, raw: dict[str, Any]) -> FridaEvent | None:
        """Return a ``FridaEvent`` or ``None`` if the payload is not recognised."""
        kind = str(raw.get("kind") or "")
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}

        if kind == "process_spawn":
            return self._command_event(raw, payload)
        if kind.startswith("file_"):
            return self._file_event(raw, payload, kind)
        if kind in {"socket_connect", "socket_send", "socket_recv", "socket_accept"}:
            return self._network_event(raw, payload, kind)
        if kind == "frida_ready":
            return self._process_event(raw, payload)
        # Silently skip control / unrecognised kinds.
        return None

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _base(self, raw: dict[str, Any], event_type: str) -> dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": _ts(raw),
            "source": "frida",
            "run_id": self._run_id,
            "session_id": self._session_id,
            "pid": raw.get("pid"),
            "process_name": str(raw.get("process_name") or ""),
            "process_role": str(raw.get("process_role") or "unknown"),
            "event_type": event_type,
            "raw": raw,
        }

    def _process_event(self, raw: dict[str, Any], payload: dict[str, Any]) -> FridaEvent:
        base = self._base(raw, "process_event")
        base["normalized"] = {"action": "attach", "message": payload.get("message", "")}
        base["risk_tags"] = []
        return FridaEvent(**base)

    def _command_event(self, raw: dict[str, Any], payload: dict[str, Any]) -> FridaEvent:
        base = self._base(raw, "command_execution_event")
        command = str(payload.get("commandLine") or payload.get("command") or "")
        args = payload.get("args") or []
        base["normalized"] = {
            "command": command,
            "args": args,
            "cwd": payload.get("cwd"),
            "api": payload.get("api"),
        }
        base["risk_tags"] = self._command_risk_tags(command, args)
        return FridaEvent(**base)

    def _file_event(self, raw: dict[str, Any], payload: dict[str, Any], kind: str) -> FridaEvent:
        base = self._base(raw, "file_access_event")
        file_path = str(payload.get("path") or "")
        operation = kind.replace("file_", "")
        base["normalized"] = {
            "operation": operation,
            "path": file_path,
            "flags": payload.get("flags"),
        }
        base["risk_tags"] = self._file_risk_tags(file_path)
        return FridaEvent(**base)

    def _network_event(self, raw: dict[str, Any], payload: dict[str, Any], kind: str) -> FridaEvent:
        base = self._base(raw, "network_event")
        method = str(payload.get("method") or "").upper()
        url = str(payload.get("url") or "")
        body_preview = str(payload.get("body_preview") or payload.get("previewAscii") or "")
        base["normalized"] = {
            "method": method,
            "url": url,
            "host": payload.get("host") or payload.get("remoteIp") or "",
            "port": payload.get("remotePort"),
            "protocol": payload.get("protocol") or "",
            "request_body_preview": body_preview,
            "api": payload.get("api") or kind.replace("socket_", ""),
        }
        base["risk_tags"] = self._network_risk_tags(method, url, body_preview)
        return FridaEvent(**base)

    # ------------------------------------------------------------------
    # Risk tagging
    # ------------------------------------------------------------------

    @staticmethod
    def _command_risk_tags(command: str, args: Any) -> list[str]:
        tags: list[str] = []
        full = (command + " " + " ".join(str(a) for a in (args or []))).lower()
        if any(tok in full for tok in ("curl", "wget")):
            tags.append("non_browser_network_bypass")
        if any(tok in full for tok in ("exec", "spawn", "fork")):
            tags.append("child_process_spawn")
        return sorted(set(tags))

    @staticmethod
    def _file_risk_tags(path: str) -> list[str]:
        path_lower = path.lower()
        if "/.openclaw/" in path_lower or "/node_modules/openclaw/" in path_lower:
            return ["runtime_config_access"]
        tags: list[str] = ["local_file_access"]
        if any(frag in path_lower for frag in SENSITIVE_PATH_FRAGMENTS):
            tags.append("sensitive_file_access")
        if any(tok in path_lower for tok in ("id_rsa", "id_ed25519", "credential", "token", ".env")):
            tags.append("credential_file_candidate")
        if "/tmp/openclaw/uploads" in path_lower:
            tags.append("upload_source_candidate")
        return sorted(set(tags))

    @staticmethod
    def _network_risk_tags(method: str, url: str, body_preview: str) -> list[str]:
        tags: list[str] = ["network_request"]
        combined = (url + " " + body_preview).lower()
        if method == "POST":
            tags.append("post_request")
        if "upload" in combined:
            tags.append("upload_candidate")
        if "consent=false" in combined:
            tags.append("no_user_consent")
        if any(tok in combined for tok in ("photo", "image", "file")):
            tags.append("file_upload_candidate")
        if not any(tok in url.lower() for tok in ("127.0.0.1", "localhost", "0.0.0.0")):
            tags.append("external_network")
        return sorted(set(tags))
