from __future__ import annotations

import re
from pathlib import Path
from typing import Any


URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
EXEC_TOOL_NAMES = {"exec", "bash", "shell", "shell_command", "run_command", "command"}
WEB_FETCH_TOOL_NAMES = {"web_fetch", "fetch", "http_fetch", "http_get", "web.fetch"}
NETWORK_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def extract_urls(text: str) -> list[str]:
    return [match.rstrip(").,;]") for match in URL_RE.findall(text or "")]


def _tool_name(action: dict[str, Any]) -> str:
    raw = action.get("toolName") or action.get("tool_name") or action.get("name") or action.get("actionType") or action.get("action")
    return str(raw or "").strip().lower()


def _command_text(action: dict[str, Any]) -> str:
    return str(action.get("command") or action.get("cmd") or action.get("script") or action.get("commandLine") or "")


def normalize_action(action: dict[str, Any] | None) -> dict[str, Any]:
    # Coordination-layer normalization: maps toolName → actionType to drive
    # policy matching (evaluate_policy).  Distinct from the capability-layer
    # classification in guardrail.security.risk_scoring.action_name(), which drives
    # risk scoring.  The two lookup tables serve different purposes and may
    # produce different results for the same input.
    source = dict(action or {})
    tool = _tool_name(source)
    url = str(source.get("url") or source.get("href") or source.get("target") or "").strip()
    command = _command_text(source)
    method = str(source.get("method") or "").upper()

    if tool in WEB_FETCH_TOOL_NAMES and url.lower().startswith(("http://", "https://")):
        source["actionType"] = "network_request" if method in NETWORK_METHODS else "open_external_link"
        source["target"] = url
        source.setdefault("url", url)
        source["normalizedBy"] = "agent_defense.normalizers.web_fetch"
        return source

    if tool in EXEC_TOOL_NAMES or command:
        source["actionType"] = "execute_command"
        if command:
            source["target"] = command
            source.setdefault("command", command)
        source["commandUrls"] = extract_urls(command)
        source["normalizedBy"] = "agent_defense.normalizers.exec"
        return source

    if tool in {"read", "read_file", "local_file_read"}:
        source["actionType"] = "read_local_file"
        source["target"] = str(source.get("path") or source.get("target") or "")
        source["normalizedBy"] = "agent_defense.normalizers.file"
        return source

    if "upload" in tool:
        source["actionType"] = "upload_photo" if "photo" in tool or "image" in tool else "upload_file"
        source["target"] = str(source.get("path") or source.get("target") or source.get("url") or "")
        source["normalizedBy"] = "agent_defense.normalizers.upload"
        return source

    if tool in {"browser.navigate", "navigate", "open_url"} and url.lower().startswith(("http://", "https://")):
        source["actionType"] = "open_external_link"
        source["target"] = url
        source.setdefault("url", url)
        source["normalizedBy"] = "agent_defense.normalizers.browser"
        return source

    return source


def normalize_behavior_event(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    normalized.setdefault("source", "openclaw")
    normalized.setdefault("traceSource", "behavior-events.jsonl")
    return normalized


def normalize_frida_event(row: dict[str, Any], *, seq: int, run_id: str | None = None) -> dict[str, Any]:
    event_type = str(row.get("event_type") or row.get("eventType") or row.get("kind") or "event")
    timestamp = row.get("timestamp") or row.get("ts")
    normalized_payload = row.get("normalized") if isinstance(row.get("normalized"), dict) else {}
    return {
        "schemaVersion": "transpect.merged-trace.v1",
        "seq": seq,
        "sourceSeq": row.get("seq"),
        "ts": timestamp,
        "kind": "frida",
        "name": f"frida.{event_type}",
        "status": "ok",
        "runId": row.get("run_id") or row.get("runId") or run_id,
        "sessionKey": row.get("session_id") or row.get("sessionId"),
        "source": "frida",
        "traceSource": "frida-events.jsonl",
        "eventType": event_type,
        "riskTags": list(row.get("risk_tags") or row.get("riskTags") or []),
        "preview": {
            "eventType": event_type,
            "riskTags": list(row.get("risk_tags") or row.get("riskTags") or []),
            "normalized": normalized_payload,
        },
        "evidence": {
            "frida": row,
            "normalized": normalized_payload,
        },
    }


def path_status(path: Path) -> str:
    if path.exists():
        return "ok"
    return "missing"
