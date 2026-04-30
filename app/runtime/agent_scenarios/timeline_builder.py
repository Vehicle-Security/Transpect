"""Builds a global chronologically sorted timeline from multiple trace sources."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.runtime.agent_scenarios.schema import AgentScenario
from app.runtime.agent_scenarios.trace_collector import _parse_ts


class TimelineBuilder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def _add_event(self, timestamp: str, source: str, event_type: str, summary: str, original: dict[str, Any] | None = None) -> None:
        if not timestamp:
            return
        self.events.append({
            "t": timestamp,
            "source": source,
            "type": event_type,
            "summary": summary,
            "original": original,
        })

    def process_agent_result(self, agent_result: Any | None, scenario: AgentScenario, started_at: str) -> None:
        self._add_event(started_at, "agent", "user_prompt", scenario.user_prompt)
        if agent_result and getattr(agent_result, "ok", False):
            # Not an exact timestamp, but indicates the end of the agent run
            self._add_event(started_at, "agent", "final_answer", "Agent run completed")

    def process_behavior_events(self, raw_events: list[dict[str, Any]]) -> None:
        for event in raw_events:
            ts = event.get("ts") or event.get("timestamp")
            if not ts:
                continue
            kind = event.get("kind", "unknown")
            if kind == "tool":
                name = event.get("name") or event.get("tool", {}).get("name", "unknown_tool")
                self._add_event(ts, "openclaw", "tool_call", name, original=event)
            elif kind == "request":
                self._add_event(ts, "openclaw", "request", event.get("name", ""), original=event)

    def process_browser_events(self, browser_events: list[Any]) -> None:
        for event in browser_events:
            summary = f"{event.tool_name} {event.url_after}"
            if event.element_text:
                summary += f" [text: {event.element_text}]"
            self._add_event(event.timestamp, "browser", event.event_type, summary.strip())

    def process_server_events(self, server_events_path: Path | None) -> None:
        if not server_events_path or not server_events_path.exists():
            return
        with server_events_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    ts = event.get("ts") or event.get("timestamp")
                    req = event.get("request", {})
                    method = req.get("method", "GET")
                    url = req.get("url", "")
                    self._add_event(ts, "server", "server_request", f"{method} {url}")
                except Exception:
                    continue

    def process_frida_events(self, frida_events: list[dict[str, Any]]) -> None:
        for event in frida_events:
            event_type = event.get("event_type", "unknown")
            normalized = event.get("normalized", {})
            summary = ""
            if event_type == "network_event":
                summary = f"{normalized.get('method', 'GET')} {normalized.get('url', '')}"
            elif event_type == "command_execution_event":
                summary = normalized.get("command", "")
            elif event_type == "file_access_event":
                summary = f"{normalized.get('operation', 'access')} {normalized.get('path', '')}"
            
            tags = event.get("risk_tags", [])
            if "no_user_consent" in tags:
                summary += " consent=false"

            self._add_event(event.get("timestamp", ""), "frida", event_type, summary.strip())

    def process_decision(self, decision: Any, ended_at: str) -> None:
        summary = f"{getattr(decision, 'decision', 'allow')} / {getattr(decision, 'severity', 'low')}"
        if not getattr(decision, "experiment_validity", True):
            summary += " (invalid experiment)"
        self._add_event(ended_at, "analyzer", "decision", summary)

    def build_and_write(self, output_path: Path) -> list[dict[str, Any]]:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Sort by timestamp, treating missing/unparseable timestamps carefully
        def get_ts(evt: dict[str, Any]) -> datetime:
            parsed = _parse_ts(evt["t"])
            return parsed if parsed else datetime.min
            
        sorted_events = sorted(self.events, key=get_ts)
        # remove original payloads before writing to disk for the timeline.json
        disk_events = [
            {k: v for k, v in evt.items() if k != "original"} for evt in sorted_events
        ]
        
        output_path.write_text(json.dumps(disk_events, ensure_ascii=False, indent=2), encoding="utf-8")
        return sorted_events
