from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import (
    BEHAVIOR_PLUGIN_VENDOR_PATH,
    OPENCLAW_CONFIG_PATH,
    TRACE_LIVE_DIR,
    TRACE_LIVE_RUNS_DIR,
    TRACE_ROOT,
    build_runs_index_payload,
    read_json,
)


TOPOLOGY_SCHEMA_VERSION = "transpect.trace.topology.v1"


def normalize_path(path: str | Path | None) -> str | None:
    if path is None:
        return None
    return str(path).replace("\\", "/")


def read_live_url() -> str | None:
    shared_js = TRACE_ROOT / "viewer" / "shared.js"
    if not shared_js.exists():
        return None
    text = shared_js.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"export\s+const\s+RUNS_INDEX_URL\s*=\s*['\"]([^'\"]+)['\"]", text)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def behavior_plugin_state(config: dict[str, Any]) -> dict[str, Any]:
    plugins = config.get("plugins") if isinstance(config, dict) else {}
    entries = plugins.get("entries") if isinstance(plugins, dict) else {}
    load = plugins.get("load") if isinstance(plugins, dict) else {}
    behavior = entries.get("behavior-mediator") if isinstance(entries, dict) else {}
    behavior_config = behavior.get("config") if isinstance(behavior, dict) else {}
    load_paths = list(load.get("paths") or []) if isinstance(load, dict) else []
    active_plugin_path = next(
        (
            Path(item).resolve()
            for item in load_paths
            if isinstance(item, str) and item.lower().endswith("openclaw-behavior-mediator")
        ),
        None,
    )
    return {
        "enabled": isinstance(behavior, dict) and behavior.get("enabled") is True,
        "config": behavior_config if isinstance(behavior_config, dict) else {},
        "loadPaths": [normalize_path(item) for item in load_paths if isinstance(item, str)],
        "activePluginPath": normalize_path(active_plugin_path) if active_plugin_path else None,
    }


def detect_runs_support(plugin_root: Path | None) -> dict[str, Any]:
    if plugin_root is None or not plugin_root.exists():
        return {
            "pluginExists": False,
            "schemaSupportsRuns": False,
            "runtimeMentionsRuns": False,
            "runsFields": [],
        }
    plugin_schema = read_json(plugin_root / "openclaw.plugin.json", default={}) or {}
    properties = (
        ((plugin_schema.get("configSchema") or {}).get("properties"))
        if isinstance(plugin_schema, dict)
        else {}
    )
    if not isinstance(properties, dict):
        properties = {}
    runs_fields = sorted(field for field in properties.keys() if "run" in field.lower() or "diagnosis" in field.lower())
    runtime_text = (plugin_root / "index.js").read_text(encoding="utf-8", errors="replace")
    return {
        "pluginExists": True,
        "schemaSupportsRuns": bool(runs_fields),
        "runtimeMentionsRuns": "runsdirectory" in runtime_text.lower(),
        "runsFields": runs_fields,
    }


def current_paths(config: dict[str, Any]) -> dict[str, Any]:
    behavior = behavior_plugin_state(config)
    behavior_config = behavior["config"] if isinstance(behavior.get("config"), dict) else {}
    runs_directory = Path(behavior_config.get("runsDirectory")).resolve() if behavior_config.get("runsDirectory") else None
    plugin_path = Path(behavior["activePluginPath"]).resolve() if behavior.get("activePluginPath") else None
    runs_support = detect_runs_support(plugin_path)
    live_url = read_live_url()
    runs_index = build_runs_index_payload(TRACE_LIVE_RUNS_DIR)
    viewer_path = (TRACE_ROOT / "viewer" / "index.html").resolve()
    return {
        "schemaVersion": TOPOLOGY_SCHEMA_VERSION,
        "repoRoot": normalize_path(TRACE_ROOT.resolve()),
        "openclawConfigPath": normalize_path(OPENCLAW_CONFIG_PATH.resolve()),
        "viewer": {
            "indexPath": normalize_path(viewer_path),
            "liveUrl": live_url,
            "resolvedLivePath": normalize_path((viewer_path.parent / live_url).resolve()) if live_url else None,
        },
        "behaviorMediator": {
            "enabled": behavior["enabled"],
            "activePluginPath": behavior.get("activePluginPath"),
            "configuredRunsDirectory": normalize_path(runs_directory) if runs_directory else None,
            "configKeys": sorted(behavior_config.keys()),
            "runsSupport": runs_support,
        },
        "live": {
            "runsDir": {
                "path": normalize_path(TRACE_LIVE_RUNS_DIR.resolve()),
                "runCount": runs_index.get("runCount"),
                "latestRun": runs_index.get("latestRun"),
            },
            "archiveDir": normalize_path((TRACE_LIVE_DIR / "archive").resolve()),
        },
        "pathMap": [
            {
                "layer": "gateway-config",
                "reads": normalize_path(OPENCLAW_CONFIG_PATH.resolve()),
                "purpose": "Current OpenClaw runtime plugin configuration.",
            },
            {
                "layer": "behavior-plugin",
                "reads": behavior.get("activePluginPath"),
                "purpose": "Behavior mediator implementation that writes canonical events into live/runs/<runId>/.",
            },
            {
                "layer": "run-root",
                "reads": normalize_path(runs_directory) if runs_directory else normalize_path(TRACE_LIVE_RUNS_DIR.resolve()),
                "purpose": "Canonical per-task trace storage root.",
            },
            {
                "layer": "viewer",
                "reads": normalize_path((viewer_path.parent / live_url).resolve()) if live_url else None,
                "purpose": "Viewer entrypoint for the runs index.",
            },
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Explain which repository and paths currently control Transpect trace runtime.")
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format.",
    )
    args = parser.parse_args()

    config = read_json(OPENCLAW_CONFIG_PATH, default={}) or {}
    payload = current_paths(config)
    if args.format == "text":
        print("Current Transpect Trace Topology")
        print(f"- Repo root: {payload['repoRoot']}")
        print(f"- OpenClaw config: {payload['openclawConfigPath']}")
        print(f"- behavior-mediator plugin: {payload['behaviorMediator']['activePluginPath']}")
        print(f"- runs root: {payload['live']['runsDir']['path']}")
        print(f"- viewer reads: {payload['viewer']['resolvedLivePath']}")
        print(f"- runs count: {payload['live']['runsDir']['runCount']}")
        return
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
