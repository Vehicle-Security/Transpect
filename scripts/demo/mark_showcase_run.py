from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from trace_common import normalize_path, now_utc_iso, read_json, write_json, write_runs_index  # noqa: E402


def mark_showcase_run(run_dir: Path | str, *, reason: str | None = None) -> dict[str, Any]:
    resolved = Path(run_dir).resolve()
    manifest_path = resolved / "manifest.json"
    manifest = read_json(manifest_path, default=None)
    if not isinstance(manifest, dict):
        raise FileNotFoundError(f"run manifest not found: {manifest_path}")

    manifest["showcase"] = True
    manifest["showcaseReason"] = reason or "Transpect product demo showcase run"
    manifest["showcaseMarkedAt"] = now_utc_iso()
    write_json(manifest_path, manifest)
    index_path = write_runs_index(resolved.parent)
    return {
        "ok": True,
        "runId": manifest.get("runId") or resolved.name,
        "runDir": normalize_path(resolved),
        "indexPath": normalize_path(index_path.resolve()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Mark a Transpect run as the preferred showcase run.")
    parser.add_argument("--run-dir", required=True, help="Path to live/runs/<runId>.")
    parser.add_argument("--reason", default=None, help="Optional reason stored in manifest.json.")
    args = parser.parse_args()
    result = mark_showcase_run(Path(args.run_dir), reason=args.reason)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
