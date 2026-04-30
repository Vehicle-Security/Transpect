from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "common"))
sys.path.insert(0, str(ROOT / "scripts" / "export"))

from export_codetracer_bundle import export_bundles  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


class CodeTracerMergedExportTests(unittest.TestCase):
    def test_export_prefers_merged_trace_and_copies_frida_sources(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="codetracer-merged-"))
        run_dir = root / "run-merged"
        write_json(run_dir / "manifest.json", {"schemaVersion": "openclaw.run.v1", "runId": "run-merged", "traceId": "trace-merged"})
        write_json(run_dir / "runtime_status.json", {"schemaVersion": "openclaw.run.runtime.v1"})
        behavior_row = {
            "seq": 1,
            "ts": "2026-04-29T00:00:01Z",
            "traceId": "trace-merged",
            "spanId": "req-1",
            "kind": "request",
            "name": "openclaw.request",
            "status": "ok",
            "runId": "run-merged",
            "preview": {"message": "hello"},
        }
        frida_row = {
            "seq": 2,
            "ts": "2026-04-29T00:00:02Z",
            "kind": "frida",
            "name": "frida.network_event",
            "status": "ok",
            "runId": "run-merged",
            "source": "frida",
            "riskTags": ["upload_candidate"],
        }
        write_jsonl(run_dir / "behavior-events.jsonl", [behavior_row])
        write_jsonl(run_dir / "frida-events.jsonl", [{"event_type": "network_event", "risk_tags": ["upload_candidate"]}])
        write_jsonl(run_dir / "merged-trace.jsonl", [behavior_row, frida_row])
        write_json(run_dir / "trace_index.json", {"schemaVersion": "transpect.agent-defense.trace-index.v1"})

        with patch("export_codetracer_bundle.call_runtime_statuses", return_value=({}, {})):
            result = export_bundles(run_dir=run_dir)

        bundle_dir = Path(result["bundles"][0]["bundlePath"])
        manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(result["inputFile"], str((run_dir / "merged-trace.jsonl").resolve()))
        self.assertEqual(manifest["traceSources"]["frida"]["status"], "ok")
        self.assertTrue((bundle_dir / "source" / "behavior-events.jsonl").exists())
        self.assertTrue((bundle_dir / "source" / "frida-events.jsonl").exists())
        self.assertTrue((bundle_dir / "source" / "merged-trace.jsonl").exists())
        self.assertTrue((bundle_dir / "source" / "trace_index.json").exists())


if __name__ == "__main__":
    unittest.main()
