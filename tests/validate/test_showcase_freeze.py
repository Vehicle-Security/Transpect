from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT / "common"))
sys.path.insert(0, str(SCRIPTS_ROOT / "demo"))

from trace_common import write_json  # noqa: E402


class ShowcaseFreezeTests(unittest.TestCase):
    def make_run(self, root: Path, *, with_codetracer: bool = True, with_frida: bool = True) -> Path:
        run_dir = root / "live" / "runs" / "run-123"
        write_json(run_dir / "manifest.json", {"runId": "run-123", "artifactCount": 2, "eventCount": 3})
        write_json(run_dir / "task_input.json", {"prompt": "Summarize camping comments"})
        write_json(
            run_dir / "trace_index.json",
            {
                "sources": {
                    "behavior": {"status": "ok", "eventCount": 3},
                    "frida": {"status": "degraded", "eventCount": 0, "error": "permission required"},
                }
            },
        )
        write_json(
            run_dir / "security-reasoning" / "final_judgment.json",
            {
                "finalDecision": "block",
                "riskLevel": "critical",
                "reasons": ["Online Agent Defense blocked a high-risk action."],
                "evidence": {
                    "frida": {"status": "degraded", "eventCount": 0, "summary": "permission required"},
                    "codeTracer": {"status": "ok", "summary": "diagnosis ready"},
                },
                "riskChain": {"nodes": [{"label": "Low-trust comment", "eventId": "risk-1"}]},
            },
        )
        write_json(run_dir / "security-reasoning" / "security_state.json", {"riskTimeline": [{"eventId": "risk-1"}]})
        (run_dir / "behavior-events.jsonl").write_text(
            json.dumps({"schemaVersion": "2.0.0", "seq": 1, "ts": "2026-05-08T00:00:00Z", "traceId": "t", "spanId": "s", "kind": "tool", "name": "tool.call", "status": "ok"})
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "merged-trace.jsonl").write_text((run_dir / "behavior-events.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
        if with_frida:
            (run_dir / "frida-events.jsonl").write_text("", encoding="utf-8")
        if with_codetracer:
            write_json(run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json", {"ok": True, "analysis": {"summary": "ready"}})
            write_json(run_dir / "diagnosis" / "codetracer" / "bundle" / "steps.json", [{"id": 1}])
        write_json(run_dir / "artifacts" / "task_repo" / "harness_report.json", {"ok": True})
        return run_dir

    def test_freeze_run_copies_evidence_and_writes_index_entry(self) -> None:
        from freeze_showcase_run import freeze_showcase_run

        root = Path(tempfile.mkdtemp(prefix="showcase-freeze-"))
        run_dir = self.make_run(root)
        showcase_root = root / "state" / "showcase"

        result = freeze_showcase_run(
            run_dir,
            showcase_root=showcase_root,
            showcase_id="staged_attack_block",
            title="Cross-step Waterhole Attack",
            description="低可信评论诱导外部跳转并触发敏感上传，最终被阻断",
        )

        frozen = showcase_root / "staged_attack_block"
        self.assertTrue(result["ok"])
        self.assertTrue((frozen / "manifest.json").exists())
        self.assertTrue((frozen / "security-reasoning" / "final_judgment.json").exists())
        self.assertTrue((frozen / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json").exists())
        payload = json.loads((showcase_root / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["showcases"][0]["id"], "staged_attack_block")
        self.assertEqual(payload["showcases"][0]["decision"], "block")
        self.assertEqual(payload["showcases"][0]["riskLevel"], "critical")
        self.assertEqual(payload["showcases"][0]["fridaStatus"], "degraded")
        self.assertEqual(payload["showcases"][0]["codeTracerStatus"], "ok")
        self.assertEqual(payload["showcases"][0]["evidenceEventCount"], 3)

    def test_freeze_run_updates_existing_index_entry_without_duplicate(self) -> None:
        from freeze_showcase_run import freeze_showcase_run

        root = Path(tempfile.mkdtemp(prefix="showcase-freeze-update-"))
        run_dir = self.make_run(root, with_codetracer=False, with_frida=False)
        showcase_root = root / "state" / "showcase"

        freeze_showcase_run(run_dir, showcase_root=showcase_root, showcase_id="normal_browsing_allow", title="Old", description="Old")
        freeze_showcase_run(run_dir, showcase_root=showcase_root, showcase_id="normal_browsing_allow", title="New", description="New")

        payload = json.loads((showcase_root / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(len(payload["showcases"]), 1)
        self.assertEqual(payload["showcases"][0]["title"], "New")

    def test_freeze_normalizes_frida_attach_failure_as_degraded(self) -> None:
        from freeze_showcase_run import freeze_showcase_run

        root = Path(tempfile.mkdtemp(prefix="showcase-freeze-frida-"))
        run_dir = self.make_run(root)
        final_path = run_dir / "security-reasoning" / "final_judgment.json"
        payload = json.loads(final_path.read_text(encoding="utf-8"))
        payload["evidence"]["frida"]["status"] = "attach_failed"
        final_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        showcase_root = root / "state" / "showcase"

        freeze_showcase_run(run_dir, showcase_root=showcase_root, showcase_id="frida_degraded", title="Frida", description="Frida")

        index = json.loads((showcase_root / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["showcases"][0]["fridaStatus"], "degraded")


if __name__ == "__main__":
    unittest.main()
