from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parents[2] / "tools"
sys.path.insert(0, str(SCRIPTS_ROOT / "common"))
sys.path.insert(0, str(SCRIPTS_ROOT / "demo"))

from trace_common import write_json  # noqa: E402


class ShowcaseValidateTests(unittest.TestCase):
    def make_showcase(self, root: Path, showcase_id: str, *, final_judgment: dict | None, trace: bool = True) -> Path:
        run_dir = root / showcase_id
        if final_judgment is not None:
            write_json(run_dir / "security-reasoning" / "final_judgment.json", final_judgment)
        if trace:
            (run_dir / "behavior-events.jsonl").parent.mkdir(parents=True, exist_ok=True)
            (run_dir / "behavior-events.jsonl").write_text(
                json.dumps({"schemaVersion": "2.0.0", "seq": 1, "ts": "2026-05-08T00:00:00Z", "traceId": "t", "spanId": "s", "kind": "tool", "name": "tool.call", "status": "ok"})
                + "\n",
                encoding="utf-8",
            )
        return run_dir

    def write_index(self, root: Path, entries: list[dict]) -> None:
        write_json(root / "index.json", {"schemaVersion": "transpect.showcase.index.v1", "showcases": entries})

    def test_validate_showcase_accepts_degraded_frida_and_available_codetracer(self) -> None:
        from validate_showcase import validate_showcase

        root = Path(tempfile.mkdtemp(prefix="showcase-validate-ok-"))
        run_dir = self.make_showcase(
            root,
            "staged_attack_block",
            final_judgment={
                "finalDecision": "block",
                "riskLevel": "critical",
                "reasons": ["blocked"],
                "evidence": {
                    "frida": {"status": "degraded", "eventCount": 0, "summary": "permission required"},
                    "codeTracer": {"status": "ok", "summary": "diagnosis ready"},
                },
                "riskChain": {"nodes": [{"label": "Low-trust comment"}]},
            },
        )
        self.write_index(root, [{"id": "staged_attack_block", "runDir": str(run_dir), "title": "Block", "description": "Block"}])

        report = validate_showcase(showcase_root=root)

        self.assertTrue(report["ok"])
        self.assertEqual(report["showcases"][0]["decision"], "block")
        self.assertEqual(report["showcases"][0]["fridaStatus"], "degraded")
        self.assertEqual(report["showcases"][0]["codeTracerStatus"], "ok")

    def test_validate_showcase_reports_missing_codetracer_as_unavailable_without_failing(self) -> None:
        from validate_showcase import validate_showcase

        root = Path(tempfile.mkdtemp(prefix="showcase-validate-unavailable-"))
        run_dir = self.make_showcase(
            root,
            "normal_browsing_allow",
            final_judgment={
                "decision": "allow",
                "risk_level": "low",
                "reason": "no risk",
                "evidence": {"frida": {"status": "unavailable"}},
                "task": {"stages": [{"name": "topic_read", "text": "normal browsing"}]},
            },
        )
        self.write_index(root, [{"id": "normal_browsing_allow", "runDir": str(run_dir), "title": "Allow", "description": "Allow"}])

        report = validate_showcase(showcase_root=root)

        self.assertTrue(report["ok"])
        self.assertEqual(report["showcases"][0]["decision"], "allow")
        self.assertEqual(report["showcases"][0]["riskLevel"], "low")
        self.assertEqual(report["showcases"][0]["codeTracerStatus"], "unavailable")

    def test_validate_showcase_marks_missing_final_judgment_as_not_ok(self) -> None:
        from validate_showcase import validate_showcase

        root = Path(tempfile.mkdtemp(prefix="showcase-validate-bad-"))
        run_dir = self.make_showcase(root, "broken", final_judgment=None)
        self.write_index(root, [{"id": "broken", "runDir": str(run_dir), "title": "Broken", "description": "Broken"}])

        report = validate_showcase(showcase_root=root)

        self.assertFalse(report["ok"])
        self.assertTrue(any("final_judgment.json" in issue for issue in report["showcases"][0]["issues"]))

    def test_validate_showcase_can_require_report_model(self) -> None:
        from validate_showcase import validate_showcase

        root = Path(tempfile.mkdtemp(prefix="showcase-validate-report-model-"))
        run_dir = self.make_showcase(
            root,
            "staged_attack_block",
            final_judgment={
                "finalDecision": "block",
                "riskLevel": "critical",
                "reasons": ["blocked"],
                "evidence": {"frida": {"status": "degraded"}, "codeTracer": {"status": "ok"}},
                "riskChain": {"nodes": [{"label": "Low-trust comment"}]},
            },
        )
        self.write_index(root, [{"id": "staged_attack_block", "runDir": str(run_dir), "title": "Block", "description": "Block"}])

        missing_report = validate_showcase(showcase_root=root, require_report_model=True)
        self.assertFalse(missing_report["ok"])
        self.assertFalse(missing_report["showcases"][0]["hasReportModel"])

        write_json(run_dir / "report_model.json", {"id": "staged_attack_block", "verdict": "block"})
        ok_report = validate_showcase(showcase_root=root, require_report_model=True)
        self.assertTrue(ok_report["ok"])
        self.assertTrue(ok_report["showcases"][0]["hasReportModel"])


if __name__ == "__main__":
    unittest.main()
