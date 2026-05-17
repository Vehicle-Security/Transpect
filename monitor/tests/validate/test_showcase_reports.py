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


class ShowcaseReportModelTests(unittest.TestCase):
    def make_showcase(
        self,
        root: Path,
        showcase_id: str,
        *,
        final_judgment: dict,
        security_state: dict | None = None,
        manifest: dict | None = None,
        frida_text: str | None = "",
        codetracer: bool = True,
    ) -> Path:
        run_dir = root / showcase_id
        write_json(run_dir / "manifest.json", manifest or {"runId": f"run-{showcase_id}", "eventCount": 2})
        write_json(run_dir / "task_input.json", {"prompt": "Summarize camping comments"})
        write_json(
            run_dir / "trace_index.json",
            {
                "sources": {
                    "behavior": {"status": "ok", "eventCount": 2},
                    "frida": {"status": "degraded", "eventCount": 0},
                }
            },
        )
        write_json(run_dir / "security-reasoning" / "final_judgment.json", final_judgment)
        write_json(run_dir / "security-reasoning" / "security_state.json", security_state or {})
        (run_dir / "behavior-events.jsonl").parent.mkdir(parents=True, exist_ok=True)
        (run_dir / "behavior-events.jsonl").write_text(
            "\n".join(
                [
                    json.dumps({"eventId": "evt-1", "kind": "navigation", "name": "browser.goto", "preview": {"url": "http://example.test"}}),
                    json.dumps({"eventId": "evt-2", "kind": "security", "name": "security_intervention", "status": "warn"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "merged-trace.jsonl").write_text((run_dir / "behavior-events.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
        if frida_text is not None:
            (run_dir / "frida-events.jsonl").write_text(frida_text, encoding="utf-8")
        if codetracer:
            write_json(run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json", {"ok": True, "analysis": {"summary": "diagnosis ready"}})
            write_json(run_dir / "diagnosis" / "codetracer" / "bundle" / "steps.json", [{"id": 1, "summary": "step"}])
        return run_dir

    def write_index(self, root: Path, entries: list[dict]) -> None:
        write_json(root / "index.json", {"schemaVersion": "transpect.showcase.index.v1", "showcases": entries})

    def test_build_report_model_from_observed_chain_and_degraded_frida(self) -> None:
        from build_showcase_reports import build_showcase_reports

        root = Path(tempfile.mkdtemp(prefix="showcase-report-observed-"))
        final_judgment = {
            "runId": "run-observed",
            "finalDecision": "block",
            "riskLevel": "critical",
            "reasons": ["Online Agent Defense blocked a high-risk action."],
            "riskChain": {
                "nodes": [
                    {"summary": "Plan step open_external_link inspected. Plan opens an external link.", "eventId": "evt-1"},
                    {"summary": "Bypass escalation: command-line network access targets a stopped URL.", "eventId": "evt-2"},
                ]
            },
            "evidence": {
                "frida": {"status": "attach_failed", "eventCount": 0, "degradedReason": "permission required"},
                "codeTracer": {"status": "ok", "summary": "diagnosis ready"},
                "bypassDetected": True,
            },
        }
        run_dir = self.make_showcase(root, "staged_attack_block", final_judgment=final_judgment, manifest={"runId": "run-observed"})
        self.write_index(root, [{"id": "staged_attack_block", "runDir": str(run_dir), "title": "Block", "description": "Block"}])

        result = build_showcase_reports(showcase_root=root)

        report = json.loads((run_dir / "report_model.json").read_text(encoding="utf-8"))
        self.assertTrue(result["ok"])
        self.assertEqual(report["verdict"], "block")
        self.assertEqual(report["dataSource"], "real_run")
        self.assertEqual(report["sourceRunId"], "run-observed")
        self.assertIn("cross-step risk chain", report["securityConclusion"])
        self.assertEqual(report["pipeline"][1]["status"], "ok")
        self.assertEqual(report["pipeline"][1]["outcome"], "blocked")
        self.assertEqual(report["pipeline"][2]["status"], "degraded")
        self.assertEqual(report["pipeline"][2]["outcome"], "attach_failed")
        self.assertEqual(report["pipeline"][3]["status"], "ok")
        self.assertEqual(report["pipeline"][3]["outcome"], "diagnosis_ready")
        self.assertEqual(report["pipeline"][4]["status"], "ok")
        self.assertEqual(report["pipeline"][4]["outcome"], "critical_risk")
        self.assertEqual(report["riskChain"][0]["source"], "observed")
        self.assertEqual(report["riskChain"][0]["label"], "External Navigation")
        self.assertEqual(report["riskChain"][1]["label"], "Bypass Escalation")
        self.assertEqual(report["riskChain"][0]["evidenceCount"], 1)
        self.assertEqual(report["riskChain"][0]["relatedEvents"], ["evt-1"])
        self.assertEqual(report["previews"]["runtime"][0]["summary"], "browser.goto -> http://example.test")
        self.assertNotIn("preview", report["previews"]["runtime"][0])
        self.assertTrue(any(item["source"] == "Final Judgment" and item["severity"] == "critical" for item in report["findings"]))

    def test_build_report_model_compresses_duplicate_risk_chain_nodes(self) -> None:
        from build_showcase_reports import build_showcase_reports

        root = Path(tempfile.mkdtemp(prefix="showcase-report-compressed-"))
        final_judgment = {
            "runId": "run-compressed",
            "finalDecision": "block",
            "riskLevel": "critical",
            "reason": "Bypass escalation evidence was found in the merged trace.",
            "riskChain": {
                "nodes": [
                    {"summary": "Plan step open_external_link inspected. Plan opens an external link.", "eventId": "evt-1"},
                    {"summary": "Plan step open_external_link inspected. Plan opens an external link.", "eventId": "evt-2"},
                    {"summary": "low-trust-external-navigation: Low-trust external navigation requires user confirmation.", "eventId": "evt-3"},
                ]
            },
            "evidence": {"frida": {"status": "unavailable"}, "codeTracer": {"status": "ok"}},
        }
        run_dir = self.make_showcase(root, "staged_attack_block", final_judgment=final_judgment)
        self.write_index(root, [{"id": "staged_attack_block", "runDir": str(run_dir), "title": "Block", "description": "Block"}])

        build_showcase_reports(showcase_root=root)

        report = json.loads((run_dir / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual([node["label"] for node in report["riskChain"]], ["External Navigation", "Low-trust Trigger"])
        self.assertEqual(report["riskChain"][0]["evidenceCount"], 2)
        self.assertEqual(report["riskChain"][0]["relatedEvents"], ["evt-1", "evt-2"])

    def test_build_report_model_falls_back_to_scenario_stages_and_missing_codetracer(self) -> None:
        from build_showcase_reports import build_showcase_reports

        root = Path(tempfile.mkdtemp(prefix="showcase-report-scenario-"))
        final_judgment = {
            "decision": "allow",
            "risk_level": "low",
            "reason": "No risk found.",
            "task": {"stages": [{"name": "topic_read", "text": "Normal browsing"}]},
            "evidence": {"frida": {"status": "unavailable"}},
        }
        run_dir = self.make_showcase(
            root,
            "normal_browsing_allow",
            final_judgment=final_judgment,
            manifest={"runId": "fixture-run", "generatedBy": "designed_showcase_fixture"},
            frida_text=None,
            codetracer=False,
        )
        self.write_index(root, [{"id": "normal_browsing_allow", "runDir": str(run_dir), "title": "Allow", "description": "Allow"}])

        build_showcase_reports(showcase_root=root)

        report = json.loads((run_dir / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(report["verdict"], "allow")
        self.assertEqual(report["dataSource"], "curated_fixture")
        self.assertEqual(report["pipeline"][2]["status"], "unavailable")
        self.assertEqual(report["pipeline"][3]["status"], "unavailable")
        self.assertEqual(report["riskChain"][0]["source"], "scenario")
        self.assertTrue(any("Continue monitoring" in item for item in report["recommendations"]))

    def test_build_report_model_uses_canonical_trace_metrics_when_available(self) -> None:
        from build_showcase_reports import build_showcase_reports

        root = Path(tempfile.mkdtemp(prefix="showcase-report-canonical-"))
        final_judgment = {
            "runId": "run-canonical",
            "finalDecision": "block",
            "riskLevel": "critical",
            "reasons": ["blocked"],
            "evidence": {"frida": {"status": "ok", "eventCount": 1}, "codeTracer": {"status": "ok"}},
        }
        run_dir = self.make_showcase(root, "staged_attack_block", final_judgment=final_judgment, manifest={"runId": "run-canonical"})
        write_json(
            run_dir / "canonical_trace.json",
            {
                "schemaVersion": "transpect.canonical_trace.v1",
                "traceId": "trace-canonical",
                "runId": "run-canonical",
                "rootSpanId": "span-root",
                "spans": [
                    {"spanId": "span-root", "kind": "AGENT_RUN", "source": "manifest"},
                    {"spanId": "span-tool", "kind": "TOOL_CALL", "source": "behavior_mediator"},
                ],
                "events": [{"eventId": "evt-tool"}],
                "sources": {"behavior_mediator": {"status": "ok", "eventCount": 1}},
            },
        )
        self.write_index(root, [{"id": "staged_attack_block", "runDir": str(run_dir), "title": "Block", "description": "Block"}])

        build_showcase_reports(showcase_root=root)

        report = json.loads((run_dir / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(report["traceBackbone"]["status"], "available")
        self.assertEqual(report["metrics"]["canonicalSpans"], 2)
        self.assertEqual(report["metrics"]["canonicalEvents"], 1)
        self.assertEqual(report["traceBackbone"]["spanCount"], 2)
        self.assertEqual(report["traceBackbone"]["primarySpanCount"], 2)
        self.assertEqual(report["traceBackbone"]["evidenceSpanCount"], 0)
        self.assertEqual(report["traceBackbone"]["rawSpanCount"], 0)
        self.assertFalse(report["traceBackbone"]["exportAvailable"])
        self.assertIn("traceQuality", report["metrics"])

    def test_build_report_model_surfaces_deep_trace_backbone_and_export(self) -> None:
        from build_showcase_reports import build_showcase_reports

        root = Path(tempfile.mkdtemp(prefix="showcase-report-deep-canonical-"))
        final_judgment = {
            "runId": "run-deep",
            "finalDecision": "block",
            "riskLevel": "critical",
            "reasons": ["blocked"],
            "evidence": {"frida": {"status": "ok", "eventCount": 1}, "codeTracer": {"status": "ok"}},
        }
        run_dir = self.make_showcase(root, "staged_attack_block_frida", final_judgment=final_judgment, manifest={"runId": "run-deep"})
        write_json(
            run_dir / "canonical_trace.json",
            {
                "schemaVersion": "transpect.canonical_trace.v1",
                "traceId": "trace-deep",
                "runId": "run-deep",
                "rootSpanId": "span-root",
                "spans": [
                    {"spanId": "span-root", "kind": "AGENT_RUN", "source": "manifest", "displayTier": "primary"},
                    {"spanId": "span-turn", "parentSpanId": "span-root", "kind": "AGENT_TURN", "source": "openclaw_stream", "displayTier": "primary"},
                    {"spanId": "span-llm", "parentSpanId": "span-turn", "kind": "LLM_CALL", "source": "openclaw_stream", "displayTier": "primary"},
                    {"spanId": "span-tool", "parentSpanId": "span-turn", "kind": "TOOL_CALL", "source": "openclaw_stream", "displayTier": "primary"},
                    {"spanId": "span-defense", "parentSpanId": "span-tool", "kind": "AGENT_DEFENSE", "source": "behavior_mediator", "displayTier": "primary"},
                    {"spanId": "span-frida", "parentSpanId": "span-root", "kind": "FRIDA_EVIDENCE", "source": "frida", "displayTier": "evidence"},
                    {"spanId": "span-code", "parentSpanId": "span-root", "kind": "CODETRACER_DIAGNOSIS", "source": "codetracer", "displayTier": "evidence"},
                    {"spanId": "span-judge", "parentSpanId": "span-root", "kind": "FINAL_JUDGMENT", "source": "final_judgment", "displayTier": "primary"},
                ],
                "events": [{"eventId": "evt-tool"}],
                "sources": {
                    "openclaw_stream": {
                        "status": "ok",
                        "eventCount": 5,
                        "streams": {
                            "lifecycle": {"status": "ok", "eventCount": 2},
                            "assistant": {"status": "ok", "eventCount": 2},
                            "tool": {"status": "ok", "eventCount": 2},
                            "plugin_hooks": {"status": "ok", "eventCount": 1},
                            "session_transcript": {"status": "ok", "eventCount": 1},
                        },
                    },
                    "behavior_mediator": {"status": "ok", "eventCount": 1},
                    "frida": {"status": "ok", "eventCount": 1},
                    "codetracer": {"status": "ok", "eventCount": 1},
                    "final_judgment": {"status": "ok", "eventCount": 1},
                },
            },
        )
        write_json(run_dir / "trace_quality.json", {"schemaVersion": "transpect.trace-quality.v1", "traceDepth": "deep", "gaps": []})
        write_json(run_dir / "exports" / "openinference_spans.json", {"spans": [{"spanId": "span-root"}]})
        self.write_index(root, [{"id": "staged_attack_block_frida", "runDir": str(run_dir), "title": "Block", "description": "Block"}])

        build_showcase_reports(showcase_root=root)

        report = json.loads((run_dir / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(report["traceBackbone"]["status"], "available")
        self.assertEqual(report["traceBackbone"]["traceDepth"], "deep")
        self.assertEqual(report["traceBackbone"]["spanCount"], 8)
        self.assertTrue(report["traceBackbone"]["exportAvailable"])
        self.assertEqual(report["traceBackbone"]["missingSources"], [])


if __name__ == "__main__":
    unittest.main()
