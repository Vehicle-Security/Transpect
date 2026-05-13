from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


class AgentTraceBackboneTests(unittest.TestCase):
    def make_run(self, *, with_deep_trace: bool = True) -> Path:
        root = Path(tempfile.mkdtemp(prefix="canonical-trace-"))
        run_dir = root / "run-001"
        write_json(
            run_dir / "manifest.json",
            {
                "runId": "run-001",
                "traceId": "trace-001",
                "sessionKey": "session-001",
                "startedAt": "2026-05-01T00:00:00Z",
                "completedAt": "2026-05-01T00:00:10Z",
            },
        )
        if with_deep_trace:
            write_jsonl(
                run_dir / "merged-trace.jsonl",
                [
                    {
                        "eventId": "evt-tool",
                        "kind": "tool",
                        "name": "browser.open",
                        "status": "ok",
                        "ts": "2026-05-01T00:00:01Z",
                        "preview": {"url": "http://example.test"},
                    },
                    {
                        "eventId": "evt-defense",
                        "kind": "security",
                        "name": "security_intervention",
                        "status": "block",
                        "ts": "2026-05-01T00:00:02Z",
                        "preview": {"reason": "Sensitive upload attempt blocked."},
                    },
                ],
            )
            write_jsonl(
                run_dir / "frida-events.jsonl",
                [
                    {
                        "event_id": "frida-1",
                        "source": "frida",
                        "event_type": "file_access_event",
                        "timestamp": "2026-05-01T00:00:03Z",
                        "risk_tags": ["sensitive_file_access"],
                        "normalized": {"path": "/tmp/demo-secret.txt"},
                    }
                ],
            )
            write_json(
                run_dir / "diagnosis" / "codetracer" / "analysis" / "diagnosis_report.json",
                {
                    "ok": True,
                    "analysis": {"summary": "CodeTracer linked the runtime action to a cross-step chain."},
                },
            )
            write_json(
                run_dir / "security-reasoning" / "final_judgment.json",
                {
                    "runId": "run-001",
                    "finalDecision": "block",
                    "riskLevel": "critical",
                    "reasons": ["Online Agent Defense blocked a high-risk action."],
                    "evidence": {"frida": {"status": "ok", "eventCount": 1}, "codeTracer": {"status": "ok"}},
                },
            )
        return run_dir

    def test_build_canonical_trace_unifies_behavior_frida_codetracer_and_judgment(self) -> None:
        from app.trace_model.build_canonical_trace import build_canonical_trace

        run_dir = self.make_run()

        trace = build_canonical_trace(run_dir)

        self.assertEqual(trace["schemaVersion"], "transpect.canonical_trace.v1")
        self.assertEqual(trace["runId"], "run-001")
        self.assertEqual(trace["traceId"], "trace-001")
        kinds = {span["kind"] for span in trace["spans"]}
        self.assertIn("AGENT_RUN", kinds)
        self.assertIn("TOOL_CALL", kinds)
        self.assertIn("AGENT_DEFENSE", kinds)
        self.assertIn("FRIDA_EVIDENCE", kinds)
        self.assertIn("CODETRACER_DIAGNOSIS", kinds)
        self.assertIn("FINAL_JUDGMENT", kinds)
        self.assertEqual(trace["sources"]["openclaw_stream"]["status"], "unavailable")
        frida_span = next(span for span in trace["spans"] if span["kind"] == "FRIDA_EVIDENCE" and span["name"] != "Frida low-level evidence summary")
        self.assertEqual(frida_span["source"], "frida")
        self.assertEqual(frida_span["sourceConfidence"], "high")
        self.assertEqual(frida_span["displayTier"], "evidence")
        self.assertEqual(frida_span["importance"], "critical")
        defense_span = next(span for span in trace["spans"] if span["kind"] == "AGENT_DEFENSE")
        self.assertEqual(defense_span["displayTier"], "primary")
        self.assertEqual(defense_span["importance"], "critical")
        self.assertTrue((run_dir / "canonical_trace.json").exists())

    def test_frida_low_value_events_are_summarized_and_critical_events_remain_individual(self) -> None:
        from app.trace_model.build_canonical_trace import build_canonical_trace

        run_dir = self.make_run(with_deep_trace=False)
        rows = [
            {
                "event_id": f"frida-noise-{index}",
                "source": "frida",
                "event_type": "file_access_event",
                "timestamp": "2026-05-01T00:00:03Z",
                "risk_tags": [],
                "normalized": {"path": f"/tmp/cache-{index}.json"},
            }
            for index in range(100)
        ]
        rows.append(
            {
                "event_id": "frida-critical",
                "source": "frida",
                "event_type": "network_event",
                "timestamp": "2026-05-01T00:00:04Z",
                "risk_tags": ["non_browser_network_bypass", "upload_candidate"],
                "normalized": {"url": "https://evil.example/upload"},
            }
        )
        write_jsonl(run_dir / "frida-events.jsonl", rows)

        trace = build_canonical_trace(run_dir)

        frida_spans = [span for span in trace["spans"] if span["kind"] == "FRIDA_EVIDENCE"]
        self.assertEqual(len(frida_spans), 2)
        summary = next(span for span in frida_spans if span["name"] == "Frida low-level evidence summary")
        self.assertEqual(summary["displayTier"], "evidence")
        self.assertEqual(summary["importance"], "high")
        self.assertEqual(summary["attributes"]["totalEvents"], 101)
        self.assertEqual(summary["attributes"]["criticalEvents"], 1)
        self.assertEqual(summary["attributes"]["networkBypass"], 1)
        critical = next(span for span in frida_spans if span["name"] == "network_event")
        self.assertEqual(critical["importance"], "critical")
        self.assertEqual(critical["attributes"]["eventId"], "frida-critical")

    def test_trace_quality_detects_empty_shallow_moderate_and_deep(self) -> None:
        from scripts.validate.evaluate_trace_quality import evaluate_trace_quality

        empty = self.make_run(with_deep_trace=False)
        empty_report = evaluate_trace_quality(empty)
        self.assertEqual(empty_report["traceDepth"], "empty")
        self.assertFalse(empty_report["substantiveAgentBehavior"])

        shallow = self.make_run(with_deep_trace=False)
        write_jsonl(shallow / "behavior-events.jsonl", [{"eventId": "evt-start", "name": "openclaw.request", "kind": "turn"}])
        shallow_report = evaluate_trace_quality(shallow)
        self.assertEqual(shallow_report["traceDepth"], "shallow")

        moderate = self.make_run(with_deep_trace=False)
        write_jsonl(moderate / "behavior-events.jsonl", [{"eventId": "evt-tool", "name": "browser.open", "kind": "tool"}])
        moderate_report = evaluate_trace_quality(moderate)
        self.assertEqual(moderate_report["traceDepth"], "moderate")

        complete_without_native = self.make_run()
        complete_without_native_report = evaluate_trace_quality(complete_without_native)
        self.assertEqual(complete_without_native_report["traceDepth"], "moderate")
        self.assertTrue(complete_without_native_report["coverage"]["frida"])
        self.assertTrue(complete_without_native_report["coverage"]["codetracer"])
        self.assertTrue(complete_without_native_report["coverage"]["finalJudgment"])

    def test_native_openclaw_sources_create_parented_spans_and_enable_deep_quality(self) -> None:
        from app.trace_model.build_canonical_trace import build_canonical_trace
        from scripts.validate.evaluate_trace_quality import evaluate_trace_quality

        run_dir = self.make_run()
        write_jsonl(
            run_dir / "openclaw-lifecycle.jsonl",
            [
                {
                    "eventId": "native-message",
                    "event": "message_received",
                    "timestamp": "2026-05-01T00:00:00Z",
                    "traceId": "trace-001",
                    "spanId": "native-request",
                    "sessionKey": "session-001",
                    "runId": "run-001",
                    "preview": {"message": "Summarize comments"},
                },
                {
                    "eventId": "native-turn-start",
                    "event": "before_agent_start",
                    "timestamp": "2026-05-01T00:00:01Z",
                    "traceId": "trace-001",
                    "spanId": "native-turn",
                    "parentSpanId": "native-request",
                    "sessionKey": "session-001",
                    "runId": "run-001",
                    "agentId": "main",
                },
                {
                    "eventId": "native-agent-end",
                    "event": "agent_end",
                    "timestamp": "2026-05-01T00:00:09Z",
                    "traceId": "trace-001",
                    "spanId": "native-turn",
                    "parentSpanId": "native-request",
                    "sessionKey": "session-001",
                    "runId": "run-001",
                    "status": "ok",
                },
            ],
        )
        write_jsonl(
            run_dir / "openclaw-assistant.jsonl",
            [
                {
                    "eventId": "native-llm-in",
                    "event": "llm_input",
                    "timestamp": "2026-05-01T00:00:02Z",
                    "traceId": "trace-001",
                    "spanId": "native-llm",
                    "parentSpanId": "native-turn",
                    "llmCallId": "llm-1",
                    "runId": "run-001",
                    "sessionKey": "session-001",
                    "model": "demo-model",
                },
                {
                    "eventId": "native-llm-out",
                    "event": "llm_output",
                    "timestamp": "2026-05-01T00:00:03Z",
                    "traceId": "trace-001",
                    "spanId": "native-llm",
                    "parentSpanId": "native-turn",
                    "llmCallId": "llm-1",
                    "runId": "run-001",
                    "sessionKey": "session-001",
                    "status": "ok",
                },
            ],
        )
        write_jsonl(
            run_dir / "openclaw-tools.jsonl",
            [
                {
                    "eventId": "native-tool-start",
                    "event": "before_tool_call",
                    "timestamp": "2026-05-01T00:00:04Z",
                    "traceId": "trace-001",
                    "spanId": "native-tool",
                    "parentSpanId": "native-turn",
                    "toolCallId": "tool-1",
                    "toolName": "browser.open",
                    "runId": "run-001",
                    "sessionKey": "session-001",
                },
                {
                    "eventId": "native-tool-end",
                    "event": "after_tool_call",
                    "timestamp": "2026-05-01T00:00:05Z",
                    "traceId": "trace-001",
                    "spanId": "native-tool",
                    "parentSpanId": "native-turn",
                    "toolCallId": "tool-1",
                    "toolName": "browser.open",
                    "status": "ok",
                    "runId": "run-001",
                    "sessionKey": "session-001",
                },
            ],
        )
        write_jsonl(run_dir / "openclaw-plugin-hooks.jsonl", [{"eventId": "hook-1", "hook": "before_tool_call", "runId": "run-001"}])
        write_json(run_dir / "session_transcript.json", {"runId": "run-001", "sessionKey": "session-001", "messages": [{"role": "assistant", "preview": "done"}]})

        trace = build_canonical_trace(run_dir)
        quality = evaluate_trace_quality(run_dir)

        native = [span for span in trace["spans"] if span["source"] == "openclaw_stream"]
        by_name = {span["name"]: span for span in native}
        self.assertEqual(trace["sources"]["openclaw_stream"]["status"], "ok")
        self.assertEqual(trace["sources"]["openclaw_stream"]["streams"]["lifecycle"]["status"], "ok")
        self.assertEqual(by_name["openclaw.agent.turn"]["parentSpanId"], by_name["openclaw.request"]["spanId"])
        self.assertEqual(by_name["llm.demo-model"]["parentSpanId"], by_name["openclaw.agent.turn"]["spanId"])
        self.assertEqual(by_name["tool.browser.open"]["parentSpanId"], by_name["openclaw.agent.turn"]["spanId"])
        self.assertEqual(quality["traceDepth"], "deep")
        self.assertTrue(quality["coverage"]["lifecycle"])
        self.assertTrue(quality["coverage"]["assistant"])
        self.assertTrue(quality["coverage"]["llm"])

    def test_trace_quality_write_persists_schema_versioned_report(self) -> None:
        from scripts.validate.evaluate_trace_quality import evaluate_trace_quality

        run_dir = self.make_run()

        report = evaluate_trace_quality(run_dir, write=True)

        persisted = json.loads((run_dir / "trace_quality.json").read_text(encoding="utf-8"))
        self.assertEqual(report["schemaVersion"], "transpect.trace-quality.v1")
        self.assertEqual(persisted["schemaVersion"], "transpect.trace-quality.v1")
        self.assertIn("evaluatedAt", persisted)
        self.assertEqual(persisted["traceDepth"], "moderate")

    def test_openinference_export_maps_canonical_span_kinds(self) -> None:
        from app.trace_model.build_canonical_trace import build_canonical_trace
        from scripts.export.export_openinference_trace import export_openinference_trace

        run_dir = self.make_run()
        build_canonical_trace(run_dir)

        result = export_openinference_trace(run_dir)

        output_path = Path(result["path"])
        self.assertTrue(output_path.exists())
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        span_kinds = {span["attributes"]["openinference.span.kind"] for span in payload["spans"]}
        self.assertIn("AGENT", span_kinds)
        self.assertIn("TOOL", span_kinds)
        self.assertIn("GUARDRAIL", span_kinds)
        self.assertIn("EVALUATOR", span_kinds)

    def test_audit_canonical_trace_reports_distribution_and_coverage(self) -> None:
        from app.trace_model.build_canonical_trace import build_canonical_trace
        from scripts.validate.audit_canonical_trace import audit_canonical_trace

        run_dir = self.make_run()
        build_canonical_trace(run_dir)

        audit = audit_canonical_trace(run_dir)

        self.assertTrue(audit["ok"])
        self.assertGreater(audit["spanCount"], 0)
        self.assertEqual(audit["spanKinds"]["FRIDA_EVIDENCE"], 2)
        self.assertIn("primary", audit["displayTiers"])
        self.assertGreater(audit["parentCoverage"], 0.8)
        self.assertGreater(audit["artifactRefCoverage"], 0.8)
        self.assertIn("OpenClaw native stream unavailable.", audit["warnings"])

    def test_audit_warns_when_frida_spans_dominate(self) -> None:
        from scripts.validate.audit_canonical_trace import audit_canonical_trace

        run_dir = self.make_run(with_deep_trace=False)
        spans = [{"spanId": "root", "kind": "AGENT_RUN", "source": "manifest", "artifactRefs": ["manifest.json"]}]
        spans.extend(
            {
                "spanId": f"frida-{index}",
                "parentSpanId": "root",
                "kind": "FRIDA_EVIDENCE",
                "source": "frida",
                "artifactRefs": ["frida-events.jsonl"],
                "displayTier": "evidence",
                "importance": "low",
            }
            for index in range(20)
        )
        write_json(
            run_dir / "canonical_trace.json",
            {
                "schemaVersion": "transpect.canonical_trace.v1",
                "traceId": "trace-001",
                "runId": "run-001",
                "rootSpanId": "root",
                "spans": spans,
                "events": [],
                "artifacts": [{"path": "manifest.json"}, {"path": "frida-events.jsonl"}],
                "sources": {"openclaw_stream": {"status": "unavailable"}, "frida": {"status": "ok", "eventCount": 20}},
            },
        )
        (run_dir / "frida-events.jsonl").write_text("{}", encoding="utf-8")

        audit = audit_canonical_trace(run_dir)

        self.assertTrue(any("Frida spans dominate canonical trace" in warning for warning in audit["warnings"]))

    def test_openinference_validator_accepts_valid_export_and_rejects_missing_parent(self) -> None:
        from app.trace_model.build_canonical_trace import build_canonical_trace
        from scripts.export.export_openinference_trace import export_openinference_trace
        from scripts.validate.validate_openinference_export import validate_openinference_export

        run_dir = self.make_run()
        build_canonical_trace(run_dir)
        result = export_openinference_trace(run_dir)

        valid = validate_openinference_export(Path(result["path"]))
        self.assertTrue(valid["ok"])

        payload = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
        payload["spans"][0]["parentSpanId"] = "missing-parent"
        bad_path = run_dir / "exports" / "bad_openinference_spans.json"
        write_json(bad_path, payload)

        invalid = validate_openinference_export(bad_path)
        self.assertFalse(invalid["ok"])
        self.assertTrue(any("missing parent" in error for error in invalid["errors"]))

    def test_discover_openclaw_native_sources_reports_run_file_coverage(self) -> None:
        from scripts.validate.discover_openclaw_native_sources import discover_openclaw_native_sources

        run_dir = self.make_run(with_deep_trace=False)
        write_jsonl(run_dir / "openclaw-lifecycle.jsonl", [{"event": "message_received"}])
        write_jsonl(run_dir / "openclaw-tools.jsonl", [{"event": "before_tool_call"}])

        report = discover_openclaw_native_sources(run_dir=run_dir)

        self.assertIn("openclaw", report)
        self.assertIn("behaviorMediator", report)
        self.assertEqual(report["runSources"]["lifecycle"]["status"], "ok")
        self.assertEqual(report["runSources"]["tool"]["status"], "ok")
        self.assertEqual(report["runSources"]["assistant"]["status"], "missing")
        self.assertFalse(report["ok"])
        self.assertTrue(any("openclaw-assistant.jsonl" in item for item in report["recommendations"]))


if __name__ == "__main__":
    unittest.main()
