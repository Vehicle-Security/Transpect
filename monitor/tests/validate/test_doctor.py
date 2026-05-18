from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parents[2] / "tools"
sys.path.insert(0, str(SCRIPT_DIR.parents[2] / "tools" / "validate"))

import doctor  # noqa: E402
from doctor import build_summary, get_runtime_config, inspect_behavior_evidence  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


class DoctorTests(unittest.TestCase):
    def test_inspect_behavior_evidence_detects_real_run_artifacts(self) -> None:
        runs_root = Path(tempfile.mkdtemp(prefix="doctor-runs-"))
        run_dir = runs_root / "run-123"
        write_json(
            run_dir / "manifest.json",
            {
                "runId": "run-123",
                "traceId": "trace-123",
                "status": "completed",
                "eventCount": 2,
                "diagnosis": {"codetracer": {"analysisReady": True, "analysisOk": True}},
            },
        )
        write_json(
            run_dir / "runtime_status.json",
            {
                "behaviorMediator": {
                    "ok": True,
                    "eventsWritten": 2,
                    "lastWriteOk": True,
                }
            },
        )
        write_jsonl(
            run_dir / "behavior-events.jsonl",
            [
                {"seq": 1, "kind": "request", "status": "started"},
                {"seq": 2, "kind": "request", "status": "ok"},
            ],
        )

        evidence = inspect_behavior_evidence(runs_root)
        self.assertTrue(evidence["ok"])
        self.assertEqual(evidence["latestEvidenceRun"]["runId"], "run-123")
        self.assertEqual(evidence["latestEvidenceRun"]["eventCount"], 2)

    def test_runtime_config_aligns_with_github_main_behavior_paths(self) -> None:
        config_path = Path(tempfile.mkdtemp(prefix="doctor-config-")) / "openclaw.json"
        write_json(
            config_path,
            {
                "plugins": {
                    "load": {
                        "paths": [str(doctor.BEHAVIOR_PLUGIN_VENDOR_PATH.resolve())],
                    },
                    "entries": {
                        "behavior-mediator": {
                            "enabled": True,
                            "config": {
                                "runsDirectory": str(doctor.TRACE_LIVE_RUNS_DIR.resolve()),
                                "artifactsEnabled": True,
                                "autoDiagnosisEnabled": True,
                                "capturePreviewChars": 2000,
                                "captureNetwork": True,
                                "traceEval": False,
                                "securityMode": "enforce",
                                "policyPath": str((doctor.TRACE_ROOT / "config" / "agent-defense-policy.json").resolve()),
                                "diagnosisScript": str((doctor.TRACE_ROOT / "tools" / "diagnosis" / "run_codetracer_diagnosis.py").resolve()),
                                "securityBridgeScript": str((doctor.TRACE_ROOT / "guardrail" / "agent_defense" / "bridge.py").resolve()),
                            },
                        }
                    },
                },
                "gateway": {"port": 18789},
            },
        )

        with patch.object(doctor, "OPENCLAW_CONFIG_PATH", config_path):
            runtime = get_runtime_config()

        self.assertTrue(runtime["behaviorEnabled"])
        self.assertTrue(runtime["behaviorConfigAligned"])

    def test_runtime_config_rejects_legacy_app_agent_defense_bridge_path(self) -> None:
        config_path = Path(tempfile.mkdtemp(prefix="doctor-config-")) / "openclaw.json"
        write_json(
            config_path,
            {
                "plugins": {
                    "load": {
                        "paths": [str(doctor.BEHAVIOR_PLUGIN_VENDOR_PATH.resolve())],
                    },
                    "entries": {
                        "behavior-mediator": {
                            "enabled": True,
                            "config": {
                                "runsDirectory": str(doctor.TRACE_LIVE_RUNS_DIR.resolve()),
                                "artifactsEnabled": True,
                                "autoDiagnosisEnabled": True,
                                "capturePreviewChars": 2000,
                                "captureNetwork": True,
                                "traceEval": False,
                                "securityMode": "enforce",
                                "policyPath": str((doctor.TRACE_ROOT / "config" / "agent-defense-policy.json").resolve()),
                                "diagnosisScript": str((doctor.TRACE_ROOT / "tools" / "diagnosis" / "run_codetracer_diagnosis.py").resolve()),
                                "securityBridgeScript": str((doctor.TRACE_ROOT / "app" / "agent_defense" / "bridge.py").resolve()),
                            },
                        }
                    },
                },
                "gateway": {"port": 18789},
            },
        )

        with patch.object(doctor, "OPENCLAW_CONFIG_PATH", config_path):
            runtime = get_runtime_config()

        self.assertTrue(runtime["behaviorEnabled"])
        self.assertFalse(runtime["behaviorConfigAligned"])

    def test_build_summary_degrades_when_rpc_needs_pairing_but_run_evidence_exists(self) -> None:
        report = {
            "runtimeConfig": {
                "mode": "core",
                "behaviorEnabled": True,
                "behaviorConfigAligned": True,
                "otelPluginEnabled": False,
                "otelConfigAligned": False,
                "otelCollectorConfigExists": False,
                "diagnosticsEnabled": False,
            },
            "runs": {
                "exists": True,
                "runCount": 1,
            },
            "viewerHealth": {
                "ok": True,
            },
            "gatewayHealth": {
                "ok": True,
            },
            "gatewayRpc": {
                "ok": True,
                "status": "ok",
            },
            "behaviorMediatorStatus": {
                "ok": False,
                "status": "handler_error",
                "error": {
                    "message": "scope upgrade pending approval and pairing required",
                },
            },
            "otelStatus": {
                "ok": False,
                "status": "handler_error",
                "error": {
                    "message": "scope upgrade pending approval and pairing required",
                },
            },
            "runtimeResidue": {
                "tmpArtifacts": {"fileCount": 0},
                "legacyRootLogs": {"fileCount": 0},
                "legacyOpenclawFiles": {"fileCount": 0},
            },
            "behaviorEvidence": {
                "ok": True,
                "latestEvidenceRun": {
                    "runId": "run-123",
                    "eventCount": 2,
                },
            },
        }

        summary = build_summary(report)
        self.assertEqual(summary["verdict"], "degraded")
        self.assertEqual(summary["issues"], [])
        self.assertTrue(any("scope approval" in warning for warning in summary["warnings"]))

    def test_build_summary_stays_broken_without_rpc_or_filesystem_evidence(self) -> None:
        report = {
            "runtimeConfig": {
                "mode": "core",
                "behaviorEnabled": True,
                "behaviorConfigAligned": True,
                "otelPluginEnabled": False,
                "otelConfigAligned": False,
                "otelCollectorConfigExists": False,
                "diagnosticsEnabled": False,
            },
            "runs": {
                "exists": True,
                "runCount": 0,
            },
            "viewerHealth": {
                "ok": True,
            },
            "gatewayHealth": {
                "ok": True,
            },
            "gatewayRpc": {
                "ok": True,
                "status": "ok",
            },
            "behaviorMediatorStatus": {
                "ok": False,
                "status": "handler_error",
                "error": {
                    "message": "scope upgrade pending approval and pairing required",
                },
            },
            "otelStatus": {
                "ok": False,
                "status": "handler_error",
                "error": {
                    "message": "scope upgrade pending approval and pairing required",
                },
            },
            "runtimeResidue": {
                "tmpArtifacts": {"fileCount": 0},
                "legacyRootLogs": {"fileCount": 0},
                "legacyOpenclawFiles": {"fileCount": 0},
            },
            "behaviorEvidence": {
                "ok": False,
                "latestEvidenceRun": None,
            },
        }

        summary = build_summary(report)
        self.assertEqual(summary["verdict"], "broken")
        self.assertTrue(any("behavior-mediator.status" in issue for issue in summary["issues"]))

    def test_build_summary_degrades_when_only_viewer_is_not_running(self) -> None:
        report = {
            "runtimeConfig": {
                "mode": "core",
                "behaviorEnabled": True,
                "behaviorConfigAligned": True,
                "otelPluginEnabled": False,
                "otelConfigAligned": False,
                "otelCollectorConfigExists": False,
                "diagnosticsEnabled": False,
            },
            "runs": {
                "exists": True,
                "runCount": 1,
            },
            "viewerHealth": {
                "ok": False,
                "status": None,
                "error": "Connection refused",
            },
            "gatewayHealth": {
                "ok": True,
            },
            "gatewayRpc": {
                "ok": True,
                "status": "ok",
            },
            "behaviorMediatorStatus": {
                "ok": True,
                "status": "ok",
            },
            "otelStatus": {
                "ok": False,
                "status": "handler_error",
            },
            "runtimeResidue": {
                "tmpArtifacts": {"fileCount": 0},
                "legacyRootLogs": {"fileCount": 0},
                "legacyOpenclawFiles": {"fileCount": 0},
            },
            "behaviorEvidence": {
                "ok": True,
                "latestEvidenceRun": {
                    "runId": "run-123",
                    "eventCount": 2,
                },
            },
        }

        summary = build_summary(report)
        self.assertEqual(summary["verdict"], "degraded")
        self.assertEqual(summary["issues"], [])
        self.assertTrue(any("viewer /health is not available" in warning for warning in summary["warnings"]))


if __name__ == "__main__":
    unittest.main()
