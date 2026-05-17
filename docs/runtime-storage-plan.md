# Runtime Storage Plan

## Summary

Transpect stores runtime evidence per run under `monitor/live/runs/<runId>/`. That directory is the canonical source of truth for a task. Diagnosis input, diagnosis output, online contextual security reasoning, and compatibility security context judgment live under the same run directory.

`docs/architecture/canonical-layout.md` is the authoritative directory contract. This document focuses on flow, responsibilities, and operational commands for that same runs-based model.

The storage layers are:

1. `monitor/live/runs/<runId>/`
2. `monitor/live/runs/<runId>/diagnosis/codetracer/bundle/`
3. `monitor/live/runs/<runId>/diagnosis/codetracer/analysis/`
4. `monitor/live/runs/<runId>/security-reasoning/`
5. `monitor/live/runs/<runId>/security-context/`

`monitor/live/behavior-events.jsonl` remains only as a legacy migration source.

## End-to-End Flow

1. The runtime starts a task.
2. `behavior-mediator` creates `monitor/live/runs/<runId>/`.
3. Runtime events append to `monitor/live/runs/<runId>/behavior-events.jsonl`.
4. Tool inputs and outputs land under `monitor/live/runs/<runId>/artifacts/<toolCallId>/`.
5. Runtime metadata is written to `manifest.json`, `task_input.json`, and `runtime_status.json`.
6. `monitor/live/runs/index.json` is refreshed for viewer discovery.
7. If auto-diagnosis is enabled, the runtime launches `tools/diagnosis/run_codetracer_diagnosis.py --run-dir <runDir>`.
8. The diagnosis runner builds `diagnosis/codetracer/bundle/`.
9. CodeTracer writes diagnosis output to `diagnosis/codetracer/analysis/`.
10. The run manifest is updated with diagnosis status and derived paths.
11. During runtime, the behavior mediator invokes `guardrail/security` guards at input, planning, tool-call, and network-call points.
12. Security decisions are appended to `behavior-events.jsonl` as `kind: "security"` events.
13. Online security state is exported to `security-reasoning/security_state.json`, `defense_decision.json`, and `evidence_summary.json`.
14. The legacy context wrapper `tools/security_context/run_context_judge.py --run-dir <runDir>` also writes compatibility `security-context/` reports.

## Canonical Paths

- `monitor/live/runs/index.json`
- `monitor/live/runs/<runId>/behavior-events.jsonl`
- `monitor/live/runs/<runId>/frida-events.jsonl`
- `monitor/live/runs/<runId>/trace_index.json`
- `monitor/live/runs/<runId>/merged-trace.jsonl`
- `monitor/live/runs/<runId>/manifest.json`
- `monitor/live/runs/<runId>/task_input.json`
- `monitor/live/runs/<runId>/runtime_status.json`
- `monitor/live/runs/<runId>/artifacts/<toolCallId>/input.json`
- `monitor/live/runs/<runId>/artifacts/<toolCallId>/output.json`
- `monitor/live/runs/<runId>/diagnosis/codetracer/bundle/...`
- `monitor/live/runs/<runId>/diagnosis/codetracer/analysis/...`
- `monitor/live/runs/<runId>/security-reasoning/security_state.json`
- `monitor/live/runs/<runId>/security-reasoning/defense_decision.json`
- `monitor/live/runs/<runId>/security-reasoning/evidence_summary.json`
- `monitor/live/runs/<runId>/security-reasoning/final_judgment.json`
- `monitor/live/runs/<runId>/security-context/security_context_timeline.json`
- `monitor/live/runs/<runId>/security-context/context_report.json`

## Viewer Model

The viewer reads:

1. `/live/runs/index.json`
2. a selected run’s `behavior-events.jsonl`
3. run-local manifests, derived diagnosis files, and security context reports when needed

The viewer does not treat a global behavior log as the primary model.

## Manifest Responsibilities

`manifest.json` is the run-level index for one task. It should contain:

- run identity
- timestamps
- task status
- event and artifact counts
- relative paths for canonical evidence
- diagnosis summary under `diagnosis.codetracer`
- contextual defense summary under `securityReasoning`
- compatibility context summary under `securityContext`

## Commands

```powershell
python tools/validate/trace_topology.py --format text
python tools/diagnosis/segment_behavior_events.py --dry-run
python tools/diagnosis/segment_behavior_events.py --archive-source
python tools/export/export_codetracer_bundle.py --run-dir monitor/live/runs/<runId>
python tools/diagnosis/run_codetracer_diagnosis.py --run-dir monitor/live/runs/<runId>
python tools/security_reasoning/run_defense_reasoner.py --run-dir monitor/live/runs/<runId>
python tools/security_context/run_context_judge.py --run-dir monitor/live/runs/<runId>
python tools/runtime/serve_viewer.py
```

Diagnosis execution also requires the `codetracer` Python module plus a resolvable source tree via `CODETRACER_ROOT`, `CODETRACER_SRC`, or a sibling `../CodeTracer/src`.

## Notes

- `bundle/` is derived input, not canonical storage.
- `analysis/` is derived output, not canonical storage.
- `security-reasoning/` is the primary Layer-4 contextual defense layer attached to the canonical run.
- `security-context/` remains as a compatibility judgment layer attached to the canonical run.
- Diagnosis success is based on valid analysis output, not exit code alone.
- No `harvest/` layer is part of the current storage design.
