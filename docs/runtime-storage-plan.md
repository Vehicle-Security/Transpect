# Runtime Storage Plan

## Summary

Transpect stores runtime evidence per run under `live/runs/<runId>/`. That directory is the canonical source of truth for a task. Diagnosis input and diagnosis output are derived layers that live under the same run directory.

`docs/architecture/canonical-layout.md` is the authoritative directory contract. This document focuses on flow, responsibilities, and operational commands for that same runs-based model.

The storage layers are:

1. `live/runs/<runId>/`
2. `live/runs/<runId>/diagnosis/codetracer/bundle/`
3. `live/runs/<runId>/diagnosis/codetracer/analysis/`

`live/behavior-events.jsonl` remains only as a legacy migration source.

## End-to-End Flow

1. The runtime starts a task.
2. `behavior-mediator` creates `live/runs/<runId>/`.
3. Runtime events append to `live/runs/<runId>/behavior-events.jsonl`.
4. Tool inputs and outputs land under `live/runs/<runId>/artifacts/<toolCallId>/`.
5. Runtime metadata is written to `manifest.json`, `task_input.json`, and `runtime_status.json`.
6. `live/runs/index.json` is refreshed for viewer discovery.
7. If auto-diagnosis is enabled, the runtime launches `scripts/diagnosis/run_codetracer_diagnosis.py --run-dir <runDir>`.
8. The diagnosis runner builds `diagnosis/codetracer/bundle/`.
9. CodeTracer writes diagnosis output to `diagnosis/codetracer/analysis/`.
10. The run manifest is updated with diagnosis status and derived paths.

## Canonical Paths

- `live/runs/index.json`
- `live/runs/<runId>/behavior-events.jsonl`
- `live/runs/<runId>/manifest.json`
- `live/runs/<runId>/task_input.json`
- `live/runs/<runId>/runtime_status.json`
- `live/runs/<runId>/artifacts/<toolCallId>/input.json`
- `live/runs/<runId>/artifacts/<toolCallId>/output.json`
- `live/runs/<runId>/diagnosis/codetracer/bundle/...`
- `live/runs/<runId>/diagnosis/codetracer/analysis/...`

## Viewer Model

The viewer reads:

1. `/live/runs/index.json`
2. a selected run’s `behavior-events.jsonl`
3. run-local manifests and derived diagnosis files when needed

The viewer does not treat a global behavior log as the primary model.

## Manifest Responsibilities

`manifest.json` is the run-level index for one task. It should contain:

- run identity
- timestamps
- task status
- event and artifact counts
- relative paths for canonical evidence
- diagnosis summary under `diagnosis.codetracer`

## Commands

```powershell
python scripts/validate/trace_topology.py --format text
python scripts/diagnosis/segment_behavior_events.py --dry-run
python scripts/diagnosis/segment_behavior_events.py --archive-source
python scripts/export/export_codetracer_bundle.py --run-dir live/runs/<runId>
python scripts/diagnosis/run_codetracer_diagnosis.py --run-dir live/runs/<runId>
python scripts/runtime/serve_viewer.py
```

Diagnosis execution also requires the `codetracer` Python module plus a resolvable source tree via `CODETRACER_ROOT`, `CODETRACER_SRC`, or a sibling `../CodeTracer/src`.

## Notes

- `bundle/` is derived input, not canonical storage.
- `analysis/` is derived output, not canonical storage.
- Diagnosis success is based on valid analysis output, not exit code alone.
- No `harvest/` layer is part of the current storage design.
