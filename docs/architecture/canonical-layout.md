# Canonical Layout

This document is the authoritative description of the current Transpect repository layout.

## Canonical Storage Model

The canonical runtime source of truth is:

```text
live/runs/
├── index.json
└── <runId>/
    ├── behavior-events.jsonl
    ├── manifest.json
    ├── task_input.json
    ├── runtime_status.json
    ├── artifacts/
    └── diagnosis/
        └── codetracer/
            ├── bundle/
            └── analysis/
```

- `live/runs/<runId>/` is the canonical per-run evidence root.
- `diagnosis/codetracer/bundle/` is the derived CodeTracer input layer.
- `diagnosis/codetracer/analysis/` is the derived diagnosis output layer.
- `live/runs/index.json` is the canonical run listing that the viewer uses to discover runs.

## Derived, Runtime-Support, and Legacy Paths

These directories exist, but they are not canonical per-run storage:

- `live/logs/`: runtime-support logs
- `live/openclaw/`: runtime-support state
- `live/ports/`: runtime-support state
- `live/otel/`: optional observability output
- `live/frida/`: optional capture output
- `live/archive/`: legacy/optional archival output
- `live/behavior-events.jsonl`: legacy migration source only

`harvest/` is not part of the current architecture and must not be documented as an active storage layer.

## Scripts

Primary script locations:

- `scripts/runtime/`
- `scripts/export/`
- `scripts/diagnosis/`
- `scripts/validate/`
- `scripts/capture/`
- `scripts/common/`

Legacy flat entrypoints in `scripts/*.py` remain supported as compatibility wrappers and emit deprecation warnings.

## Vendor Boundaries

- `vendor/runtime-hooks/` contains runtime integration hooks maintained in this repository.
- `vendor/external/` contains vendored third-party dependencies.

Current key paths:

- `vendor/runtime-hooks/openclaw-behavior-mediator/`
- `vendor/external/openclaw-observability-plugin/`

## Viewer Model

The viewer’s primary data model is:

1. `live/runs/index.json`
2. run-local `behavior-events.jsonl`
3. run-local manifests and diagnosis files

The viewer must not present a single global behavior log as the primary model.
