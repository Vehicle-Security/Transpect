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
    ├── diagnosis/
    │   └── codetracer/
    │       ├── bundle/
    │       └── analysis/
    ├── security-reasoning/
    │   ├── security_state.json
    │   ├── defense_decision.json
    │   └── evidence_summary.json
    └── security-context/
        ├── security_context_timeline.json
        └── context_report.json
```

- `live/runs/<runId>/` is the canonical per-run evidence root.
- `diagnosis/codetracer/bundle/` is the derived CodeTracer input layer.
- `diagnosis/codetracer/analysis/` is the derived diagnosis output layer.
- `security-reasoning/` is the online contextual defense state exported by the runtime guards.
- `security-context/` is the legacy-compatible Layer-4 summary layer.
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

## Application Packages

- `app/agent_defense/` — Agent defense coordination layer (bridge, policy, bypass, normalizers, trace merging, final judgment).  Public entry: `handle()`.
- `app/security/` — Security guard capability layer (intent/plan/action guards, risk scoring, decision engine, model judge).  Public API: `inspect_*` functions.
- `app/instrumentation/frida/` — Optional Frida runtime tracing (observational, best-effort).
- `app/runtime/agent_scenarios/` — OpenClaw client helpers and scenario-specific report building.

Dependency direction: `agent_defense → security`.  `app/security` never imports from `app/agent_defense`.

## Scripts

Primary script locations:

- `scripts/runtime/`
- `scripts/export/`
- `scripts/diagnosis/`
- `scripts/security_reasoning/`
- `scripts/security_context/`
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
3. run-local manifests, diagnosis files, security reasoning artifacts, and compatibility security context reports

The viewer must not present a single global behavior log as the primary model.
