# Directory Layout

This document summarizes the repository layout after the runs-based cleanup pass.

`docs/architecture/canonical-layout.md` remains the authoritative layout contract. This page is a quick directory map, not a second architecture definition.

## Root Layout

```text
Transpect/
├── dashboard/     UI applications
├── monitor/       runtime monitoring, instrumentation, and trace model
├── guardrail/     agent defense and security guard packages
├── config/        templates, rendered local config, and apply backups
├── docs/          architecture and operations documentation
├── monitor/live/          runtime state (gitignored)
├── tools/       grouped operational tooling plus compat wrappers
├── monitor/task_repos/    manifest-driven adapters for external task repositories
├── monitor/tests/         validation and fixtures
└── monitor/vendor/        runtime hooks and vendored dependencies
```

## `dashboard/`

```text
dashboard/
├── console/       Next.js dashboard app
└── viewer/        static fallback/debug viewer
```

## `monitor/`

```text
monitor/
├── instrumentation/frida/   Frida tracing and JavaScript hook assets
├── runtime/                 OpenClaw scenario helpers and trace ingest
└── trace_model/             canonical trace model and builders
```

## `guardrail/`

```text
guardrail/
├── agent_defense/           bridge, policy, trace merge, final judgment
└── security/                intent/plan/action guards and risk decisions
```

## `monitor/live/`

```text
monitor/live/
├── runs/                   canonical per-run evidence
│   ├── index.json
│   └── <runId>/
│       ├── behavior-events.jsonl
│       ├── manifest.json
│       ├── task_input.json
│       ├── runtime_status.json
│       ├── artifacts/
│       └── diagnosis/
│           └── codetracer/
│               ├── bundle/
│               └── analysis/
├── logs/                   runtime-support only
├── openclaw/               runtime-support only
├── ports/                  runtime-support only
├── otel/                   optional
├── frida/                  optional
├── archive/                legacy/optional
└── behavior-events.jsonl   legacy migration input only
```

`harvest/` is not part of the current layout contract.

## `tools/`

```text
tools/
├── common/        shared path and utility helpers
├── runtime/       setup, start, cleanup, viewer serving, shell/cmd launchers
├── export/        bundle generation
├── diagnosis/     diagnosis execution and legacy segmentation
├── validate/      repo checks, topology checks, acceptance tests
├── capture/       optional capture tooling
├── compat/        helper logic for legacy wrappers
```

The grouped directories are the primary interface.

## `monitor/vendor/`

```text
monitor/vendor/
├── runtime-hooks/
│   └── openclaw-behavior-mediator/
└── external/
    └── openclaw-observability-plugin/
```

- `runtime-hooks/` is repository-owned integration code.
- `external/` is vendored third-party code.
