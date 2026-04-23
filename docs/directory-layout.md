# Directory Layout

This document summarizes the repository layout after the runs-based cleanup pass.

`docs/architecture/canonical-layout.md` remains the authoritative layout contract. This page is a quick directory map, not a second architecture definition.

## Root Layout

```text
Transpect/
├── config/        templates, rendered local config, and apply backups
├── docs/          architecture and operations documentation
├── frida/         Frida JavaScript assets
├── live/          runtime state (gitignored)
├── scripts/       grouped operational scripts plus compat wrappers
├── task_repos/    manifest-driven adapters for external task repositories
├── tests/         validation and fixtures
├── vendor/        runtime hooks and vendored dependencies
└── viewer/        browser UI
```

## `live/`

```text
live/
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

## `scripts/`

```text
scripts/
├── common/        shared path and utility helpers
├── runtime/       setup, start, cleanup, viewer serving
├── export/        bundle generation
├── diagnosis/     diagnosis execution and legacy segmentation
├── validate/      repo checks, topology checks, acceptance tests
├── capture/       optional capture tooling
├── compat/        helper logic for legacy wrappers
└── *.py           backward-compatible flat wrappers
```

The grouped directories are the primary interface. Root-level `scripts/*.py` files remain as compatibility wrappers.

## `vendor/`

```text
vendor/
├── runtime-hooks/
│   └── openclaw-behavior-mediator/
└── external/
    └── openclaw-observability-plugin/
```

- `runtime-hooks/` is repository-owned integration code.
- `external/` is vendored third-party code.
