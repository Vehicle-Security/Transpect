# Transpect

Transpect keeps OpenClaw runtime evidence, viewer tooling, diagnosis export, and optional capture integrations in one repository. The repository is organized around a runs-based storage model: one task maps to one frozen evidence directory under `live/runs/<runId>/`.

## Canonical Architecture

The canonical storage model is:

- `live/runs/<runId>/` for canonical per-run evidence
- `live/runs/<runId>/diagnosis/codetracer/bundle/` for derived CodeTracer input
- `live/runs/<runId>/diagnosis/codetracer/analysis/` for derived diagnosis output
- `live/runs/index.json` for viewer discovery and run listing

The repository does not use a separate `harvest/` layer in the current architecture, and it does not treat a single global `live/behavior-events.jsonl` file as canonical storage.

`docs/architecture/canonical-layout.md` is the authoritative layout contract. The other architecture docs summarize specific slices of that same model and should not redefine it.

## Repository Layout

```text
Transpect/
├── docs/
│   └── architecture/
│       ├── canonical-layout.md
│       └── overview.md
├── config/
├── live/
│   ├── runs/
│   ├── logs/        runtime-support only
│   ├── otel/        optional
│   ├── frida/       optional
│   ├── openclaw/    runtime-support only
│   ├── ports/       runtime-support only
│   └── archive/     legacy/optional
├── scripts/
│   ├── common/
│   ├── runtime/
│   ├── export/
│   ├── diagnosis/
│   ├── validate/
│   ├── capture/
│   └── compat/
├── task_repos/
├── vendor/
│   ├── runtime-hooks/
│   └── external/
└── viewer/
```

Grouped script paths are the primary interface. Legacy flat entrypoints such as `python scripts/start_trace.py` and `python scripts/check_repo.py` are still supported as compatibility wrappers and emit deprecation warnings.

## Quick Start

```powershell
python --version
node --version
openclaw --version
```

```powershell
python scripts/runtime/setup_runtime.py --mode hybrid
python scripts/runtime/start_trace.py
```

The viewer opens at `http://127.0.0.1:8711/viewer/index.html?view=traces`.

## Canonical Run Contents

Each canonical run directory may contain:

- `behavior-events.jsonl`
- `manifest.json`
- `task_input.json`
- `runtime_status.json`
- `artifacts/<toolCallId>/input.json`
- `artifacts/<toolCallId>/output.json`
- `diagnosis/codetracer/bundle/...`
- `diagnosis/codetracer/analysis/...`

## Legacy Compatibility

`live/behavior-events.jsonl` is retained only as a migration source for older environments. If you still have historical global logs, use:

```powershell
python scripts/diagnosis/segment_behavior_events.py --dry-run
python scripts/diagnosis/segment_behavior_events.py --archive-source
```

The canonical viewer and diagnosis flow reads runs from `live/runs/index.json` and run-local files.

External benchmark repositories can also be onboarded through manifest-driven task repo adapters under `task_repos/`, with structured reports written back into `live/runs/<runId>/`.

## Verification

```powershell
node --check viewer/app.js
node --check viewer/shared.js
python scripts/validate/check_repo.py --skip-start
python scripts/validate/doctor.py
python scripts/validate/run_acceptance.py
```

Compatibility smoke checks:

```powershell
python scripts/start_trace.py --help
python scripts/setup_runtime.py --help
python scripts/export_codetracer_bundle.py --help
python scripts/run_codetracer_diagnosis.py --help
python scripts/check_repo.py --help
```

Diagnosis execution also requires the `codetracer` Python module plus a resolvable source tree via `CODETRACER_ROOT`, `CODETRACER_SRC`, or a sibling `../CodeTracer/src`, which matches `scripts/diagnosis/run_codetracer_diagnosis.py`.

## Notes

- `scripts/runtime/setup_runtime.py` updates `~/.openclaw/openclaw.json` and writes timestamped backups under `config/applied/`.
- `vendor/runtime-hooks/openclaw-behavior-mediator/` is repository-owned runtime integration code.
- `vendor/external/openclaw-observability-plugin/` is a vendored external dependency.
- Optional Frida support lives under `scripts/capture/` and writes to `live/frida/`.

## Further Reading

- [Canonical Layout](docs/architecture/canonical-layout.md)
- [Architecture Overview](docs/architecture/overview.md)
- [Directory Layout](docs/directory-layout.md)
- [Runtime Storage Plan](docs/runtime-storage-plan.md)
- [Observability Notes](docs/observability.md)
- [Frida Notes](docs/frida.md)
- [Task Repo Adapters](docs/task-repo-adapters.md)
