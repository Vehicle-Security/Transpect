# Transpect

Transpect keeps OpenClaw runtime evidence, viewer tooling, diagnosis export, and optional capture integrations in one repository. The repository is organized around a runs-based storage model: one task maps to one frozen evidence directory under `live/runs/<runId>/`.

## Canonical Architecture

The canonical storage model is:

- `live/runs/<runId>/` for canonical per-run evidence
- `live/runs/<runId>/diagnosis/codetracer/bundle/` for derived CodeTracer input
- `live/runs/<runId>/diagnosis/codetracer/analysis/` for derived diagnosis output
- `live/runs/<runId>/security-reasoning/` for online contextual defense state and decisions
- `live/runs/<runId>/security-context/` for legacy-compatible Layer-4 context reports
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
├── app/
│   ├── agent_defense/
│   ├── instrumentation/frida/
│   └── security/          guard capability layer
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
│   ├── security_reasoning/
│   ├── security_context/
│   ├── validate/
│   ├── capture/
│   └── compat/
├── task_repos/
├── vendor/
│   ├── runtime-hooks/
│   └── external/
└── viewer/
```

Grouped script paths are the primary interface. Legacy flat `scripts/*.py` wrappers have been removed; use `scripts/runtime/`, `scripts/validate/`, `scripts/export/`, and `scripts/diagnosis/`.

## Quick Start

The lowest supported deployment path is **frozen showcase replay**. It does not require OpenClaw, Frida, CodeTracer, or R-Judge; those components are higher-level capture and diagnosis capabilities.

```bash
git clone <repo-url> Transpect
cd Transpect

python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

cd apps/console
npm ci
cd ../..

python scripts/validate/deployment_doctor.py --mode replay
python scripts/demo/validate_showcase.py --require-report-model
python scripts/demo/start_console.py --port 5000
```

Open:

```text
http://127.0.0.1:5000
```

The Console reads committed frozen data under `state/showcase/` and each run's `report_model.json`, then presents Overview, Showcase Gallery, Agent Security Report, and Artifact Viewer pages.

## LLM Configuration

Frozen showcase replay does not need an LLM or a `.env` file. Create one only when you want to run live Agent tasks, enable the Agent Defense LLM gray-zone judge, or run CodeTracer diagnosis:

```bash
cp .env.example .env
```

Then fill in the OpenAI-compatible model settings:

```bash
BASE_URL=https://api.openai.com/v1
API_KEY=...
MODEL_ID=gpt-4o-mini
```

These values are consumed by:

- `app/security/model_judge.py` for Agent Defense gray-zone decisions.
- `scripts/common/task_repo_common.py`, which maps `BASE_URL/API_KEY/MODEL_ID` to `MODEL_BASE_URL/MODEL_API_KEY/MODEL_NAME` for task repos.
- `scripts/diagnosis/run_codetracer_diagnosis.py`, which maps them to `CODETRACER_API_BASE/CODETRACER_API_KEY/CODETRACER_MODEL` unless explicit `CODETRACER_*` overrides are set.

`.env` is ignored by git. Commit only `.env.example`.

## Deployment Levels

### Level 0: Frozen Showcase Replay

Use this for GitHub clone demos, product review, and offline report browsing.

Required:

- Python 3.10+ and Node.js 20+
- `python -m pip install -r requirements.txt`
- `cd apps/console && npm ci`
- committed `state/showcase/index.json` and `report_model.json` files

Checks:

```bash
python scripts/validate/deployment_doctor.py --mode replay
python scripts/validate/check_portability.py
python scripts/demo/validate_showcase.py --require-report-model
```

Start:

```bash
python scripts/demo/start_console.py --host 127.0.0.1 --port 5000
```

### Level 1: Local Demo Services

Use this when you also want the static debug viewer or staged attack website. It still does not require rerunning an Agent.

```bash
python scripts/runtime/serve_viewer.py --host 127.0.0.1 --port 8711
python scripts/demo/run_staged_attack_site.py --host 127.0.0.1 --port 8765
```

Static fallback/debug viewer:

```text
http://127.0.0.1:8711/viewer/index.html?view=showcase
```

### Level 2: OpenClaw Agent Live Run

Use this to generate new real Agent traces. This level requires OpenClaw gateway access, behavior mediator hooks, and model/provider configuration.

```bash
cp .env.example .env  # fill BASE_URL/API_KEY/MODEL_ID before LLM-backed runs
python scripts/runtime/setup_runtime.py --mode core
python scripts/validate/discover_openclaw_native_sources.py
python scripts/validate/doctor.py
python scripts/demo/run_showcase.py --verbose
```

If `doctor.py` reports `scope upgrade pending approval` or `pairing required`, approve the requested OpenClaw scopes first, then rerun `doctor.py`.

### Level 3: Full Evidence Run

Use this for OS-level Frida evidence and CodeTracer diagnosis. Frida and CodeTracer are important for full evidence, but missing components are reported as `degraded` or `unavailable` rather than breaking Level 0 replay.

Optional environment variables:

```bash
python -m pip install -r requirements-frida.txt
export CODETRACER_ROOT="$HOME/path/to/CodeTracer"
export CODETRACER_SRC="$CODETRACER_ROOT/src"
```

Build derived trace artifacts for a run:

```bash
python scripts/validate/discover_openclaw_native_sources.py --run-dir live/runs/<runId>
python app/trace_model/build_canonical_trace.py --run-dir live/runs/<runId>
python scripts/validate/evaluate_trace_quality.py --run-dir live/runs/<runId> --write
python scripts/export/export_openinference_trace.py --run-dir live/runs/<runId>
python scripts/validate/validate_openinference_export.py --path live/runs/<runId>/exports/openinference_spans.json
```

If CodeTracer is not installed, `scripts/diagnosis/run_codetracer_diagnosis.py` writes a structured `diagnosis_report.json` with `status: "unavailable"` and a setup suggestion. The run can still produce final judgment, canonical trace, and replayable report data.

### Level 4: R-Judge Batch Evaluation

R-Judge is optional and only needed when you explicitly run `--repo rjudge`.

```bash
export R_JUDGE_ROOT="$HOME/path/to/R-Judge"
python scripts/runtime/run_task_repo.py --repo rjudge --mode list-tasks
python scripts/runtime/run_rjudge_batch.py --source-path data/Program --count 5 --concurrency 2
```

Missing R-Judge does not affect `staged_attack`, Console replay, static viewer replay, or frozen showcase validation.

## Product Showcase

For product demos, generate the real run once, freeze it, build report models, and replay it without rerunning the Agent:

```bash
python app/trace_model/build_canonical_trace.py --run-dir live/runs/<runId>
python scripts/validate/evaluate_trace_quality.py --run-dir live/runs/<runId> --write
python scripts/export/export_openinference_trace.py --run-dir live/runs/<runId>
python scripts/demo/freeze_showcase_run.py \
  --run-dir live/runs/<runId> \
  --id staged_attack_confirm_frida \
  --title "Suspicious External Navigation" \
  --description "系统发现外部跳转和低层运行时证据，并将 native OpenClaw trace、Frida、CodeTracer 与最终判断统一为 deep trace。"
python scripts/demo/build_showcase_reports.py
python scripts/demo/validate_showcase.py --require-report-model
```

`scripts/demo/freeze_showcase_run.py` sanitizes machine-local paths in frozen artifacts. To check portability before publishing:

```bash
python scripts/demo/sanitize_showcase_paths.py --check
python scripts/validate/check_portability.py
```

Current frozen showcase data includes replayable reports with real Frida evidence, CodeTracer diagnosis bundles, canonical trace summaries, and OpenInference-style exports. Reference screenshots:

![Transpect Console overview](docs/images/console-overview-dashboard.png)

![Transpect showcase gallery](docs/images/console-showcase-gallery.png)

See `docs/product-showcase-guide.md` for the full workflow.

`canonical_trace.json` is a derived standard trace view. It does not replace raw `behavior-events.jsonl`, native OpenClaw source files, Frida events, CodeTracer output, or `final_judgment.json`.

## Canonical Run Contents

Each canonical run directory may contain:

- `behavior-events.jsonl`
- `openclaw-lifecycle.jsonl`
- `openclaw-assistant.jsonl`
- `openclaw-tools.jsonl`
- `openclaw-plugin-hooks.jsonl`
- `session_transcript.json`
- `frida-events.jsonl`
- `trace_index.json`
- `merged-trace.jsonl`
- `canonical_trace.json`
- `trace_quality.json`
- `exports/openinference_spans.json`
- `manifest.json`
- `task_input.json`
- `runtime_status.json`
- `artifacts/<toolCallId>/input.json`
- `artifacts/<toolCallId>/output.json`
- `diagnosis/codetracer/bundle/...`
- `diagnosis/codetracer/analysis/...`
- `security-reasoning/security_state.json`
- `security-reasoning/defense_decision.json`
- `security-reasoning/evidence_summary.json`
- `security-reasoning/final_judgment.json`
- `security-context/security_context_timeline.json`
- `security-context/context_report.json`

## Legacy Compatibility

`live/behavior-events.jsonl` is retained only as a migration source for older environments. If you still have historical global logs, use:

```bash
python scripts/diagnosis/segment_behavior_events.py --dry-run
python scripts/diagnosis/segment_behavior_events.py --archive-source
```

The canonical viewer and diagnosis flow reads runs from `live/runs/index.json` and run-local files.

External benchmark repositories can also be onboarded through manifest-driven task repo adapters under `task_repos/`, with structured reports written back into `live/runs/<runId>/`.

## Verification

```bash
node --check viewer/app.js
node --check viewer/shared.js
node --check vendor/runtime-hooks/openclaw-behavior-mediator/index.js
python -m unittest discover -s tests -p 'test_*.py' -v
python scripts/validate/check_portability.py
python scripts/validate/deployment_doctor.py --mode replay
python scripts/validate/check_repo.py --skip-start
python scripts/validate/doctor.py
python scripts/validate/run_acceptance.py
```

Diagnosis execution can use the `codetracer` Python module plus a resolvable source tree via `CODETRACER_ROOT`, `CODETRACER_SRC`, or a sibling `../CodeTracer/src`. If it is missing, `scripts/diagnosis/run_codetracer_diagnosis.py` writes a structured unavailable report and the replay path continues.

## Notes

- `scripts/runtime/setup_runtime.py` updates `~/.openclaw/openclaw.json` and writes timestamped backups under `config/applied/`.
- `vendor/runtime-hooks/openclaw-behavior-mediator/` is repository-owned runtime integration code.
- `vendor/external/openclaw-observability-plugin/` is a vendored external dependency.
- Optional Frida support lives under `app/instrumentation/frida/`; agent-trace runs write run-local `frida-events.jsonl` when Frida can attach, or record an unavailable/attach-failed status in `trace_index.json`.

## Further Reading

- [Canonical Layout](docs/architecture/canonical-layout.md)
- [Architecture Overview](docs/architecture/overview.md)
- [Directory Layout](docs/directory-layout.md)
- [Runtime Storage Plan](docs/runtime-storage-plan.md)
- [Observability Notes](docs/observability.md)
- [Agent Trace Backbone v1](docs/agent-trace-backbone-v1.md)
- [Frida Notes](docs/frida.md)
- [Task Repo Adapters](docs/task-repo-adapters.md)
- [Staged Attack Defense Demo](docs/staged-attack-defense-demo.md)
