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

Recommended local layout:

```text
code/
├── Transpect/
├── CodeTracer/
└── R-Judge/
```

Create the runtime environment used by Transpect and CodeTracer:

```bash
conda create -n transpect-py311 python=3.11 -y
conda activate transpect-py311
pip install -r requirements.txt
pip install -e ../CodeTracer
python --version
node --version
openclaw --version
```

Optional: create a separate environment for repo-native R-Judge runs:

```bash
conda create -n rjudge-py310 python=3.10 -y
conda activate rjudge-py310
pip install -r ../R-Judge/requirements.txt
```

If `CodeTracer/` or `R-Judge/` are not siblings of `Transpect/`, set explicit roots:

```bash
export CODETRACER_ROOT="$HOME/path/to/CodeTracer"
export R_JUDGE_ROOT="$HOME/path/to/R-Judge"
```

Configure OpenClaw for canonical trace capture and auto-diagnosis:

```bash
conda activate transpect-py311
python scripts/runtime/setup_runtime.py --mode core
python scripts/validate/discover_openclaw_native_sources.py
python scripts/validate/doctor.py
```

If `doctor.py` reports `scope upgrade pending approval` or `pairing required`, approve the requested OpenClaw scopes first, then rerun `doctor.py`.

Run the trace-first task flow:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode list-tasks
python scripts/runtime/run_task_repo.py --repo rjudge --mode show-task --task-id "data/Application/chatbot.json#37"
python scripts/runtime/run_task_repo.py --repo rjudge --mode agent-trace --task-id "data/Application/chatbot.json#37"
python scripts/runtime/start_trace.py
```

Run one or more R-Judge tasks with the batch helper:

```bash
python scripts/runtime/run_rjudge_batch.py --source-path data/Program --count 5 --concurrency 2
python scripts/runtime/run_rjudge_batch.py --source-path data/Application/chatbot.json --count 3 --label 1
python scripts/runtime/run_rjudge_batch.py --task-id "data/Application/chatbot.json#37"
```

Use `--dry-run --no-start-runtime` to preview the selected tasks without launching agents.

Run the staged attack defense demo:

```bash
python scripts/demo/run_showcase.py
```

The demo task gives the agent only a normal browsing prompt. The local HTTP site contains the split attack chain: Xiaohongshu topic viewing, low-trust comment injection, watering-hole navigation, deceptive “详情” click, and a demo photo upload attempt. During the real OpenClaw run, Transpect security guards inspect input, plan-like LLM output, tool calls, and network requests. High-risk execution decisions can block the real tool/API call before it runs. The post-run path merges OpenClaw and Frida evidence, exports the merged trace to CodeTracer, and writes the final Agent Defense judgment.

The showcase wrapper starts the demo site and viewer when needed, runs the staged attack trace with Frida in auto mode, refreshes CodeTracer diagnosis, writes `final_judgment.json`, marks the run as showcase, and prints a direct viewer URL such as `http://127.0.0.1:8711/viewer/index.html?view=traces&run=<runId>`.

For a live fallback without launching a new agent, use `python scripts/demo/run_showcase.py --reuse-latest` or `python scripts/demo/run_showcase.py --no-openclaw-run --run-dir live/runs/<runId>`.

Build the Agent Trace Backbone artifacts for any run:

```bash
python scripts/validate/discover_openclaw_native_sources.py --run-dir live/runs/<runId>
python app/trace_model/build_canonical_trace.py --run-dir live/runs/<runId>
python scripts/validate/evaluate_trace_quality.py --run-dir live/runs/<runId> --write
python scripts/export/export_openinference_trace.py --run-dir live/runs/<runId>
python scripts/validate/validate_openinference_export.py --path live/runs/<runId>/exports/openinference_spans.json
```

`canonical_trace.json` is a derived standard trace view. It does not replace raw `behavior-events.jsonl`, native OpenClaw source files, Frida events, CodeTracer output, or `final_judgment.json`.

## Product Showcase

For product demos, generate the real run once, freeze it, build report models, and replay it from the Next.js Console without rerunning the agent:

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
python scripts/demo/validate_showcase.py
python scripts/demo/validate_showcase.py --require-report-model
cd apps/console
npm install
npm run dev -- --hostname 127.0.0.1 --port 5000
```

Open:

```text
http://127.0.0.1:5000
```

The Console reads `state/showcase/index.json` plus each frozen run's `report_model.json`, then presents Overview, Showcase Gallery, Agent Security Report, and Artifact Viewer pages. The old static viewer remains available as a fallback/debug surface:

Current frozen showcase data includes 8 replayable reports. The recommended product path starts with the real Frida + deep Trace Backbone case `staged_attack_confirm_frida`, followed by real Frida block/allow examples and curated fallback fixtures. The Console overview exposes Deep Trace readiness and OpenInference export availability, while each report card shows runtime, Frida, artifact, trace-depth, canonical span, and export status.

Reference screenshots:

![Transpect Console overview](docs/images/console-overview-dashboard.png)

![Transpect showcase gallery](docs/images/console-showcase-gallery.png)

```bash
python scripts/runtime/serve_viewer.py --host 127.0.0.1 --port 8711
```

```text
http://127.0.0.1:8711/viewer/index.html?view=showcase
```

See `docs/product-showcase-guide.md` for the full workflow.

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
python scripts/validate/check_repo.py --skip-start
python scripts/validate/doctor.py
python scripts/validate/run_acceptance.py
```

Diagnosis execution also requires the `codetracer` Python module plus a resolvable source tree via `CODETRACER_ROOT`, `CODETRACER_SRC`, or a sibling `../CodeTracer/src`, which matches `scripts/diagnosis/run_codetracer_diagnosis.py`.

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
