# Trace-first Agent Safety Benchmarking Architecture

This document describes the current Transpect architecture for trace-first agent
safety benchmarking. The project is being moved toward a four-layer model:

1. Benchmark / Task Source Layer
2. Real Agent Execution Layer
3. Trace + Diagnosis Layer
4. Benchmark Evaluation Layer

Layers 1-3 are implemented in the current step. Layer 4 is intentionally marked
as TODO and is not yet a benchmark judge.

## Current status

The current implementation validates the first three layers with R-Judge as the
first task source:

```text
R-Judge task
  -> normalized agent-facing prompt
  -> real OpenClaw / Transpect agent run
  -> canonical live/runs/<runId>/ trace
  -> source metadata + diagnosis artifacts
  -> evaluation_inputs_seed.json for future Layer 4
```

R-Judge is not treated as the primary evaluation engine. It is only a convenient
source of tasks, scenarios, and benchmark metadata. The primary runtime path is
the real OpenClaw / Transpect agent execution path.

## Layer 1: Benchmark / Task Source

Purpose:

- enumerate benchmark tasks
- load one task by stable id
- expose source metadata
- build a first-pass agent-facing input
- avoid leaking benchmark ground truth into the agent prompt

Current implementation:

- Runner: `scripts/runtime/run_task_repo.py`
- Shared helpers: `scripts/common/task_repo_common.py`
- R-Judge adapter: `task_repos/rjudge/adapter.py`
- R-Judge source preflight: `task_repos/rjudge/source_preflight.py`
- Manifest schema: `task_repos/manifest.schema.json`

The source adapter interface is:

- `list_tasks(manifest, prepared_env)`
- `load_task(manifest, prepared_env, task_id)`
- `build_agent_input(manifest, prepared_env, task)`

For R-Judge, tasks are loaded from:

```text
<R_JUDGE_ROOT>/data/**/*.json
```

The default local layout assumes `Transpect/`, `CodeTracer/`, and `R-Judge/` are sibling checkouts. `R_JUDGE_ROOT` can override that default when the repositories live elsewhere.

Stable task ids use this shape:

```text
data/<category>/<file>.json#<sample_id>
```

Example:

```text
data/Application/chatbot.json#37
```

The generated prompt includes role/profile, task framing, and conversation
content while preserving R-Judge round boundaries. It excludes fields such as
`label`, `risk_description`, and other benchmark-only answer hints.

## Layer 2: Real Agent Execution

Purpose:

- run the actual OpenClaw / Transpect agent
- obtain a real canonical `runId`
- resolve the canonical run directory under `live/runs/<runId>/`
- avoid creating a parallel primary taskrepo run when a real run exists

Current implementation:

- Runner mode: `--mode agent-trace`
- OpenClaw bridge: `scripts/common/trace_common.py::run_openclaw_agent`
- Run resolution/polling: `scripts/common/task_repo_common.py::wait_for_agent_trace_run`
- Source metadata attachment:
  `scripts/common/task_repo_common.py::attach_source_metadata_to_run`

The runner calls the real OpenClaw agent path and then polls the canonical run
directory. If a real `runId` is resolved, that run is the only primary artifact.
Task source metadata is merged into:

- `live/runs/<runId>/task_input.json`
- `live/runs/<runId>/manifest.json`
- `live/runs/<runId>/artifacts/task_repo/source_task.json`
- `live/runs/<runId>/artifacts/task_repo/harness_report.json`
- `live/runs/<runId>/artifacts/task_repo/artifact_manifest.json`

The harness also handles an OpenClaw CLI edge case: the CLI process may time out
after the canonical run has already been created. In agent-trace no-wait mode,
the harness can infer the real run from the known session id and continue
polling `live/runs/<runId>/`.

## Layer 3: Trace + Diagnosis

Purpose:

- preserve the canonical trajectory trace
- preserve source metadata and policy evidence
- export a CodeTracer diagnosis bundle
- run CodeTracer diagnosis
- write a stable Transpect-facing `diagnosis_report.json`
- prepare data for the future benchmark evaluation layer

Current implementation:

- CodeTracer diagnosis runner:
  `scripts/diagnosis/run_codetracer_diagnosis.py`
- CodeTracer bundle export:
  `scripts/export/export_codetracer_bundle.py`
- Seed input builder:
  `scripts/common/task_repo_common.py::build_evaluation_inputs_seed`

Artifacts currently produced or updated:

- `live/runs/<runId>/behavior-events.jsonl`
- `live/runs/<runId>/diagnosis/codetracer/bundle/*`
- `live/runs/<runId>/diagnosis/codetracer/analysis/diagnosis_run.json`
- `live/runs/<runId>/diagnosis/codetracer/analysis/codetracer_analysis.json`
- `live/runs/<runId>/diagnosis/codetracer/analysis/diagnosis_report.json`
- `live/runs/<runId>/artifacts/task_repo/evaluation_inputs_seed.json`

CodeTracer belongs to the diagnosis layer. It is not the final benchmark judge.
Its role is trajectory diagnosis: failure onset localization, evidence
retrieval, root-cause tracing, replay/debug signals, and error-relevant steps.

`evaluation_inputs_seed.json` is a bridge artifact for the future evaluator. It
contains source metadata, benchmark reference metadata, final-answer candidates,
trace paths, policy observations, and diagnosis paths. It does not score safety.

## Layer 4: Benchmark Evaluation [TODO]

Layer 4 is intentionally not implemented yet.

Future goal:

- evaluate the full trajectory, not only the final answer
- align with ATBench-style trajectory-level safety framing
- classify or report:
  - safe / unsafe
  - risk source
  - failure mode
  - real-world harm
  - benchmark alignment

Layer 4 should consume the data prepared by Layers 1-3:

- source task metadata
- benchmark labels and reference metadata
- canonical behavior trajectory
- assistant responses and final-answer candidates
- tool calls and environment feedback
- policy observations
- CodeTracer diagnosis report

Current non-goals:

- no safe/unsafe classifier
- no risk-source classifier
- no failure-mode classifier
- no harm classifier
- no final benchmark score

## Commands

List R-Judge tasks:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode list-tasks
```

Show one R-Judge task:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode show-task --task-id "data/Application/chatbot.json#37"
```

Run one sample through Layers 1-3:

```bash
conda activate transpect-py311
python scripts/runtime/setup_runtime.py --mode core
python scripts/validate/doctor.py
python scripts/runtime/run_task_repo.py --repo rjudge --mode agent-trace --task-id "data/Application/chatbot.json#37"
```

If `doctor.py` reports `scope upgrade pending approval` or `pairing required`, approve the requested OpenClaw scopes before retrying the run.

Run agent-trace without CodeTracer diagnosis:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode agent-trace --task-id "data/Application/chatbot.json#37" --skip-diagnosis
```

Inspect the resulting run:

```bash
ls -td live/runs/* | head -n 1
cat live/runs/<runId>/manifest.json
cat live/runs/<runId>/task_input.json
cat live/runs/<runId>/artifacts/task_repo/evaluation_inputs_seed.json
cat live/runs/<runId>/diagnosis/codetracer/analysis/diagnosis_report.json
```

Legacy repo-native baseline mode remains available for compatibility:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode repo-native --preflight-only
```

When `--mode` is omitted, the runner still defaults to `repo-native` for
backward compatibility. Strategically, however, `agent-trace` is the primary
path for trace-first safety benchmarking.

## Known current limitation

Layer 3 path discovery and report writing are implemented, but CodeTracer
analysis can still fail if the local CodeTracer Python dependencies are not
compatible with the active Python environment. For example, CodeTracer currently
expects a newer OpenAI Python SDK than `openai==0.28.1`. In that case the
diagnosis layer still writes a structured failed `diagnosis_report.json`, and
the canonical run, trace, source metadata, and seed evaluation inputs remain
available for debugging and future evaluation.
