# Task Repo Adapters

Transpect treats task repositories primarily as sources of benchmark tasks or scenarios. This supports a four-layer trace-first safety benchmarking architecture:

1. **Task Source**: enumerate and load source tasks without leaking labels into prompts.
2. **Real Agent Execution**: run the actual OpenClaw / Transpect agent and use the real `runId`.
3. **Trace + Diagnosis**: attach source metadata, preserve trace/policy evidence, and run CodeTracer diagnosis.
4. **Benchmark Evaluation**: future ATBench-style trajectory evaluator.

Only Layers 1-3 are implemented now. Layer 4 is deferred, and current runs only prepare its input artifacts.

The preferred path is:

1. load a source task from the external repository
2. run that task through the real OpenClaw agent harness
3. analyze the resulting trace in the canonical `live/runs/<runId>/` directory
4. prepare evaluation inputs for a later trajectory-level benchmark evaluator

Repo-native execution is still supported as an explicit baseline mode through `--mode repo-native`. For backward compatibility, omitting `--mode` also uses `repo-native`.

## Structure

Each external task repository lives under `task_repos/<repo>/` with:

- `manifest.json`: declarative configuration
- `adapter.py`: repository-specific source and optional repo-native logic
- `source_preflight.py`: optional source-mode preflight checks

The shared schema lives at `task_repos/manifest.schema.json`.

The shared runtime entrypoint is:

```bash
python scripts/runtime/run_task_repo.py --repo <repo> --mode <mode>
```

Supported modes:

- `list-tasks`: list lightweight source-task entries
- `show-task`: print one full source task
- `agent-trace`: run one source task through the real OpenClaw agent harness
- `repo-native`: run repository-native commands from the manifest

## Source Model

Source-capable adapters expose:

- `list_tasks(manifest, prepared_env)`
- `load_task(manifest, prepared_env, task_id)`
- `build_agent_input(manifest, prepared_env, task)`

Source modes run source preflight only. They verify the source repository and task data, but they do not require model resolution for `list-tasks` or `show-task`.

For `agent-trace`, the runner builds an agent-facing prompt from the source task and calls the real OpenClaw agent. When a real `runId` is returned, the runner attaches task-repo metadata to that run instead of creating a parallel primary taskrepo run.

The real run remains canonical:

- `live/runs/<runId>/task_input.json`
- `live/runs/<runId>/manifest.json`
- `live/runs/<runId>/behavior-events.jsonl`
- `live/runs/<runId>/artifacts/task_repo/source_task.json`
- `live/runs/<runId>/artifacts/task_repo/harness_report.json`
- `live/runs/<runId>/artifacts/task_repo/artifact_manifest.json`
- `live/runs/<runId>/artifacts/task_repo/evaluation_inputs_seed.json`
- `live/runs/<runId>/diagnosis/codetracer/bundle/...`
- `live/runs/<runId>/diagnosis/codetracer/analysis/diagnosis_report.json`

If the agent cannot be launched or no `runId` is returned, the runner emits a lightweight harness failure report and does not create a primary taskrepo run.

By default, `agent-trace` runs Layer-3 CodeTracer diagnosis after a real run reaches a terminal state. Use `--skip-diagnosis` for cheaper debugging runs.

`evaluation_inputs_seed.json` is not a benchmark score. It preserves source metadata, benchmark reference fields, final-answer candidates, policy evidence, trace paths, and diagnosis paths for a future Layer-4 evaluator.

## ATBench Alignment

The future evaluation layer follows ATBench's trajectory-level framing:

- evaluate the full trajectory, not only the final answer
- preserve evidence for delayed-trigger and tool-mediated risks
- prepare taxonomy fields for `safe/unsafe`, `risk_source`, `failure_mode`, and `real_world_harm`
- keep benchmark labels and risk descriptions out of the agent-facing prompt

This step does not implement those classifiers. It only makes the evidence path real and repeatable.

## Repo-Native Baseline

Repo-native mode preserves the earlier manifest-driven command execution path. It creates a taskrepo run under `live/runs/<runId>/`, writes adapter reports, executes manifest commands, and collects declared artifacts.

Repo-native preflight includes:

- Python version compatibility
- expected named environment matching for `venv` and `conda`
- required environment variables
- required file existence and readability
- optional model service checks
- adapter-provided checks

Command execution logs are written under:

- `live/runs/<runId>/artifacts/task_repo/commands/<command>/stdout.log`
- `live/runs/<runId>/artifacts/task_repo/commands/<command>/stderr.log`

Manifest-declared result paths are copied into:

- `live/runs/<runId>/artifacts/task_repo/repo_outputs/...`

## Manifest Model

The manifest declares:

- repository root
- preferred and supported Python versions
- setup commands
- preflight requirements
- environment mapping
- optional source configuration
- optional repo-native run commands
- expected result paths
- known risks

The `run` section is optional at the schema level, but it is required when `--mode repo-native` is selected.

The optional `source` section can declare:

- `data_root`
- `data_pattern`
- `task_id_format`

The runner also loads `.env` values before manifest defaults:

- shell environment variables keep highest priority
- `Transpect/.env` is loaded next
- `<task repo root>/.env` is loaded after that
- manifest `env_defaults` only fill still-missing keys

For model-oriented repositories, common aliases are normalized before execution:

- `BASE_URL -> MODEL_BASE_URL`
- `API_KEY -> MODEL_API_KEY`
- `MODEL_ID -> MODEL_NAME`

## R-Judge

`task_repos/rjudge/manifest.json` configures R-Judge as both a source adapter and a repo-native baseline.

Recommended local layout:

```text
code/
├── Transpect/
├── CodeTracer/
└── R-Judge/
```

Path resolution order for the R-Judge source repository is:

1. `R_JUDGE_ROOT`
2. manifest `repo_root`
3. relative `repo_root` resolved from the manifest directory

Source-mode assumptions:

- default checkout root: sibling `R-Judge/` repository
- data root: `<R_JUDGE_ROOT>/data`
- data pattern: `**/*.json`
- task ID format: `data/<category>/<file>.json#<sample_id>`
- `contents` is serialized round-by-round in the agent prompt
- `label`, `risk_description`, and benchmark-only evaluation metadata are not included in the agent-facing prompt

Repo-native assumptions remain explicit:

- preferred Python: `3.11`
- supported Python: `3.10`, `3.11`
- accepted environment names: `rjudge-py311`, `rjudge-py310`, or local `py310`
- required full benchmark files: `config/data_schema.json`, `eval/safety_judgment.py`, `eval/risk_identification.py`, `eval/extract_analysis.py`
- default model name: `qwen-plus`
- default model base URL: `https://dashscope.aliyuncs.com/compatible-mode/v1`
- repository env mapping: `API_KEY <- MODEL_API_KEY`

Recommended macOS environments:

- `transpect-py311`: run Transpect scripts, OpenClaw runtime hooks, and CodeTracer diagnosis
- `rjudge-py310`: optional repo-native baseline environment for upstream R-Judge scripts

`agent-trace` only requires the R-Judge dataset checkout to be readable. It does not require repo-native R-Judge commands to succeed first.

## Commands

List available source tasks:

```bash
conda activate transpect-py311
python scripts/runtime/run_task_repo.py --repo rjudge --mode list-tasks
```

Show one source task:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode show-task --task-id "data/Application/chatbot.json#37"
```

Run one source task through the real agent trace harness:

```bash
export CODETRACER_ROOT="${CODETRACER_ROOT:-$(cd .. && pwd)/CodeTracer}"
export R_JUDGE_ROOT="${R_JUDGE_ROOT:-$(cd .. && pwd)/R-Judge}"
python scripts/runtime/run_task_repo.py --repo rjudge --mode agent-trace --task-id "data/Application/chatbot.json#37"
```

Before the first `agent-trace` run on macOS, prepare OpenClaw in core mode:

```bash
python scripts/runtime/setup_runtime.py --mode core
python scripts/validate/doctor.py
```

If `doctor.py` reports `scope upgrade pending approval` or `pairing required`, approve the requested scopes in OpenClaw and rerun `doctor.py`.

Run one source task without diagnosis:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode agent-trace --task-id "data/Application/chatbot.json#37" --skip-diagnosis
```

Run repo-native preflight:

```bash
conda activate rjudge-py310
python scripts/runtime/run_task_repo.py --repo rjudge --mode repo-native --preflight-only
```

Run a repo-native baseline command:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --mode repo-native --command safety_judgment
```

Backward-compatible repo-native invocation:

```bash
python scripts/runtime/run_task_repo.py --repo rjudge --command safety_judgment_smoke
```

Inspect structured outputs:

```bash
ls -td live/runs/* | head -n 1
cat live/runs/<runId>/adapter/preflight_report.json
cat live/runs/<runId>/adapter/run_report.json
find live/runs/<runId>/artifacts/task_repo -type f | sort
cat live/runs/<runId>/artifacts/task_repo/evaluation_inputs_seed.json
cat live/runs/<runId>/diagnosis/codetracer/analysis/diagnosis_report.json
```

## Failure Reasons

Source and agent-trace modes add:

- `source_adapter_missing`
- `task_not_found`
- `agent_launch_failed`
- `agent_run_timeout`

Repo-native reasons include:

- `python_version_unsupported`
- `expected_env_missing`
- `expected_env_mismatch`
- `missing_required_env`
- `required_file_missing`
- `required_file_unreadable`
- `required_file_blocked`
- `model_service_env_missing`
- `model_service_unreachable`
- `command_failed`
- `repo_outputs_missing`
- `model_auth_failed`
- `model_quota_failed`
- `model_name_unavailable`

## Adding Another Repository

1. Create `task_repos/<repo>/manifest.json`.
2. Add source methods to `task_repos/<repo>/adapter.py`.
3. Add `source_preflight.py` if generic source capability checks are not enough.
4. Use `--mode list-tasks` and `--mode show-task` first.
5. Add repo-specific tests for custom adapter behavior.
