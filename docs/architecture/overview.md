# Architecture Overview

Transpect is built around a runs-based evidence model. The runtime writes one evidence root per task, the viewer reads the runs index plus per-run files, and diagnosis output stays attached to the same run directory instead of being stored in a separate global layer.

## Four-Layer Safety Benchmarking Architecture

Transpect now frames task repositories and agent traces as a four-layer, trace-first safety benchmarking pipeline:

1. **Benchmark / Task Source Layer**: external repositories provide tasks, scenarios, and ground-truth metadata. They do not own the primary runtime path.
2. **Real Agent Execution Layer**: OpenClaw / Transpect runs the real agent and produces the canonical `live/runs/<runId>/` directory.
3. **Trace + Diagnosis Layer**: Transpect preserves trace and policy evidence, exports CodeTracer bundles, and writes diagnosis outputs attached to the canonical run.
4. **Benchmark Evaluation Layer**: future layer for ATBench-style trajectory-level evaluation, including `safe/unsafe`, `risk_source`, `failure_mode`, and `real_world_harm`.

Only Layers 1-3 are implemented in this step. Layer 4 is intentionally deferred; current artifacts prepare its inputs without producing benchmark safety scores.

## Primary Flow

```text
task/source adapter
  -> real OpenClaw agent execution
  -> live/runs/<runId>/
  -> task-repo source metadata
  -> CodeTracer diagnosis
  -> evaluation input seed for future Layer 4
```

Each run directory stores the task-local behavior log, runtime snapshots, artifacts, and diagnosis state. This is the canonical source of truth for runtime debugging and replay.

## Derived Diagnosis Layers

Two run-local diagnosis layers are derived from canonical run evidence:

- `diagnosis/codetracer/bundle/` is the derived CodeTracer input bundle.
- `diagnosis/codetracer/analysis/` is the derived diagnosis output layer.

These are not separate storage systems. They are derived views attached to the canonical run directory. CodeTracer is diagnosis infrastructure for failure localization, evidence retrieval, and root-cause tracing; it is not the final benchmark judge.

## Future Evaluation Layer

Layer 4 will evaluate the full trajectory rather than only the final answer. The planned evaluation unit includes user requests, assistant responses, tool calls, environment feedback, final-answer candidates, policy evidence, source metadata, and CodeTracer diagnosis.

Current Layer-3 runs prepare `artifacts/task_repo/evaluation_inputs_seed.json` with placeholders for:

- `safeUnsafe`
- `riskSource`
- `failureMode`
- `realWorldHarm`
- `benchmarkAlignment`

Those fields are intentionally left unscored until the Layer-4 evaluator is implemented.

## Optional Supporting Flows

Optional integrations remain separate from the canonical run store:

- OTEL: `vendor/external/openclaw-observability-plugin/` writes optional outputs under `live/otel/`.
- Frida: `scripts/capture/capture_frida.py` writes optional host-side capture output under `live/frida/`.

These support diagnosis, but they do not replace `live/runs/<runId>/` as the primary runtime record.

## Script Organization

The repository groups scripts by responsibility:

- `scripts/common/` for shared path and utility helpers
- `scripts/runtime/` for runtime setup, startup, cleanup, and viewer serving
- `scripts/export/` for CodeTracer bundle generation
- `scripts/diagnosis/` for diagnosis execution and legacy segmentation
- `scripts/validate/` for repo, topology, and acceptance checks
- `scripts/capture/` for optional capture tooling
- `scripts/compat/` for legacy wrapper support

Legacy flat entrypoints in `scripts/*.py` remain as compatibility wrappers only.

## Legacy Notes

- `live/behavior-events.jsonl` is legacy migration input only.
- `harvest/` is not part of the current architecture.
- `live/archive/` remains available for optional archival and migration workflows.

See [canonical-layout.md](canonical-layout.md) for the authoritative directory-level contract.
