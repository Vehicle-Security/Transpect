# Architecture Overview

Transpect is built around a runs-based evidence model. The runtime writes one evidence root per task, the viewer reads the runs index plus per-run files, and diagnosis output stays attached to the same run directory instead of being stored in a separate global layer.

## Four-Layer Safety Benchmarking Architecture

Transpect now frames task repositories and agent traces as a four-layer, trace-first safety benchmarking pipeline:

1. **Benchmark / Task Source Layer**: external repositories provide tasks, scenarios, and ground-truth metadata. They do not own the primary runtime path.
2. **Real Agent Execution Layer**: OpenClaw / Transpect runs the real agent and produces the canonical `live/runs/<runId>/` directory.
3. **Trace + Diagnosis Layer**: Transpect preserves trace and policy evidence, exports CodeTracer bundles, and writes diagnosis outputs attached to the canonical run.
4. **Security Context / Benchmark Evaluation Layer**: current staged attack context judgment plus future ATBench-style trajectory-level evaluation, including `safe/unsafe`, `risk_source`, `failure_mode`, and `real_world_harm`.

Layers 1-3 are implemented for the normal task-repo flow. Layer 4 now has a first targeted defense implementation for staged attacks; broad benchmark safety scoring is still deferred.

## Primary Flow

```text
task/source adapter
  -> real OpenClaw agent execution
  -> live/runs/<runId>/
  -> task-repo source metadata
  -> Frida runtime evidence (best effort)
  -> merged trace
  -> CodeTracer diagnosis
  -> Agent Defense final judgment
  -> evaluation input seed for future Layer 4
```

Each run directory stores the task-local behavior log, optional Frida runtime evidence, merged trace, runtime snapshots, artifacts, diagnosis state, and final Agent Defense judgment. This is the canonical source of truth for runtime debugging and replay.

## Derived Diagnosis Layers

Two run-local diagnosis layers are derived from canonical run evidence:

- `diagnosis/codetracer/bundle/` is the derived CodeTracer input bundle.
- `diagnosis/codetracer/analysis/` is the derived diagnosis output layer.

These are not separate storage systems. They are derived views attached to the canonical run directory. CodeTracer is diagnosis infrastructure for failure localization, evidence retrieval, and root-cause tracing; it is not the final benchmark judge.

## Security Reasoning And Future Evaluation Layer

The current security implementation is online and fused into the runtime through `app/agent_defense/` plus the OpenClaw behavior mediator. It supports the staged Xiaohongshu watering-hole demo by maintaining security state fields such as intent constraints, source trust chain, navigation chain, scope deviation, action risk, sensitive resources, and evidence events while the agent runs. It emits `security-reasoning/security_state.json`, `security-reasoning/defense_decision.json`, `security-reasoning/evidence_summary.json`, and `security-reasoning/final_judgment.json`.

`scripts/security_reasoning/run_defense_reasoner.py` is retained for compatibility with the earlier contextual reasoner. `scripts/security_context/run_context_judge.py` remains as a compatibility wrapper that writes the older `security-context/` reports.

The future general evaluator will evaluate the full trajectory rather than only the final answer. The planned evaluation unit includes user requests, assistant responses, tool calls, environment feedback, final-answer candidates, policy evidence, source metadata, CodeTracer diagnosis, and the security reasoning artifacts.

Current Layer-3 runs prepare `artifacts/task_repo/evaluation_inputs_seed.json` with placeholders for:

- `safeUnsafe`
- `riskSource`
- `failureMode`
- `realWorldHarm`
- `benchmarkAlignment`

Those fields are intentionally left unscored until the broader Layer-4 evaluator is implemented.

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
- `scripts/security_reasoning/` for contextual defense state and decisions
- `scripts/security_context/` for compatibility security context reports
- `scripts/validate/` for repo, topology, and acceptance checks
- `scripts/capture/` for optional capture tooling
- `scripts/compat/` for legacy wrapper support

Legacy flat entrypoints in `scripts/*.py` remain as compatibility wrappers only.

## Legacy Notes

- `live/behavior-events.jsonl` is legacy migration input only.
- `harvest/` is not part of the current architecture.
- `live/archive/` remains available for optional archival and migration workflows.

See [canonical-layout.md](canonical-layout.md) for the authoritative directory-level contract.
