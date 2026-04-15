# Architecture

Transpect is organized around three complementary data paths:

## 1. JSONL Trace Path

The default path is:

```text
OpenClaw hooks -> behavior-mediator -> live/behavior-events.jsonl -> viewer/index.html
```

This path is the fastest way to inspect requests, turns, tools, tasks, and LLM activity in a single browser session.

## 2. OTEL Path

The OTEL path uses the vendored `otel-observability` plugin and optional collector config:

```text
OpenClaw hooks -> otel-observability -> OTLP -> config/otel-collector.local.yaml -> live/otel/*.jsonl
```

This path is useful when you want local OTLP output or want to forward telemetry to another backend.

## 3. Frida Path

The Frida path attaches to a running gateway process and records host-level activity:

```text
Frida attach -> frida/openclaw_gateway_windows.js -> live/frida/*.jsonl
```

It captures process, file, port, and network events and complements the JSONL and OTEL traces.

## Repository Roles

- `scripts/setup_runtime.py` patches `~/.openclaw/openclaw.json` into `core`, `hybrid`, or `otel` mode.
- `scripts/start_trace.py` prepares runtime mode, starts the gateway if needed, and serves the viewer when applicable.
- `scripts/doctor.py` inspects runtime health and reports the inferred active mode.
- `scripts/run_acceptance.py` sends a small set of safe prompts and validates the resulting trace stream.
- `scripts/check_repo.py` checks syntax, required files, ignore rules, and portability constraints.

## Mode Summary

- `core`: behavior mediator only
- `hybrid`: behavior mediator + OTEL plugin
- `otel`: OTEL plugin only

## Portability Rules

- Repository paths are derived from the cloned repository root instead of fixed machine paths.
- OTEL collector output paths are rendered into `config/otel-collector.local.yaml` from a committed template.
- Runtime state lives under `live/`, `captures/`, and `config/applied/`, all of which are ignored by git.
