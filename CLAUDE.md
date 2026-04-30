# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Transpect is a trace-first agent safety benchmarking platform. It runs real AI agent tasks (via OpenClaw), captures runtime evidence (behavior logs, Frida instrumentation, tool call artifacts), diagnoses failure trajectories, and applies online security guards to detect and block unsafe agent behavior. The primary demo scenario is a staged Xiaohongshu watering-hole attack.

## Commands

### Environment Setup
```bash
conda create -n transpect-py311 python=3.11 -y && conda activate transpect-py311
pip install -r requirements.txt
pip install -e ../CodeTracer   # sibling checkout, optional
python scripts/runtime/setup_runtime.py --mode core
python scripts/validate/doctor.py
```

If `CodeTracer/` or `R-Judge/` are not siblings of `Transpect/`:
```bash
export CODETRACER_ROOT="$HOME/path/to/CodeTracer"
export R_JUDGE_ROOT="$HOME/path/to/R-Judge"
```

### Tests
```bash
# Python (unittest)
python -m unittest discover -s tests -p 'test_*.py' -v

# Run a single test file
python -m unittest tests.test_agent_defense_chain -v
python -m unittest tests.validate.test_command_policy -v

# Node.js (behavior mediator)
node --test vendor/runtime-hooks/openclaw-behavior-mediator/tests/behavior-mediator.test.mjs
```

### Verification
```bash
node --check viewer/app.js && node --check viewer/shared.js
node --check vendor/runtime-hooks/openclaw-behavior-mediator/index.js
python scripts/validate/check_repo.py --skip-start
python scripts/validate/run_acceptance.py
```

### Task Execution
```bash
# List available R-Judge tasks
python scripts/runtime/run_task_repo.py --repo rjudge --mode list-tasks

# Run a single task
python scripts/runtime/run_task_repo.py --repo rjudge --mode agent-trace --task-id "data/Application/chatbot.json#37"

# Batch run
python scripts/runtime/run_rjudge_batch.py --source-path data/Program --count 5 --concurrency 2
# Use --dry-run --no-start-runtime to preview without launching agents

# Staged attack demo
python scripts/demo/run_staged_attack_site.py --host 127.0.0.1 --port 8765
python scripts/runtime/run_task_repo.py --repo staged_attack --mode agent-trace --task-id "data/xiaohongshu_waterhole_photo_upload.json#xhs-waterhole-photo-upload-001"
```

### Viewer
```bash
python scripts/runtime/serve_viewer.py   # http://127.0.0.1:8711
```

## Architecture

Four-layer pipeline:

```
Layer 1: Task Source         task_repos/ (R-Judge adapter, staged_attack demo)
Layer 2: Agent Execution     OpenClaw agent runs task, behavior mediator intercepts events
Layer 3: Trace + Diagnosis   Merged traces, CodeTracer bundle/analysis
Layer 4: Security Reasoning  Online guards, policy engine, LLM gray-zone judge, final judgment
```

### Key Data Flow

1. `run_task_repo.py` loads a task, builds an agent prompt, launches OpenClaw
2. The behavior mediator plugin (`vendor/runtime-hooks/openclaw-behavior-mediator/index.js`) intercepts all agent events and writes `behavior-events.jsonl`
3. Each tool call passes through the Python security bridge (`app/agent_defense/bridge.py`) which chains: policy check -> bypass detection -> security guards -> optional LLM judge
4. Security decisions are recorded inline and exported to `security-reasoning/`
5. Post-run: traces merge into `merged-trace.jsonl`, CodeTracer diagnosis runs, final judgment computed
6. Viewer reads `live/runs/index.json` for discovery

### Core Packages

- **`app/agent_defense/`** — Coordination layer: bridge entry point, policy engine, bypass escalation, action normalizers, trace merging, final judgment. Imports from `app.security`. Called by behavior-mediator.
- **`app/security/`** — Guard capability layer: intent/plan/action guards, risk scoring, trust model, command policy, decision engine, LLM gray-zone judge. Pure inspection functions. Never imports from `app.agent_defense`.
- **`app/instrumentation/frida/`** — Optional Frida tracing (observational only, degrades gracefully)
- **`app/runtime/agent_scenarios/`** — OpenClaw client helpers

### Key Design Decisions

- Every run is self-contained under `live/runs/<runId>/` — no global state
- Security is fused into the runtime (online), not just post-hoc
- Policy is declarative JSON (`config/agent-defense-policy.json`)
- The LLM judge is a second-opinion for ambiguous gray-zone cases only
- `docs/architecture/canonical-layout.md` is the authoritative directory layout contract

### Script Organization

Grouped under `scripts/` by responsibility: `runtime/`, `validate/`, `export/`, `diagnosis/`, `security_reasoning/`, `security_context/`, `capture/`, `demo/`, `common/`, `compat/`. Legacy flat `scripts/*.py` wrappers have been removed.

## Conventions

- Python scripts are invoked directly (`python scripts/...`), not installed as packages
- The JS viewer is vanilla HTML/CSS/JS with no build step — served as static files
- `setup_runtime.py` writes timestamped backups of OpenClaw config changes to `config/applied/`
- `vendor/runtime-hooks/openclaw-behavior-mediator/` is repo-owned; `vendor/external/` is vendored third-party
- Security decisions use Chinese user-facing messages (in `app/security/decision_engine.py`)
- `.env` at the repo root holds `BASE_URL`, `API_KEY`, `MODEL_ID` for LLM calls
