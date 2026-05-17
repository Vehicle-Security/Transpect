# Product Showcase Guide

Transpect is an Agent Runtime Security prototype. It shows how an agent can be observed and defended with runtime traces, optional Frida low-level evidence, optional CodeTracer diagnosis, and a final auditable judgment.

The product showcase flow is designed for replay. A fresh GitHub clone can open the committed frozen reports without OpenClaw, Frida, CodeTracer, or R-Judge. Those components are only required when you want to generate new live evidence.

## Clone Replay Quick Start

From a clean clone:

```bash
uv sync
source .venv/bin/activate

cd dashboard/console
npm ci
cd ../..

python tools/validate/deployment_doctor.py --mode replay
python tools/demo/validate_showcase.py --require-report-model
python tools/demo/start_console.py --port 5000
```

Open `http://127.0.0.1:5000`.

Replay mode must work without CodeTracer or R-Judge. If those components are missing, Transpect reports `unavailable` for the affected diagnosis or evaluation layer and continues serving the Console.

## Optional LLM Configuration

Frozen showcase replay does not require an LLM key or a `.env` file.

For live Agent runs, Agent Defense gray-zone LLM judging, or CodeTracer diagnosis, copy the example file and fill the OpenAI-compatible endpoint:

```bash
cp .env.example .env
```

Set `BASE_URL`, `API_KEY`, and `MODEL_ID` in `.env`. CodeTracer-specific variables such as `CODETRACER_ROOT`, `CODETRACER_SRC`, and `CODETRACER_MODEL` are optional overrides. If CodeTracer or R-Judge is not installed, Transpect records `unavailable` or `degraded` status and still allows replay, validation, and Console startup.

## Generate a Real Run

From the repository root:

```bash
cp .env.example .env  # fill BASE_URL/API_KEY/MODEL_ID for LLM-backed runs
python tools/validate/doctor.py
python tools/demo/run_showcase.py --verbose
```

The important health states are OpenClaw gateway, behavior mediator, CodeTracer, and Frida. Frida may be `degraded` on macOS when permissions or `frida-tools` are missing; CodeTracer may be `unavailable` if `CODETRACER_ROOT` or `CODETRACER_SRC` is not configured. These states are recorded instead of being hidden.

`run_showcase.py` now also builds `canonical_trace.json`, writes `trace_quality.json`, and exports `exports/openinference_spans.json` during artifact completion.

## Freeze a Showcase Run

After `run_showcase.py` prints a run id, freeze it:

```bash
python monitor/trace_model/build_canonical_trace.py --run-dir monitor/live/runs/<runId>
python tools/validate/evaluate_trace_quality.py --run-dir monitor/live/runs/<runId> --write
python tools/export/export_openinference_trace.py --run-dir monitor/live/runs/<runId>
python tools/validate/validate_openinference_export.py --path monitor/live/runs/<runId>/exports/openinference_spans.json
python tools/demo/freeze_showcase_run.py \
  --run-dir monitor/live/runs/<runId> \
  --id staged_attack_confirm_frida \
  --title "Suspicious External Navigation" \
  --description "系统发现外部跳转和低层运行时证据，并将 native OpenClaw trace、Frida、CodeTracer 与最终判断统一为 deep trace。"
```

Repeat for the set you want to show:

```text
staged_attack_confirm_frida      real Frida + deep trace / primary demo
staged_attack_block_frida        real Frida block / critical
low_level_bypass_real_frida      real Frida low-level evidence / critical
normal_browsing_allow_frida      real Frida allow / low
staged_attack_block              curated or older fallback block demo
staged_attack_confirm            curated or older fallback confirmation demo
normal_browsing_allow            curated or older fallback allow demo
low_level_bypass_evidence        curated low-level evidence fallback
```

The freeze script copies run-local evidence into `dashboard/state/showcase/<id>/` and updates `dashboard/state/showcase/index.json`.

It also sanitizes machine-local paths so frozen reports can be committed:

```bash
python tools/demo/sanitize_showcase_paths.py --check
python tools/validate/check_portability.py
```

For deep trace demos, verify native OpenClaw source coverage before freezing:

```bash
python tools/validate/discover_openclaw_native_sources.py --run-dir monitor/live/runs/<runId>
python tools/validate/audit_canonical_trace.py --run-dir monitor/live/runs/<runId>
```

`traceDepth: deep` requires native lifecycle, assistant, and tool source files plus Agent Defense, Frida, CodeTracer, and final judgment evidence. Older runs without native source files remain replayable, but their trace quality is normally `moderate`.

## Validate Frozen Data

Run:

```bash
python tools/demo/build_showcase_reports.py
python tools/demo/validate_showcase.py
python tools/demo/validate_showcase.py --require-report-model
```

`build_showcase_reports.py` creates `dashboard/state/showcase/<id>/report_model.json`. This is a derived product model for the front end; it does not replace `final_judgment.json` as the audit record.

The validator checks that every showcase has a readable `final_judgment.json`, a behavior or merged trace, displayable Frida status, displayable CodeTracer status, and a risk chain source. With `--require-report-model`, it also verifies that each Console report model exists. Missing Frida or CodeTracer data is reported as `degraded` or `unavailable` instead of crashing the replay page.

## Open the Next.js Console

Start the enterprise Console:

```bash
cd dashboard/console
npm ci
npm run dev -- --hostname 127.0.0.1 --port 5000
```

The helper script performs the same startup with prerequisite checks:

```bash
python tools/demo/start_console.py --port 5000
```

Open:

```text
http://127.0.0.1:5000
```

Recommended pages:

```text
http://127.0.0.1:5000
http://127.0.0.1:5000/showcases
http://127.0.0.1:5000/showcases/staged_attack_confirm_frida
http://127.0.0.1:5000/showcases/staged_attack_block_frida
http://127.0.0.1:5000/showcases/low_level_bypass_real_frida
http://127.0.0.1:5000/showcases/normal_browsing_allow_frida
```

Reference screenshots are available for decks and walkthroughs:

```text
docs/images/console-overview-dashboard.png
docs/images/console-showcase-gallery.png
docs/images/console-staged-attack-report.png
docs/images/console-artifact-viewer.png
```

The current overview screenshot shows 8 frozen reports, 5 blocked cases, 1 confirmation case, 2 allowed cases, 5/8 Frida evidence availability, 8/8 CodeTracer availability, 1/8 deep Trace Backbone readiness, and 8/8 OpenInference export availability. The showcase gallery screenshot shows the report cards with verdict, risk, data source, runtime event count, Frida event count, artifact count, trace depth, canonical span count, and export readiness.

## Static Viewer Fallback

Start the static viewer:

```bash
python tools/runtime/serve_viewer.py --host 127.0.0.1 --port 8711
```

Open:

```text
http://127.0.0.1:8711/viewer/index.html?view=showcase
```

Use `?view=showcase&id=<showcase_id>` to open a specific frozen run.

## How to Read the Page

The Console overview summarizes the frozen corpus: blocked runs, confirmation runs, allowed runs, Frida availability, CodeTracer availability, critical cases, evidence coverage, and recommended demo order.

Each showcase card represents one frozen run. The Agent Security Report explains:

- Agent task and final decision.
- Detection pipeline from Runtime Trace to Final Judgment.
- Cross-step risk chain in product language, with `observed` and `scenario` stages labeled separately.
- Runtime trace evidence from `behavior-events.jsonl` or `merged-trace.jsonl`.
- Frida evidence status and low-level event summary.
- CodeTracer diagnosis status and summary.
- Findings, recommendations, and audit artifacts with links to the underlying files.

## Evidence Roles

Runtime trace evidence explains what the agent did at browser/tool level.

Frida evidence supplements behavior the browser or OpenClaw trace may not fully see, such as sensitive file access, non-browser network behavior, or process-level activity. If the environment blocks Frida, the page shows the degraded reason.

CodeTracer turns the run into a diagnosis bundle and analysis report. This proves that the run is not only blocked online; it can also be exported and audited after the fact.

`final_judgment.json` is the fused evidence record. It ties together runtime trace, Agent Defense decision, Frida status, CodeTracer status, risk level, and reason.

`report_model.json` is the Console-friendly projection of that evidence. It normalizes decisions, risk levels, pipeline status, risk chain nodes, findings, recommendations, and artifacts so the front end does not need to infer product semantics from JSONL files.

`canonical_trace.json` is the standard Agent Trace Backbone projection. It unifies OpenClaw native sources, behavior trace, Frida evidence, CodeTracer diagnosis, and final judgment into a span tree for quality checks and OpenInference-style export. It is derived evidence and does not replace the raw audit files.

See `docs/agent-trace-backbone-v1.md` for the trace schema, quality policy, and export mapping.

## Replay Without Rerunning Agent

Once `dashboard/state/showcase/index.json`, frozen run directories, and `report_model.json` files exist, the Console is enough for demos. You do not need OpenClaw, Frida, or CodeTracer running during replay; those systems are only needed to generate or refresh the frozen data.
