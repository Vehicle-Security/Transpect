# Product Showcase Guide

Transpect is an Agent Runtime Security prototype. It shows how an agent can be observed and defended with runtime traces, Frida low-level evidence, CodeTracer diagnosis, and a final auditable judgment.

The product showcase flow is designed for replay. Run the real agent once on your Mac, freeze the resulting run into `state/showcase/`, build front-end report models, then show the Console without rerunning the agent live.

## Generate a Real Run

From the repository root:

```bash
python scripts/validate/doctor.py
python scripts/demo/run_showcase.py --verbose
```

The important health states are OpenClaw gateway, behavior mediator, CodeTracer, and Frida. Frida may be `degraded` on macOS when permissions or `frida-tools` are missing; that state is still useful because Transpect records the degraded low-level evidence capability instead of hiding it.

## Freeze a Showcase Run

After `run_showcase.py` prints a run id, freeze it:

```bash
python scripts/demo/freeze_showcase_run.py \
  --run-dir live/runs/<runId> \
  --id staged_attack_block \
  --title "Cross-step Waterhole Attack" \
  --description "低可信评论诱导外部跳转并触发敏感上传，最终被阻断"
```

Repeat for the set you want to show:

```text
staged_attack_block       block / critical
staged_attack_confirm     require_confirmation / medium-or-high
normal_browsing_allow     allow / low
```

The freeze script copies run-local evidence into `state/showcase/<id>/` and updates `state/showcase/index.json`.

## Validate Frozen Data

Run:

```bash
python scripts/demo/build_showcase_reports.py
python scripts/demo/validate_showcase.py
python scripts/demo/validate_showcase.py --require-report-model
```

`build_showcase_reports.py` creates `state/showcase/<id>/report_model.json`. This is a derived product model for the front end; it does not replace `final_judgment.json` as the audit record.

The validator checks that every showcase has a readable `final_judgment.json`, a behavior or merged trace, displayable Frida status, displayable CodeTracer status, and a risk chain source. With `--require-report-model`, it also verifies that each Console report model exists. Missing Frida or CodeTracer data is reported as `degraded` or `unavailable` instead of crashing the replay page.

## Open the Next.js Console

Start the enterprise Console:

```bash
cd apps/console
npm install
npm run dev -- --hostname 127.0.0.1 --port 5000
```

Open:

```text
http://127.0.0.1:5000
```

Recommended pages:

```text
http://127.0.0.1:5000
http://127.0.0.1:5000/showcases
http://127.0.0.1:5000/showcases/staged_attack_block
http://127.0.0.1:5000/showcases/staged_attack_confirm
http://127.0.0.1:5000/showcases/normal_browsing_allow
http://127.0.0.1:5000/showcases/low_level_bypass_evidence
```

Reference screenshots are available for decks and walkthroughs:

```text
docs/images/console-overview-dashboard.png
docs/images/console-staged-attack-report.png
docs/images/console-artifact-viewer.png
```

## Static Viewer Fallback

Start the static viewer:

```bash
python scripts/runtime/serve_viewer.py --host 127.0.0.1 --port 8711
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

## Replay Without Rerunning Agent

Once `state/showcase/index.json`, frozen run directories, and `report_model.json` files exist, the Console is enough for demos. You do not need OpenClaw, Frida, or CodeTracer running during replay; those systems are only needed to generate or refresh the frozen data.
