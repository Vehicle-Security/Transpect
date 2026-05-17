# Agent Trace Backbone v1

Transpect Agent Trace Backbone v1 is the standard trace layer that turns a run directory into a portable, auditable Agent execution record.

It does not replace raw evidence. It derives a stable view from run-local files such as `behavior-events.jsonl`, OpenClaw native source files, `frida-events.jsonl`, CodeTracer diagnosis, and `final_judgment.json`.

## Data Flow

```text
OpenClaw run
  -> OpenClaw native source files
  -> behavior-events.jsonl / merged-trace.jsonl
  -> frida-events.jsonl
  -> CodeTracer diagnosis
  -> final_judgment.json
  -> canonical_trace.json
  -> trace_quality.json
  -> exports/openinference_spans.json
  -> frozen showcase report_model.json
```

## Native OpenClaw Source Files

The repository-owned behavior mediator writes these run-local files when a new OpenClaw task runs:

| File | Purpose |
| --- | --- |
| `openclaw-lifecycle.jsonl` | Request, agent start, agent end, and request completion lifecycle. |
| `openclaw-assistant.jsonl` | LLM input/output and assistant response previews. |
| `openclaw-tools.jsonl` | Tool call start/end with sanitized params and result preview. |
| `openclaw-plugin-hooks.jsonl` | Sanitized typed-hook envelopes for audit and importer fallback. |
| `session_transcript.json` | Minimal redacted session transcript for replay context. |

These files are intentionally smaller than the raw OpenClaw process state. They keep IDs, timestamps, parent span IDs, sanitized previews, and tool/LLM metadata needed to reconstruct the span tree.

Use discovery before and after a run:

```bash
python tools/validate/discover_openclaw_native_sources.py
python tools/validate/discover_openclaw_native_sources.py --run-dir monitor/live/runs/<runId>
```

## Canonical Trace

Build the canonical trace after merge, Frida, CodeTracer, and final judgment are available:

```bash
python monitor/trace_model/build_canonical_trace.py --run-dir monitor/live/runs/<runId>
```

Output:

```text
monitor/live/runs/<runId>/canonical_trace.json
```

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | `transpect.canonical_trace.v1`. |
| `traceId`, `runId`, `sessionId` | Stable run identity. |
| `rootSpanId` | Root `AGENT_RUN` span. |
| `spans` | Standardized span tree. |
| `events` | Event-level records linked to spans. |
| `artifacts` | Run-local evidence files. |
| `securityEdges` | Runtime-to-security decision links. |
| `sources` | Source status and event counts. |

Span kinds:

```text
AGENT_RUN
AGENT_TURN
LLM_CALL
TOOL_CALL
BROWSER_ACTION
AGENT_DEFENSE
FRIDA_EVIDENCE
CODETRACER_DIAGNOSIS
FINAL_JUDGMENT
ARTIFACT
```

Display fields:

| Field | Values | Meaning |
| --- | --- | --- |
| `displayTier` | `primary`, `evidence`, `raw` | Product display level. |
| `importance` | `critical`, `high`, `medium`, `low`, `debug` | Security/audit priority. |
| `sourceConfidence` | `high`, `medium`, `low` | Confidence in the source linkage. |

Native OpenClaw spans are preferred for parentage:

```text
AGENT_RUN
  -> AGENT_TURN
    -> LLM_CALL
    -> TOOL_CALL / BROWSER_ACTION
      -> AGENT_DEFENSE
  -> FRIDA_EVIDENCE
  -> CODETRACER_DIAGNOSIS
  -> FINAL_JUDGMENT
```

If native OpenClaw files are missing, Transpect falls back to behavior-mediator events, but trace quality is capped below `deep`.

## Frida Summarization

Raw Frida can produce many low-level events. Canonical trace keeps the raw file as the audit source and emits:

- one `Frida low-level evidence summary` span
- separate high/critical Frida evidence spans
- no one-span-per-noise-event expansion

The raw evidence remains in `frida-events.jsonl`.

## Trace Quality

Evaluate and optionally persist quality:

```bash
python tools/validate/evaluate_trace_quality.py --run-dir monitor/live/runs/<runId>
python tools/validate/evaluate_trace_quality.py --run-dir monitor/live/runs/<runId> --write
```

`trace_quality.json` records:

- `traceDepth`: `empty`, `shallow`, `moderate`, or `deep`
- coverage for lifecycle, assistant, LLM, tool/browser, Agent Defense, Frida, CodeTracer, and final judgment
- gaps and recommendations
- score

Depth policy:

| Depth | Meaning |
| --- | --- |
| `empty` | No substantive spans beyond root. |
| `shallow` | Request/turn shell only. |
| `moderate` | Runtime/security evidence exists, but native OpenClaw streams are incomplete. |
| `deep` | Native lifecycle + assistant + tool stream, LLM/tool behavior, Agent Defense, Frida, CodeTracer, and final judgment are all present. |

Audit trace health:

```bash
python tools/validate/audit_canonical_trace.py --run-dir monitor/live/runs/<runId>
```

The audit checks span kinds, sources, display tiers, parent coverage, artifact reference coverage, duplicate rate, Frida dominance, and missing native sources.

## OpenInference Export

Export a local OpenInference-style artifact:

```bash
python tools/export/export_openinference_trace.py --run-dir monitor/live/runs/<runId>
python tools/validate/validate_openinference_export.py --path monitor/live/runs/<runId>/exports/openinference_spans.json
```

Mapping:

| Canonical kind | OpenInference style |
| --- | --- |
| `AGENT_RUN`, `AGENT_TURN` | `AGENT` |
| `LLM_CALL` | `LLM` |
| `TOOL_CALL`, `BROWSER_ACTION` | `TOOL` |
| `AGENT_DEFENSE` | `GUARDRAIL` |
| `FRIDA_EVIDENCE` | `TOOL` with OS evidence attributes |
| `CODETRACER_DIAGNOSIS`, `FINAL_JUDGMENT` | `EVALUATOR` / `GUARDRAIL` |

The exporter does not require Phoenix, Langfuse, or an OTLP collector. It writes a local JSON artifact first.

## Frozen Showcase

Before freezing a showcase, generate the trace backbone artifacts:

```bash
python monitor/trace_model/build_canonical_trace.py --run-dir monitor/live/runs/<runId>
python tools/validate/evaluate_trace_quality.py --run-dir monitor/live/runs/<runId> --write
python tools/export/export_openinference_trace.py --run-dir monitor/live/runs/<runId>
python tools/validate/validate_openinference_export.py --path monitor/live/runs/<runId>/exports/openinference_spans.json
```

Then freeze:

```bash
python tools/demo/freeze_showcase_run.py --run-dir monitor/live/runs/<runId> --id <showcase_id> --title "<title>" --description "<description>"
python tools/demo/build_showcase_reports.py
python tools/demo/validate_showcase.py --require-report-model
```

`report_model.json` reads canonical trace first when available and exposes `traceBackbone` summary fields for the Console.
