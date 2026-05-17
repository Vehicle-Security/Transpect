# Observability Notes

Transpect includes an optional vendored OTEL integration under `monitor/vendor/external/openclaw-observability-plugin/`.

## Purpose

The OTEL path is optional support for:

- exporting OTLP traces, metrics, and logs
- running alongside the canonical runs-based JSONL flow in `hybrid` mode
- writing optional local outputs under `monitor/live/otel/`

This path does not replace `monitor/live/runs/<runId>/` as the primary runtime record.

## Usage

```powershell
npm ci --prefix monitor/vendor/external/openclaw-observability-plugin
python tools/runtime/setup_runtime.py --mode hybrid --render-otel-config
otelcol-contrib --config config/otel-collector.local.yaml
python tools/runtime/start_trace.py --mode hybrid
```

## Output

- `monitor/live/otel/traces.jsonl`
- `monitor/live/otel/logs.jsonl`
- `monitor/live/otel/metrics.jsonl`

## Notes

- `config/otel-collector.template.yaml` is the committed template.
- `config/otel-collector.local.yaml` is a local rendered file.
- Switch back to canonical runs-only mode with `python tools/runtime/setup_runtime.py --mode core`.
