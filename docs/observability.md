# Observability Notes

Transpect includes an optional vendored OTEL integration under `vendor/external/openclaw-observability-plugin/`.

## Purpose

The OTEL path is optional support for:

- exporting OTLP traces, metrics, and logs
- running alongside the canonical runs-based JSONL flow in `hybrid` mode
- writing optional local outputs under `live/otel/`

This path does not replace `live/runs/<runId>/` as the primary runtime record.

## Usage

```powershell
npm ci --prefix vendor/external/openclaw-observability-plugin
python scripts/runtime/setup_runtime.py --mode hybrid --render-otel-config
otelcol-contrib --config config/otel-collector.local.yaml
python scripts/runtime/start_trace.py --mode hybrid
```

## Output

- `live/otel/traces.jsonl`
- `live/otel/logs.jsonl`
- `live/otel/metrics.jsonl`

## Notes

- `config/otel-collector.template.yaml` is the committed template.
- `config/otel-collector.local.yaml` is a local rendered file.
- Switch back to canonical runs-only mode with `python scripts/runtime/setup_runtime.py --mode core`.
