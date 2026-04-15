# OTEL Observability

Transpect ships with the `otel-observability` plugin under `vendor/openclaw-observability-plugin/`.

## What It Does

- Emits OTLP traces, metrics, and logs from the OpenClaw gateway
- Keeps the behavior-mediator JSONL path available in `hybrid` mode
- Can be paired with a local collector that writes JSON to `live/otel/`

## Setup

1. Install plugin dependencies.

```powershell
npm ci --prefix vendor/openclaw-observability-plugin
```

2. Render a local collector config.

```powershell
python scripts/setup_runtime.py --mode hybrid --render-otel-config
```

3. Start the collector.

```powershell
otelcol-contrib --config config/otel-collector.local.yaml
```

4. Start the runtime in `hybrid` or `otel` mode.

```powershell
python scripts/start_trace.py --mode hybrid
```

## Resulting Files

- `live/otel/traces.jsonl`
- `live/otel/logs.jsonl`
- `live/otel/metrics.jsonl`

## Switching Back

To return to the JSONL-only path:

```powershell
python scripts/setup_runtime.py --mode core
```

## Notes

- The repository keeps a portable collector template in `config/otel-collector.template.yaml`.
- The rendered `config/otel-collector.local.yaml` is machine-specific and ignored by git.
- If you want to forward OTLP data to another backend, edit the rendered local config or adjust the plugin settings in `~/.openclaw/openclaw.json`.
