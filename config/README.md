# Config Directory

`config/` stores committed templates plus locally generated runtime configuration.

- `otel-collector.template.yaml` is the committed collector template.
- `otel-collector.local.yaml` is generated locally by `python scripts/runtime/setup_runtime.py --mode hybrid --render-otel-config`.
- `config/applied/` stores timestamped backups when runtime setup rewrites `~/.openclaw/openclaw.json`.

Only templates and documentation belong in git. Local rendered files and backups are ignored.
