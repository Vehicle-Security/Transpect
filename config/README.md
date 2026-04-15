# 配置目录说明

`config/` 目录用于存放可移植模板和本机渲染生成的运行配置。

- `otel-collector.template.yaml` 会随仓库提交，里面保留模板占位符。
- `otel-collector.local.yaml` 由 `python scripts/setup_runtime.py --mode hybrid --render-otel-config` 在本机生成。
- `config/applied/` 会在写入 `~/.openclaw/openclaw.json` 备份时于本地自动创建。
- 只有模板和说明文档应进入 git，本机备份和渲染产物默认保持忽略。
