# OTEL 说明

Transpect 内置了 `vendor/openclaw-observability-plugin/` 下的 `otel-observability` 插件，用于把 OpenClaw gateway 的遥测数据以 OTLP 形式输出。

## 它能做什么

- 导出 OTLP traces、metrics 和 logs
- 在 `hybrid` 模式下与 JSONL 主链路并行工作
- 配合本地 collector，把结果落到 `live/otel/`

## 启用步骤

1. 安装插件依赖。

```powershell
npm ci --prefix vendor/openclaw-observability-plugin
```

2. 渲染本机 collector 配置。

```powershell
python scripts/setup_runtime.py --mode hybrid --render-otel-config
```

3. 启动 collector。

```powershell
otelcol-contrib --config config/otel-collector.local.yaml
```

4. 启动 `hybrid` 或 `otel` 模式。

```powershell
python scripts/start_trace.py --mode hybrid
```

## 输出文件

- `live/otel/traces.jsonl`
- `live/otel/logs.jsonl`
- `live/otel/metrics.jsonl`

## 切回默认链路

如果要回到仅使用 JSONL 主链路的状态：

```powershell
python scripts/setup_runtime.py --mode core
```

## 注意事项

- 仓库中提交的是可移植模板 `config/otel-collector.template.yaml`。
- `config/otel-collector.local.yaml` 是本机生成文件，默认不会进入 git。
- 如果你希望把 OTLP 数据发往其他后端，可以直接修改本机生成的 collector 配置，或者调整 `~/.openclaw/openclaw.json` 里的插件配置。
