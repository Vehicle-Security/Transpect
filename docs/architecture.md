# 架构说明

Transpect 围绕三条互补的数据路径组织：

## 1. JSONL 主链路

默认链路如下：

```text
OpenClaw hooks -> behavior-mediator -> live/behavior-events.jsonl -> viewer/index.html?view=traces
```

这是最轻量、最直接的一条路径，适合在一个页面里查看请求、轮次、工具调用、任务节点和 LLM 调用过程。

当前查看器有两个正式路由：

- `view=traces`：显示 `请求列表`
- `view=timeline&traceId=<trace-id>`：显示某一条 trace 的 `链路主视图`
- `查看原始事件与调试信息`：展开当前 trace 的原始事件抽屉
- `view=timeline&traceId=<trace-id>&evidence=1`：直接打开当前 trace 的证据抽屉，便于文档引用和问题定位

## 2. OTEL 链路

OTEL 链路依赖 vendored 的 `otel-observability` 插件和可选的 collector 配置：

```text
OpenClaw hooks -> otel-observability -> OTLP -> config/otel-collector.local.yaml -> live/otel/*.jsonl
```

当你需要本地保存 OTLP 输出，或者准备把遥测数据转发到其他后端时，可以使用这条路径。

## 3. Frida 链路

Frida 链路会附着到一个正在运行的 gateway 进程，并记录宿主侧事件：

```text
Frida attach -> frida/openclaw_gateway_windows.js -> live/frida/*.jsonl
```

这条路径会补充进程、文件、端口和网络层面的信息，与 JSONL 主链路和 OTEL 链路互补。

## 关键脚本职责

- `scripts/setup_runtime.py`：把 `~/.openclaw/openclaw.json` 调整到 `core`、`hybrid` 或 `otel` 模式
- `scripts/start_trace.py`：准备运行模式、按需启动 gateway，并在启用查看器时打开 `请求列表`
- `scripts/doctor.py`：检查运行健康状态，并给出当前推断出的运行模式
- `scripts/run_acceptance.py`：发送一组安全的最小输入并校验产出的 trace
- `scripts/check_repo.py`：检查语法、必需文件、忽略规则和可移植性约束

## 模式说明

- `core`：只启用 behavior mediator
- `hybrid`：同时启用 behavior mediator 和 OTEL 插件
- `otel`：只启用 OTEL 插件

## 可移植性约束

- 仓库路径从当前克隆目录动态推导，不依赖固定机器路径。
- OTEL collector 输出路径由模板渲染到 `config/otel-collector.local.yaml`，不把本机绝对路径提交进仓库。
- 运行态数据统一落在 `live/`、`captures/` 和 `config/applied/`，这些目录都默认被 git 忽略。
