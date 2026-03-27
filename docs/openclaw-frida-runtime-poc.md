# OpenClaw Frida Runtime PoC

这个仓库提供一个可重复执行的 OpenClaw Frida 验证闭环。默认入口不是手工命令，而是仓库级 smoke runner：

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
```

下面的命令默认都在仓库根目录执行。

## 文件

- `scripts/verify_openclaw_frida.py`
  统一编排 smoke 场景、落盘产物、解析 JSONL、执行断言。
- `tools/frida/openclaw_runtime_driver.py`
  Frida Python 驱动。负责 attach/spawn、child gating、JSONL 输出。
- `tools/frida/openclaw_runtime_hook.js`
  Frida agent。负责 `uv_spawn`、`execve`/`execvp`、`write`/`writev`、`exit`/`_exit`。
- `tools/frida/openclaw_exec_probe.mjs`
  隔离触发器。直接调用 OpenClaw runtime helper。

## 依赖前提

- 本机安装 `frida` Python 包。
- 本机已有 OpenClaw CLI。
- `/usr/lib/node_modules/openclaw/openclaw.mjs` 和 `/usr/lib/node_modules/openclaw/dist/exec-*.js` 存在。
- 建议 root 身份运行，以减少 `ptrace_scope=1` 带来的 attach 限制。
- 当前环境里，Frida 可以稳定 attach 自己 `spawn` 出来的进程；直接 attach 已运行的 `openclaw-gateway` 可能出现 `ProcessNotFoundError`。

## Smoke 场景

### 1. `isolated-observe`

```bash
python3 scripts/verify_openclaw_frida.py --scenario isolated-observe
```

通过条件：

- JSONL 里出现 `spawn_intent`
- JSONL 里出现 `/bin/sh` 的 `exec_call`
- JSONL 里出现包含 `FRIDA_STDOUT` 的 `stdout`
- JSONL 里出现 `exit`
- probe 返回 JSON 中：
  - `ok == true`
  - `result.stdout == "FRIDA_STDOUT"`
  - `result.stderr == "FRIDA_STDERR"`

### 2. `isolated-block`

```bash
python3 scripts/verify_openclaw_frida.py --scenario isolated-block
```

通过条件：

- deny 规则固定为 `^/usr/bin/id$`
- JSONL 里出现 `spawn_intent.blocked == true`
- JSONL 里出现 `spawn_blocked`
- probe 返回 JSON 中：
  - `ok == true`
  - `blocked == true`

说明：

- 当前环境允许 `spawn /usr/bin/id ENOENT` 作为阻断成功的表现形式
- 不要求固定返回 `EACCES`

### 3. `gateway-startup`

```bash
python3 scripts/verify_openclaw_frida.py --scenario gateway-startup
```

通过条件：

- runner 在 Frida 下新拉起 gateway，而不是 attach 已运行进程
- JSONL 中命中任一真实 runtime 子进程活动即可通过：
  - `ip neigh show`
  - `/usr/bin/ip`
  - `sqlite3 -version`

说明：

- 默认会从 `19001` 开始选择首个空闲端口
- 如果端口占用，可以改成：

```bash
python3 scripts/verify_openclaw_frida.py --scenario gateway-startup --gateway-port 19002
```

### 4. `gateway-agent`

```bash
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent
```

这是单独实验场景，不纳入默认 `all`。

通过条件：

- gateway 启动成功
- `openclaw agent --json` 返回成功
- JSONL 中必须出现目标命令对应的 runtime 事件

说明：

- token 默认从 `/root/.openclaw/openclaw.json` 读取
- 可以显式覆盖：

```bash
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent --gateway-token <token>
```

- 如果只有模型文字回复、没有 JSONL 对应命令事件，这个场景会判失败

## 默认入口

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
```

默认会依次执行：

- `isolated-observe`
- `isolated-block`
- `gateway-startup`

`gateway-agent` 不在默认 smoke 中，原因是它受模型是否真的触发工具调用影响，容易把模型文本输出误当成 runtime 命中。

## 产物

默认输出目录：

```text
/tmp/transpect-openclaw-frida-smoke/<timestamp>/
```

每个场景都会保留自己的目录，例如：

- `isolated-observe/events.jsonl`
- `isolated-observe/probe.stdout`
- `isolated-observe/probe.stderr`
- `gateway-startup/gateway.events.jsonl`
- `gateway-startup/gateway.stdout`
- `gateway-startup/gateway.stderr`
- `gateway-agent/agent.stdout`
- `gateway-agent/agent.stderr`

runner 会在结束时打印每个场景的结论和产物路径。

## 常见失败

### `ProcessNotFoundError`

常见于试图 attach 已运行的 `openclaw-gateway`。当前实现默认通过 Frida `spawn` 新 gateway 来规避。

### `Permission denied (publickey)`

说明这台机器还没有 GitHub SSH 凭据，和 Frida 验证本身无关。需要先修好仓库访问。

### `spawn ... ENOENT`

在当前 block 策略下，这是可接受的阻断成功表现。判断标准以 `spawn_intent.blocked == true`、`spawn_blocked` 和 probe 的 `ok == true` 为准。

### gateway 没有产生预期后台子进程

这会导致 `gateway-startup` 失败。优先检查：

- 端口是否被占用
- OpenClaw gateway 是否正常启动
- JSONL 是否有 `spawn_intent` / `exec_call`
- `gateway.stderr` 是否包含启动异常
- 当前环境里的后台子进程可能出现得比较慢，runner 已把观察窗口拉长到 75 秒
