# OpenClaw Frida Runtime PoC

这个目录提供一个独立的 Frida/OpenClaw runtime 工具链 PoC，不修改 OpenClaw 本体，只在进程外做注入。

下面的命令默认都在这个项目根目录执行。

## 文件

- `tools/frida/openclaw_runtime_driver.py`
  Frida Python 驱动。支持 attach 运行中进程，也支持直接 spawn 一个新根进程。
- `tools/frida/openclaw_runtime_hook.js`
  Frida agent。父进程只打 `uv_spawn`，子进程负责 `execve`/`execvp`、`write`/`writev`、`exit`/`_exit`。
- `tools/frida/openclaw_exec_probe.mjs`
  隔离触发器。直接调用当前安装的 OpenClaw exec runtime helper，绕开模型不确定性。

## 依赖前提

- 本机安装 `frida` Python 包。
- 本机已有 OpenClaw CLI 和 `/usr/lib/node_modules/openclaw/dist/exec-*.js`。
- 建议 root 身份运行，以尽量减小 `ptrace_scope=1` 带来的 attach 限制。
- 当前机器上，Frida 可以稳定 attach 自己刚 `spawn` 出来的进程；直接 attach 已经在跑的 `openclaw-gateway` 会命中 `ProcessNotFoundError`，所以第二阶段默认走“在 Frida 下拉起一个新 gateway”。

## JSONL 输出协议

驱动会把事件统一标准化成 JSONL，每条至少包含这些字段：

- `ts`
- `parent_pid`
- `child_pid`
- `phase`
- `exe`
- `argv`
- `fd`
- `chunk`
- `blocked`
- `errno`
- `exit_code`

其中：

- `spawn_intent` 来自父进程的 `uv_spawn`
- `exec_call` 来自子进程的 `execve` / `execvp`
- `stdout` / `stderr` 来自子进程的 `write` / `writev`
- `exit` 来自子进程的 `exit` / `_exit`

## 隔离验证

### 1. observe

```bash
python3 tools/frida/openclaw_runtime_driver.py \
  --mode observe \
  --spawn-program /usr/bin/node \
  --spawn-arg=tools/frida/openclaw_exec_probe.mjs \
  --spawn-arg=--sample \
  --spawn-arg=observe \
  --jsonl /tmp/openclaw-frida-observe.jsonl \
  --exit-on-root-detach
```

期望：

- JSONL 里出现 `spawn_intent`
- JSONL 里出现 `exec_call`
- `stdout` 的 `chunk` 包含 `FRIDA_STDOUT`
- 有 `exit` 事件
- probe 返回 JSON 里 `result.stdout == "FRIDA_STDOUT"`，`result.stderr == "FRIDA_STDERR"`

实测说明：

- 当前样本固定走 `/bin/sh -lc 'printf FRIDA_STDOUT; printf FRIDA_STDERR >&2'`
- OpenClaw runtime helper 能稳定拿到 `stdout/stderr`
- Frida 侧对这个 shell builtin 样本的 `stderr` syscall 采集有时不稳定，因此 v1 的验收以 `spawn_intent -> exec_call -> stdout -> exit` 链路加 probe 返回值为准

### 2. block

```bash
python3 tools/frida/openclaw_runtime_driver.py \
  --mode block \
  --deny-exe-regex '^/usr/bin/id$' \
  --spawn-program /usr/bin/node \
  --spawn-arg=tools/frida/openclaw_exec_probe.mjs \
  --spawn-arg=--sample \
  --spawn-arg=block \
  --jsonl /tmp/openclaw-frida-block.jsonl \
  --exit-on-root-detach
```

期望：

- `spawn_intent.blocked == true`
- 有单独的 `spawn_blocked` 事件
- probe 以“已拦截”为成功退出，并带回原始 spawn 错误
- 没有 `/usr/bin/id` 的真实命令输出

实测说明：

- 当前 block 策略是父进程 `uv_spawn` 命中 deny 后，把命令改写成一个立即失败的 stub
- 这样可以稳定证明“命令已被 Frida 阻止”，而不会改 OpenClaw 本体
- 当前机器上，底层失败最终会表现成 `spawn /usr/bin/id ENOENT`；JSONL 里会同时保留 `blocked=true` 和 `uv_result=-2`

## 现网网关验证

### 1. 优先在 Frida 下拉起一个新 `openclaw-gateway`

```bash
timeout 45s python3 tools/frida/openclaw_runtime_driver.py \
  --mode observe \
  --spawn-program /usr/bin/node \
  --spawn-arg=/usr/lib/node_modules/openclaw/openclaw.mjs \
  --spawn-arg=gateway \
  --spawn-arg=--port \
  --spawn-arg=19001 \
  --jsonl /tmp/openclaw-gateway-runtime.jsonl
```

如果你的环境允许直接 attach，下面这个命令也支持：

```bash
python3 tools/frida/openclaw_runtime_driver.py \
  --mode observe \
  --process-name openclaw-gateway \
  --jsonl /tmp/openclaw-gateway-runtime.jsonl
```

### 2. 触发一次 agent 请求

```bash
OPENCLAW_GATEWAY_URL=ws://127.0.0.1:19001 \
OPENCLAW_GATEWAY_TOKEN="$(python3 -c 'import json, pathlib; print(json.loads(pathlib.Path("/root/.openclaw/openclaw.json").read_text())["gateway"]["token"])')" \
openclaw agent \
  --to +15555550123 \
  --message 'You must use the exec or bash tool. Run `/bin/sh -lc "printf FRIDA_STDOUT; printf FRIDA_STDERR >&2"` and return the exact tool output. Do not answer from memory.' \
  --json
```

期望：

- Frida 侧仍能看到 `spawn_intent -> exec_call -> stdout/stderr -> exit`
- OpenClaw 侧正常返回工具输出

实测说明：

- 在当前机器上，Frida 已经能稳定看到 gateway 自己的真实 runtime 子进程，例如 `ip neigh show`、`sqlite3 -version`
- 但 `openclaw agent --message ...` 这种 prompt 驱动方式并不保证模型真的会调用 `exec`/`bash`
- 我们观察到一次 agent 返回了 `FRIDA_STDOUTFRIDA_STDERR`，但 JSONL 没有对应的工具调用，因此这条回复不能当成 runtime 工具已命中的证据
- 对第二阶段来说，JSONL 里是否出现目标命令，才是唯一可信的验收标准

### 3. 阻断验证

```bash
python3 tools/frida/openclaw_runtime_driver.py \
  --mode block \
  --deny-argv-regex 'FRIDA_STDOUT' \
  --process-name openclaw-gateway \
  --jsonl /tmp/openclaw-gateway-runtime-block.jsonl
```

再重复上面的 `openclaw agent --message ... --json`。

如果这台机器仍然不允许 attach 已运行进程，就把第一步的 gateway 启动命令改成 `--mode block` 后重跑一次，再对这个新 gateway 发 agent 请求。

期望：

- OpenClaw 侧出现工具执行失败
- Frida 侧至少出现 `spawn_intent.blocked=true` 和 `spawn_blocked`
- 没有新的真实目标命令输出

## 备注

- 当前实现默认只覆盖 `exec` / `bash` / `process` 这条 runtime 工具链。
- `nodes -> system.run`、文件系统写入阻断、网络阻断留到下一阶段扩展。
- `uv_spawn` 是父进程侧“边界命中”信号，也是当前 v1 block 的主拦截点。
- 子进程 `execve` / `execvp`、`write` / `writev`、`exit` / `_exit` 目前主要用于 observe 模式下的链路还原。
