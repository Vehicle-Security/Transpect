# OpenClaw Frida Runtime PoC

这个仓库提供两个并行入口：

- 正式演示/直接使用入口：`scripts/start_openclaw_frida_chat.py`
- 可重复验证入口：`scripts/verify_openclaw_frida.py`

如果目标是“直接启动后和 OpenClaw 对话，并把 Frida 事件持续写进 JSONL”，优先使用：

```bash
python3 scripts/start_openclaw_frida_chat.py
```

如果目标是做回归验证或能力验收，再使用 smoke runner：

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
python3 scripts/verify_openclaw_frida.py --scenario sandbox-all
```

下面的命令默认都在仓库根目录执行。

## 组件

- `scripts/start_openclaw_frida_chat.py`
  直接启动入口。负责拉起被 Frida 包裹的 OpenClaw gateway，提供交互式对话，并把事件持续写入 JSONL。
- `scripts/verify_openclaw_frida.py`
  统一编排场景、落盘产物、解析 JSONL、执行断言。
- `tools/frida/openclaw_runtime_driver.py`
  Frida Python 驱动。负责 attach/spawn、child gating、策略文件加载和 JSONL 输出。
- `tools/frida/openclaw_runtime_hook.js`
  Frida agent。负责进程、文件系统、网络三类 hook。
- `tools/frida/openclaw_exec_probe.mjs`
  隔离触发器。直接调用 OpenClaw runtime helper，支持固定样本和自定义 `argv`。

## 依赖前提

- 本机安装 `frida` Python 包。
- 本机已有 OpenClaw CLI。
- `/usr/lib/node_modules/openclaw/openclaw.mjs` 和 `/usr/lib/node_modules/openclaw/dist/exec-*.js` 存在。
- 建议 root 身份运行，以减少 `ptrace_scope=1` 带来的 attach 限制。
- 当前实现默认通过 Frida `spawn` 新进程来做验证，不依赖 attach 已运行的 `openclaw-gateway`。

## Driver 接口

核心入口：

```bash
python3 tools/frida/openclaw_runtime_driver.py --mode observe|block ...
```

当前对外固定接口：

- `--mode observe|block`
- `--pid`
- `--process-name`
- `--spawn-program`
- `--deny-exe-regex`
- `--deny-argv-regex`
- `--policy-file`
- `--jsonl`
- `--child-gating on|off`

`--policy-file` 的 JSON 结构分三段：

```json
{
  "exec": [
    {
      "id": "deny-id",
      "exeRegex": "^/usr/bin/id$"
    }
  ],
  "filesystem": [
    {
      "id": "deny-protected-write",
      "pathRegex": "^/tmp/protected.txt$",
      "ops": ["create", "open_write"]
    }
  ],
  "network": [
    {
      "id": "deny-local-http",
      "addressRegex": "^127\\.0\\.0\\.1$",
      "ports": [24080],
      "ops": ["connect", "sendto"]
    }
  ]
}
```

说明：

- `exec` 规则沿用 `exeRegex` / `argvRegex`
- `filesystem` 规则按 `pathRegex + ops`
- `network` 规则按 `addressRegex + ports + ops`
- 每条规则都必须有稳定的 `id`
- 命中规则后会把 `rule_id` 写回 JSONL

## 直接启动接口

官方直接启动入口：

```bash
python3 scripts/start_openclaw_frida_chat.py
```

当前固定接口：

- `--message`
- `--json`
- `--output-dir`
- `--mode observe|block`
- `--policy-file`
- `--disable-filesystem-hooks`
- `--disable-network-hooks`

行为约定：

- 默认模式是 `observe`
- 默认会打开文件和网络 hook，但会对 gateway bootstrap 自身做稳定性豁免
- `--mode block` 必须搭配 `--policy-file`
- 默认产物目录是 `/tmp/transpect-openclaw-chat/<timestamp>/`
- 每轮对话至少会落盘：
  - `gateway.events.jsonl`
  - `gateway.stdout`
  - `gateway.stderr`
  - `turn-XXX.agent.stdout`
  - `turn-XXX.agent.stderr`

抓取范围约定：

- 对外承诺的是“被 hook 到的 OpenClaw 运行时进程树中的操作”
- 默认覆盖进程创建、命令执行、子进程文件系统事件、子进程网络事件
- 不把“OpenClaw 内部所有实现细节”作为对外承诺

## Hook 能力

### 进程级

已实现：

- 父进程 `uv_spawn`
- 子进程 `execve`
- 子进程 `execvp`
- 子进程 `write`
- 子进程 `writev`
- 子进程 `exit`
- 子进程 `_exit`

行为：

- `observe` 模式记录 `spawn_intent`、`exec_call`、`stdout`、`stderr`、`exit`
- `block` 模式对命中的 `exec` 规则在 `uv_spawn` 边界做阻断

### 文件系统

已实现：

- `open`
- `open64`
- `openat`
- `openat64`
- `creat`
- `unlink`
- `unlinkat`
- `rename`
- `renameat`
- `mkdir`
- `rmdir`

事件类型：

- `file_open_read`
- `file_open_write`
- `file_create`
- `file_delete`
- `file_rename`
- `file_mkdir`
- `file_rmdir`

说明：

- 默认稳定基线不会主动打开文件系统 hook
- `file-observe` / `file-block` 场景会显式打开
- 文件阻断在 libc 调用层直接返回失败并设置 `errno=EACCES`

### 网络

已实现：

- `socket`
- `connect`
- `sendto`
- `getaddrinfo`

事件类型：

- `dns_query`
- `net_connect`
- `net_sendto`

说明：

- `observe` 模式对 `connect` / `sendto` 走低侵入 `attach`
- `block` 模式对 `connect` / `sendto` 走 `replace` 并返回 `EACCES`
- `getaddrinfo` 只做观察，不在 DNS 阶段阻断

## JSONL 字段

输出协议固定为 JSONL。当前标准字段包括：

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
- `resource`
- `op`
- `path`
- `path2`
- `family`
- `address`
- `port`
- `rule_id`

其中：

- `resource` 用于区分 `process` / `filesystem` / `network`
- `op` 用于表达动作，例如 `spawn`、`exec`、`open_read`、`connect`
- `path` / `path2` 主要服务文件系统事件
- `family` / `address` / `port` 主要服务网络事件
- `rule_id` 只在命中策略时出现

## Smoke 场景

### 稳定基线

`all` 默认依次执行：

- `isolated-observe`
- `isolated-block`
- `gateway-startup`

运行命令：

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
```

通过条件：

- `isolated-observe`
  - 出现 `spawn_intent`
  - 出现 `/bin/sh` 的 `exec_call`
  - 出现包含 `FRIDA_STDOUT` 的 `stdout`
  - 出现 `exit`
  - probe 返回 `ok == true`
- `isolated-block`
  - 命中 `^/usr/bin/id$`
  - 出现 `spawn_intent.blocked == true`
  - 出现 `spawn_blocked`
  - probe 返回 `ok == true`
  - probe 返回 `blocked == true`
- `gateway-startup`
  - 在 Frida 下新拉起 gateway
  - JSONL 中命中任一真实 runtime 子进程活动
  - 当前实现会匹配 `/bin/sh -c 'ip neigh show'`、`/usr/bin/ip` 或 `sqlite3 -version`

### 沙盒扩展

`sandbox-all` 默认依次执行：

- `file-observe`
- `file-block`
- `network-observe`
- `network-block`

运行命令：

```bash
python3 scripts/verify_openclaw_frida.py --scenario sandbox-all
```

各场景通过条件：

- `file-observe`
  - 产生至少一个读事件和一个写/创建事件
  - probe 返回 `ok == true`
  - probe stdout 精确匹配 `FILE_OBSERVE_OK\n`
- `file-block`
  - 命中受保护路径的阻断规则
  - 目标文件不能实际落盘
  - JSONL 带 `blocked == true` 和 `rule_id`
- `network-observe`
  - 本地临时 HTTP 服务收到请求
  - JSONL 至少命中 `net_connect`
  - 如出现 `dns_query` 则一并保留
- `network-block`
  - 本地临时 HTTP 服务不能收到请求
  - JSONL 中出现阻断的 `net_connect` 或 `net_sendto`
  - 事件带 `rule_id`

### 实验场景

```bash
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent
```

说明：

- 这是独立实验场景，不纳入默认 `all`
- token 默认从 `/root/.openclaw/openclaw.json` 读取
- 只有 JSONL 中命中真实 runtime 事件才算通过
- 纯模型文本回复不算通过

## 当前验证证据

2026-03-27 已完成的可重复验证产物：

- 稳定基线 `all`
  - `/tmp/transpect-openclaw-frida-smoke/final-all-20260327b`
- 沙盒扩展 `sandbox-all`
  - `/tmp/transpect-openclaw-frida-smoke/final-sandbox-20260327`
- 实验场景 `gateway-agent`
  - `/tmp/transpect-openclaw-frida-smoke/20260327-173145`

## 产物

默认输出目录：

```text
/tmp/transpect-openclaw-frida-smoke/<timestamp>/
```

每个场景都会保留独立目录。常见文件包括：

- `events.jsonl`
- `probe.stdout`
- `probe.stderr`
- `policy.json`
- `http.requests.json`
- `gateway.events.jsonl`
- `gateway.stdout`
- `gateway.stderr`
- `agent.stdout`
- `agent.stderr`

runner 结束时会打印每个场景的结论和产物路径，适合直接放进汇报或复盘。

## 常见失败

### `ProcessNotFoundError`

常见于试图 attach 已运行的 `openclaw-gateway`。当前默认通过 Frida `spawn` 新进程规避。

### `Permission denied (publickey)`

说明这台机器没有 GitHub SSH 凭据，和 Frida 验证本身无关，需要先修复仓库访问。

### `spawn ... ENOENT`

在当前 block 策略下，这是可接受的阻断成功表现。判断标准以 `spawn_intent.blocked == true`、`spawn_blocked` 和 probe 的 `ok == true` 为准。

### gateway 没有产生预期后台子进程

优先检查：

- 端口是否被占用
- OpenClaw gateway 是否正常启动
- JSONL 是否有 `spawn_intent` / `exec_call`
- `gateway.stderr` 是否包含启动异常
- 当前环境里的后台子进程可能出现较慢，runner 已把观察窗口拉长到 75 秒
