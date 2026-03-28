# OpenClaw Frida Agent 能力汇报

## 1. 背景与目标

本项目的目标，是在不改 OpenClaw 代码的前提下，基于 Frida 对 OpenClaw runtime 工具链做进程外注入，先完成可观测，再完成可阻断，最后逐步扩成动态沙盒。

这轮工作的重点不是做“攻击秀”，而是做工程闭环：

- 能稳定命中 OpenClaw runtime 边界
- 能输出结构化证据
- 能做可重复验证
- 能在真实 gateway 路径上复验
- 能向文件系统和网络两类沙盒能力扩展

## 2. 当前已完成能力矩阵

| 能力域 | 观察 | 阻断 | 验证状态 |
| --- | --- | --- | --- |
| 进程创建与命令执行 | 已完成 | 已完成 | 已通过 |
| `stdout` / `stderr` 输出采集 | 已完成 | 不适用 | 已通过 |
| 文件系统访问 | 已完成 | 已完成 | 已通过 |
| 网络访问 | 已完成 | 已完成 | 已通过 |
| 真实 gateway 启动路径 | 已完成 | 不作为默认阻断项 | 已通过 |
| `gateway-agent` 工具命中 | 已完成 | 保留实验属性 | 已通过 |

当前已实现的关键 hook 点：

- 父进程：`uv_spawn`
- 子进程进程级：`execve`、`execvp`、`write`、`writev`、`exit`、`_exit`
- 子进程文件系统：`open`、`open64`、`openat`、`openat64`、`creat`、`unlink`、`unlinkat`、`rename`、`renameat`、`mkdir`、`rmdir`
- 子进程网络：`socket`、`connect`、`sendto`、`getaddrinfo`

## 3. 架构与数据流

整体架构分三层：

### 3.1 驱动层

`tools/frida/openclaw_runtime_driver.py`

职责：

- 连接本机 Frida device
- attach 已运行进程或 spawn 新进程
- 开启 child gating
- 给父进程和子进程分别注入 agent
- 统一输出标准化 JSONL
- 载入统一策略文件 `--policy-file`

### 3.2 Agent 层

`tools/frida/openclaw_runtime_hook.js`

职责：

- 在父进程观测 `uv_spawn`
- 在子进程观测 `exec`、文件系统、网络、输出流和退出事件
- 对命中的规则写入 `blocked` 与 `rule_id`
- 在阻断场景直接返回失败并设置 `errno`

### 3.3 验证层

`scripts/verify_openclaw_frida.py`

职责：

- 统一编排 smoke 场景
- 自动构造最小样本
- 自动解析 JSONL 与 probe 输出
- 自动给出通过/失败结论

数据流如下：

1. smoke runner 拉起 driver
2. driver 在 Frida 下 spawn 或 attach 目标进程
3. 父进程 agent 命中 `uv_spawn`
4. child gating 自动跟随到真实子进程
5. 子进程 agent 记录 `exec`、文件系统、网络、输出与退出
6. 所有事件统一写入 JSONL
7. runner 对 JSONL 与 probe 输出执行断言

## 4. 五个里程碑

### 里程碑 1. 命中 OpenClaw runtime 边界

结论：

- 已通过父进程 `uv_spawn` 稳定命中 OpenClaw runtime 工具边界
- 证明点不是模型输出，而是 runtime 真实拉起子进程的事实

### 里程碑 2. 观察真实命令执行与输出

结论：

- 已稳定观察 `exec_call`
- 已采集 `stdout` / `stderr`
- 已补齐 `exit`

对应验证场景：

- `isolated-observe`
- `gateway-agent`

### 里程碑 3. 阻断命令执行

结论：

- 已支持对命中的 `exec` 规则做阻断
- 当前命令阻断点在父进程 `uv_spawn` 边界
- 调用方会收到可见失败

对应验证场景：

- `isolated-block`

### 里程碑 4. 对真实 gateway 路径做可重复验证

结论：

- 已在 Frida 下新拉起真实 `openclaw gateway`
- 已在默认 smoke 中稳定命中真实 runtime 子进程活动
- 额外实验场景中，已命中 `gateway-agent` 的真实工具调用

对应验证场景：

- `gateway-startup`
- `gateway-agent`

### 里程碑 5. 向文件与网络沙盒扩展

结论：

- 文件系统观察与阻断已完成
- 网络观察与阻断已完成
- 已把它们收敛进独立 `sandbox-all`
- 默认稳定基线 `all` 不受额外沙盒 hook 干扰

对应验证场景：

- `file-observe`
- `file-block`
- `network-observe`
- `network-block`

## 5. 已验证证据

2026 年 3 月 27 日已经保留的验证产物如下。

稳定基线：

- `/tmp/transpect-openclaw-frida-smoke/final-all-20260327b`

可确认：

- `isolated-observe` 通过
- `isolated-block` 通过
- `gateway-startup` 通过

沙盒扩展：

- `/tmp/transpect-openclaw-frida-smoke/final-sandbox-20260327`

可确认：

- `file-observe` 通过
- `file-block` 通过
- `network-observe` 通过
- `network-block` 通过

真实 agent 工具链实验：

- `/tmp/transpect-openclaw-frida-smoke/20260327-173145`

可确认：

- 命中 `/bin/bash -c '/bin/sh -lc "printf FRIDA_STDOUT; printf FRIDA_STDERR >&2"'`

## 6. 当前限制与风险

当前限制：

- 文件系统 hook 仍然是 libc 函数级，不覆盖直接 syscall 绕过
- 网络 hook 当前只覆盖 `connect` / `sendto` / `getaddrinfo` / `socket`
- 进程阻断当前仍以 runtime 边界的 `uv_spawn` 为主，不是全面系统调用级拦截
- 真实环境里 attach 已运行进程仍不如 Frida `spawn` 新进程稳定

工程取舍：

- 默认稳定基线 `all` 只打开进程级 hook
- 文件和网络 hook 只在沙盒场景里显式打开
- 这样可以降低对真实 gateway 启动路径的侵入性，避免把验证本身变成不稳定因素

## 7. 下一阶段路线图

建议按下面顺序推进：

1. 扩展文件系统覆盖面
   重点补 `link`、`symlink`、`chmod`、`chown`、`truncate` 等写操作
2. 扩展网络覆盖面
   重点补 `recvfrom`、`sendmsg`、`recvmsg`、`bind`、`listen`
3. 进程阻断从 `uv_spawn` 向更底层扩展
   目标是把直接 `execve` 拦截做成可选能力
4. 引入更完整的策略体系
   支持 allow/deny、规则优先级、命中计数与审计标签
5. 对接更正式的动态沙盒输出接口
   让 JSONL 事件可直接被上层决策或展示系统消费

## 8. 当前结论

这轮工作已经把项目从“只能证明能挂上 Frida”推进到“可重复验证的动态沙盒雏形”。

更具体地说，当前状态已经满足三件对外可汇报的事：

- 不是概念验证，而是可重复执行的工程验证闭环
- 不仅能看见 OpenClaw runtime 工具链，还能做阻断
- 能力已经从命令执行扩展到文件系统和网络，具备继续演进成动态沙盒的基础
