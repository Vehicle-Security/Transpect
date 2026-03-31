# `gateway.events.jsonl` 字段与事件说明

## 目的

这份文档用于解释 OpenClaw Frida 运行时抓取文件 `gateway.events.jsonl` 中每一项记录的含义，便于：

- 读日志
- 做汇报
- 编写后续解析程序
- 对接策略引擎或动态沙盒

本文档结合以下两部分信息整理：

- 样本文件：`/tmp/transpect-openclaw-chat/manual-smoke-20260329/gateway.events.jsonl`
- 当前实现：
  - `tools/frida/openclaw_runtime_driver.py`
  - `tools/frida/openclaw_runtime_hook.js`

## 这份样本文件当前体现出的能力

样本文件共包含 `217` 条事件，已经体现出当前系统具备以下能力：

- 记录 OpenClaw 根进程和子进程的生命周期
- 记录 OpenClaw 实际拉起的命令与参数
- 记录 `stdout` / `stderr`
- 记录子进程文件访问
- 记录子进程网络连接
- 记录进程退出状态
- 为阻断模式预留 `blocked` / `errno` / `rule_id`

样本文件中实际出现的事件类型如下：

| `phase` | 数量 | 含义 |
| --- | ---: | --- |
| `script_loaded` | 22 | Frida hook 脚本已注入进程 |
| `attached` | 22 | Driver 已 attach 到进程 |
| `spawn_intent` | 1 | 父进程准备拉起子进程 |
| `child_added` | 21 | Frida 发现新子进程 |
| `child_removed` | 21 | Frida 的 pending child 生命周期结束 |
| `exec_call` | 18 | 子进程真正调用 `execve` / `execvp` |
| `detached` | 22 | Frida 会话从进程脱离 |
| `stdout` | 58 | 抓到标准输出 |
| `stderr` | 1 | 抓到标准错误 |
| `net_connect` | 5 | 抓到连接动作 |
| `file_open_read` | 14 | 抓到文件读打开 |
| `file_open_write` | 5 | 抓到文件写打开 |
| `file_create` | 1 | 抓到文件创建 |
| `exit` | 5 | 抓到进程退出 |
| `driver_signal` | 1 | Driver 自己收到退出信号 |

## 标准字段说明

这些字段是每条 JSONL 记录的主字段。即使某条记录不需要其中某个字段，该字段通常也会保留为 `null`。

| 字段 | 含义 | 常见在哪些事件里有值 | 示例 |
| --- | --- | --- | --- |
| `ts` | 事件时间，UTC ISO8601 格式 | 所有事件 | `2026-03-29T08:44:39.818Z` |
| `parent_pid` | 父进程 PID | 子进程、driver、hook 事件 | `1010817` |
| `child_pid` | 当前事件对应的子进程 PID；根进程级事件可能为 `null` | 大多数事件 | `1011055` |
| `phase` | 事件类型，最关键字段 | 所有事件 | `exec_call` |
| `exe` | 可执行文件路径 | `spawn_intent`、`exec_call` | `/bin/sh` |
| `argv` | 参数数组，表示真实命令行 | `spawn_intent`、`exec_call`、`child_*` | `["/bin/sh", "-c", "ip neigh show"]` |
| `fd` | 文件描述符 | `stdout`、`stderr`、网络事件 | `1`、`2`、`44` |
| `chunk` | 输出内容片段 | `stdout`、`stderr` | `"[gateway] listening on ws://..."` |
| `blocked` | 是否被策略拦截 | block 模式事件最重要 | `false` / `true` |
| `errno` | 拦截或失败时的 errno | block 模式事件 | `13` 或 `EACCES` 对应含义 |
| `exit_code` | 退出码 | `exit` | `0`、`2` |
| `resource` | 资源类别 | 大多数事件 | `process` / `filesystem` / `network` / `meta` |
| `op` | 归一化动作名 | 大多数事件 | `spawn`、`exec`、`stdout`、`open_read`、`connect` |
| `path` | 主路径；文件事件里表示文件路径，child 事件里有时表示进程路径 | `file_*`、`child_*` | `/etc/profile` |
| `path2` | 第二路径，主要给双路径文件操作用 | `rename` 一类事件 | 这份样本里没有出现 |
| `family` | 网络地址族 | `net_connect`、`net_sendto` | `AF_INET`、`AF_INET6`、`AF_1` |
| `address` | 网络地址，或 DNS 查询时的域名 | `dns_query`、`net_connect`、`net_sendto` | `127.0.0.1` |
| `port` | 网络端口 | `dns_query`、`net_connect`、`net_sendto` | `80`、`443`、`24080` |
| `rule_id` | 命中的策略规则 ID | block 模式事件 | `deny-demo-command` |

## 辅助字段说明

这些字段不是所有事件都会出现，但对排障和汇报很有用。

| 字段 | 含义 | 常见事件 | 样本中的典型值 |
| --- | --- | --- | --- |
| `detail` | 额外说明文本 | `script_loaded`、`detached`、`driver_signal` | `role=parent`、`process-replaced`、`received signal 15` |
| `role` | 当前 attach 的角色 | `attached` | `parent` / `child` |
| `origin` | 子进程来源 | `child_added`、`child_removed` | `fork`、`exec` |
| `identifier` | Frida child-gating 标识 | `child_added`、`child_removed` | 样本里基本为 `null` |
| `api` | 命中的底层 API | `exec_call`、`file_*`、`net_*` | `execve`、`execvp`、`open`、`connect` |
| `crash` | 进程 crash 信息 | `detached` | 正常情况下是 `null` |
| `raw_fd` | 原始输出 fd | `stdout`、`stderr` | `1`、`2` |
| `chunk_bytes` | 原始输出字节数 | `stdout`、`stderr` | `89`、`261` |

## 每种事件的具体含义

### 1. `script_loaded`

表示 Frida agent 已经注入到某个进程内。

典型特征：

- `resource = "meta"`
- `op = "load"`
- `detail = "role=parent"` 或 `detail = "role=child"`

用途：

- 证明 hook 脚本已经进入目标进程
- 帮助确认 parent/child 两层都已挂上

### 2. `attached`

表示 Frida driver 已成功 attach 到一个进程。

典型特征：

- `role = "parent"` 或 `role = "child"`

用途：

- 判断 driver 是否真的挂上目标进程

### 3. `spawn_intent`

表示父进程准备拉起一个新的命令进程，这是“OpenClaw 打到了 runtime 边界”的第一个关键证据。

典型特征：

- `resource = "process"`
- `op = "spawn"`
- `exe`、`argv` 有值

样本示例：

```json
{
  "phase": "spawn_intent",
  "exe": "/usr/bin/node",
  "argv": [
    "/usr/bin/node",
    "--disable-warning=ExperimentalWarning",
    "/usr/lib/node_modules/openclaw/openclaw.mjs",
    "gateway",
    "--port",
    "19040"
  ],
  "blocked": false
}
```

### 4. `child_added`

表示 Frida 发现了新子进程。

典型特征：

- `origin` 表示来源，常见是 `fork` 或 `exec`
- `path` / `argv` 有时能带出子进程的可执行路径与参数

用途：

- 画出进程树
- 知道谁拉起了谁

### 5. `child_removed`

表示 Frida child-gating 里的 child 生命周期结束。它不是业务失败信号，也不等于进程一定异常退出。

常见场景：

- 进程刚被 `exec` 替换
- child 已被新的 attach 会话接管

### 6. `exec_call`

表示进程真正调用了 `execve` 或 `execvp`。这是“真实执行了哪个命令”的关键证据。

典型特征：

- `resource = "process"`
- `op = "exec"`
- `exe` 与 `argv` 直接给出真实命令
- `api` 表示是 `execve` 还是 `execvp`

样本里就有：

- `/bin/sh -c "ip neigh show"`
- `/usr/bin/ip`

### 7. `detached`

表示 Frida 会话从目标进程脱离。

常见 `detail`：

- `process-replaced`

这通常意味着：

- 进程已经执行了 `exec`
- 原来的进程镜像被新镜像替换
- driver 随后会重新 attach 到新进程

所以它通常是“进程切换”的信号，不是 bug。

### 8. `stdout`

表示抓到了标准输出。

典型特征：

- `fd = 1`
- `resource = "process"`
- `op = "stdout"`
- `chunk` 是具体输出文本

用途：

- 还原 OpenClaw 或子进程输出
- 直接取证命令执行结果

### 9. `stderr`

表示抓到了标准错误。

典型特征：

- `fd = 2`
- `op = "stderr"`
- `chunk` 是 stderr 文本

样本里的这一条记录到了插件加载告警。

### 10. `file_open_read`

表示文件被以读方式打开。

典型特征：

- `resource = "filesystem"`
- `op = "open_read"`
- `path` 是文件路径
- `api` 通常是 `open`

样本里出现过：

- `/dev/urandom`
- `/etc/profile`
- `/root/.profile`

### 11. `file_open_write`

表示文件被以写方式打开。

样本里出现过：

- `/dev/null`
- `/dev/tty`

### 12. `file_create`

表示发生了创建动作。

典型特征：

- `resource = "filesystem"`
- `op = "create"`

说明：

- 这是“意图创建”级别的记录
- 目标路径未必最终持久存在，需要结合后续行为一起判断

### 13. `net_connect`

表示进程调用了 `connect`。

典型特征：

- `resource = "network"`
- `op = "connect"`
- `family` / `address` / `port` 描述目标端点

关于你这份样本里的 `AF_1`：

- 这是一个推断值，表示地址族编号为 `1`
- 在 Linux 上它通常对应本地 Unix socket，而不是外网 TCP
- 所以这份样本虽然出现了 `net_connect`，但更像是 OpenClaw 内部或本机通信，不是外部联网证据

### 14. `exit`

表示进程退出。

典型特征：

- `resource = "process"`
- `op = "exit"`
- `exit_code` 是退出码

样本里可以看到：

- `exit_code = 0` 表示正常退出
- `exit_code = 2` 表示命令或进程以错误状态结束

### 15. `driver_signal`

表示 Frida driver 自己收到了终止信号。

样本里最后一条是：

```json
{
  "phase": "driver_signal",
  "detail": "received signal 15"
}
```

这通常意味着：

- 外部把 driver 停掉了
- 或会话正常收尾时收到了 `SIGTERM`

## 如何阅读这份 JSONL

推荐按下面顺序理解一段行为：

1. 看 `spawn_intent`
2. 看 `child_added`
3. 看 `exec_call`
4. 看 `stdout` / `stderr`
5. 看 `file_*` / `net_*`
6. 看 `exit`
7. 看 `driver_signal` 或最终 `detached`

也就是说，一条比较完整的链路通常长这样：

```text
spawn_intent
-> child_added
-> exec_call
-> stdout / stderr
-> file_* / net_*
-> exit
```

## 这份样本文件当前没有出现，但系统已经支持的记录能力

虽然这份样本里没出现，当前实现还支持这些事件：

- `dns_query`
- `net_sendto`
- `file_delete`
- `file_rename`
- `file_mkdir`
- `file_rmdir`
- block 模式下的 `blocked = true`
- block 模式下的 `errno`
- block 模式下的 `rule_id`

## 汇报时可以怎么概括

可以用一句话概括为：

> 当前 `gateway.events.jsonl` 已经能把 OpenClaw 运行时的进程链路、真实命令执行、输出、文件访问、网络连接和退出状态统一落成结构化事件流，并为后续阻断策略保留标准字段。

