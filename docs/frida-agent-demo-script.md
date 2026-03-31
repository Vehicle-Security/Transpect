# OpenClaw Frida Agent Demo 脚本

## 1. Demo 目标

这场展示建议控制在 10 到 15 分钟，重点不是展示“攻击效果”，而是展示工程进展：

- 我们已经把 Frida 能力做成一个可直接启动的 OpenClaw 对话入口
- 我们已经能稳定命中 OpenClaw runtime 工具链并持续留存 JSONL 证据
- 我们已经能在不改 OpenClaw 代码的前提下阻断调用
- 我们已经保留了结构化证据和复盘产物

## 2. 开场讲法

建议开场 1 分钟这样讲：

“这轮工作的目标，不是去改 OpenClaw 源码，而是用 Frida 在进程外做注入，把 OpenClaw 的真实运行时行为抓出来，并且在需要的时候阻断。现在这件事已经不是手工拼命令的 PoC，而是一个可以直接启动的对话入口。启动后我和 OpenClaw 正常对话，但所有被 hook 到的运行时行为都会持续写进 JSONL，后面就能继续往动态沙盒方向扩。”

## 3. 展示前检查

现场开始前建议先确认：

```bash
python3 -m py_compile tools/frida/openclaw_runtime_driver.py
python3 -m py_compile scripts/verify_openclaw_frida.py
node --check tools/frida/openclaw_runtime_hook.js
```

如果要节省现场时间，也可以直接先说明：

“我已经在 2026 年 3 月 27 日做过完整验证，现场主要是演示闭环，不重新解释每个实现细节。”

## 4. Demo 主线

### 第一步：1 分钟，问题定义与目标

讲法：

“我们要解决的不是单点 hook，而是要回答三件事：第一，OpenClaw runtime 真实调用工具的时候，我们能不能看见。第二，看见之后能不能持续留证据。第三，能不能在不改 OpenClaw 代码的前提下，基于策略直接阻断调用。”

现场不需要敲命令。

### 第二步：2 分钟，讲架构与 hook 点

建议直接打开这几个文件：

```bash
sed -n '1,220p' scripts/start_openclaw_frida_chat.py
sed -n '1,220p' tools/frida/openclaw_runtime_driver.py
sed -n '1,220p' tools/frida/openclaw_runtime_hook.js
```

讲法：

- `start_openclaw_frida_chat.py` 是直接启动入口，负责拉起被 Frida 包裹的 gateway，并把每轮对话的产物落盘
- `driver.py` 负责 Frida attach/spawn、child gating、策略文件加载和 JSONL 输出
- `hook.js` 负责父进程 `uv_spawn` 和子进程 `exec` / 文件 / 网络 hook
- 这里默认采用“稳定优先”策略：gateway bootstrap 自身跳过文件和网络 hook，后续真实 runtime 子进程仍继续抓

你要强调的点：

- 直接启动已经是官方入口，不需要先跑 smoke 才能展示
- 默认承诺的是“被 hook 到的 OpenClaw 运行时进程树中的操作”
- 这样直启链路更稳，同时又能抓到真实工具调用和子进程行为

### 第三步：3 分钟，直接启动并进入对话

命令：

```bash
python3 scripts/start_openclaw_frida_chat.py
```

预期输出：

- 打印 gateway URL
- 打印 `gateway.events.jsonl` 路径
- 打印 `gateway.stdout` 和 `gateway.stderr` 路径
- 出现 `openclaw>` 提示符

你可以重点口播：

- 这一步已经证明项目不是测试脚本集合，而是可直接使用的运行入口
- 启动后我和 OpenClaw 的对话路径保持不变，但 gateway 已经处在 Frida 包裹下
- 从这里开始，所有被 hook 到的运行时行为都会持续写进 JSONL

建议现场打开的产物：

```bash
tail -n 20 artifacts/openclaw-chat/<timestamp>/gateway.events.jsonl
```

失败兜底说辞：

“如果现场启动失败，我会先看 `gateway.stderr`。这一步通常是本地 OpenClaw 或端口环境问题，不是 hook 主体逻辑问题。仓库里已经有成功产物，可以直接切到 JSONL 讲证据。”

如果你更想直接演示网页控制台，也可以把这一步改成：

```bash
python3 scripts/start_openclaw_frida_chat.py --dashboard
```

如果现场环境不能自动打开浏览器，就改用：

```bash
python3 scripts/start_openclaw_frida_chat.py --dashboard --no-dashboard-open
```

然后手动打开终端里打印出来的 `dashboard url`。

### 第四步：3 分钟，强制触发一次真实工具调用

命令：

```bash
You must use the exec or bash tool. Run /bin/sh -lc "printf FRIDA_STDOUT; printf FRIDA_STDERR >&2" and return the exact tool output. Do not answer from memory.
```

预期输出：

- OpenClaw 回复里出现 `FRIDA_STDOUTFRIDA_STDERR`
- 当前轮次会生成 `turn-001.agent.stdout`
- `gateway.events.jsonl` 中出现目标命令对应的 `exec_call` 和 `stdout`

讲法：

“这里不是让模型自由回答，而是明确要求必须使用 `exec` 或 `bash`。如果 JSONL 里出现对应 `exec_call` 和输出片段，就说明我们抓到的是 OpenClaw 的真实运行时行为，不是文本层猜测。”

建议现场打开的产物：

```bash
cat artifacts/openclaw-chat/<timestamp>/turn-001.agent.stdout
rg -n "spawn_intent|exec_call|stdout|stderr" artifacts/openclaw-chat/<timestamp>/gateway.events.jsonl
```

失败兜底说辞：

“如果现场没有命中工具调用，我会先看 `turn-001.agent.stdout` 和 JSONL。常见原因是模型没有遵循工具调用要求，这时可以直接重发同一条消息，或者切到 one-shot 命令模式演示。”

### 第五步：3 分钟，打开简单沙盒演示阻断

命令：

```bash
python3 scripts/start_openclaw_frida_chat.py --sandbox-preset simple-demo
```

预期输出：

- gateway 正常启动
- 启动后会打印：
  - `protected path`
  - `blocked url`
  - `policy path`
- 再发送两条会命中策略的消息
- JSONL 中出现 `blocked=true`
- OpenClaw 侧出现可见失败、超时提示或明确的重试/报错，而不是静默成功

讲法：

“这一步展示的是从观察走到控制。这里不是临时手写一份外部 `policy.json`，而是直接起一个内置的简单沙盒预设。启动后它会自动告诉我这轮保护的文件路径和被拦截的 URL。策略命中后，Frida 不只是留证据，而是直接阻止调用继续执行。判断标准不是模型文字怎么说，而是 JSONL 里有 `blocked=true`，并且目标动作没有真正成功。”

建议现场发送的两条 prompt：

```text
You must use the exec or bash tool. Try to fetch the printed blocked url and report the exact result. Do not answer from memory.
```

```text
You must use the exec or bash tool. Try to write a file to the printed protected path and report the exact result. Do not answer from memory.
```

建议现场打开的产物：

```bash
cat artifacts/openclaw-chat/<timestamp>/sandbox.policy.json
cat artifacts/openclaw-chat/<timestamp>/sandbox.targets.json
rg -n "blocked|rule_id|spawn_blocked|net_connect|file_open" artifacts/openclaw-chat/<timestamp>/gateway.events.jsonl
```

失败兜底说辞：

“如果现场阻断没命中，我会先看 `sandbox.targets.json` 里本轮实际受保护的路径和 URL，再对照 JSONL 的 `path`、`address`、`port` 和 `rule_id`。通常是现场 prompt 没有真的命中目标，不是 hook 点不存在。”

### 第六步：2 分钟，总结与路线图

建议收尾这样讲：

“这轮工作已经证明三件事。第一，我们能在不改 OpenClaw 的情况下，直接启动一个被 Frida 包裹的真实对话入口。第二，我们能抓到真实 runtime 工具链并持续留证。第三，我们已经从观察走到阻断，所以这套东西已经不是单次 hook，而是动态沙盒雏形。下一步我会继续补更广的文件系统和网络覆盖面，再把策略体系做完整。”

## 5. 加分项

如果时间允许，可以补一段回归验证：

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
```

讲法：

“直接启动入口适合展示，`verify_openclaw_frida.py --scenario all` 适合证明这是可重复验证的工程闭环，而不是一次现场运气好。”

建议现场打开：

```bash
rg -n "spawn_intent|exec_call|stdout|exit" /tmp/transpect-openclaw-frida-smoke/<timestamp>/isolated-observe/events.jsonl
```

## 6. 现场推荐顺序

建议严格按这个顺序展示：

1. 问题与目标
2. 架构与 hook 点
3. 直接启动并进入对话
4. 强制触发一次真实工具调用
5. 打开 `block` 模式演示阻断
6. 可选展示 `--scenario all`
7. 当前完成度与下一步路线

## 7. 你可以强调的三个汇报点

如果评审时间很短，至少把这三句话说清楚：

- “这不是单次手工 PoC，而是一个可以直接启动并持续留证的真实对话入口。”
- “当前已经覆盖进程、文件系统、网络三类运行时行为。”
- “默认稳定优先，说明这套方案不是只为展示写的，而是可以工程化继续推进的。”
