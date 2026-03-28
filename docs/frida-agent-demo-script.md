# OpenClaw Frida Agent Demo 脚本

## 1. Demo 目标

这场展示建议控制在 10 到 15 分钟，重点不是展示“攻击效果”，而是展示工程进展：

- 我们已经能稳定命中 OpenClaw runtime 工具链
- 我们已经有可重复的 smoke 入口
- 我们已经能做文件系统和网络阻断
- 我们已经保留了结构化证据和复盘产物

## 2. 开场讲法

建议开场 1 分钟这样讲：

“这轮工作的目标，不是去改 OpenClaw 源码，而是用 Frida 在进程外做注入，先把 runtime 工具链观察清楚，再逐步扩成动态沙盒。现在我们已经把这件事做成可重复执行的工程闭环，默认 smoke 可以证明真实工具链命中，扩展 smoke 可以证明文件和网络阻断能力。”

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

“我们要解决的不是单点 hook，而是要回答三件事：第一，OpenClaw runtime 真实调用工具的时候，我们能不能看见。第二，看见之后能不能留证据。第三，能不能在不改 OpenClaw 代码的前提下，基于策略直接阻断调用。”

现场不需要敲命令。

### 第二步：2 分钟，讲架构与 hook 点

建议直接打开这几个文件：

```bash
sed -n '1,220p' tools/frida/openclaw_runtime_driver.py
sed -n '1,220p' tools/frida/openclaw_runtime_hook.js
sed -n '1,220p' scripts/verify_openclaw_frida.py
```

讲法：

- `driver.py` 负责 Frida attach/spawn、child gating、策略文件加载和 JSONL 输出
- `hook.js` 负责父进程 `uv_spawn` 和子进程 `exec` / 文件 / 网络 hook
- `verify_openclaw_frida.py` 负责把这些能力变成可重复 smoke

你要强调的点：

- 稳定基线 `all` 只打开进程级 hook
- `sandbox-all` 再显式打开文件和网络 hook
- 这样默认链路更稳，沙盒扩展又可以单独验证

### 第三步：3 分钟，跑默认稳定 smoke

命令：

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
```

预期输出：

- `isolated-observe` 通过
- `isolated-block` 通过
- `gateway-startup` 通过

你可以重点口播：

- `isolated-observe` 证明我们能抓到真实命令执行和输出
- `isolated-block` 证明我们能阻断调用
- `gateway-startup` 证明这不是脱离真实产品路径的假样本

建议现场打开的产物：

```bash
rg -n "spawn_intent|exec_call|stdout|stderr|exit" /tmp/transpect-openclaw-frida-smoke/<timestamp>/isolated-observe/events.jsonl
rg -n "spawn_intent|spawn_blocked" /tmp/transpect-openclaw-frida-smoke/<timestamp>/isolated-block/events.jsonl
rg -n "exec_call" /tmp/transpect-openclaw-frida-smoke/<timestamp>/gateway-startup/gateway.events.jsonl
```

失败兜底说辞：

“如果现场 `gateway-startup` 因环境端口或 OpenClaw 状态失败，不影响进程级链路能力判断。我已经保留了 2026-03-27 的完整成功产物，可以直接切到产物文件展示证据。”

### 第四步：3 分钟，跑 `file-block`

命令：

```bash
python3 scripts/verify_openclaw_frida.py --scenario file-block
```

预期输出：

- 场景通过
- 输出 `protected_path`
- 输出 `policy.json`
- 输出 `events.jsonl`

讲法：

“这里展示的是最小文件系统阻断能力。不是模拟返回，而是在 libc 文件调用层直接拒绝写入，并保留规则命中证据。”

建议现场打开的产物：

```bash
cat /tmp/transpect-openclaw-frida-smoke/<timestamp>/file-block/policy.json
rg -n "filesystem|blocked|rule_id" /tmp/transpect-openclaw-frida-smoke/<timestamp>/file-block/events.jsonl
```

失败兜底说辞：

“如果现场文件场景失败，我会先看 `policy.json` 和 `events.jsonl`。这类失败通常不是策略设计问题，而是运行环境或临时路径不一致。”

### 第五步：3 分钟，跑 `network-block`

命令：

```bash
python3 scripts/verify_openclaw_frida.py --scenario network-block
```

预期输出：

- 场景通过
- 输出本地 `url`
- 输出 `policy.json`
- 输出 `http.requests.json`

讲法：

“这里不依赖公网，我们自己起一个 `127.0.0.1` 的临时 HTTP 服务，再让 OpenClaw runtime 样本去访问它。阻断成功的标准不是模型说失败了，而是本地 HTTP 服务根本没有收到请求，而且 JSONL 里有命中的 `rule_id`。”

建议现场打开的产物：

```bash
cat /tmp/transpect-openclaw-frida-smoke/<timestamp>/network-block/policy.json
cat /tmp/transpect-openclaw-frida-smoke/<timestamp>/network-block/http.requests.json
rg -n "net_connect|net_sendto|blocked|rule_id" /tmp/transpect-openclaw-frida-smoke/<timestamp>/network-block/events.jsonl
```

失败兜底说辞：

“如果现场网络场景失败，我会先看本地 HTTP 服务有没有被访问。如果 `http.requests.json` 为空而 JSONL 有命中，说明阻断能力是好的；如果两边都没有，就优先检查本地端口和服务是否起来。”

### 第六步：2 分钟，总结与路线图

建议收尾这样讲：

“这轮工作已经证明三件事。第一，我们能在不改 OpenClaw 的情况下，命中真实 runtime 工具链。第二，我们已经把它做成可重复 smoke，而不是手工 PoC。第三，能力已经从进程执行扩到文件和网络，所以它已经不是单一 hook，而是动态沙盒雏形。下一步我会继续补更广的文件系统和网络覆盖面，再把策略体系做完整。”

## 5. 加分项

如果时间允许，可以补一段实验场景：

```bash
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent
```

讲法：

“这个场景不进默认 smoke，因为它受模型是否真的触发工具调用影响。但我们也已经在真实 agent 路径上验证过一次，当前仓库里保留了 2026-03-27 的成功产物。”

建议现场打开：

```bash
rg -n "exec_call" /tmp/transpect-openclaw-frida-smoke/20260327-173145/gateway-agent/gateway.events.jsonl
cat /tmp/transpect-openclaw-frida-smoke/20260327-173145/gateway-agent/agent.stdout
```

## 6. 现场推荐顺序

建议严格按这个顺序展示：

1. 问题与目标
2. 架构与 hook 点
3. `--scenario all`
4. `--scenario file-block`
5. `--scenario network-block`
6. 可选 `--scenario gateway-agent`
7. 当前完成度与下一步路线

## 7. 你可以强调的三个汇报点

如果评审时间很短，至少把这三句话说清楚：

- “这不是单次手工 PoC，而是可重复执行的 smoke 闭环。”
- “当前已经覆盖进程、文件系统、网络三类运行时行为。”
- “默认稳定链路和沙盒扩展链路已经分开，说明这套方案是可以工程化继续推进的。”
