# OpenClaw Frida Sandbox PoC

这个仓库提供一个基于 Frida 的 OpenClaw 动态沙盒 PoC，目标是在不修改 OpenClaw 代码的前提下，对 runtime 工具链做可重复的观察与阻断。

当前能力分成两层：

- 稳定基线：进程创建与命令执行链路，覆盖 `exec` / `bash` / `process`
- 沙盒扩展：文件系统与网络访问的观察/阻断

## Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

运行前提：

- 本机已安装 `openclaw`
- 本机可用 `frida` Python 包
- `/usr/lib/node_modules/openclaw/openclaw.mjs` 存在

## Smoke Entry Points

默认稳定 smoke：

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
```

沙盒扩展 smoke：

```bash
python3 scripts/verify_openclaw_frida.py --scenario sandbox-all
```

单场景入口：

```bash
python3 scripts/verify_openclaw_frida.py --scenario isolated-observe
python3 scripts/verify_openclaw_frida.py --scenario isolated-block
python3 scripts/verify_openclaw_frida.py --scenario gateway-startup
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent
python3 scripts/verify_openclaw_frida.py --scenario file-observe
python3 scripts/verify_openclaw_frida.py --scenario file-block
python3 scripts/verify_openclaw_frida.py --scenario network-observe
python3 scripts/verify_openclaw_frida.py --scenario network-block
```

常用参数：

```bash
python3 scripts/verify_openclaw_frida.py --scenario all --output-dir /tmp/transpect-frida
python3 scripts/verify_openclaw_frida.py --scenario gateway-startup --gateway-port 19002
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent --gateway-token <token>
```

如果没有显式传 `--gateway-port`，runner 会从 `19001` 开始自动选择首个空闲端口。所有产物默认保留在 `/tmp/transpect-openclaw-frida-smoke/<timestamp>/`。

## Direct Start

如果你想直接起一个可对话的 OpenClaw 会话，并把 Frida 事件持续写进 JSONL，官方入口就是：

```bash
python3 scripts/start_openclaw_frida_chat.py
```

启动后：

- Frida 会包裹 OpenClaw gateway
- 终端里可以逐条输入消息和 OpenClaw 对话
- 事件会持续写入 `gateway.events.jsonl`
- 默认产物目录在 `/tmp/transpect-openclaw-chat/<timestamp>/`
- 默认抓的是被 hook 到的 OpenClaw 运行时进程树中的操作，不承诺覆盖 OpenClaw 内部全部实现细节
- 为了避免 gateway 启动阶段异常，gateway bootstrap 自身默认跳过文件和网络 hook；后续真实 runtime 子进程仍会继续抓取

常用示例：

```bash
python3 scripts/start_openclaw_frida_chat.py --message "你必须使用 exec 工具执行 /bin/sh -lc 'printf HELLO'"
python3 scripts/start_openclaw_frida_chat.py --timeout 30 --mode block --policy-file /path/to/policy.json
python3 scripts/start_openclaw_frida_chat.py --disable-filesystem-hooks --disable-network-hooks
```

说明：

- `--mode block` 必须搭配 `--policy-file`
- 默认 `observe` 会抓进程链路，并抓子进程文件和网络事件

如果你想快速验证“对话触发工具调用后，JSONL 里确实有命中”，可以直接运行：

```bash
python3 scripts/start_openclaw_frida_chat.py \
  --json \
  --message 'You must use the exec or bash tool. Run /bin/sh -lc "printf FRIDA_STDOUT; printf FRIDA_STDERR >&2" and return the exact tool output. Do not answer from memory.'
```

运行过程中你可以另开一个终端实时看日志：

```bash
tail -f /tmp/transpect-openclaw-chat/<timestamp>/gateway.events.jsonl
```

## More Detail

详细实现、策略文件格式、事件字段、场景通过标准、汇报材料和 Demo 脚本见：

- `docs/openclaw-frida-runtime-poc.md`
- `docs/frida-agent-capability-report.md`
- `docs/frida-agent-demo-script.md`
