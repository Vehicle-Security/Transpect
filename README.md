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

## More Detail

详细实现、策略文件格式、事件字段、场景通过标准、汇报材料和 Demo 脚本见：

- `docs/openclaw-frida-runtime-poc.md`
- `docs/frida-agent-capability-report.md`
- `docs/frida-agent-demo-script.md`
