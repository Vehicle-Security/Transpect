# Frida 说明

Transpect 提供了一条可选的 Frida 捕获链路，用于观察 Windows 上 OpenClaw gateway 进程的宿主侧行为。

## 依赖要求

- Windows
- Python `frida` 包
- 一个正在运行的 OpenClaw gateway 进程

如果当前环境还没有安装 `frida`，先执行：

```powershell
pip install -r requirements.txt
```

## 启动方式

直接让脚本自动寻找 gateway 进程：

```powershell
python scripts/capture_frida.py
```

如果你希望附着到指定进程：

```powershell
python scripts/capture_frida.py --pid <gateway-pid>
```

## 输出文件

输出会写到 `live/frida/`：

- `frida-control.jsonl`
- `frida-process.jsonl`
- `frida-file.jsonl`
- `frida-port.jsonl`
- `frida-network.jsonl`

## 注意事项

- `frida/openclaw_gateway_windows.js` 目前按 Windows gateway 的行为特征编写。
- 如果 `capture_frida.py` 无法自动解析 gateway PID，请先确认 gateway 已经启动，再显式传入 `--pid`。
- Frida 输出是补充信息，不替代 JSONL 主链路或 OTEL 链路。
