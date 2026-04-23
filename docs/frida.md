# Frida Notes

Transpect includes optional Frida capture support for Windows gateway processes.

## Requirements

- Windows
- Python `frida`
- a running OpenClaw gateway process

Install the optional dependency with:

```powershell
pip install -r requirements.txt
```

## Usage

```powershell
python scripts/capture/capture_frida.py
python scripts/capture/capture_frida.py --pid <gateway-pid>
```

## Output

Frida writes optional host-side capture output under `live/frida/`, including:

- `frida-control.jsonl`
- `frida-process.jsonl`
- `frida-file.jsonl`
- `frida-port.jsonl`
- `frida-network.jsonl`

## Notes

- `frida/openclaw_gateway_windows.js` contains the Windows-specific instrumentation logic.
- If PID auto-detection fails, start the gateway first and provide `--pid`.
- Frida output is supplementary. It does not replace the canonical run evidence under `live/runs/<runId>/`.
