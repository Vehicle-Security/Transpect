# Frida Capture

Transpect includes an optional Windows Frida capture path for the OpenClaw gateway.

## Requirements

- Windows
- Python package `frida`
- A running OpenClaw gateway process

Install the Python dependency if needed:

```powershell
pip install -r requirements.txt
```

## Start Capture

```powershell
python scripts/capture_frida.py
```

To target a specific process:

```powershell
python scripts/capture_frida.py --pid <gateway-pid>
```

## Output Files

Files are written to `live/frida/`:

- `frida-control.jsonl`
- `frida-process.jsonl`
- `frida-file.jsonl`
- `frida-port.jsonl`
- `frida-network.jsonl`

## Notes

- The Frida script in `frida/openclaw_gateway_windows.js` is currently tailored to Windows gateway behavior.
- If `capture_frida.py` cannot resolve a gateway PID automatically, start the gateway first and pass `--pid`.
- Frida output is supplementary. It does not replace the JSONL trace or OTEL paths.
