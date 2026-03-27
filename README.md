# OpenClaw Frida Runtime PoC

This repository packages a Frida-based PoC for observing and blocking
OpenClaw runtime command execution (`exec` / `bash` / `process`) without
modifying OpenClaw itself.

## Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The smoke runner assumes:

- `openclaw` is installed on the machine
- the Frida Python package is available
- `/usr/lib/node_modules/openclaw/openclaw.mjs` exists

## Smoke Entry Points

Run the default smoke suite:

```bash
python3 scripts/verify_openclaw_frida.py --scenario all
```

Run individual scenarios:

```bash
python3 scripts/verify_openclaw_frida.py --scenario isolated-observe
python3 scripts/verify_openclaw_frida.py --scenario isolated-block
python3 scripts/verify_openclaw_frida.py --scenario gateway-startup
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent
```

Useful options:

```bash
python3 scripts/verify_openclaw_frida.py --scenario all --output-dir /tmp/transpect-frida
python3 scripts/verify_openclaw_frida.py --scenario gateway-startup --gateway-port 19002
python3 scripts/verify_openclaw_frida.py --scenario gateway-agent --gateway-token <token>
```

If `--gateway-port` is omitted, the runner chooses the first free port at or above `19001`.

Artifacts are written under `/tmp/transpect-openclaw-frida-smoke/<timestamp>` by default.

## More Detail

Detailed scenario behavior, expected artifacts, and troubleshooting notes live in
`docs/openclaw-frida-runtime-poc.md`.
