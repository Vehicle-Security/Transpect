# OpenClaw Frida Runtime PoC

This project is a standalone Frida-based PoC for observing and blocking
OpenClaw runtime command execution (`exec` / `bash` / `process`) without
modifying OpenClaw source code.

## Project Layout

- `tools/frida/openclaw_runtime_driver.py`:
  Python driver using the Frida API (attach/spawn, child gating, JSONL output).
- `tools/frida/openclaw_runtime_hook.js`:
  Frida agent for `uv_spawn`, `execve`/`execvp`, `write`/`writev`, and `exit`.
- `tools/frida/openclaw_exec_probe.mjs`:
  Deterministic runtime probe script using OpenClaw's runtime helper.
- `docs/openclaw-frida-runtime-poc.md`:
  End-to-end verification guide and known environment caveats.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Observe mode:

```bash
python3 tools/frida/openclaw_runtime_driver.py \
  --mode observe \
  --spawn-program /usr/bin/node \
  --spawn-arg=tools/frida/openclaw_exec_probe.mjs \
  --spawn-arg=--sample \
  --spawn-arg=observe \
  --jsonl /tmp/openclaw-frida-observe.jsonl \
  --exit-on-root-detach
```

Block mode:

```bash
python3 tools/frida/openclaw_runtime_driver.py \
  --mode block \
  --deny-exe-regex '^/usr/bin/id$' \
  --spawn-program /usr/bin/node \
  --spawn-arg=tools/frida/openclaw_exec_probe.mjs \
  --spawn-arg=--sample \
  --spawn-arg=block \
  --jsonl /tmp/openclaw-frida-block.jsonl \
  --exit-on-root-detach
```
