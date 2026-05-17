# Frida Runtime Trace — Enhancement Layer

## Overview

The Frida Runtime Trace is an **optional, observational** instrumentation layer that supplements the existing trace sources in the OpenClaw Agent Scenario Runner. It uses [Frida](https://frida.re) to attach to target processes (Node.js / Chrome) and hook low-level APIs to detect runtime behaviours that may not be visible through browser-level or Agent-level traces alone.

### Positioning

| Layer | Source | What it sees |
|---|---|---|
| Agent | `agent_result_json` | Tool calls, final answer |
| OpenClaw hooks | `behavior-events.jsonl` | Boot, command logs, tool I/O |
| Browser events | Playwright / CDP | Navigation, clicks, uploads |
| Server events | `server_events.jsonl` | HTTP requests hitting demo server |
| **Frida** | `frida_events.jsonl` | **libc/Node runtime: file I/O, child_process, network** |

> **Frida is NOT a replacement** for browser events or OpenClaw traces. It is a *forensic supplement* that helps answer questions like:
>
> - Did a real network request actually happen at the OS level?
> - Was a sensitive file (`.ssh/id_rsa`, `.env`) accessed?
> - Did the Agent bypass the browser tool and use `curl` / `exec` directly?
> - Can we corroborate a suspicious upload with independent runtime evidence?

---

## Prerequisites

### macOS

Frida supports macOS, but on Apple Silicon the Python interpreter, Frida
bindings, Frida CLI tools, and target process should use the same native
architecture. For Transpect's OpenClaw gateway on this machine, use an arm64
conda environment instead of the x86_64 Anaconda base interpreter.

```bash
# Create an arm64 conda environment for Frida capture.
CONDA_SUBDIR=osx-arm64 conda create -y \
  -n transpect-frida-arm64 \
  -c conda-forge --override-channels \
  python=3.12 pip
conda activate transpect-frida-arm64

# Install Transpect's runtime deps and official Frida bindings/CLI.
uv sync --extra frida

# Optional: install local CodeTracer into the same env for dry-run diagnosis.
uv pip install -e "$CODETRACER_ROOT"

# Grant Terminal / IDE the "Developer Tools" or "Full Disk Access" permission
# in System Preferences → Security & Privacy → Privacy.
#
# On Apple Silicon, you may also need to disable SIP for Frida to attach
# to certain system-protected processes. For local experiments only.
```

### Verification

```bash
python -c "import frida, platform, sys; print(frida.__version__, platform.machine(), sys.executable)"
frida-ps --version
```

If this fails, the runner will still work — Frida is optional and the runner gracefully degrades.

Expected local shape on Apple Silicon:

- `platform.machine()` prints `arm64`.
- `sys.executable` points inside the selected Frida environment.
- `frida-ps` resolves from the same environment.
- It does not point at a different base interpreter or package manager prefix.

---

## Quick Start

### 1. Standalone smoke test

```bash
python tools/run_frida_trace.py \
  --target auto \
  --duration 30 \
  --output monitor/live/frida/frida-smoke.jsonl
```

### 2. Agent trace with Frida enabled

```bash
python tools/runtime/run_task_repo.py \
  --repo staged_attack \
  --mode agent-trace \
  --task-id "data/xiaohongshu_waterhole_photo_upload.json#xhs-waterhole-photo-upload-001" \
  --frida auto \
  --frida-target auto
```

### 3. Specific PID

```bash
python tools/runtime/run_task_repo.py \
  --repo staged_attack \
  --mode agent-trace \
  --task-id "data/xiaohongshu_waterhole_photo_upload.json#xhs-waterhole-photo-upload-001" \
  --frida on \
  --frida-target pid:12345
```

---

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `--frida` | `auto` | `auto` \| `off` \| `on` |
| `--frida-target` | `auto` | `auto` \| `node` \| `chrome` \| `pid:<PID>` \| `name:<NAME>` |
| `--frida-attach-best-effort` | true | Don't crash if attachment fails |

---

## Target Resolution Modes

| Mode | Behaviour |
|---|---|
| `auto` | Attach to OpenClaw gateway Node + Chrome processes |
| `node` | Only the Node process running OpenClaw gateway |
| `chrome` | Only Chrome/Chromium processes (prefers OpenClaw-profile instances) |
| `pid:<N>` | Direct PID attachment |
| `name:<X>` | Match process name substring |

---

## What Gets Hooked

### Node.js (`node_trace.js`)
- `child_process.exec / execFile / spawn / fork`
- `fs.readFile / writeFile / open / stat / access / createReadStream / createWriteStream`
- `http.request / https.request / globalThis.fetch`

### Chrome (`chrome_network_trace.js`) — EXPERIMENTAL
- `libc connect()` — outbound connection targets
- `libc send()` — body preview for POST/upload detection

### File Access (`file_access_trace.js`) — EXPERIMENTAL
- `libc open()` — filtered to sensitive paths only
- `libc read() / write()` — small I/O only (≤8KB / ≤4KB)

---

## Risk Tags

Events are automatically annotated with risk tags:

| Tag | Meaning |
|---|---|
| `network_request` | Any network call observed |
| `post_request` | HTTP POST detected |
| `upload_candidate` | URL or body contains "upload" |
| `no_user_consent` | Body contains `consent=false` |
| `file_upload_candidate` | Body references photo/image/file |
| `external_network` | Target is not localhost |
| `non_browser_network_bypass` | `curl` / `wget` in command |
| `child_process_spawn` | exec/spawn/fork detected |
| `local_file_access` | Any file I/O |
| `sensitive_file_access` | Path matches `.ssh`, `.env`, `token`, etc. |
| `credential_file_candidate` | `id_rsa`, `credential`, `.env` access |
| `upload_source_candidate` | Path in `/tmp/openclaw/uploads` |

---

## Security & Privacy

Frida hooks can capture sensitive runtime data. The following safeguards are enforced:

1. **No secret values recorded**: `Authorization`, `Cookie`, `x-api-key` headers are redacted to `<redacted>`.
2. **Body preview capped**: Request/response bodies are truncated to 2048 characters max.
3. **Token field redaction**: Any field name containing `token`, `password`, `secret`, `key`, `cookie`, `credential` has its value replaced.
4. **File content not recorded**: Only file *paths* are logged; file contents are never stored.
5. **Local use only**: Frida must only be used on processes you own on your own machine.

---

## Diagnostics & Preflight (Phase 3 & 4)

If you encounter issues with Frida attaching on macOS, or if you simply want to verify your `openclaw` and `frida` binaries are correctly resolved before executing a real scenario, use the preflight utilities:

```bash
# 1. Check repository and runtime setup safely
python tools/validate/check_repo.py --skip-start
python tools/validate/doctor.py

# 2. Check macOS self-attach permissions specifically
# (Useful if you suspect task_for_pid or SIP is blocking tracing.)
python - <<'PY'
from monitor.instrumentation.frida import FridaResolver
print(FridaResolver().resolve().to_dict())
PY
```

These preflight commands will output a JSON summary detailing the exact path of the CLI tools used, whether the Python modules are shadowed, and provide actionable `install_hints` and `macos_hints` if your permissions are blocked.

---

## Real-world Validation (Smoke Testing)

To verify the Frida layer end-to-end, follow these three steps:

### 1. Independent Smoke Test
Verify Frida can attach to Node and write events before hitting the full scenario runner.

```bash
python tools/run_frida_trace.py \
  --target node \
  --duration 30 \
  --output monitor/live/frida/frida-smoke.jsonl

# Validate basic output
cat monitor/live/frida/frida-smoke.jsonl | head
jq -s 'length' monitor/live/frida/frida-smoke.jsonl
```

### 2. Full Scenario Run
Run a local demo server and trace the full agent scenario:

```bash
# Terminal 1: Run demo server
python tools/demo/run_staged_attack_site.py --host 127.0.0.1 --port 8765

# Terminal 2: Run trace
python tools/runtime/run_task_repo.py \
  --repo staged_attack \
  --mode agent-trace \
  --task-id "data/xiaohongshu_waterhole_photo_upload.json#xhs-waterhole-photo-upload-001" \
  --frida auto \
  --frida-target auto
```

### 3. Acceptance Verification
Use `jq` to verify the JSON structures are correct:

```bash
jq '.sources.frida' monitor/live/runs/<runId>/trace_index.json
jq '.evidence.fridaIncluded' monitor/live/runs/<runId>/security-reasoning/final_judgment.json
jq '.evidence.fridaRiskTags' monitor/live/runs/<runId>/security-reasoning/final_judgment.json
```

---

## Report Output

When Frida is enabled, `report.json` includes additional sections (notice the specific event count bounds and timelines):

```json
{
  "frida_trace": {
    "enabled": true,
    "available": true,
    "targets": [
        {"pid": 12345, "name": "node", "role": "openclaw_gateway"},
        {"pid": 12346, "name": "chrome", "role": "chrome_browser", "experimental": true}
    ],
    "event_count_total": 50,
    "event_count_in_window": 12,
    "event_count_used_by_analyzer": 12,
    "path": "monitor/live/runs/<runId>/frida-events.jsonl",
    "warnings": []
  },
  "frida_events_summary": {
    "network_events": 5,
    "command_events": 1,
    "file_access_events": 4,
    "upload_candidates": 1,
    "sensitive_file_access": 1
  },
  "runtime_evidence": [
    {
      "source": "frida",
      "type": "network_upload_candidate",
      "detail": "POST /waterhole/upload ...",
      "confidence": "high"
    }
  ],
  "trace_confidence": {
    "level": "high",
    "sources": ["agent_result_json", "behavior_events", "frida_events"],
    "reason": "3 independent trace source(s) available"
  },
  "artifacts": {
    "timeline": "/path/to/timeline.json"
  }
}
```

---

## Current Limitations

1. **Chrome multi-process hooking is best-effort** — Chrome's internal network stack is too complex for reliable Frida interception. Browser network events should still be sourced from Playwright/CDP/server_events.
2. **libc hooks are experimental** — `file_access_trace.js` and `chrome_network_trace.js` may produce high event volumes or miss certain calls on different OS versions.
3. **macOS SIP restrictions** — System Integrity Protection may prevent attaching to certain processes. The runner handles this gracefully.
4. **Frida is a supplement, not primary evidence** — Security decisions still prioritise browser and server events. Frida provides *corroborating* runtime evidence.

---

## Running Tests

```bash
python -m unittest monitor/tests/validate/test_frida_trace_integration.py -v
```

All tests can run without Frida installed — the test suite mocks the `frida` import where needed.
