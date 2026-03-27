#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import url from "node:url";

const DEFAULT_RUNTIME_MODULE = "/usr/lib/node_modules/openclaw/dist/exec-Dt_VCeCB.js";
const DIST_DIR = "/usr/lib/node_modules/openclaw/dist";
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

const args = parseArgs(process.argv.slice(2));
process.title = "openclaw-frida-probe";

const runtimeModulePath = await resolveRuntimeModule(args.runtimeModule ?? DEFAULT_RUNTIME_MODULE);
const runtimeModule = await import(url.pathToFileURL(runtimeModulePath).href);
if (typeof runtimeModule.t !== "function") {
  throw new Error(`Resolved runtime module does not export runCommandWithTimeout alias "t": ${runtimeModulePath}`);
}

if (args.delayMs > 0) {
  console.error(`[probe] sleeping ${args.delayMs}ms before trigger`);
  await sleep(args.delayMs);
}

const sample = resolveSample(args.sample);
console.error(`[probe] using runtime module: ${runtimeModulePath}`);
console.error(`[probe] sample=${args.sample} argv=${JSON.stringify(sample.argv)}`);

try {
  const result = await runtimeModule.t(sample.argv, { timeoutMs: args.timeoutMs });
  const blocked = args.sample === "block" && Number(result?.code) !== 0;
  const ok = args.sample === "block" ? blocked : Number(result?.code) === 0;
  console.log(
    JSON.stringify(
      {
        ok,
        blocked,
        sample: args.sample,
        runtimeModulePath,
        result,
      },
      null,
      2,
    ),
  );
  if (!ok) {
    process.exitCode = 1;
  }
} catch (error) {
  const errorMessage = error instanceof Error ? error.message : String(error);
  const blockedBySpawnFailure =
    args.sample === "block" && /\bspawn\b.*\b(ENOENT|EACCES|EPERM)\b/i.test(errorMessage);
  const payload = {
    ok: blockedBySpawnFailure,
    blocked: blockedBySpawnFailure,
    sample: args.sample,
    runtimeModulePath,
    error: errorMessage,
    stack: error instanceof Error ? error.stack : null,
  };
  const sink = blockedBySpawnFailure ? console.log : console.error;
  sink(JSON.stringify(payload, null, 2));
  if (!blockedBySpawnFailure) {
    process.exitCode = 1;
  }
}

function parseArgs(argv) {
  const parsed = {
    sample: "observe",
    runtimeModule: undefined,
    delayMs: 0,
    timeoutMs: 5000,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === "--sample") {
      parsed.sample = argv[++index] ?? parsed.sample;
      continue;
    }
    if (current === "--runtime-module") {
      parsed.runtimeModule = argv[++index];
      continue;
    }
    if (current === "--delay-ms") {
      parsed.delayMs = Number(argv[++index] ?? parsed.delayMs);
      continue;
    }
    if (current === "--timeout-ms") {
      parsed.timeoutMs = Number(argv[++index] ?? parsed.timeoutMs);
      continue;
    }
    if (current === "--help" || current === "-h") {
      printHelp();
      process.exit(0);
    }
    throw new Error(`Unknown argument: ${current}`);
  }

  return parsed;
}

function resolveSample(sample) {
  if (sample === "observe") {
    return {
      argv: ["/bin/sh", "-lc", "printf FRIDA_STDOUT; printf FRIDA_STDERR >&2"],
    };
  }
  if (sample === "block") {
    return {
      argv: ["/usr/bin/id"],
    };
  }
  throw new Error(`Unsupported sample: ${sample}`);
}

async function resolveRuntimeModule(preferredPath) {
  if (preferredPath && fs.existsSync(preferredPath)) {
    return preferredPath;
  }

  const candidates = fs
    .readdirSync(DIST_DIR, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /^exec-.*\.js$/.test(entry.name))
    .map((entry) => path.join(DIST_DIR, entry.name))
    .sort();

  for (const candidate of candidates) {
    try {
      const mod = await import(url.pathToFileURL(candidate).href);
      if (typeof mod.t === "function") return candidate;
    } catch (_error) {
      continue;
    }
  }

  throw new Error(`Unable to resolve an OpenClaw exec runtime module under ${DIST_DIR}`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function printHelp() {
  console.log(`Usage: node ${path.join(__dirname, "openclaw_exec_probe.mjs")} [options]

Options:
  --sample <observe|block>   Probe scenario to run (default: observe)
  --runtime-module <path>    Override the OpenClaw exec runtime module path
  --delay-ms <ms>            Sleep before executing the runtime helper
  --timeout-ms <ms>          Timeout passed to runCommandWithTimeout
`);
}
