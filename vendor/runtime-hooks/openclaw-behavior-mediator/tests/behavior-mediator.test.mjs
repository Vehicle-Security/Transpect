import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import behaviorMediatorPlugin from "../index.js";

function createFakeApi(pluginConfig) {
  const hooks = new Map();
  const services = [];
  const methods = new Map();
  return {
    pluginConfig,
    logger: {
      info() {},
      warn() {},
      error() {},
    },
    on(name, handler) {
      hooks.set(name, handler);
    },
    registerGatewayMethod(name, handler) {
      methods.set(name, handler);
    },
    registerService(service) {
      services.push(service);
    },
    hooks,
    services,
    methods,
  };
}

test("behavior mediator writes per-run events, artifacts, and manifest", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "transpect-behavior-"));
  const runsDirectory = path.join(root, "runs");
  const api = createFakeApi({
    runsDirectory,
    artifactsEnabled: true,
    autoDiagnosisEnabled: false,
    capturePreviewChars: 2000,
    captureNetwork: false,
    traceEval: false,
  });

  behaviorMediatorPlugin.register(api);
  assert.equal(api.services.length, 1);
  await api.services[0].start();

  api.hooks.get("message_received")?.(
    { sessionKey: "sess-1", text: "Read README and explain it", timestamp: "2026-04-22T10:00:00Z" },
    {},
  );
  api.hooks.get("before_agent_start")?.(
    { sessionKey: "sess-1", runId: "run-1", prompt: "Read README and explain it", agentId: "main" },
    {},
  );
  api.hooks.get("before_tool_call")?.(
    {
      sessionKey: "sess-1",
      runId: "run-1",
      toolCallId: "tc-read",
      toolName: "Read",
      params: { path: "README.md" },
    },
    {},
  );
  api.hooks.get("after_tool_call")?.(
    {
      sessionKey: "sess-1",
      runId: "run-1",
      toolCallId: "tc-read",
      result: { content: [{ type: "text", text: "README content" }] },
    },
    {},
  );
  await api.hooks.get("agent_end")?.(
    {
      sessionKey: "sess-1",
      runId: "run-1",
      success: true,
      messages: [{ role: "assistant", content: "README explains the project." }],
    },
    {},
  );

  const runDir = path.join(runsDirectory, "run-1");
  const eventsPath = path.join(runDir, "behavior-events.jsonl");
  const manifestPath = path.join(runDir, "manifest.json");
  const taskInputPath = path.join(runDir, "task_input.json");
  const artifactInputPath = path.join(runDir, "artifacts", "tc-read", "input.json");
  const artifactOutputPath = path.join(runDir, "artifacts", "tc-read", "output.json");

  assert.equal(fs.existsSync(eventsPath), true);
  assert.equal(fs.existsSync(manifestPath), true);
  assert.equal(fs.existsSync(taskInputPath), true);
  assert.equal(fs.existsSync(artifactInputPath), true);
  assert.equal(fs.existsSync(artifactOutputPath), true);

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const taskInput = JSON.parse(fs.readFileSync(taskInputPath, "utf8"));
  const lines = fs
    .readFileSync(eventsPath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  assert.equal(manifest.runId, "run-1");
  assert.equal(manifest.status, "completed");
  assert.equal(taskInput.userInput.message, "Read README and explain it");
  assert.equal(taskInput.agentTask.prompt, "Read README and explain it");
  assert.ok(lines.some((row) => row.kind === "tool" && row.status === "started"));
  assert.ok(lines.some((row) => row.kind === "tool" && row.status === "ok"));

  await api.services[0].stop();
});
