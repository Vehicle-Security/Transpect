import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { AsyncLocalStorage } from "node:async_hooks";
import { appendCanonicalEvent, cleanObject, createId, createWriterState, nowIso } from "./canonical.js";

const als = new AsyncLocalStorage();

const DEFAULT_RUNS_DIRECTORY = path.resolve(process.cwd(), "live", "runs");
const DEFAULT_PREVIEW_CHARS = 2000;
const DEFAULT_REDACT_HEADERS = ["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"];
const DEFAULT_REDACT_PATTERNS = [
  "Bearer\\s+[A-Za-z0-9._-]+",
  "sk-[A-Za-z0-9_-]+",
  "(?:api[_-]?key|token|secret|password)\\s*[:=]\\s*['\\\"]?[^'\\\"\\s,}]+",
];

function safeStringify(value) {
  try {
    return JSON.stringify(value);
  } catch (error) {
    return String(value);
  }
}

function clipText(value, limit) {
  if (value == null) {
    return null;
  }
  const text = typeof value === "string" ? value : safeStringify(value);
  return text.length <= limit ? text : `${text.slice(0, limit)}...`;
}

function compilePatterns(patterns) {
  return patterns
    .map((pattern) => {
      try {
        return new RegExp(pattern, "gi");
      } catch (error) {
        return null;
      }
    })
    .filter(Boolean);
}

function parseConfig(value) {
  const config = value && typeof value === "object" ? value : {};
  const configuredSecurityMode =
    typeof config.securityMode === "string" && ["off", "audit", "enforce"].includes(config.securityMode)
      ? config.securityMode
      : null;
  const securityMode = configuredSecurityMode || (config.securityEnabled === true ? "enforce" : "off");
  const llmJudge = config.llmJudge && typeof config.llmJudge === "object" ? config.llmJudge : {};
  const legacyOutputFile = typeof config.outputFile === "string" && config.outputFile ? path.resolve(config.outputFile) : null;
  const runsDirectory =
    typeof config.runsDirectory === "string" && config.runsDirectory
      ? path.resolve(config.runsDirectory)
      : legacyOutputFile
        ? path.resolve(path.dirname(legacyOutputFile), "runs")
        : DEFAULT_RUNS_DIRECTORY;
  return {
    runsDirectory,
    artifactsEnabled: config.artifactsEnabled !== false,
    autoDiagnosisEnabled: config.autoDiagnosisEnabled === true,
    diagnosisScript:
      typeof config.diagnosisScript === "string" && config.diagnosisScript.trim()
        ? path.resolve(config.diagnosisScript)
        : path.resolve(process.cwd(), "scripts", "run_codetracer_diagnosis.py"),
    diagnosisPython:
      typeof config.diagnosisPython === "string" && config.diagnosisPython.trim()
        ? config.diagnosisPython.trim()
        : process.env.PYTHON || "python",
    legacyOutputFile,
    capturePreviewChars:
      typeof config.capturePreviewChars === "number" && Number.isFinite(config.capturePreviewChars)
        ? Math.max(128, Math.floor(config.capturePreviewChars))
        : DEFAULT_PREVIEW_CHARS,
    captureNetwork: config.captureNetwork !== false,
    securityEnabled: securityMode !== "off",
    securityMode,
    policyPath:
      typeof config.policyPath === "string" && config.policyPath.trim()
        ? path.resolve(config.policyPath)
        : null,
    llmJudge: {
      enabled: llmJudge.enabled === true,
      mode: typeof llmJudge.mode === "string" && llmJudge.mode.trim() ? llmJudge.mode.trim() : "gray_zone_only",
    },
    securityPython:
      typeof config.securityPython === "string" && config.securityPython.trim()
        ? config.securityPython.trim()
        : process.env.PYTHON || "python",
    securityBridgeScript:
      typeof config.securityBridgeScript === "string" && config.securityBridgeScript.trim()
        ? path.resolve(config.securityBridgeScript)
        : path.resolve(process.cwd(), "app", "agent_defense", "bridge.py"),
    traceEval: config.traceEval === true,
    redactHeaders: Array.isArray(config.redactHeaders)
      ? config.redactHeaders.filter((item) => typeof item === "string" && item.trim()).map((item) => item.toLowerCase())
      : DEFAULT_REDACT_HEADERS,
    redactPatterns: Array.isArray(config.redactPatterns)
      ? config.redactPatterns.filter((item) => typeof item === "string" && item.trim())
      : DEFAULT_REDACT_PATTERNS,
  };
}

function redactText(value, state) {
  if (value == null) {
    return null;
  }
  let text = typeof value === "string" ? value : safeStringify(value);
  for (const pattern of state.redactPatterns) {
    text = text.replace(pattern, "[REDACTED]");
  }
  return text;
}

function previewText(value, state) {
  return clipText(redactText(value, state), state.config.capturePreviewChars);
}

function headersToObject(headers) {
  if (!headers) {
    return null;
  }
  try {
    if (typeof headers.entries === "function") {
      return Object.fromEntries(headers.entries());
    }
    if (Array.isArray(headers)) {
      return Object.fromEntries(headers);
    }
    if (typeof headers === "object") {
      return { ...headers };
    }
  } catch (error) {
    return null;
  }
  return null;
}

function sanitizeHeaders(headers, state) {
  const data = headersToObject(headers);
  if (!data) {
    return null;
  }
  const output = {};
  for (const [key, value] of Object.entries(data)) {
    output[key] = state.config.redactHeaders.includes(key.toLowerCase()) ? "[REDACTED]" : previewText(value, state);
  }
  return output;
}

function summarizeContentParts(content, state) {
  if (!Array.isArray(content)) {
    return null;
  }
  const text = content
    .filter((item) => item && item.type === "text")
    .map((item) => previewText(item.text, state))
    .filter(Boolean)
    .join("\n");
  return text || null;
}

function summarizeAssistant(messages, state) {
  if (!Array.isArray(messages)) {
    return null;
  }
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (!message || message.role !== "assistant") {
      continue;
    }
    if (typeof message.content === "string" && message.content.trim()) {
      return previewText(message.content, state);
    }
    const summary = summarizeContentParts(message.content, state);
    if (summary) {
      return summary;
    }
  }
  return null;
}

function summarizeExecCommand(commandLine) {
  const text = String(commandLine || "").trim();
  if (!text) {
    return "exec 命令";
  }
  const match = text.match(/^"([^"]+)"|^([^\s]+)/);
  const token = match?.[1] || match?.[2] || text;
  const parts = token.split(/[\\/]/);
  return parts[parts.length - 1] || token;
}

function extractExitCodeFromText(value) {
  const match = String(value || "").match(/\(Command exited with code (-?\d+)\)/i);
  if (!match) {
    return null;
  }
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) ? parsed : null;
}

function isPowerShellCurlAliasError(value) {
  const text = String(value || "");
  return (
    /Invoke-WebRequest/i.test(text) &&
    (/MissingMandatoryParameter/i.test(text) || /ParameterBindingException/i.test(text) || /\bUri\b/i.test(text))
  );
}

function normalizeExecToolResult(result, rawText, tool) {
  const text = typeof rawText === "string" ? rawText.trim() : "";
  const exitCode = numeric(result?.details?.exitCode) ?? extractExitCodeFromText(text);
  const commandLine =
    tool?.target?.commandLine || tool?.params?.command || tool?.params?.cmd || tool?.params?.script || null;
  const commandLabel = summarizeExecCommand(commandLine);

  if (isPowerShellCurlAliasError(text)) {
    const summary = /\bcurl(?:\.exe)?\b/i.test(String(commandLine || ""))
      ? "PowerShell 将 curl 解析为 Invoke-WebRequest，缺少必填参数 Uri"
      : "Invoke-WebRequest 缺少必填参数 Uri";
    return exitCode == null ? summary : `${summary}（exit code ${exitCode}）`;
  }

  if (!text) {
    return exitCode == null ? null : `${commandLabel} 执行失败（exit code ${exitCode}）`;
  }

  if (/^\(Command exited with code -?\d+\)$/i.test(text)) {
    return exitCode == null ? `${commandLabel} 执行失败` : `${commandLabel} 执行失败（exit code ${exitCode}）`;
  }

  if (text.includes("�")) {
    return exitCode == null ? `${commandLabel} 执行失败，输出编码异常` : `${commandLabel} 执行失败，输出编码异常（exit code ${exitCode}）`;
  }

  return text;
}

function summarizeToolResult(result, state, tool = null) {
  if (!result) {
    return null;
  }
  const rawText =
    summarizeContentParts(result.content, state) ||
    summarizeContentParts(result.result?.content, state) ||
    previewText(result, state);

  if (tool?.toolName === "exec") {
    return normalizeExecToolResult(result, rawText, tool);
  }

  return rawText;
}

function deriveToolTarget(toolName, params = {}) {
  const normalized = String(toolName || "").toLowerCase();
  if (["read", "write", "edit", "apply_patch"].includes(normalized)) {
    return { toolName, path: params.path || params.filePath || params.target || null };
  }
  if (["exec", "bash", "shell_command"].includes(normalized)) {
    return {
      toolName,
      commandLine: params.command || params.cmd || params.script || null,
      cwd: params.cwd || params.workdir || null,
    };
  }
  return { toolName };
}

function safePathSegment(value, fallback) {
  const normalized = String(value || "")
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^[.-]+|[.-]+$/g, "");
  return normalized || fallback;
}

function buildRunDirName(details = {}) {
  return safePathSegment(details.runId || details.traceId || details.sessionKey || `run-${Date.now()}`, "run");
}

function diagnosisPathsForRun(runDir) {
  return {
    bundleDir: path.resolve(runDir, "diagnosis", "codetracer", "bundle"),
    analysisDir: path.resolve(runDir, "diagnosis", "codetracer", "analysis"),
    diagnosisRunPath: path.resolve(runDir, "diagnosis", "codetracer", "analysis", "diagnosis_run.json"),
  };
}

function securityPathsForRun(runDir) {
  return {
    dir: path.resolve(runDir, "security-reasoning"),
    statePath: path.resolve(runDir, "security-reasoning", "security_state.json"),
    decisionPath: path.resolve(runDir, "security-reasoning", "defense_decision.json"),
    evidenceSummaryPath: path.resolve(runDir, "security-reasoning", "evidence_summary.json"),
  };
}

function createRuntime(config, logger) {
  fs.mkdirSync(config.runsDirectory, { recursive: true });
  return {
    config,
    logger,
    runsDirectory: config.runsDirectory,
    eventsWritten: 0,
    lastEventTs: null,
    lastWriteOk: null,
    lastWriteError: null,
    redactPatterns: compilePatterns(config.redactPatterns),
    runStores: new Map(),
    runStoreByRunId: new Map(),
    runStoreByTraceId: new Map(),
    runStoreBySessionKey: new Map(),
    requestContexts: new Map(),
    requestByRunId: new Map(),
    turnContexts: new Map(),
    turnBySession: new Map(),
    toolContexts: new Map(),
    llmContexts: new Map(),
    taskContexts: new Map(),
    taskBySession: new Map(),
    taskByRunId: new Map(),
    originalFetch: null,
    originalEval: null,
    originalFunction: null,
    cleanupTimer: null,
    active: false,
    hookNames: new Set(),
    hookEventsObserved: 0,
    firstHookEventTs: null,
    lastHookEventTs: null,
    artifactsWritten: 0,
    diagnosesTriggered: 0,
    diagnosisInFlight: 0,
    lastDiagnosisError: null,
    securityBridgeFailures: 0,
    lastSecurityDecision: null,
    lastSecurityError: null,
  };
}

function getStoreArtifactDirectory(store) {
  return path.resolve(store.runDir, "artifacts");
}

function buildRunRuntimeStatus(state, store) {
  return {
    schemaVersion: "openclaw.run.runtime.v1",
    capturedAt: nowIso(),
    ids: {
      runId: store.runId,
      traceId: store.traceId,
      sessionKey: store.sessionKey,
    },
    behaviorMediator: buildRuntimeStatus(state),
  };
}

function readJsonFile(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    return null;
  }
}

function buildTaskInput(store) {
  return {
    schemaVersion: "openclaw.run.task-input.v1",
    capturedAt: nowIso(),
    userInput: {
      message: store.requestMessage || null,
      source: store.requestMessage ? "request.started.preview.message" : null,
    },
    agentTask: {
      prompt: store.turnPrompt || null,
      source: store.turnPrompt ? "turn.started.preview.prompt" : null,
    },
    securityScenario: store.securityScenario || null,
    policyObservations: [...store.policyObservations.values()],
  };
}

function buildRunManifest(state, store) {
  const diagnosisPaths = diagnosisPathsForRun(store.runDir);
  const diagnosisRun = fs.existsSync(diagnosisPaths.diagnosisRunPath) ? readJsonFile(diagnosisPaths.diagnosisRunPath) : null;
  const securityPaths = securityPathsForRun(store.runDir);
  const securityDecision = fs.existsSync(securityPaths.decisionPath) ? readJsonFile(securityPaths.decisionPath) : null;
  return {
    schemaVersion: "openclaw.run.v1",
    runId: store.runId || null,
    traceId: store.traceId || null,
    sessionKey: store.sessionKey || null,
    scenarioId: store.securityScenario?.id || null,
    createdAt: store.createdAt,
    completedAt: store.completedAt || null,
    status: store.status || "running",
    eventCount: store.writer.eventsWritten || 0,
    artifactCount: store.artifactCount || 0,
    hasRuntimeStatus: true,
    hasTaskInput: true,
    paths: {
      events: "behavior-events.jsonl",
      runtimeStatus: "runtime_status.json",
      taskInput: "task_input.json",
      artifacts: "artifacts",
      codetracerBundle: fs.existsSync(diagnosisPaths.bundleDir) ? "diagnosis/codetracer/bundle" : null,
      codetracerAnalysis: fs.existsSync(diagnosisPaths.analysisDir) ? "diagnosis/codetracer/analysis" : null,
      securityReasoning: fs.existsSync(securityPaths.decisionPath) ? "security-reasoning/defense_decision.json" : null,
    },
    diagnosis: {
      codetracer: {
        bundleReady: fs.existsSync(diagnosisPaths.bundleDir),
        analysisReady: Boolean(diagnosisRun?.analysisExists),
        analysisOk: diagnosisRun?.ok ?? null,
        lastRunAt: diagnosisRun?.completedAt ?? null,
        status: diagnosisRun?.status ?? null,
      },
    },
    securityReasoning: securityDecision
      ? {
          ready: true,
          decision: securityDecision.decision || null,
          riskLevel: securityDecision.riskLevel || null,
          riskScore: securityDecision.riskScore ?? securityDecision.score ?? null,
          hardBlockTriggered: securityDecision.hardBlockTriggered ?? null,
          lastStage: securityDecision.lastStage || null,
          decisionPath: "security-reasoning/defense_decision.json",
          statePath: fs.existsSync(securityPaths.statePath) ? "security-reasoning/security_state.json" : null,
          evidenceSummaryPath: fs.existsSync(securityPaths.evidenceSummaryPath) ? "security-reasoning/evidence_summary.json" : null,
        }
      : null,
  };
}

function writeRunsIndexFile(state) {
  const runs = [];
  if (fs.existsSync(state.runsDirectory)) {
    for (const entry of fs.readdirSync(state.runsDirectory, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      const manifestPath = path.resolve(state.runsDirectory, entry.name, "manifest.json");
      if (!fs.existsSync(manifestPath)) {
        continue;
      }
      const manifest = readJsonFile(manifestPath);
      if (!manifest || typeof manifest !== "object") {
        continue;
      }
      runs.push({
        runId: manifest.runId || null,
        traceId: manifest.traceId || null,
        sessionKey: manifest.sessionKey || null,
        scenarioId: manifest.scenarioId || null,
        showcase: manifest.showcase === true,
        showcaseReason: manifest.showcaseReason || null,
        startedAt: manifest.startedAt || null,
        createdAt: manifest.createdAt || null,
        completedAt: manifest.completedAt || null,
        status: manifest.status || "unknown",
        analysisReady: Boolean(manifest?.diagnosis?.codetracer?.analysisReady),
        analysisOk: manifest?.diagnosis?.codetracer?.analysisOk ?? null,
        eventCount: manifest.eventCount || 0,
        artifactCount: manifest.artifactCount || 0,
        dirName: entry.name,
        runPath: path.resolve(state.runsDirectory, entry.name).replaceAll("\\", "/"),
        manifestPath: manifestPath.replaceAll("\\", "/"),
        eventsPath: `/live/runs/${entry.name}/behavior-events.jsonl`,
        securityReasoning: manifest.securityReasoning || null,
      });
    }
  }
  runs.sort((left, right) => {
    const activeStatuses = new Set(["running", "completed", "timeout_with_trace", "security_intervened"]);
    const leftKey = `${left.showcase ? 1 : 0}|${activeStatuses.has(left.status) ? 1 : 0}|${left.startedAt || left.createdAt || left.completedAt || ""}|${left.createdAt || ""}|${left.runId || left.traceId || left.dirName}`;
    const rightKey = `${right.showcase ? 1 : 0}|${activeStatuses.has(right.status) ? 1 : 0}|${right.startedAt || right.createdAt || right.completedAt || ""}|${right.createdAt || ""}|${right.runId || right.traceId || right.dirName}`;
    return rightKey.localeCompare(leftKey);
  });
  const payload = {
    schemaVersion: "openclaw.runs.index.v1",
    generatedAt: nowIso(),
    runsRoot: state.runsDirectory.replaceAll("\\", "/"),
    runCount: runs.length,
    latestRun: runs[0] || null,
    runs,
  };
  fs.writeFileSync(path.resolve(state.runsDirectory, "index.json"), `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function writeRunMetadata(state, store) {
  fs.mkdirSync(store.runDir, { recursive: true });
  fs.writeFileSync(path.resolve(store.runDir, "task_input.json"), `${JSON.stringify(buildTaskInput(store), null, 2)}\n`, "utf8");
  fs.writeFileSync(
    path.resolve(store.runDir, "runtime_status.json"),
    `${JSON.stringify(buildRunRuntimeStatus(state, store), null, 2)}\n`,
    "utf8",
  );
  fs.writeFileSync(path.resolve(store.runDir, "manifest.json"), `${JSON.stringify(buildRunManifest(state, store), null, 2)}\n`, "utf8");
  writeRunsIndexFile(state);
}

function indexRunStore(state, store) {
  if (store.runId) {
    state.runStoreByRunId.set(store.runId, store.storeId);
  }
  if (store.traceId) {
    state.runStoreByTraceId.set(store.traceId, store.storeId);
  }
  if (store.sessionKey) {
    state.runStoreBySessionKey.set(store.sessionKey, store.storeId);
  }
}

function resolveRunStore(state, details = {}) {
  const storeId =
    (details.runId && state.runStoreByRunId.get(details.runId)) ||
    (details.traceId && state.runStoreByTraceId.get(details.traceId)) ||
    (details.sessionKey && state.runStoreBySessionKey.get(details.sessionKey)) ||
    null;
  return storeId ? state.runStores.get(storeId) || null : null;
}

function moveRunDirectory(store, nextDirName) {
  if (store.dirName === nextDirName) {
    return;
  }
  const nextRunDir = path.resolve(path.dirname(store.runDir), nextDirName);
  if (fs.existsSync(store.runDir) && !fs.existsSync(nextRunDir)) {
    fs.renameSync(store.runDir, nextRunDir);
  } else {
    fs.mkdirSync(nextRunDir, { recursive: true });
  }
  store.dirName = nextDirName;
  store.runDir = nextRunDir;
  store.writer.outputFile = path.resolve(nextRunDir, "behavior-events.jsonl");
}

function ensureRunStore(state, details = {}) {
  let store = resolveRunStore(state, details);
  if (!store) {
    const dirName = buildRunDirName(details);
    const runDir = path.resolve(state.runsDirectory, dirName);
    fs.mkdirSync(runDir, { recursive: true });
    store = {
      storeId: createId("run"),
      dirName,
      runDir,
      writer: createWriterState(path.resolve(runDir, "behavior-events.jsonl")),
      runId: details.runId || null,
      traceId: details.traceId || null,
      sessionKey: details.sessionKey || null,
      createdAt: nowIso(),
      completedAt: null,
      status: "running",
      requestMessage: null,
      turnPrompt: null,
      securityScenario: null,
      policyObservations: new Map(),
      artifactCount: 0,
      diagnosisTriggered: false,
    };
    state.runStores.set(store.storeId, store);
  }
  store.runId = store.runId || details.runId || null;
  store.traceId = store.traceId || details.traceId || null;
  store.sessionKey = store.sessionKey || details.sessionKey || null;
  if (store.runId) {
    moveRunDirectory(store, buildRunDirName({ runId: store.runId }));
  }
  indexRunStore(state, store);
  writeRunMetadata(state, store);
  return store;
}

function normalizePolicyObservation(payload, status = null) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  const normalized = {};
  const effectiveStatus = status || payload.status || payload.outcome || null;
  if (effectiveStatus) {
    normalized.status = effectiveStatus;
  }
  for (const key of [
    "ruleId",
    "code",
    "severity",
    "category",
    "reason",
    "description",
    "decision",
    "outcome",
    "matches",
    "linkedToolCallId",
    "linkedObservationSpanId",
    "observedExecution",
    "pathSecurity",
    "mode",
    "effectiveMode",
  ]) {
    if (payload[key] != null) {
      normalized[key] = payload[key];
    }
  }
  return Object.keys(normalized).length ? normalized : null;
}

function extractPolicyObservation(...sources) {
  for (const source of sources) {
    if (!source || typeof source !== "object") {
      continue;
    }
    if (source.policyObservation && typeof source.policyObservation === "object") {
      return normalizePolicyObservation(source.policyObservation, source.status || null);
    }
    if (source.policy && typeof source.policy === "object") {
      return normalizePolicyObservation(source.policy, source.status || null);
    }
    if (source.evidence && typeof source.evidence === "object" && source.evidence.policy) {
      return normalizePolicyObservation(source.evidence.policy, source.status || null);
    }
  }
  return null;
}

function extractSecurityScenario(...sources) {
  for (const source of sources) {
    if (!source || typeof source !== "object") {
      continue;
    }
    const candidate =
      source.securityScenario ||
      (source.evidence && typeof source.evidence === "object" ? source.evidence.securityScenario : null);
    if (candidate && typeof candidate === "object") {
      return candidate;
    }
  }
  return null;
}

function updateRunStoreFromPayload(state, store, payload) {
  store.lastEventTs = payload.ts;
  const preview = payload.preview && typeof payload.preview === "object" ? payload.preview : {};
  if (payload.kind === "request" && payload.status === "started" && typeof preview.message === "string" && preview.message.trim()) {
    store.requestMessage = preview.message.trim();
  }
  if (payload.kind === "turn" && payload.status === "started" && typeof preview.prompt === "string" && preview.prompt.trim()) {
    store.turnPrompt = preview.prompt.trim();
  }
  const securityScenario = extractSecurityScenario(payload);
  if (securityScenario) {
    store.securityScenario = securityScenario;
  }
  const policyObservation = extractPolicyObservation(payload.evidence || null, payload);
  if (policyObservation) {
    store.policyObservations.set(JSON.stringify(policyObservation), policyObservation);
  }
  if (payload.kind === "request" && (payload.status === "ok" || payload.status === "error")) {
    store.completedAt = payload.ts || nowIso();
    store.status = payload.status === "error" ? "failed" : "completed";
  }
  writeRunMetadata(state, store);
}

function appendRunEvent(state, row) {
  const store = ensureRunStore(state, {
    runId: row.runId,
    traceId: row.traceId,
    sessionKey: row.sessionKey,
  });
  const payload = appendCanonicalEvent(store.writer, row);
  state.eventsWritten = (state.eventsWritten || 0) + 1;
  state.lastEventTs = payload.ts;
  state.lastWriteOk = store.writer.lastWriteOk;
  state.lastWriteError = store.writer.lastWriteError;
  updateRunStoreFromPayload(state, store, payload);
  return { payload, store };
}

function emitSecurityEvent(state, details = {}, parent = {}) {
  const decision = details.decision || {};
  const securityEvent = details.securityEvent || {};
  const context = ambientContext(state, parent);
  const name = securityEvent.eventType || details.eventType || `security.decision.${decision.decision || "allow"}`;
  const status = decision.decision || securityEvent.decision || "allow";
  appendRunEvent(state, {
    traceId: context.traceId,
    spanId: createId("sec"),
    parentSpanId: context.parentSpanId,
    kind: "security",
    name,
    status,
    sessionKey: context.sessionKey,
    runId: context.runId,
    taskId: context.taskId,
    toolCallId: context.toolCallId,
    llmCallId: context.llmCallId,
    target: cleanObject({
      stage: securityEvent.stage || details.stage || null,
      decision: decision.decision || securityEvent.decision || null,
      riskLevel: decision.riskLevel || securityEvent.riskLevel || null,
      riskScore: decision.riskScore ?? securityEvent.riskScore ?? null,
    }),
    preview: cleanObject({
      reason:
        (Array.isArray(decision.reasons) && decision.reasons[0]) ||
        securityEvent.reason ||
        details.reason ||
        null,
      suggestedUserMessage: decision.suggestedUserMessage || null,
    }),
    evidence: cleanObject({
      eventType: name,
      stage: securityEvent.stage || details.stage || null,
      decision: decision.decision || securityEvent.decision || null,
      riskLevel: decision.riskLevel || securityEvent.riskLevel || null,
      riskScore: decision.riskScore ?? securityEvent.riskScore ?? null,
      reason:
        (Array.isArray(decision.reasons) && decision.reasons[0]) ||
        securityEvent.reason ||
        details.reason ||
        null,
      securityContextSnapshot: securityEvent.securityContextSnapshot || details.snapshot || null,
      bridge: cleanObject({
        operation: details.operation || null,
        paths: details.paths || null,
      }),
    }),
  });
}

function callSecurityBridge(state, store, payload) {
  if (!state.config.securityEnabled || state.config.securityMode === "off") {
    return null;
  }
  const bridgePayload = {
    ...payload,
    runDir: store.runDir,
    runId: store.runId,
    policyPath: state.config.policyPath,
    securityMode: state.config.securityMode,
    llmJudge: state.config.llmJudge,
  };
  const completed = spawnSync(state.config.securityPython, [state.config.securityBridgeScript], {
    cwd: process.cwd(),
    input: JSON.stringify(bridgePayload),
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 8,
  });
  if (completed.error || completed.status !== 0) {
    state.securityBridgeFailures += 1;
    state.lastSecurityError = completed.error?.message || completed.stderr || `security bridge exited ${completed.status}`;
    state.logger?.warn?.(`[behavior] security bridge failed: ${state.lastSecurityError}`);
    return null;
  }
  try {
    const result = JSON.parse(completed.stdout || "{}");
    if (!result.ok) {
      state.securityBridgeFailures += 1;
      state.lastSecurityError = result.error || "security bridge returned ok=false";
      return null;
    }
    state.lastSecurityDecision = result.decision?.decision || null;
    state.lastSecurityError = null;
    emitSecurityEvent(state, result, payload.parent || {});
    return result;
  } catch (error) {
    state.securityBridgeFailures += 1;
    state.lastSecurityError = error?.message || String(error);
    state.logger?.warn?.(`[behavior] security bridge JSON parse failed: ${state.lastSecurityError}`);
    return null;
  }
}

function securityBlockResult(result) {
  const decision = result?.decision || {};
  return {
    ok: false,
    blocked: true,
    block: true,
    reason: decision.reasons?.[0] || "security guard blocked this action",
    decision: decision.decision || "block",
    riskLevel: decision.riskLevel || "critical",
    suggestedUserMessage: decision.suggestedUserMessage || "该动作被安全机制阻断。",
    security: decision,
  };
}

function redactStructuredValue(value, state, seen = new WeakSet()) {
  if (value == null) {
    return value;
  }
  if (typeof value === "string") {
    return redactText(value, state);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactStructuredValue(item, state, seen));
  }
  if (typeof value === "object") {
    if (seen.has(value)) {
      return "[Circular]";
    }
    seen.add(value);
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      output[key] = redactStructuredValue(item, state, seen);
    }
    seen.delete(value);
    return output;
  }
  return String(value);
}

function buildToolArtifactPayload(tool, status, kind, payload, state) {
  return {
    schemaVersion: "openclaw.tool-sidecar.v1",
    generatedAt: nowIso(),
    kind,
    status,
    traceId: tool.traceId,
    spanId: tool.spanId,
    parentSpanId: tool.parentSpanId ?? null,
    sessionKey: tool.sessionKey ?? null,
    runId: tool.runId ?? null,
    toolCallId: tool.toolCallId ?? null,
    toolName: tool.toolName || tool.target?.toolName || tool.name?.replace(/^tool\./, "") || null,
    payload: redactStructuredValue(payload, state),
  };
}

function writeToolArtifact(state, tool, status, kind, payload) {
  const store = ensureRunStore(state, {
    runId: tool.runId,
    traceId: tool.traceId,
    sessionKey: tool.sessionKey,
  });
  const baseName = kind === "output" ? "output.json" : "input.json";
  const relativePath = path.join("artifacts", safePathSegment(tool.toolCallId || tool.spanId, "tool"), baseName);
  const targetPath = path.resolve(store.runDir, relativePath);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  const sidecar = buildToolArtifactPayload(tool, status, kind, payload, state);
  fs.writeFileSync(targetPath, `${JSON.stringify(sidecar, null, 2)}\n`, "utf8");
  store.artifactCount += 1;
  state.artifactsWritten += 1;
  writeRunMetadata(state, store);
  return { relativePath: relativePath.replaceAll("\\", "/"), payload: sidecar };
}

function scheduleDiagnosis(state, details = {}) {
  if (!state.config.autoDiagnosisEnabled) {
    return;
  }
  const store = resolveRunStore(state, details);
  if (!store || store.diagnosisTriggered || !store.completedAt) {
    return;
  }
  store.diagnosisTriggered = true;
  state.diagnosisInFlight += 1;
  state.diagnosesTriggered += 1;
  state.lastDiagnosisError = null;
  const child = spawn(state.config.diagnosisPython, [state.config.diagnosisScript, "--run-dir", store.runDir], {
    cwd: process.cwd(),
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += String(chunk || "");
  });
  child.on("error", (error) => {
    state.diagnosisInFlight = Math.max(state.diagnosisInFlight - 1, 0);
    state.lastDiagnosisError = String(error?.message || error || "diagnosis_spawn_failed");
    store.diagnosisTriggered = false;
    writeRunMetadata(state, store);
  });
  child.on("close", (code) => {
    state.diagnosisInFlight = Math.max(state.diagnosisInFlight - 1, 0);
    if (code !== 0) {
      state.lastDiagnosisError = (stderr || `diagnosis exit code ${code}`).trim();
    }
    writeRunMetadata(state, store);
  });
}

function observeHookEvent(state, hookName) {
  state.hookEventsObserved += 1;
  state.lastHookEventTs = nowIso();
  if (!state.firstHookEventTs) {
    state.firstHookEventTs = state.lastHookEventTs;
    state.logger?.info?.(`[behavior] first hook event captured via ${hookName}`);
  }
}

function registerHook(api, state, hookName, handler, options) {
  state.hookNames.add(hookName);
  api.on(
    hookName,
    (...args) => {
      observeHookEvent(state, hookName);
      return handler(...args);
    },
    options,
  );
}

function buildRuntimeStatus(state) {
  return {
    ok: true,
    method: "behavior-mediator.status",
    active: state.active,
    runsDirectory: state.runsDirectory,
    artifactsEnabled: state.config.artifactsEnabled,
    autoDiagnosisEnabled: state.config.autoDiagnosisEnabled,
    capturePreviewChars: state.config.capturePreviewChars,
    captureNetwork: state.config.captureNetwork,
    traceEval: state.config.traceEval,
    securityEnabled: state.config.securityEnabled,
    securityMode: state.config.securityMode,
    policyPath: state.config.policyPath,
    llmJudge: state.config.llmJudge,
    hooksRegistered: state.hookNames.size,
    hookNames: [...state.hookNames],
    hookEventsObserved: state.hookEventsObserved,
    firstHookEventTs: state.firstHookEventTs,
    lastHookEventTs: state.lastHookEventTs,
    eventsWritten: state.eventsWritten,
    lastEventTs: state.lastEventTs,
    lastWriteOk: state.lastWriteOk,
    lastWriteError: state.lastWriteError,
    artifactsWritten: state.artifactsWritten,
    diagnosesTriggered: state.diagnosesTriggered,
    diagnosisInFlight: state.diagnosisInFlight,
    lastDiagnosisError: state.lastDiagnosisError,
    securityBridgeFailures: state.securityBridgeFailures,
    lastSecurityDecision: state.lastSecurityDecision,
    lastSecurityError: state.lastSecurityError,
    runStoreCount: state.runStores.size,
    openRequests: state.requestContexts.size,
    openTurns: state.turnContexts.size,
    openTools: state.toolContexts.size,
    openLlms: state.llmContexts.size,
    openTasks: state.taskContexts.size,
  };
}

function normalizeProvidedScopes(params) {
  const raw =
    params?._rpcDiag && typeof params._rpcDiag === "object" ? params._rpcDiag.providedScopes : params?.providedScopes;
  if (!Array.isArray(raw)) {
    return null;
  }
  const scopes = raw
    .map((item) => String(item || "").trim())
    .filter(Boolean);
  return scopes.length ? [...new Set(scopes)] : null;
}

function computeScopeMatch(requiredScopes, providedScopes) {
  if (!Array.isArray(providedScopes) || providedScopes.length === 0) {
    return null;
  }
  if (providedScopes.includes("operator.admin")) {
    return true;
  }
  return requiredScopes.every((scope) => {
    if (scope === "operator.read") {
      return providedScopes.includes("operator.read") || providedScopes.includes("operator.write");
    }
    return providedScopes.includes(scope);
  });
}

function runKey(runId, sessionKey) {
  return runId || `session:${sessionKey || "unknown"}`;
}

function numeric(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function parseMaybeJson(value) {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed || !["{", "["].includes(trimmed[0])) {
    return null;
  }
  try {
    return JSON.parse(trimmed);
  } catch (error) {
    return null;
  }
}

function inferActionFromTool(toolName, params = {}, event = {}) {
  const normalized = String(toolName || "").toLowerCase();
  const command = params.command || params.cmd || params.script || null;
  const pathValue = params.path || params.filePath || params.target || null;
  const url = params.url || params.href || params.targetUrl || params.target || null;
  const method = String(params.method || params.httpMethod || "GET").toUpperCase();
  if (["web_fetch", "fetch", "http_fetch", "http_get", "web.fetch"].includes(normalized) && String(url || "").match(/^https?:\/\//i)) {
    return {
      actionType: ["POST", "PUT", "PATCH", "DELETE"].includes(method) ? "network_request" : "open_external_link",
      sourceType: event.sourceType || event.source || "external_website",
      target: url || "",
      url: url || "",
      method,
      body: params.body || params.data || null,
      toolName,
    };
  }
  if (["exec", "bash", "shell_command"].includes(normalized)) {
    return {
      actionType: "execute_command",
      sourceType: event.sourceType || event.source || "unknown",
      target: command || "",
      command: command || "",
      toolName,
    };
  }
  if (["read"].includes(normalized)) {
    return {
      actionType: "read_local_file",
      sourceType: event.sourceType || event.source || "unknown",
      target: pathValue || "",
      path: pathValue || "",
    };
  }
  if (normalized.includes("upload")) {
    return {
      actionType: normalized.includes("photo") ? "upload_photo" : "upload_file",
      sourceType: event.sourceType || event.source || "unknown",
      target: pathValue || url || "",
      url: url || null,
    };
  }
  if (normalized.includes("navigate") || normalized.includes("open")) {
    return {
      actionType: "open_external_link",
      sourceType: event.sourceType || event.source || "unknown",
      target: url || "",
      url: url || "",
    };
  }
  if (normalized.includes("click")) {
    return {
      actionType: "click_unknown_button",
      sourceType: event.sourceType || event.source || "button",
      target: params.buttonText || params.text || params.label || url || "",
      url: url || null,
    };
  }
  return {
    actionType: "tool_call",
    sourceType: event.sourceType || event.source || "unknown",
    target: toolName || "unknown",
  };
}

function summarizeUserPrompt(messages, state) {
  if (!Array.isArray(messages)) {
    return null;
  }
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (!message || message.role !== "user") {
      continue;
    }
    if (typeof message.content === "string" && message.content.trim()) {
      return previewText(message.content, state);
    }
    const summary = summarizeContentParts(message.content, state);
    if (summary) {
      return summary;
    }
  }
  return null;
}

function extractUsageMetrics(value) {
  const usage = value && typeof value === "object" ? value : {};
  const promptDetails = usage.prompt_tokens_details && typeof usage.prompt_tokens_details === "object" ? usage.prompt_tokens_details : {};
  const inputTokens =
    numeric(usage.input) ??
    numeric(usage.inputTokens) ??
    numeric(usage.input_tokens) ??
    numeric(usage.prompt_tokens) ??
    0;
  const outputTokens =
    numeric(usage.output) ??
    numeric(usage.outputTokens) ??
    numeric(usage.output_tokens) ??
    numeric(usage.completion_tokens) ??
    0;
  const cacheReadTokens =
    numeric(usage.cacheRead) ??
    numeric(usage.cache_read) ??
    numeric(usage.cacheReadTokens) ??
    numeric(promptDetails.cached_tokens) ??
    0;
  const cacheWriteTokens =
    numeric(usage.cacheWrite) ??
    numeric(usage.cache_write) ??
    numeric(usage.cacheWriteTokens) ??
    0;
  const totalTokens =
    numeric(usage.total) ??
    numeric(usage.totalTokens) ??
    numeric(usage.total_tokens) ??
    numeric(usage.total_tokens) ??
    inputTokens + outputTokens + cacheReadTokens + cacheWriteTokens;

  return cleanObject({
    inputTokens,
    outputTokens,
    cacheReadTokens,
    cacheWriteTokens,
    totalTokens,
  });
}

function summarizeAgentOutcome(messages, state) {
  return summarizeAssistant(messages, state);
}

function isLikelyLlmRequest(url, method, headers, body) {
  const lowerUrl = String(url || "").toLowerCase();
  const lowerMethod = String(method || "GET").toUpperCase();
  if (lowerMethod === "POST" && /(chat\/completions|\/responses\b|\/messages\b|\/completions\b|anthropic|openai|bigmodel|claude|gemini)/.test(lowerUrl)) {
    return true;
  }
  const lowerHeaders = Object.keys(headers || {}).join(" ").toLowerCase();
  const bodyPreview = typeof body === "string" ? body.slice(0, 2000).toLowerCase() : "";
  return (
    lowerHeaders.includes("authorization") &&
    (bodyPreview.includes("\"messages\"") || bodyPreview.includes("\"model\"") || bodyPreview.includes("\"stream\""))
  );
}

function responseBodyPreview(response, state) {
  const contentType = String(response?.headers?.get?.("content-type") || "").toLowerCase();
  if (!/(json|text|javascript|xml)/.test(contentType)) {
    return Promise.resolve(null);
  }
  try {
    return response
      .clone()
      .text()
      .then((text) => previewText(text, state))
      .catch(() => null);
  } catch (error) {
    return Promise.resolve(null);
  }
}

function ambientContext(state, explicit = {}) {
  const store = als.getStore() || {};
  const sessionKey = explicit.sessionKey || store.sessionKey || null;
  const runId = explicit.runId || store.runId || null;
  const taskId = explicit.taskId || store.taskId || null;
  const toolCallId = explicit.toolCallId || store.toolCallId || null;
  const llmCallId = explicit.llmCallId || store.llmCallId || null;
  const turn = explicit.turn || resolveTurnContext(state, sessionKey, runId);
  const request = explicit.request || resolveRequestContext(state, sessionKey, runId);
  const task = explicit.task || resolveTaskContext(state, sessionKey, runId);
  return {
    sessionKey,
    runId,
    taskId,
    toolCallId,
    llmCallId,
    traceId: explicit.traceId || store.traceId || turn?.traceId || request?.traceId || task?.traceId || createId("trace"),
    parentSpanId:
      explicit.parentSpanId ??
      store.spanId ??
      explicit.spanId ??
      turn?.spanId ??
      request?.spanId ??
      task?.spanId ??
      null,
  };
}

function createSpanContext(state, details) {
  return {
    kind: details.kind,
    name: details.name,
    traceId: details.traceId || createId("trace"),
    spanId: details.spanId || createId("spn"),
    parentSpanId: details.parentSpanId ?? null,
    sessionKey: details.sessionKey ?? null,
    runId: details.runId ?? null,
    taskId: details.taskId ?? null,
    toolCallId: details.toolCallId ?? null,
    llmCallId: details.llmCallId ?? null,
    target: details.target || null,
    startedAt: Date.now(),
    startedTs: details.ts || nowIso(),
  };
}

function emitSpanStarted(state, span, details = {}) {
  appendRunEvent(state, {
    ts: span.startedTs,
    traceId: span.traceId,
    spanId: span.spanId,
    parentSpanId: span.parentSpanId,
    kind: span.kind,
    name: span.name,
    status: "started",
    sessionKey: span.sessionKey,
    runId: span.runId,
    taskId: span.taskId,
    toolCallId: span.toolCallId,
    llmCallId: span.llmCallId,
    target: details.target || span.target,
    metrics: details.metrics,
    preview: details.preview,
    evidence: details.evidence,
  });
}

function emitSpanFinished(state, span, details = {}) {
  const durationMs = numeric(details.durationMs) ?? Math.max(0, Date.now() - span.startedAt);
  appendRunEvent(state, {
    ts: details.ts || nowIso(),
    traceId: span.traceId,
    spanId: span.spanId,
    parentSpanId: span.parentSpanId,
    kind: span.kind,
    name: span.name,
    status: details.status || "ok",
    sessionKey: span.sessionKey,
    runId: span.runId,
    taskId: span.taskId,
    toolCallId: span.toolCallId,
    llmCallId: span.llmCallId,
    target: details.target || span.target,
    metrics: {
      durationMs,
      ...(details.metrics || {}),
    },
    preview: details.preview,
    evidence: details.evidence,
  });
}

function resolveRequestContext(state, sessionKey, runId) {
  return (runId && state.requestByRunId.get(runId)) || (sessionKey && state.requestContexts.get(sessionKey)) || null;
}

function resolveTurnContext(state, sessionKey, runId) {
  return state.turnContexts.get(runKey(runId, sessionKey)) || (sessionKey && state.turnBySession.get(sessionKey)) || null;
}

function resolveTaskContext(state, sessionKey, runId) {
  return (runId && state.taskByRunId.get(runId)) || (sessionKey && state.taskBySession.get(sessionKey)) || null;
}

function ensureTaskContext(state, details = {}) {
  const childSessionKey = details.childSessionKey || details.sessionKey || null;
  const childRunId = details.childRunId || details.runId || null;
  const existing = resolveTaskContext(state, childSessionKey, childRunId);
  if (existing) {
    existing.runId = existing.runId || childRunId || null;
    existing.taskId = existing.taskId || details.taskId || null;
    existing.target = {
      ...(existing.target || {}),
      ...(details.target || {}),
    };
    if (childSessionKey) {
      state.taskBySession.set(childSessionKey, existing);
    }
    if (childRunId) {
      state.taskByRunId.set(childRunId, existing);
    }
    return existing;
  }

  const parent = ambientContext(state, {
    sessionKey: details.parentSessionKey,
    runId: details.parentRunId,
  });
  const task = createSpanContext(state, {
    kind: "task",
    name: "openclaw.subagent.run",
    traceId: parent.traceId,
    parentSpanId: parent.parentSpanId,
    sessionKey: childSessionKey,
    runId: childRunId,
    taskId: details.taskId || null,
    target: {
      parentSessionKey: details.parentSessionKey || null,
      childSessionKey,
      mode: details.mode || null,
      runtime: details.runtime || "subagent",
      agentId: details.agentId || null,
      toolCallId: details.toolCallId || null,
      ...(details.target || {}),
    },
  });

  emitSpanStarted(state, task, {
    preview: {
      task: previewText(details.taskText || details.task || null, state),
    },
    evidence: {
      hook: details.hook || "subagent_spawned",
      surface: "typed-hook",
    },
  });

  state.taskContexts.set(task.spanId, task);
  if (childSessionKey) {
    state.taskBySession.set(childSessionKey, task);
  }
  if (childRunId) {
    state.taskByRunId.set(childRunId, task);
  }
  return task;
}

function finishTaskContext(state, task, details = {}) {
  if (!task) {
    return;
  }
  emitSpanFinished(state, task, {
    status: details.status || "ok",
    durationMs: details.durationMs,
    metrics: details.metrics,
    preview: details.preview,
    evidence: {
      hook: details.hook || "agent_end",
      surface: "typed-hook",
      ...(details.evidence || {}),
    },
  });
  state.taskContexts.delete(task.spanId);
  if (task.sessionKey) {
    state.taskBySession.delete(task.sessionKey);
  }
  if (task.runId) {
    state.taskByRunId.delete(task.runId);
  }
}

function closeOpenRequest(state, sessionKey, details = {}) {
  const request = sessionKey && state.requestContexts.get(sessionKey);
  if (!request) {
    return null;
  }
  emitSpanFinished(state, request, details);
  state.requestContexts.delete(sessionKey);
  if (request.runId) {
    state.requestByRunId.delete(request.runId);
  }
  return request;
}

function openRequestContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  closeOpenRequest(state, sessionKey, {
    status: "error",
    preview: {
      error: "replaced by a newer request",
    },
    evidence: {
      hook: "message_received",
      reason: "replaced",
    },
  });

  const task = resolveTaskContext(state, sessionKey, null);
  const securityScenario = extractSecurityScenario(event, ctx);
  const policyObservation = extractPolicyObservation(event, ctx);
  const request = createSpanContext(state, {
    kind: "request",
    name: "openclaw.request",
    traceId: task?.traceId || createId("trace"),
    parentSpanId: task?.spanId ?? null,
    sessionKey,
    target: {
      channel: event.channel || null,
      from: event.from || event.senderId || null,
      sourceSessionKey: event.provenance?.sourceSessionKey || null,
    },
    ts: event.timestamp || event.ts || nowIso(),
  });

  emitSpanStarted(state, request, {
    preview: {
      message: previewText(event.text || event.message || event.content || null, state),
    },
    evidence: cleanObject({
      hook: "message_received",
      surface: "typed-hook",
      provenanceKind: event.provenance?.kind || null,
      policy: policyObservation,
      securityScenario,
    }),
  });

  state.requestContexts.set(sessionKey, request);
  return request;
}

function openTurnContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  const runId = event.runId || ctx.runId || null;
  const request = resolveRequestContext(state, sessionKey, runId) || openRequestContext(state, event, ctx);
  const currentTurn = resolveTurnContext(state, sessionKey, runId);
  const securityScenario = extractSecurityScenario(event, ctx);
  const policyObservation = extractPolicyObservation(event, ctx);
  if (currentTurn) {
    emitSpanFinished(state, currentTurn, {
      status: "error",
      preview: {
        error: "replaced by a newer turn",
      },
      evidence: {
        hook: "before_agent_start",
        reason: "replaced",
      },
    });
  }

  const turn = createSpanContext(state, {
    kind: "turn",
    name: "openclaw.agent.turn",
    traceId: request.traceId,
    parentSpanId: request.spanId,
    sessionKey,
    runId,
    target: {
      agentId: event.agentId || ctx.agentId || null,
      model: event.model || ctx.model || null,
      provider: event.provider || ctx.provider || null,
    },
  });

  request.runId = request.runId || runId || null;
  if (runId) {
    state.requestByRunId.set(runId, request);
  }

  emitSpanStarted(state, turn, {
    preview: {
      prompt: previewText(event.prompt || event.task || event.systemPrompt || null, state),
    },
    evidence: cleanObject({
      hook: "before_agent_start",
      surface: "typed-hook",
      policy: policyObservation,
      securityScenario,
    }),
  });

  state.turnContexts.set(runKey(runId, sessionKey), turn);
  state.turnBySession.set(sessionKey, turn);
  return turn;
}

function closeTurnContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  const runId = event.runId || ctx.runId || null;
  const turn = resolveTurnContext(state, sessionKey, runId);
  if (!turn) {
    return null;
  }

  const usage = extractUsageMetrics(event.usage || event.lastAssistant?.usage || null);
  const status = event.success === false || event.error ? "error" : "ok";
  emitSpanFinished(state, turn, {
    status,
    durationMs: event.durationMs,
    metrics: usage,
    preview: {
      assistant: summarizeAgentOutcome(event.messages || [event.lastAssistant].filter(Boolean), state),
      error: previewText(event.error || event.lastAssistant?.errorMessage || null, state),
    },
    evidence: {
      hook: "agent_end",
      surface: "typed-hook",
      policy: extractPolicyObservation(event, ctx),
      securityScenario: extractSecurityScenario(event, ctx),
    },
  });

  state.turnContexts.delete(runKey(runId, sessionKey));
  state.turnBySession.delete(sessionKey);
  return turn;
}

function closeRequestContext(state, sessionKey, details = {}) {
  return closeOpenRequest(state, sessionKey, details);
}

function openToolContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  const runId = event.runId || ctx.runId || null;
  const toolCallId = event.toolCallId || createId("tool");
  const toolName = event.toolName || event.name || "unknown";
  const toolParams = event.params || event.input || event.arguments || {};
  const turn = resolveTurnContext(state, sessionKey, runId) || openTurnContext(state, event, ctx);
  const policyObservation = extractPolicyObservation(event, ctx);
  const securityScenario = extractSecurityScenario(event, ctx);
  const tool = createSpanContext(state, {
    kind: "tool",
    name: `tool.${toolName}`,
    traceId: turn.traceId,
    parentSpanId: turn.spanId,
    sessionKey,
    runId,
    toolCallId,
    target: deriveToolTarget(toolName, toolParams),
  });
  const inputArtifact =
    state.config.artifactsEnabled === false ? null : writeToolArtifact(state, { ...tool, toolName }, "started", "input", toolParams);

  emitSpanStarted(state, tool, {
    preview: {
      params: previewText(toolParams || null, state),
    },
    evidence: cleanObject({
      hook: "before_tool_call",
      surface: "typed-hook",
      policy: policyObservation,
      securityScenario,
      artifacts: cleanObject({
        input: inputArtifact?.relativePath || null,
      }),
    }),
  });

  state.toolContexts.set(toolCallId, {
    ...tool,
    toolName,
    params: toolParams,
    policyObservation,
    securityScenario,
    inputArtifact,
  });
  return tool;
}

function openLlmContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  const runId = event.runId || ctx.runId || null;
  const llmCallId = event.llmCallId || createId("llm");
  const turn = resolveTurnContext(state, sessionKey, runId) || openTurnContext(state, event, ctx);
  const llm = createSpanContext(state, {
    kind: "llm",
    name: `llm.${event.provider || event.api || "call"}`,
    traceId: turn.traceId,
    parentSpanId: turn.spanId,
    sessionKey,
    runId,
    llmCallId,
    target: {
      provider: event.provider || null,
      model: event.model || null,
      api: event.api || null,
    },
  });

  emitSpanStarted(state, llm, {
    preview: {
      prompt: previewText(event.systemPrompt, state),
      user: summarizeUserPrompt(event.messages, state),
    },
    evidence: {
      hook: "llm_input",
      surface: "typed-hook",
    },
  });

  state.llmContexts.set(llmCallId, llm);
  return llm;
}

function finishLlmContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  const runId = event.runId || ctx.runId || null;
  const llmCallId = event.llmCallId || null;
  const llm =
    (llmCallId && state.llmContexts.get(llmCallId)) ||
    Array.from(state.llmContexts.values()).find((item) => item.sessionKey === sessionKey && item.runId === runId) ||
    null;
  if (!llm) {
    return null;
  }

  const lastAssistant = event.lastAssistant || null;
  const usage = extractUsageMetrics(event.usage || lastAssistant?.usage || null);
  const status = event.error || lastAssistant?.errorMessage ? "error" : "ok";
  emitSpanFinished(state, llm, {
    status,
    metrics: usage,
    preview: {
      response:
        (Array.isArray(event.assistantTexts) && event.assistantTexts.map((item) => previewText(item, state)).filter(Boolean).join("\n")) ||
        summarizeAssistant([lastAssistant].filter(Boolean), state),
      error: previewText(event.error || lastAssistant?.errorMessage || null, state),
    },
    evidence: {
      hook: "llm_output",
      surface: "typed-hook",
    },
  });

  state.llmContexts.delete(llm.llmCallId);
  return llm;
}

function parseSubagentResult(result, state) {
  const details = result?.details && typeof result.details === "object" ? result.details : {};
  if (details.childSessionKey || details.runId || details.taskId) {
    return details;
  }
  const text =
    summarizeContentParts(result?.content, state) ||
    summarizeContentParts(result?.result?.content, state) ||
    previewText(result, state);
  return parseMaybeJson(text) || {};
}

function finishToolContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  const runId = event.runId || ctx.runId || null;
  const toolCallId = event.toolCallId || null;
  const tool = toolCallId && state.toolContexts.get(toolCallId);
  if (!tool) {
    return null;
  }

  const result = event.result || null;
  const isError = event.error != null || result?.isError === true;
  const toolResultPreview = summarizeToolResult(result, state, tool);
  const outputArtifact =
    state.config.artifactsEnabled === false ? null : writeToolArtifact(state, tool, isError ? "error" : "ok", "output", {
      result: event.result || null,
      error: event.error || null,
    });
  emitSpanFinished(state, tool, {
    status: isError ? "error" : "ok",
    durationMs: event.durationMs,
    metrics: cleanObject({
      exitCode: numeric(result?.details?.exitCode),
      resultChars: toolResultPreview?.length || null,
    }),
    preview: {
      result: toolResultPreview,
      error: previewText(event.error || result?.error || null, state),
    },
    evidence: cleanObject({
      hook: "after_tool_call",
      surface: "typed-hook",
      policy: tool.policyObservation || extractPolicyObservation(event, ctx),
      securityScenario: tool.securityScenario || extractSecurityScenario(event, ctx),
      artifacts: cleanObject({
        input: tool.inputArtifact?.relativePath || null,
        output: outputArtifact?.relativePath || null,
      }),
    }),
  });

  if (tool.toolName === "sessions_spawn" && !isError) {
    const subagent = parseSubagentResult(result, state);
    const childSessionKey = subagent.childSessionKey || subagent.targetSessionKey || null;
    const childRunId = subagent.runId || null;
    if (childSessionKey || childRunId) {
      ensureTaskContext(state, {
        parentSessionKey: sessionKey,
        parentRunId: runId,
        childSessionKey,
        childRunId,
        taskId: subagent.taskId || null,
        toolCallId,
        mode: subagent.mode || null,
        runtime: subagent.runtime || "subagent",
        agentId: subagent.agentId || ctx.agentId || null,
        taskText: tool.params?.task || null,
        hook: "after_tool_call",
      });
    }
  }

  state.toolContexts.delete(tool.toolCallId);
  return tool;
}

function patchFetch(state) {
  if (!state.config.captureNetwork || typeof globalThis.fetch !== "function" || state.originalFetch) {
    return;
  }
  state.originalFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async function tracedFetch(input, init) {
    const request = input && typeof input === "object" ? input : null;
    const url = String(init?.url || request?.url || input || "");
    const method = String(init?.method || request?.method || "GET").toUpperCase();
    const requestHeaders = sanitizeHeaders(init?.headers || request?.headers, state);
    const bodyPreview = previewText(init?.body ?? null, state);
    if (isLikelyLlmRequest(url, method, requestHeaders, init?.body)) {
      return state.originalFetch(input, init);
    }

    const parent = ambientContext(state);
    const store = ensureRunStore(state, {
      runId: parent.runId,
      traceId: parent.traceId,
      sessionKey: parent.sessionKey,
    });
    const network = createSpanContext(state, {
      kind: "network",
      name: `network.${method.toLowerCase()}`,
      traceId: parent.traceId,
      parentSpanId: parent.parentSpanId,
      sessionKey: parent.sessionKey,
      runId: parent.runId,
      taskId: parent.taskId,
      toolCallId: parent.toolCallId,
      llmCallId: parent.llmCallId,
      target: {
        url,
        method,
      },
    });

    emitSpanStarted(state, network, {
      preview: {
        requestBody: bodyPreview,
      },
      evidence: {
        surface: "fetch",
        headers: requestHeaders,
      },
    });

    const lowerUrl = url.toLowerCase();
    const lowerBody = String(bodyPreview || "").toLowerCase();
    const networkAction =
      lowerUrl.includes("upload") || lowerBody.includes("upload") || lowerBody.includes("photo")
        ? lowerBody.includes("photo") || lowerBody.includes("local_user_photo")
          ? "upload_photo"
          : "upload_file"
        : method === "POST" || method === "PUT"
          ? "network_request"
          : "open_external_link";
    const securityResult = callSecurityBridge(state, store, {
      operation: "inspect_action",
      action: {
        actionType: networkAction,
        sourceType: "external_website",
        target: url,
        url,
        method,
        body: bodyPreview,
      },
      parent: {
        traceId: network.traceId,
        parentSpanId: network.spanId,
        sessionKey: parent.sessionKey,
        runId: parent.runId,
        toolCallId: parent.toolCallId,
      },
    });
    if (securityResult?.shouldBlock && state.config.securityMode === "enforce") {
      emitSpanFinished(state, network, {
        status: "blocked",
        preview: {
          error: securityBlockResult(securityResult).reason,
        },
        evidence: {
          surface: "fetch",
          blockedBy: "behavior-mediator.security",
          security: securityResult.decision || null,
        },
      });
      throw new Error(securityBlockResult(securityResult).reason);
    }

    try {
      const response = await state.originalFetch(input, init);
      const responsePreview = await responseBodyPreview(response, state);
      emitSpanFinished(state, network, {
        status: response.ok ? "ok" : "error",
        metrics: {
          statusCode: response.status,
        },
        target: {
          ...network.target,
          status: response.status,
        },
        preview: {
          responseBody: responsePreview,
        },
        evidence: {
          surface: "fetch",
          responseHeaders: sanitizeHeaders(response.headers, state),
        },
      });
      return response;
    } catch (error) {
      emitSpanFinished(state, network, {
        status: "error",
        preview: {
          error: previewText(error?.message || String(error), state),
        },
        evidence: {
          surface: "fetch",
        },
      });
      throw error;
    }
  };
}

function traceCodeActivity(state, kind, code, execute) {
  const parent = ambientContext(state);
  const span = createSpanContext(state, {
    kind: "code",
    name: `code.${kind}`,
    traceId: parent.traceId,
    parentSpanId: parent.parentSpanId,
    sessionKey: parent.sessionKey,
    runId: parent.runId,
    taskId: parent.taskId,
    toolCallId: parent.toolCallId,
    llmCallId: parent.llmCallId,
    target: {
      kind,
    },
  });
  emitSpanStarted(state, span, {
    preview: {
      code: previewText(code, state),
    },
    evidence: {
      surface: kind,
    },
  });
  try {
    const result = execute();
    emitSpanFinished(state, span, {
      status: "ok",
    });
    return result;
  } catch (error) {
    emitSpanFinished(state, span, {
      status: "error",
      preview: {
        error: previewText(error?.message || String(error), state),
      },
    });
    throw error;
  }
}

function patchEval(state) {
  if (!state.config.traceEval) {
    return;
  }

  if (!state.originalEval && typeof globalThis.eval === "function") {
    state.originalEval = globalThis.eval;
    globalThis.eval = function tracedEval(code) {
      return traceCodeActivity(state, "eval", code, () => state.originalEval(code));
    };
  }

  if (!state.originalFunction && typeof globalThis.Function === "function") {
    state.originalFunction = globalThis.Function;
    const TracedFunction = function (...args) {
      const source = args.join(", ");
      return traceCodeActivity(state, "function", source, () => Reflect.apply(state.originalFunction, this, args));
    };
    TracedFunction.prototype = state.originalFunction.prototype;
    Object.defineProperty(TracedFunction, "name", { value: "Function" });
    globalThis.Function = TracedFunction;
  }
}

function restorePatchedGlobals(state) {
  if (state.originalFetch) {
    globalThis.fetch = state.originalFetch;
    state.originalFetch = null;
  }
  if (state.originalEval) {
    globalThis.eval = state.originalEval;
    state.originalEval = null;
  }
  if (state.originalFunction) {
    globalThis.Function = state.originalFunction;
    state.originalFunction = null;
  }
}

function cleanupStaleContexts(state) {
  const maxAgeMs = 15 * 60 * 1000;
  const now = Date.now();

  for (const [sessionKey, request] of state.requestContexts.entries()) {
    if (now - request.startedAt <= maxAgeMs) {
      continue;
    }
    closeRequestContext(state, sessionKey, {
      status: "error",
      preview: {
        error: "timed out waiting for request completion",
      },
      evidence: {
        hook: "cleanup",
      },
    });
  }

  for (const [key, turn] of state.turnContexts.entries()) {
    if (now - turn.startedAt <= maxAgeMs) {
      continue;
    }
    emitSpanFinished(state, turn, {
      status: "error",
      preview: {
        error: "timed out waiting for turn completion",
      },
      evidence: {
        hook: "cleanup",
      },
    });
    state.turnContexts.delete(key);
    if (turn.sessionKey) {
      state.turnBySession.delete(turn.sessionKey);
    }
  }

  for (const [toolCallId, tool] of state.toolContexts.entries()) {
    if (now - tool.startedAt <= maxAgeMs) {
      continue;
    }
    emitSpanFinished(state, tool, {
      status: "error",
      preview: {
        error: "timed out waiting for tool completion",
      },
      evidence: {
        hook: "cleanup",
      },
    });
    state.toolContexts.delete(toolCallId);
  }

  for (const [llmCallId, llm] of state.llmContexts.entries()) {
    if (now - llm.startedAt <= maxAgeMs) {
      continue;
    }
    emitSpanFinished(state, llm, {
      status: "error",
      preview: {
        error: "timed out waiting for llm completion",
      },
      evidence: {
        hook: "cleanup",
      },
    });
    state.llmContexts.delete(llmCallId);
  }

  for (const task of state.taskContexts.values()) {
    if (now - task.startedAt <= maxAgeMs) {
      continue;
    }
    finishTaskContext(state, task, {
      status: "error",
      preview: {
        error: "timed out waiting for subagent completion",
      },
      hook: "cleanup",
    });
  }
}

function registerTypedHooks(api, state) {
  registerHook(api, state, "message_received", async (event, ctx) => {
    try {
      const request = openRequestContext(state, event, ctx);
      const store = ensureRunStore(state, {
        runId: request.runId,
        traceId: request.traceId,
        sessionKey: request.sessionKey,
      });
      callSecurityBridge(state, store, {
        operation: "inspect_user_input",
        message: event.text || event.message || event.content || "",
        parent: {
          traceId: request.traceId,
          parentSpanId: request.spanId,
          sessionKey: request.sessionKey,
          runId: request.runId,
        },
      });
      als.enterWith({
        traceId: request.traceId,
        spanId: request.spanId,
        sessionKey: request.sessionKey,
      });
    } catch (error) {
      state.logger?.warn?.(`[behavior] message_received failed: ${error?.message || error}`);
    }
  }, { priority: 100 });

  registerHook(api, state, "before_agent_start", (event, ctx) => {
    try {
      const turn = openTurnContext(state, event, ctx);
      const store = ensureRunStore(state, {
        runId: turn.runId,
        traceId: turn.traceId,
        sessionKey: turn.sessionKey,
      });
      callSecurityBridge(state, store, {
        operation: "inspect_plan",
        message: event.prompt || event.task || event.systemPrompt || "",
        plan: event.plan || event.steps || event.prompt || event.task || event.systemPrompt || "",
        parent: {
          traceId: turn.traceId,
          parentSpanId: turn.spanId,
          sessionKey: turn.sessionKey,
          runId: turn.runId,
        },
      });
      als.enterWith({
        traceId: turn.traceId,
        spanId: turn.spanId,
        sessionKey: turn.sessionKey,
        runId: turn.runId,
      });
    } catch (error) {
      state.logger?.warn?.(`[behavior] before_agent_start failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: 90 });

  registerHook(api, state, "before_tool_call", (event, ctx) => {
    try {
      const sessionKey = event.sessionKey || ctx?.sessionKey || "unknown";
      const runId = event.runId || ctx?.runId || null;
      const toolCallId = event.toolCallId || createId("tool");
      const toolName = event.toolName || event.name || "unknown";
      const toolParams = event.params || event.input || event.arguments || {};
      const turn = resolveTurnContext(state, sessionKey, runId) || openTurnContext(state, event, ctx);
      const store = ensureRunStore(state, {
        runId,
        traceId: turn.traceId,
        sessionKey,
      });
      const tool = openToolContext(state, { ...event, toolCallId }, ctx);
      const securityResult = callSecurityBridge(state, store, {
        operation: "inspect_action",
        action: inferActionFromTool(toolName, toolParams, event),
        parent: {
          traceId: tool.traceId,
          parentSpanId: tool.spanId,
          sessionKey,
          runId,
          toolCallId,
        },
      });
      if (securityResult?.shouldBlock && state.config.securityMode === "enforce") {
        emitSpanFinished(state, tool, {
          status: "blocked",
          preview: {
            error: securityBlockResult(securityResult).reason,
          },
          evidence: cleanObject({
            hook: "before_tool_call",
            surface: "typed-hook",
            blockedBy: "behavior-mediator.security",
            security: securityResult.decision || null,
            artifacts: cleanObject({
              input: tool.inputArtifact?.relativePath || null,
            }),
          }),
        });
        state.toolContexts.delete(tool.toolCallId);
        return securityBlockResult(securityResult);
      }
      als.enterWith({
        traceId: tool.traceId,
        spanId: tool.spanId,
        sessionKey: tool.sessionKey,
        runId: tool.runId,
        toolCallId: tool.toolCallId,
      });
    } catch (error) {
      state.logger?.warn?.(`[behavior] before_tool_call failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: 80 });

  registerHook(api, state, "after_tool_call", (event, ctx) => {
    try {
      finishToolContext(state, event, ctx);
      const turn = resolveTurnContext(state, event?.sessionKey || ctx?.sessionKey, event?.runId || ctx?.runId);
      if (turn) {
        als.enterWith({
          traceId: turn.traceId,
          spanId: turn.spanId,
          sessionKey: turn.sessionKey,
          runId: turn.runId,
        });
      }
    } catch (error) {
      state.logger?.warn?.(`[behavior] after_tool_call failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: -90 });

  registerHook(api, state, "llm_input", (event, ctx) => {
    try {
      const llm = openLlmContext(state, event, ctx);
      als.enterWith({
        traceId: llm.traceId,
        spanId: llm.spanId,
        sessionKey: llm.sessionKey,
        runId: llm.runId,
        llmCallId: llm.llmCallId,
      });
    } catch (error) {
      state.logger?.warn?.(`[behavior] llm_input failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: 70 });

  registerHook(api, state, "llm_output", (event, ctx) => {
    try {
      const llm = finishLlmContext(state, event, ctx);
      const sessionKey = event?.sessionKey || ctx?.sessionKey || "unknown";
      const runId = event?.runId || ctx?.runId || null;
      const parent = llm || resolveTurnContext(state, sessionKey, runId);
      if (parent) {
        const store = ensureRunStore(state, {
          runId,
          traceId: parent.traceId,
          sessionKey,
        });
        const planText =
          (Array.isArray(event?.assistantTexts) && event.assistantTexts.join("\n")) ||
          summarizeAssistant([event?.lastAssistant].filter(Boolean), state) ||
          "";
        callSecurityBridge(state, store, {
          operation: "inspect_plan",
          message: planText,
          plan: event?.plan || event?.steps || planText,
          parent: {
            traceId: parent.traceId,
            parentSpanId: parent.spanId,
            sessionKey,
            runId,
            llmCallId: parent.llmCallId,
          },
        });
      }
    } catch (error) {
      state.logger?.warn?.(`[behavior] llm_output failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: -70 });

  registerHook(api, state, "subagent_spawning", (event, ctx) => {
    try {
      ensureTaskContext(state, {
        parentSessionKey: event?.parentSessionKey || ctx?.sessionKey,
        parentRunId: event?.parentRunId || ctx?.runId,
        childSessionKey: event?.childSessionKey || null,
        childRunId: event?.runId || null,
        taskId: event?.taskId || null,
        toolCallId: event?.toolCallId || null,
        mode: event?.mode || null,
        runtime: event?.runtime || "subagent",
        agentId: event?.agentId || ctx?.agentId || null,
        taskText: event?.task || null,
        hook: "subagent_spawning",
      });
    } catch (error) {
      state.logger?.warn?.(`[behavior] subagent_spawning failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: 60 });

  registerHook(api, state, "subagent_spawned", (event, ctx) => {
    try {
      ensureTaskContext(state, {
        parentSessionKey: event?.parentSessionKey || ctx?.sessionKey,
        parentRunId: event?.parentRunId || ctx?.runId,
        childSessionKey: event?.childSessionKey || event?.target?.childSessionKey || null,
        childRunId: event?.runId || null,
        taskId: event?.taskId || null,
        toolCallId: event?.toolCallId || null,
        mode: event?.mode || null,
        runtime: event?.runtime || "subagent",
        agentId: event?.agentId || ctx?.agentId || null,
        taskText: event?.task || null,
        hook: "subagent_spawned",
      });
    } catch (error) {
      state.logger?.warn?.(`[behavior] subagent_spawned failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: 55 });

  registerHook(api, state, "subagent_ended", (event, ctx) => {
    try {
      const task = resolveTaskContext(state, event?.childSessionKey || event?.sessionKey, event?.runId || null);
      if (task) {
        finishTaskContext(state, task, {
          status: event?.error ? "error" : "ok",
          durationMs: event?.durationMs,
          preview: {
            result: previewText(event?.result || null, state),
            error: previewText(event?.error || null, state),
          },
          hook: "subagent_ended",
        });
      }
    } catch (error) {
      state.logger?.warn?.(`[behavior] subagent_ended failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: -55 });

  registerHook(api, state, "agent_end", async (event, ctx) => {
    try {
      const sessionKey = event?.sessionKey || ctx?.sessionKey || "unknown";
      const runId = event?.runId || ctx?.runId || null;
      closeTurnContext(state, event, ctx);
      const request = closeRequestContext(state, sessionKey, {
        status: event?.success === false || event?.error ? "error" : "ok",
        durationMs: event?.durationMs,
        preview: {
          assistant: summarizeAgentOutcome(event?.messages, state),
          error: previewText(event?.error || null, state),
        },
        evidence: {
          hook: "agent_end",
          surface: "typed-hook",
        },
      });

      const task = resolveTaskContext(state, sessionKey, runId);
      if (task) {
        finishTaskContext(state, task, {
          status: event?.success === false || event?.error ? "error" : "ok",
          durationMs: event?.durationMs,
          preview: {
            assistant: summarizeAgentOutcome(event?.messages, state),
            error: previewText(event?.error || null, state),
          },
          metrics: extractUsageMetrics(event?.usage || event?.lastAssistant?.usage || null),
          hook: "agent_end",
        });
      }
      scheduleDiagnosis(state, {
        runId: request?.runId || runId,
        traceId: request?.traceId || null,
        sessionKey,
      });
    } catch (error) {
      state.logger?.warn?.(`[behavior] agent_end failed: ${error?.message || error}`);
    }
    return undefined;
  }, { priority: -100 });
}

const behaviorMediatorPlugin = {
  id: "behavior-mediator",
  name: "Behavior Mediator",
  description: "Emit one canonical trace-aware behavior JSONL stream for OpenClaw.",

  register(api) {
    const config = parseConfig(api.pluginConfig);
    const logger = api.logger;
    const state = createRuntime(config, logger);

    registerTypedHooks(api, state);

    api.registerGatewayMethod(
      "behavior-mediator.status",
      ({ params, respond }) => {
        const requiredScopes = ["operator.read"];
        const providedScopes = normalizeProvidedScopes(params);
        const requestId =
          params?._rpcDiag && typeof params._rpcDiag === "object" && typeof params._rpcDiag.requestId === "string"
            ? params._rpcDiag.requestId.trim()
            : null;
        const statusPayload = {
          ...buildRuntimeStatus(state),
          requiredScopes,
          providedScopes,
          scopeMatch: computeScopeMatch(requiredScopes, providedScopes),
          rpcRequestId: requestId,
        };
        if (requestId) {
          logger?.info?.(
            `[behavior][rpc] status enter requestId=${requestId} providedScopes=${(providedScopes || []).join(",") || "n/a"}`,
          );
        }
        respond(true, statusPayload);
        if (requestId) {
          logger?.info?.(`[behavior][rpc] status exit requestId=${requestId} eventsWritten=${state.eventsWritten}`);
        }
      },
      { scope: "operator.read" },
    );

    api.registerService({
      id: "behavior-mediator",
      start: async () => {
        state.active = true;
        patchFetch(state);
        patchEval(state);
        if (!state.cleanupTimer) {
          state.cleanupTimer = setInterval(() => cleanupStaleContexts(state), 60_000);
        }
        logger?.info?.(`[behavior] registered ${state.hookNames.size} typed hooks`);
        logger?.info?.(`[behavior] writing canonical events under ${state.runsDirectory}`);
      },
      stop: async () => {
        state.active = false;
        if (state.cleanupTimer) {
          clearInterval(state.cleanupTimer);
          state.cleanupTimer = null;
        }
        restorePatchedGlobals(state);
      },
    });
  },
};

export default behaviorMediatorPlugin;
