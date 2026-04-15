import path from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { appendCanonicalEvent, cleanObject, createId, createWriterState, nowIso } from "./canonical.js";

const als = new AsyncLocalStorage();

const DEFAULT_OUTPUT_FILE = path.resolve(process.cwd(), "live", "behavior-events.jsonl");
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
  return {
    outputFile: typeof config.outputFile === "string" && config.outputFile ? config.outputFile : DEFAULT_OUTPUT_FILE,
    capturePreviewChars:
      typeof config.capturePreviewChars === "number" && Number.isFinite(config.capturePreviewChars)
        ? Math.max(128, Math.floor(config.capturePreviewChars))
        : DEFAULT_PREVIEW_CHARS,
    captureNetwork: config.captureNetwork !== false,
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

function createRuntime(config, logger) {
  const writer = createWriterState(config.outputFile);
  return {
    config,
    logger,
    ...writer,
    redactPatterns: compilePatterns(config.redactPatterns),
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
  };
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
    outputFile: state.outputFile,
    capturePreviewChars: state.config.capturePreviewChars,
    captureNetwork: state.config.captureNetwork,
    traceEval: state.config.traceEval,
    hooksRegistered: state.hookNames.size,
    hookNames: [...state.hookNames],
    hookEventsObserved: state.hookEventsObserved,
    firstHookEventTs: state.firstHookEventTs,
    lastHookEventTs: state.lastHookEventTs,
    eventsWritten: state.eventsWritten,
    lastEventTs: state.lastEventTs,
    lastWriteOk: state.lastWriteOk,
    lastWriteError: state.lastWriteError,
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
  appendCanonicalEvent(state, {
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
  appendCanonicalEvent(state, {
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
    evidence: {
      hook: "message_received",
      surface: "typed-hook",
      provenanceKind: event.provenance?.kind || null,
    },
  });

  state.requestContexts.set(sessionKey, request);
  return request;
}

function openTurnContext(state, event = {}, ctx = {}) {
  const sessionKey = event.sessionKey || ctx.sessionKey || "unknown";
  const runId = event.runId || ctx.runId || null;
  const request = resolveRequestContext(state, sessionKey, runId) || openRequestContext(state, event, ctx);
  const currentTurn = resolveTurnContext(state, sessionKey, runId);
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
    evidence: {
      hook: "before_agent_start",
      surface: "typed-hook",
    },
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
  const turn = resolveTurnContext(state, sessionKey, runId) || openTurnContext(state, event, ctx);
  const tool = createSpanContext(state, {
    kind: "tool",
    name: `tool.${toolName}`,
    traceId: turn.traceId,
    parentSpanId: turn.spanId,
    sessionKey,
    runId,
    toolCallId,
    target: deriveToolTarget(toolName, event.params || event.input || event.arguments || {}),
  });

  emitSpanStarted(state, tool, {
    preview: {
      params: previewText(event.params || event.input || event.arguments || null, state),
    },
    evidence: {
      hook: "before_tool_call",
      surface: "typed-hook",
    },
  });

  state.toolContexts.set(toolCallId, {
    ...tool,
    toolName,
    params: event.params || event.input || event.arguments || {},
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
    evidence: {
      hook: "after_tool_call",
      surface: "typed-hook",
    },
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
      const tool = openToolContext(state, event, ctx);
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
      finishLlmContext(state, event, ctx);
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
      closeRequestContext(state, sessionKey, {
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
        logger?.info?.(`[behavior] writing canonical events to ${state.outputFile}`);
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
