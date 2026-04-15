export const LIVE_URL = "../live/behavior-events.jsonl";
export const REQUIRED_FIELDS = ["schemaVersion", "seq", "ts", "traceId", "spanId", "kind", "name", "status"];
export const DEMO_VISIBLE_KINDS = ["request", "turn", "llm", "tool", "task"];
export const MIN_VISIBLE_WATERFALL_PCT = 1.2;

const PREVIEW_TEXT_KEYS = ["message", "prompt", "user", "assistant", "result", "response", "error"];
const ERROR_TEXT_KEYS = ["error", "message", "result", "response", "assistant"];

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function prettyJson(value) {
  return JSON.stringify(value ?? null, null, 2);
}

export function formatDateTime(value) {
  if (!value) {
    return "n/a";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return String(value);
  }
  return parsed.toLocaleString("zh-CN", { hour12: false });
}

export function formatClock(value) {
  if (!value) {
    return "--:--:--";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return String(value);
  }
  return parsed.toLocaleTimeString("zh-CN", { hour12: false });
}

export function formatDuration(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "n/a";
  }
  if (value < 1000) {
    return `${Math.round(value)} ms`;
  }
  return `${(value / 1000).toFixed(value >= 10_000 ? 1 : 2)} s`;
}

export function shortId(value) {
  if (!value) {
    return "n/a";
  }
  const text = String(value);
  return text.length > 24 ? `${text.slice(0, 8)}...${text.slice(-8)}` : text;
}

function validateEventShape(event, lineNumber) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw new Error(`Line ${lineNumber} is not a valid event object`);
  }
  const missing = REQUIRED_FIELDS.filter((field) => event[field] == null || event[field] === "");
  if (missing.length) {
    throw new Error(`第 ${lineNumber} 行缺少字段: ${missing.join(", ")}`);
  }
}

export function parseJsonl(text, sourceLabel = "JSONL") {
  const lines = String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) {
    throw new Error(`${sourceLabel} 文件为空`);
  }
  return lines.map((line, index) => {
    try {
      const parsed = JSON.parse(line);
      validateEventShape(parsed, index + 1);
      return parsed;
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error(`第 ${index + 1} 行不是合法 JSON`);
      }
      throw error;
    }
  });
}

export function sortEvents(events) {
  return [...events].sort((left, right) => {
    const seqDelta = Number(left.seq || 0) - Number(right.seq || 0);
    if (seqDelta !== 0) {
      return seqDelta;
    }
    return String(left.ts || "").localeCompare(String(right.ts || ""));
  });
}

function normalizeWhitespace(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim();
}

function clampText(value, maxLength = 140) {
  const normalized = normalizeWhitespace(value);
  if (!normalized) {
    return "";
  }
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized;
}

function basenameFromPath(value) {
  if (!value) {
    return "";
  }
  const text = String(value);
  const parts = text.split(/[\\/]/);
  return parts[parts.length - 1] || text;
}

function stripTimestampPrefix(value) {
  return String(value || "").replace(/^\[[^\]]+\]\s*/, "").trim();
}

function firstSentence(value) {
  const normalized = stripTimestampPrefix(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean);
  if (!normalized) {
    return "";
  }
  const match = normalized.match(/^(.{1,160}?)([。！？.!?]|$)/);
  return clampText(match ? match[1] : normalized, 110);
}

function tryParseEmbeddedJson(value) {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    return null;
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function looksErrorText(value) {
  const normalized = String(value || "").toLowerCase();
  return ["error", "enoent", "not found", "failed", "denied", "timeout"].some((token) => normalized.includes(token));
}

function previewText(preview, keys = PREVIEW_TEXT_KEYS) {
  if (!preview || typeof preview !== "object") {
    return "";
  }
  for (const key of keys) {
    const raw = preview[key];
    if (typeof raw === "string" && raw.trim()) {
      return raw.trim();
    }
  }
  return "";
}

function isLowSignalText(value) {
  const normalized = normalizeWhitespace(value);
  if (!normalized) {
    return true;
  }
  return !/[A-Za-z0-9\u4e00-\u9fff]/.test(normalized);
}

function parseParamsPreview(preview = {}) {
  if (!preview || typeof preview !== "object") {
    return null;
  }
  const raw = preview.params;
  if (typeof raw !== "string" || !raw.trim()) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function summarizeToolTarget(span) {
  const toolName = span.target?.toolName || span.name?.replace(/^tool\./, "") || "tool";
  const targetPath = span.target?.path ? basenameFromPath(span.target.path) : "";
  if (toolName === "read" && targetPath) {
    return `read ${targetPath}`;
  }
  if (toolName === "write" && targetPath) {
    return `write ${targetPath}`;
  }
  if (toolName === "exec") {
    return "exec command";
  }
  return targetPath ? `${toolName} ${targetPath}` : toolName;
}

function summarizeExecCommandLabel(commandLine) {
  const text = String(commandLine || "").trim();
  if (!text) {
    return "exec command";
  }
  const match = text.match(/^"([^"]+)"|^([^\s]+)/);
  const token = match?.[1] || match?.[2] || text;
  return basenameFromPath(token);
}

function extractExitCodeFromText(value) {
  const match = String(value || "").match(/\(Command exited with code (-?\d+)\)/i);
  if (!match) {
    return null;
  }
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) ? parsed : null;
}

function isPowerShellCurlAliasErrorText(value) {
  const text = String(value || "");
  return (
    /Invoke-WebRequest/i.test(text) &&
    (/MissingMandatoryParameter/i.test(text) || /ParameterBindingException/i.test(text) || /\bUri\b/i.test(text))
  );
}

function normalizeExecResultText(value, details = {}) {
  const normalized = normalizeWhitespace(value);
  const exitCode =
    (typeof details.exitCode === "number" && Number.isFinite(details.exitCode) ? details.exitCode : null) ??
    extractExitCodeFromText(normalized);
  const commandLabel = summarizeExecCommandLabel(details.commandLine);

  if (isPowerShellCurlAliasErrorText(normalized)) {
    const summary = /\bcurl(?:\.exe)?\b/i.test(String(details.commandLine || ""))
      ? "PowerShell 将 curl 解析为 Invoke-WebRequest，缺少必填参数 Uri"
      : "Invoke-WebRequest 缺少必填参数 Uri";
    return exitCode == null ? summary : `${summary}（exit code ${exitCode}）`;
  }

  if (!normalized) {
    return exitCode == null ? "" : `${commandLabel} 执行失败（exit code ${exitCode}）`;
  }

  if (/^\(Command exited with code -?\d+\)$/i.test(normalized)) {
    return exitCode == null ? `${commandLabel} 执行失败` : `${commandLabel} 执行失败（exit code ${exitCode}）`;
  }

  if (normalized.includes("�")) {
    return exitCode == null ? `${commandLabel} 执行失败，输出编码异常` : `${commandLabel} 执行失败，输出编码异常（exit code ${exitCode}）`;
  }

  return normalized;
}

function summarizeExecEventText(event) {
  if (!event || event.kind !== "tool" || event.target?.toolName !== "exec") {
    return "";
  }
  const preview = event.preview || {};
  return normalizeExecResultText(previewText(preview, ["error", "result", "response", "assistant"]), {
    commandLine: event.target?.commandLine,
    exitCode: event.metrics?.exitCode,
  });
}

function summarizeExecSpanText(span) {
  if (!span || span.kind !== "tool" || span.target?.toolName !== "exec") {
    return "";
  }
  const rawText =
    previewText(span.endEvent?.preview || {}, ["error", "result", "response", "assistant"]) ||
    previewText(span.startEvent?.preview || {}, ["error", "result", "response", "assistant"]);
  return normalizeExecResultText(rawText, {
    commandLine: span.target?.commandLine,
    exitCode: span.metrics?.exitCode ?? span.endEvent?.metrics?.exitCode ?? span.startEvent?.metrics?.exitCode,
  });
}

function summarizePromptForTitle(span) {
  const prompt = previewText(span.startEvent?.preview, ["prompt", "message", "user"]);
  if (!prompt) {
    return "";
  }
  const lowered = prompt.toLowerCase();
  if (lowered.includes("reply with exactly `ok`") || lowered.includes("reply with exactly ok")) {
    return "reply exactly ok";
  }
  const pathMatch = prompt.match(/`([^`]+)`/);
  if (pathMatch?.[1]) {
    return `${lowered.includes("read") ? "read" : "process"} ${basenameFromPath(pathMatch[1])}`;
  }
  return firstSentence(prompt);
}

function buildEventSummary(event) {
  if (event.kind === "tool" && event.target?.toolName === "exec") {
    const execSummary = summarizeExecEventText(event);
    if (execSummary) {
      return clampText(execSummary, 140);
    }
  }
  const preview = event.preview || {};
  const primary = previewText(preview, ["error", "assistant", "response", "result", "prompt", "message"]);
  if (primary) {
    return clampText(primary, 140);
  }
  if (event.target?.path) {
    return clampText(`${event.name} ${basenameFromPath(event.target.path)}`, 140);
  }
  return clampText(event.name || `${event.kind}.${event.status}`, 140);
}

function pickReasonFromPreview(preview = {}, keys = ERROR_TEXT_KEYS) {
  for (const key of keys) {
    const raw = preview[key];
    if (typeof raw !== "string" || !raw.trim()) {
      continue;
    }
    const embedded = tryParseEmbeddedJson(raw);
    if (embedded && typeof embedded === "object") {
      if (typeof embedded.error === "string" && embedded.error.trim()) {
        return embedded.error.trim();
      }
      if (typeof embedded.message === "string" && embedded.message.trim()) {
        return embedded.message.trim();
      }
      if (typeof embedded.status === "string" && embedded.status.toLowerCase() === "error") {
        return clampText(raw, 140);
      }
    }
    if (looksErrorText(raw) || key === "error") {
      return raw.trim();
    }
  }
  return "";
}

function computeDurationMs(startEvent, endEvent) {
  const metricValue = endEvent?.metrics?.durationMs ?? startEvent?.metrics?.durationMs;
  if (typeof metricValue === "number" && Number.isFinite(metricValue)) {
    return metricValue;
  }
  const start = startEvent?.ts ? Date.parse(startEvent.ts) : Number.NaN;
  const end = endEvent?.ts ? Date.parse(endEvent.ts) : Number.NaN;
  if (Number.isFinite(start) && Number.isFinite(end) && end >= start) {
    return end - start;
  }
  return null;
}

function isBenignReplacement(span) {
  const reason = span.endEvent?.evidence?.reason || "";
  const errorText = pickReasonFromPreview(span.endEvent?.preview || {}, ["error", "result", "message"]);
  return reason === "replaced" || errorText === "replaced by a newer turn";
}

function buildSpanMap(events) {
  const spanMap = new Map();
  for (const event of events) {
    const key = String(event.spanId);
    const existing = spanMap.get(key) || {
      spanId: key,
      parentSpanId: event.parentSpanId || null,
      kind: event.kind || "unknown",
      name: event.name || event.kind || "span",
      sessionKey: event.sessionKey || null,
      runId: event.runId || null,
      taskId: event.taskId || null,
      toolCallId: event.toolCallId || null,
      llmCallId: event.llmCallId || null,
      events: [],
      children: [],
      parent: null,
    };
    existing.parentSpanId = event.parentSpanId || existing.parentSpanId;
    existing.kind = event.kind || existing.kind;
    existing.name = event.name || existing.name;
    existing.sessionKey = event.sessionKey || existing.sessionKey;
    existing.runId = event.runId || existing.runId;
    existing.taskId = event.taskId || existing.taskId;
    existing.toolCallId = event.toolCallId || existing.toolCallId;
    existing.llmCallId = event.llmCallId || existing.llmCallId;
    existing.events.push(event);
    spanMap.set(key, existing);
  }

  for (const span of spanMap.values()) {
    span.events = sortEvents(span.events);
    span.startEvent = span.events.find((event) => event.status === "started") || span.events[0] || null;
    span.endEvent = [...span.events].reverse().find((event) => event.status !== "started") || null;
    span.status = span.endEvent?.status || (span.startEvent ? "running" : "unknown");
    span.startedAt = span.startEvent?.ts || span.endEvent?.ts || null;
    span.endedAt = span.endEvent?.ts || null;
    span.durationMs = computeDurationMs(span.startEvent, span.endEvent);
    span.target = span.endEvent?.target || span.startEvent?.target || null;
    span.metrics = span.endEvent?.metrics || span.startEvent?.metrics || null;
    span.isBenignReplacement = isBenignReplacement(span);
    span.summaryLine = "";
  }

  for (const span of spanMap.values()) {
    if (!span.parentSpanId) {
      continue;
    }
    const parent = spanMap.get(span.parentSpanId);
    if (!parent) {
      continue;
    }
    span.parent = parent;
    parent.children.push(span);
  }

  const sortChildren = (items) =>
    items.sort((left, right) => {
      const seqDelta = Number(left.startEvent?.seq || 0) - Number(right.startEvent?.seq || 0);
      if (seqDelta !== 0) {
        return seqDelta;
      }
      return String(left.startedAt || "").localeCompare(String(right.startedAt || ""));
    });

  for (const span of spanMap.values()) {
    sortChildren(span.children);
  }

  return spanMap;
}

function collectRoots(spanMap) {
  return [...spanMap.values()]
    .filter((span) => !span.parentSpanId || !spanMap.has(span.parentSpanId))
    .sort((left, right) => Number(left.startEvent?.seq || 0) - Number(right.startEvent?.seq || 0));
}

function collectVisibleChildren(span, depth) {
  const visible = [];
  for (const child of span.children || []) {
    if (DEMO_VISIBLE_KINDS.includes(child.kind)) {
      visible.push(buildVisibleNode(child, depth + 1));
      continue;
    }
    visible.push(...collectVisibleChildren(child, depth + 1));
  }
  return visible;
}

function buildVisibleNode(span, depth) {
  return {
    spanId: span.spanId,
    parentSpanId: span.parentSpanId,
    kind: span.kind || "unknown",
    name: span.name || span.kind || "span",
    status: span.status || "unknown",
    startedAt: span.startedAt,
    durationMs: span.durationMs,
    depth,
    span,
    summaryLine: conciseWaterfallSummary(span),
    detailSummary: "",
    offsetMs: 0,
    offsetPct: 0,
    durationPct: 0,
    isReplaced: false,
    isEffective: true,
    children: collectVisibleChildren(span, depth),
  };
}

function flattenVisibleNodes(nodes, output = []) {
  for (const node of nodes) {
    output.push(node);
    flattenVisibleNodes(node.children || [], output);
  }
  return output;
}

function extractFailureReasonFromSpan(span) {
  if (!span) {
    return "";
  }
  const execSummary = summarizeExecSpanText(span);
  if (execSummary) {
    return execSummary;
  }
  const endPreview = span.endEvent?.preview || {};
  const startPreview = span.startEvent?.preview || {};
  const previewReason = pickReasonFromPreview(endPreview) || pickReasonFromPreview(startPreview);
  if (previewReason) {
    return previewReason;
  }
  const evidenceReason = span.endEvent?.evidence?.reason || span.startEvent?.evidence?.reason || "";
  if (typeof evidenceReason === "string" && evidenceReason.trim()) {
    return evidenceReason.trim();
  }
  if (span.target?.path) {
    return `${summarizeToolTarget(span)} failed`;
  }
  return "";
}

function summarizeVisibleNode(span) {
  if (span.status === "error" && !span.isBenignReplacement) {
    const reason = extractFailureReasonFromSpan(span);
    return clampText(reason || `${span.name} failed`, 100);
  }
  if (span.kind === "tool") {
    const execSummary = summarizeExecSpanText(span);
    if (execSummary) {
      return clampText(execSummary, 100);
    }
    const params = parseParamsPreview(span.startEvent?.preview || {});
    if (params?.path) {
      return clampText(`input: ${basenameFromPath(params.path)}`, 100);
    }
    if (span.target?.path) {
      return clampText(`target: ${basenameFromPath(span.target.path)}`, 100);
    }
    const resultText = previewText(span.endEvent?.preview || {}, ["result", "response", "assistant"]);
    if (resultText) {
      return clampText(resultText, 100);
    }
    return clampText(summarizeToolTarget(span), 100);
  }
  const endText = previewText(span.endEvent?.preview || {}, ["assistant", "response", "result"]);
  if (endText && !isLowSignalText(endText)) {
    return clampText(endText, 100);
  }
  const startText = previewText(span.startEvent?.preview || {}, ["prompt", "message"]);
  if (startText) {
    const snippet = firstSentence(startText);
    if (!isLowSignalText(snippet)) {
      return clampText(snippet, 100);
    }
  }
  return clampText(span.name || `${span.kind} ${span.status}`, 100);
}

function conciseWaterfallSummary(span) {
  if (span.isBenignReplacement || span.isReplaced) {
    return "replaced by a newer turn";
  }

  if (span.kind === "turn") {
    if (span.status === "error") {
      return clampText(extractFailureReasonFromSpan(span) || "turn failed", 128);
    }
    const resultText = previewText(span.endEvent?.preview || {}, ["assistant", "response", "result"]);
    if (resultText) {
      const snippet = firstSentence(resultText);
      if (!isLowSignalText(snippet)) {
        return clampText(snippet, 128);
      }
    }
    const promptText = previewText(span.startEvent?.preview || {}, ["prompt", "message"]);
    if (promptText) {
      const snippet = firstSentence(promptText);
      if (!isLowSignalText(snippet)) {
        return clampText(snippet, 120);
      }
    }
    return span.status === "ok" ? "turn completed" : "turn running";
  }

  if (span.kind === "tool") {
    const execSummary = summarizeExecSpanText(span);
    if (execSummary) {
      return clampText(execSummary, 112);
    }
    if (span.status === "error") {
      return clampText(extractFailureReasonFromSpan(span) || `${summarizeToolTarget(span)} failed`, 116);
    }
    const params = parseParamsPreview(span.startEvent?.preview || {});
    if (params?.path) {
      return clampText(`input: ${basenameFromPath(params.path)}`, 112);
    }
    if (span.target?.path) {
      return clampText(`target: ${basenameFromPath(span.target.path)}`, 112);
    }
    const resultText = previewText(span.endEvent?.preview || {}, ["result", "response", "assistant"]);
    if (resultText) {
      const snippet = firstSentence(resultText);
      if (!isLowSignalText(snippet)) {
        return clampText(snippet, 112);
      }
    }
    return clampText(summarizeToolTarget(span), 112);
  }

  if (span.kind === "request") {
    if (span.status === "error") {
      return clampText(extractFailureReasonFromSpan(span) || "request failed", 128);
    }
    const resultText = previewText(span.endEvent?.preview || {}, ["assistant", "response", "result"]);
    if (resultText) {
      const snippet = firstSentence(resultText);
      if (!isLowSignalText(snippet)) {
        return clampText(snippet, 128);
      }
    }
    return "request processing";
  }

  return clampText(summarizeVisibleNode(span) || span.name, 104);
}

function summarizeMainPath(trace) {
  const kinds = [];
  for (const token of ["request", "turn", "llm", "tool", "task"]) {
    if (trace.visibleNodes.some((node) => node.kind === token)) {
      kinds.push(token);
    }
  }
  return kinds.join(" -> ") || "request";
}

function traceFinalResponse(trace) {
  const candidates = [...trace.events].reverse();
  for (const event of candidates) {
    const text =
      (event.kind === "tool" && event.target?.toolName === "exec" ? summarizeExecEventText(event) : "") ||
      previewText(event.preview || {}, ["assistant", "response", "result", "error"]);
    if (text) {
      return text;
    }
  }
  return "";
}

function buildRootCause(trace) {
  const requestOrTurnTerminalErrors = [...trace.allSpans]
    .reverse()
    .filter((span) => ["request", "turn"].includes(span.kind) && span.status === "error" && !span.isBenignReplacement)
    .map((span) => ({ span, reason: extractFailureReasonFromSpan(span) }))
    .filter((item) => item.reason);
  if (requestOrTurnTerminalErrors.length) {
    return clampText(requestOrTurnTerminalErrors[0].reason, 120);
  }

  const failedOperationalNodes = [...trace.allSpans]
    .reverse()
    .filter((span) => ["tool", "task", "llm"].includes(span.kind) && span.status === "error" && !span.isBenignReplacement)
    .map((span) => ({ span, reason: extractFailureReasonFromSpan(span) }))
    .filter((item) => item.reason);
  if (failedOperationalNodes.length) {
    const latest = failedOperationalNodes[0];
    if (latest.span.kind === "tool") {
      return clampText(`${summarizeToolTarget(latest.span)}: ${latest.reason}`, 120);
    }
    return clampText(latest.reason, 120);
  }

  const errorLike = [...trace.events]
    .reverse()
    .map((event) => buildEventSummary(event))
    .find((text) => looksErrorText(text));
  return clampText(errorLike || "", 120);
}

function deriveTraceStatus(trace) {
  const terminalOutcome = trace.requestTerminal || trace.turnTerminal || null;
  if (terminalOutcome?.status === "ok") {
    return "ok";
  }
  if (terminalOutcome?.status === "error" && !terminalOutcome.isBenignReplacement) {
    return "error";
  }

  const running = trace.visibleNodes.some((node) => node.status === "started" || node.status === "running");
  if (running) {
    return "running";
  }

  const criticalErrors = trace.allSpans.filter((span) => span.status === "error" && !span.isBenignReplacement);
  if (criticalErrors.some((span) => ["request", "turn", "tool", "task", "llm"].includes(span.kind))) {
    return "error";
  }

  const hasSuccess = trace.allSpans.some((span) => span.status === "ok");
  return hasSuccess ? "ok" : "unknown";
}

function deriveTraceTitle(trace) {
  const failedTool = trace.allSpans.find((span) => span.kind === "tool" && span.status === "error" && !span.isBenignReplacement);
  if (failedTool?.target?.path) {
    const base = basenameFromPath(failedTool.target.path);
    if (/missing|not.?found/i.test(base) || /enoent|not found/i.test(extractFailureReasonFromSpan(failedTool))) {
      return "read missing file";
    }
    return `read ${base}`;
  }

  const successfulTool = [...trace.allSpans]
    .reverse()
    .find((span) => span.kind === "tool" && span.status === "ok" && !span.isBenignReplacement);
  if (successfulTool?.target?.path) {
    return `read ${basenameFromPath(successfulTool.target.path)}`;
  }

  const promptTitle = summarizePromptForTitle(trace.requestStart || trace.turnStart || trace.requestSpan || null);
  if (promptTitle) {
    return promptTitle;
  }

  const response = traceFinalResponse(trace);
  if (response) {
    return clampText(response, 80);
  }

  return trace.traceId;
}

function deriveOneLineResult(trace, status, rootCause) {
  if (status === "error" && rootCause) {
    return rootCause;
  }
  const tool = [...trace.allSpans].reverse().find((span) => span.kind === "tool" && span.status === "ok");
  if (tool?.target?.path) {
    return `${basenameFromPath(tool.target.path)} processed`;
  }
  const response = traceFinalResponse(trace);
  return clampText(response || "completed", 100);
}

function isRoutineTrace(trace, oneLineResult) {
  const promptText = [trace.requestStart, trace.turnStart]
    .map((span) => previewText(span?.startEvent?.preview || {}, ["prompt", "message"]))
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
  const resultText = `${oneLineResult || ""}\n${traceFinalResponse(trace)}`.toLowerCase();
  return (
    resultText.includes("heartbeat_ok") ||
    promptText.includes("heartbeat") ||
    (trace.summary?.mainPath === "request -> turn" && /heartbeat/i.test(trace.summary?.title || ""))
  );
}

function createTraceSummary(trace) {
  const status = deriveTraceStatus(trace);
  const rootCause = buildRootCause(trace);
  const title = deriveTraceTitle(trace);
  const mainPath = summarizeMainPath(trace);
  const durationMs =
    trace.requestTerminal?.metrics?.durationMs ??
    trace.turnTerminal?.metrics?.durationMs ??
    computeDurationMs(trace.requestStart?.startEvent, trace.requestTerminal?.endEvent);
  const toolCount = new Set(trace.allSpans.filter((span) => span.kind === "tool").map((span) => span.spanId)).size;
  const oneLineResult = deriveOneLineResult(trace, status, rootCause);
  const summary = {
    traceId: trace.traceId,
    title,
    status,
    rootCause,
    mainPath,
    durationLabel: formatDuration(durationMs),
    toolCount,
    startedAt: trace.firstTs,
    updatedAt: trace.lastTs,
    oneLineResult,
    isRoutine: false,
  };
  summary.isRoutine = isRoutineTrace(trace, oneLineResult);
  return summary;
}

function annotateSiblingPriority(trace) {
  const groups = new Map();
  for (const span of trace.allSpans) {
    const key = `${span.parentSpanId || "root"}::${span.kind}`;
    const bucket = groups.get(key) || [];
    bucket.push(span);
    groups.set(key, bucket);
  }

  for (const spans of groups.values()) {
    if (spans.length === 1) {
      spans[0].isEffective = true;
      spans[0].isReplaced = spans[0].isBenignReplacement;
      continue;
    }
    const effectiveSpan =
      [...spans].reverse().find((span) => !span.isBenignReplacement && span.status !== "started") ||
      [...spans].reverse().find((span) => !span.isBenignReplacement) ||
      spans[spans.length - 1];
    for (const span of spans) {
      span.isEffective = span.spanId === effectiveSpan.spanId;
      span.isReplaced =
        span.isBenignReplacement ||
        (span.kind === "turn" && !span.isEffective && spans.some((item) => item.kind === "turn"));
    }
  }
}

function annotateTimelineMetrics(trace) {
  const traceStartMs = Date.parse(trace.firstTs || "") || 0;
  const timelineEndMs = Math.max(
    ...trace.visibleNodes.map((node) => {
      const startedAtMs = Date.parse(node.startedAt || "") || traceStartMs;
      return startedAtMs + (node.durationMs || 0);
    }),
    traceStartMs + 1,
  );
  const timelineTotalMs = Math.max(timelineEndMs - traceStartMs, 1);
  trace.timelineStartMs = traceStartMs;
  trace.timelineDurationMs = timelineTotalMs;

  for (const node of trace.visibleNodes) {
    const startedAtMs = Date.parse(node.startedAt || "") || traceStartMs;
    node.isReplaced = Boolean(node.span.isReplaced);
    node.isEffective = node.span.isEffective !== false;
    node.offsetMs = Math.max(0, startedAtMs - traceStartMs);
    node.offsetPct = Math.max(0, Math.min(100, (node.offsetMs / timelineTotalMs) * 100));
    node.durationPct = Math.max(0, Math.min(100, ((node.durationMs || 0) / timelineTotalMs) * 100));
  }
}

function createTraceModel(traceId, events) {
  const orderedEvents = sortEvents(events);
  const spanMap = buildSpanMap(orderedEvents);
  const roots = collectRoots(spanMap);
  const visibleRoots = roots
    .filter((span) => DEMO_VISIBLE_KINDS.includes(span.kind))
    .map((span) => buildVisibleNode(span, 0));
  const visibleNodes = flattenVisibleNodes(visibleRoots);
  const allSpans = [...spanMap.values()].sort((left, right) => Number(left.startEvent?.seq || 0) - Number(right.startEvent?.seq || 0));
  const trace = {
    traceId,
    events: orderedEvents,
    roots,
    visibleRoots,
    visibleNodes,
    allSpans,
    spanMap,
    firstTs: orderedEvents[0]?.ts || null,
    lastTs: orderedEvents[orderedEvents.length - 1]?.ts || null,
  };
  annotateSiblingPriority(trace);
  trace.requestSpan = allSpans.find((span) => span.kind === "request") || null;
  trace.turnStart = allSpans.find((span) => span.kind === "turn" && span.startEvent) || null;
  trace.requestStart = trace.requestSpan || trace.turnStart || null;
  trace.requestTerminal = [...allSpans].reverse().find((span) => span.kind === "request" && span.endEvent) || trace.requestSpan;
  trace.turnTerminal = [...allSpans].reverse().find((span) => span.kind === "turn" && span.endEvent && !span.isBenignReplacement) || trace.turnStart;
  trace.counts = {
    events: orderedEvents.length,
    turns: new Set(allSpans.filter((span) => span.kind === "turn").map((span) => span.spanId)).size,
    tools: new Set(allSpans.filter((span) => span.kind === "tool").map((span) => span.spanId)).size,
    llm: new Set(allSpans.filter((span) => span.kind === "llm").map((span) => span.spanId)).size,
    tasks: new Set(allSpans.filter((span) => span.kind === "task").map((span) => span.spanId)).size,
  };
  trace.summary = createTraceSummary(trace);
  annotateTimelineMetrics(trace);
  return trace;
}

export function buildTraces(events) {
  const grouped = new Map();
  for (const event of sortEvents(events)) {
    const traceId = event.traceId || `trace-missing-${event.seq || Math.random()}`;
    const bucket = grouped.get(traceId) || [];
    bucket.push(event);
    grouped.set(traceId, bucket);
  }
  return [...grouped.entries()]
    .map(([traceId, traceEvents]) => createTraceModel(traceId, traceEvents))
    .sort((left, right) => String(right.lastTs || "").localeCompare(String(left.lastTs || "")));
}

export function filterTraces(traces, mode = "important") {
  if (mode === "all") {
    return traces;
  }
  return traces.filter((trace) => !trace.summary.isRoutine);
}

export function chooseDefaultTrace(traces) {
  return traces[0] || null;
}

export function findTraceById(traces, traceId) {
  return traces.find((trace) => trace.traceId === traceId) || null;
}

export function findSpanById(trace, spanId) {
  if (!trace || !spanId) {
    return null;
  }
  return trace.allSpans.find((span) => span.spanId === spanId) || null;
}

export function chooseDefaultSpan(trace) {
  if (!trace) {
    return null;
  }
  const nodes = trace.visibleNodes || [];
  const errorNode = [...nodes].reverse().find((node) => node.status === "error" && !node.span.isBenignReplacement);
  if (errorNode) {
    return errorNode.span;
  }
  const completedTool = [...nodes].reverse().find((node) => node.kind === "tool" && node.status === "ok" && node.isEffective);
  if (completedTool) {
    return completedTool.span;
  }
  const completedTurn = [...nodes].reverse().find((node) => node.kind === "turn" && node.status === "ok" && node.isEffective);
  if (completedTurn) {
    return completedTurn.span;
  }
  return trace.requestSpan || nodes[0]?.span || null;
}

export function buildRawEventEntries(trace) {
  if (!trace) {
    return [];
  }
  return trace.events.map((event) => ({
    seq: event.seq,
    ts: event.ts,
    label: `${event.kind}.${event.status}`,
    name: event.name,
    summary: buildEventSummary(event),
    raw: event,
  }));
}

export async function fetchHealth() {
  const response = await fetch("/health", { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

export async function fetchLiveText() {
  const response = await fetch(`${LIVE_URL}?t=${Date.now()}`);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  const text = await response.text();
  if (!text.trim()) {
    throw new Error("live JSONL 文件为空");
  }
  return text;
}

