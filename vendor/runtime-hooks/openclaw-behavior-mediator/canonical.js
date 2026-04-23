import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const CANONICAL_SCHEMA_VERSION = "2.0.0";
export const CANONICAL_REQUIRED_FIELDS = ["schemaVersion", "seq", "ts", "traceId", "spanId", "kind", "name", "status"];

export function nowIso() {
  return new Date().toISOString();
}

export function createId(prefix) {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

export function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

export function readLastSequence(filePath) {
  if (!fs.existsSync(filePath)) {
    return 0;
  }
  try {
    const handle = fs.openSync(filePath, "r");
    const stat = fs.fstatSync(handle);
    const size = Math.min(stat.size, 64 * 1024);
    const buffer = Buffer.alloc(size);
    fs.readSync(handle, buffer, 0, size, stat.size - size);
    fs.closeSync(handle);
    const lines = buffer.toString("utf8").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      try {
        const row = JSON.parse(lines[index]);
        if (typeof row.seq === "number") {
          return row.seq;
        }
      } catch (error) {
        continue;
      }
    }
  } catch (error) {
    return 0;
  }
  return 0;
}

export function cleanObject(input) {
  const output = {};
  for (const [key, value] of Object.entries(input || {})) {
    if (value != null && value !== "") {
      output[key] = value;
    }
  }
  return Object.keys(output).length ? output : null;
}

function safeStringify(value) {
  try {
    return JSON.stringify(value);
  } catch (error) {
    return String(value);
  }
}

function normalizeText(value) {
  if (value == null) {
    return null;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || null;
  }
  return safeStringify(value);
}

function normalizeTypeAlias(row) {
  if (row.kind || typeof row.type !== "string" || !row.type.trim()) {
    return row;
  }
  const rawType = row.type.trim();
  if (!rawType.includes(".")) {
    return {
      ...row,
      kind: rawType,
    };
  }
  const [kind, status] = rawType.split(".", 2);
  return {
    ...row,
    kind: kind || row.kind,
    status: row.status || status || null,
  };
}

export function normalizeCanonicalRow(row, sequence) {
  const base = normalizeTypeAlias({ ...(row || {}) });
  return {
    schemaVersion: CANONICAL_SCHEMA_VERSION,
    seq: sequence,
    ts: normalizeText(base.ts || base.timestamp) || nowIso(),
    eventId: normalizeText(base.eventId) || createId("evt"),
    traceId: normalizeText(base.traceId),
    spanId: normalizeText(base.spanId),
    parentSpanId: normalizeText(base.parentSpanId) ?? null,
    kind: normalizeText(base.kind),
    name: normalizeText(base.name),
    status: normalizeText(base.status),
    sessionKey: normalizeText(base.sessionKey) ?? null,
    runId: normalizeText(base.runId) ?? null,
    taskId: normalizeText(base.taskId) ?? null,
    toolCallId: normalizeText(base.toolCallId) ?? null,
    llmCallId: normalizeText(base.llmCallId) ?? null,
    target: cleanObject(base.target),
    metrics: cleanObject(base.metrics),
    preview: cleanObject(base.preview),
    evidence: cleanObject(base.evidence),
  };
}

export function validateCanonicalEvent(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("canonical event must be an object");
  }
  const missing = CANONICAL_REQUIRED_FIELDS.filter((field) => payload[field] == null || payload[field] === "");
  if (missing.length) {
    throw new Error(`missing required fields: ${missing.join(", ")}`);
  }
  if (payload.schemaVersion !== CANONICAL_SCHEMA_VERSION) {
    throw new Error(`unsupported schemaVersion: ${payload.schemaVersion}`);
  }
  if (typeof payload.seq !== "number" || !Number.isFinite(payload.seq) || payload.seq <= 0) {
    throw new Error(`invalid seq: ${payload.seq}`);
  }
  const parsedTs = Date.parse(payload.ts);
  if (Number.isNaN(parsedTs)) {
    throw new Error(`invalid ts: ${payload.ts}`);
  }
  for (const field of ["target", "metrics", "preview", "evidence"]) {
    if (payload[field] != null && (typeof payload[field] !== "object" || Array.isArray(payload[field]))) {
      throw new Error(`${field} must be an object when present`);
    }
  }
  return payload;
}

export function createWriterState(outputFile) {
  const resolved = path.resolve(outputFile);
  ensureDir(path.dirname(resolved));
  return {
    outputFile: resolved,
    seq: readLastSequence(resolved),
    eventsWritten: 0,
    lastEventTs: null,
    lastWriteOk: null,
    lastWriteError: null,
  };
}

export function appendCanonicalEvent(state, row) {
  const nextSeq = (state.seq || 0) + 1;
  try {
    const payload = validateCanonicalEvent(normalizeCanonicalRow(row, nextSeq));
    fs.appendFileSync(state.outputFile, `${JSON.stringify(payload)}\n`, "utf8");
    state.seq = payload.seq;
    state.eventsWritten = (state.eventsWritten || 0) + 1;
    state.lastEventTs = payload.ts;
    state.lastWriteOk = true;
    state.lastWriteError = null;
    return payload;
  } catch (error) {
    state.lastWriteOk = false;
    state.lastWriteError = error?.message || String(error);
    throw error;
  }
}

function buildSmokeRows(label) {
  const traceId = `trace-smoke-${label}`;
  const requestSpanId = `span-request-${label}`;
  const turnSpanId = `span-turn-${label}`;
  const sessionKey = `smoke-session-${label}`;
  const runId = `smoke-run-${label}`;
  return [
    {
      traceId,
      spanId: requestSpanId,
      kind: "request",
      name: "openclaw.request",
      status: "started",
      sessionKey,
      runId,
      preview: {
        message: "trace writer smoke",
      },
      evidence: {
        source: "trace_writer_smoke",
      },
    },
    {
      traceId,
      spanId: turnSpanId,
      parentSpanId: requestSpanId,
      kind: "turn",
      name: "openclaw.agent.turn",
      status: "started",
      sessionKey,
      runId,
      preview: {
        user: "trace writer smoke",
      },
      evidence: {
        source: "trace_writer_smoke",
      },
    },
    {
      traceId,
      spanId: turnSpanId,
      parentSpanId: requestSpanId,
      kind: "turn",
      name: "openclaw.agent.turn",
      status: "ok",
      sessionKey,
      runId,
      metrics: {
        durationMs: 1,
      },
      preview: {
        assistant: "trace writer smoke ok",
      },
      evidence: {
        source: "trace_writer_smoke",
      },
    },
    {
      traceId,
      spanId: requestSpanId,
      kind: "request",
      name: "openclaw.request",
      status: "ok",
      sessionKey,
      runId,
      metrics: {
        durationMs: 2,
      },
      preview: {
        result: "trace writer smoke ok",
      },
      evidence: {
        source: "trace_writer_smoke",
      },
    },
  ];
}

export function writeSmokeTrace(outputFile, label = Date.now().toString()) {
  const state = createWriterState(outputFile);
  const rows = buildSmokeRows(label);
  const payloads = rows.map((row) => appendCanonicalEvent(state, row));
  return {
    outputFile: state.outputFile,
    written: payloads.length,
    traceId: payloads[0]?.traceId || null,
    firstSeq: payloads[0]?.seq || null,
    lastSeq: payloads[payloads.length - 1]?.seq || null,
    lastEventTs: state.lastEventTs,
  };
}
