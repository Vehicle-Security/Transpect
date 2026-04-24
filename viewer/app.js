import {
  MIN_VISIBLE_WATERFALL_PCT,
  RUNS_INDEX_URL,
  buildRawEventEntries,
  buildTraces,
  chooseDefaultSpan,
  chooseDefaultTrace,
  escapeHtml,
  fetchHealth,
  fetchRunText,
  fetchRunsIndex,
  filterTraces,
  findSpanById,
  findTraceById,
  formatClock,
  formatDateTime,
  formatDuration,
  parseJsonl,
  prettyJson,
  shortId,
} from "./shared.js?v=20260414-2";

const VIEW_TRACES = "traces";
const VIEW_TIMELINE = "timeline";

function parseBooleanFlag(value) {
  const text = String(value || "")
    .trim()
    .toLowerCase();
  return text === "1" || text === "true" || text === "yes" || text === "open";
}

function parseRouteFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const rawView = params.get("view");
  const view = rawView === VIEW_TIMELINE ? VIEW_TIMELINE : VIEW_TRACES;
  const run = params.get("run");
  const traceId = params.get("traceId");
  return {
    view,
    run: run && run.trim() ? run.trim() : null,
    traceId: traceId && traceId.trim() ? traceId.trim() : null,
    evidenceExpanded: view === VIEW_TIMELINE && parseBooleanFlag(params.get("evidence")),
  };
}

const initialRoute = parseRouteFromUrl();

const state = {
  health: null,
  runs: [],
  runGroupsInitialized: false,
  expandedRunGroups: new Set(),
  selectedRunDir: initialRoute.run,
  sourceLabel: "",
  allTraces: [],
  visibleTraces: [],
  view: initialRoute.view,
  traceFilter: "important",
  selectedTraceId: initialRoute.traceId,
  selectedSpanId: null,
  expandedTraceId: null,
  expandedSpanIds: new Set(),
  evidenceExpanded: initialRoute.evidenceExpanded,
  loadStatus: "loading",
  statusBadge: "empty",
  statusLabel: "正在加载",
  statusMessage: "正在读取 runs 索引",
};

const elements = {
  liveBadge: document.getElementById("live-badge"),
  eventCount: document.getElementById("event-count"),
  lastUpdated: document.getElementById("last-updated"),
  sourceLine: document.getElementById("source-line"),
  topbarActions: document.querySelector(".topbar-actions"),
  backToTraces: document.getElementById("back-to-traces"),
  refreshButton: document.getElementById("refresh-button"),
  filterButton: document.getElementById("filter-button"),
  bannerArea: document.getElementById("banner-area"),
  tracesPage: document.getElementById("traces-page"),
  timelinePage: document.getElementById("timeline-page"),
  runCount: document.getElementById("run-count"),
  runGroupList: document.getElementById("run-group-list"),
  traceCount: document.getElementById("trace-count"),
  traceList: document.getElementById("trace-list"),
  traceJsonlInput: document.getElementById("trace-jsonl-input"),
  heroEmpty: document.getElementById("hero-empty"),
  traceHeaderCard: document.getElementById("trace-header-card"),
  timelinePanel: document.getElementById("timeline-panel"),
  timelineList: document.getElementById("timeline-list"),
  toggleEvidence: document.getElementById("toggle-evidence"),
  evidenceDrawer: document.getElementById("evidence-drawer"),
};

if (!document.getElementById("run-select") && elements.topbarActions) {
  const select = document.createElement("select");
  select.id = "run-select";
  select.className = "meta-chip";
  select.setAttribute("aria-label", "Select run");
  elements.topbarActions.insertBefore(select, elements.backToTraces);
}
elements.runSelect = document.getElementById("run-select");

function basename(value) {
  const text = String(value || "");
  if (!text) {
    return "";
  }
  const parts = text.split(/[\\/]/);
  return parts[parts.length - 1] || text;
}

function buildRouteHref(view, runDir = null, traceId = null, evidenceExpanded = false) {
  const url = new URL(window.location.href);
  if (runDir) {
    url.searchParams.set("run", runDir);
  } else {
    url.searchParams.delete("run");
  }
  if (view === VIEW_TIMELINE) {
    url.searchParams.set("view", VIEW_TIMELINE);
    if (traceId) {
      url.searchParams.set("traceId", traceId);
    } else {
      url.searchParams.delete("traceId");
    }
    if (evidenceExpanded) {
      url.searchParams.set("evidence", "1");
    } else {
      url.searchParams.delete("evidence");
    }
  } else {
    url.searchParams.set("view", VIEW_TRACES);
    url.searchParams.delete("traceId");
    url.searchParams.delete("evidence");
  }
  const query = url.searchParams.toString();
  return `${url.pathname}${query ? `?${query}` : ""}${url.hash}`;
}

function syncRoute(options = {}) {
  const { push = false } = options;
  const href = buildRouteHref(state.view, state.selectedRunDir, state.selectedTraceId, state.evidenceExpanded);
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (href === current) {
    return;
  }
  if (push) {
    window.history.pushState({}, "", href);
    return;
  }
  window.history.replaceState({}, "", href);
}

function classifyLoadError(error) {
  const message = String(error?.message || error || "");
  if (message.includes("404")) {
    return {
      badge: "disconnected",
      label: "Runs 缺失",
      message: "默认 runs 索引还不存在，当前页面暂时没有可展示的数据。",
    };
  }
  if (message.includes("文件为空")) {
    return {
      badge: "empty",
      label: "Runs 为空",
      message: "当前选中的 run 还没有事件，等待下一次写入后会出现 trace。",
    };
  }
  if (message.includes("不是合法 JSON") || message.includes("缺少字段") || message.includes("合法事件对象")) {
    return {
      badge: "schema_error",
      label: "Schema 异常",
      message,
    };
  }
  return {
    badge: "disconnected",
    label: "加载失败",
    message,
  };
}

function syncVisibleTraces() {
  state.visibleTraces = filterTraces(state.allTraces, state.traceFilter);
  const trace = findTraceById(state.visibleTraces, state.selectedTraceId) || chooseDefaultTrace(state.visibleTraces);
  state.selectedTraceId = trace?.traceId || null;
  state.selectedSpanId = (trace && findSpanById(trace, state.selectedSpanId)?.spanId) || chooseDefaultSpan(trace)?.spanId || null;
  ensureExpandedRows(trace);
}

function normalizeViewState() {
  if (state.view === VIEW_TIMELINE && !selectedTrace()) {
    state.view = VIEW_TRACES;
  }
  if (state.view !== VIEW_TIMELINE) {
    state.evidenceExpanded = false;
  }
}

function ensureExpandedRows(trace) {
  if (!trace) {
    state.expandedTraceId = null;
    state.expandedSpanIds = new Set();
    return;
  }
  if (state.expandedTraceId === trace.traceId) {
    return;
  }
  state.expandedTraceId = trace.traceId;
  state.expandedSpanIds = new Set(trace.visibleNodes.map((node) => node.spanId));
}

function selectedRun() {
  return state.runs.find((run) => run.dirName === state.selectedRunDir) || state.runs[0] || null;
}

function selectedTrace() {
  return findTraceById(state.visibleTraces, state.selectedTraceId);
}

function countEvents(traces) {
  return traces.reduce((sum, trace) => sum + trace.events.length, 0);
}

function parseTimestamp(value) {
  const parsed = new Date(value || "");
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function dateKey(value) {
  const parsed = parseTimestamp(value);
  return parsed ? parsed.toISOString().slice(0, 10) : "unknown-date";
}

function taskGroupFromPath(value) {
  const parts = String(value || "").split("/");
  return parts.length > 1 && parts[1] ? parts[1] : "manual";
}

function formatPercent(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "n/a";
  }
  return `${Math.round(value * 100)}%`;
}

function formatRunDuration(run) {
  const start = parseTimestamp(run?.createdAt);
  const end = parseTimestamp(run?.completedAt);
  if (!start || !end || end.getTime() < start.getTime()) {
    return "n/a";
  }
  return formatDuration(end.getTime() - start.getTime());
}

function runTitle(run) {
  return run?.taskRepo?.taskId || run?.runId || run?.traceId || run?.dirName || "unknown run";
}

function runSubtitle(run) {
  const taskRepo = run?.taskRepo || {};
  return [taskRepo.sourcePath, taskRepo.scenario].filter(Boolean).join(" · ") || run?.traceId || run?.eventsPath || "";
}

function labelText(value) {
  return value === null || value === undefined ? "?" : String(value);
}

function runIssueClass(run) {
  if (run?.status && run.status !== "completed") {
    return "running";
  }
  if (run?.analysisOk === false) {
    return "diagnosis-failed";
  }
  if (run?.labelMatched === false) {
    return "mismatch";
  }
  return "ok";
}

function runIssueLabel(run) {
  const issue = runIssueClass(run);
  if (issue === "running") {
    return run?.status || "running";
  }
  if (issue === "diagnosis-failed") {
    return "diagnosis failed";
  }
  if (issue === "mismatch") {
    return "mismatch";
  }
  return "ok";
}

function buildRunGroups(runs) {
  const groups = new Map();
  const ensureGroup = (key, group) => {
    if (!groups.has(key)) {
      groups.set(key, { ...group, runs: [] });
    }
    return groups.get(key);
  };

  for (const run of runs || []) {
    const batchId = run.batchId || "";
    const key = batchId ? `batch:${batchId}` : `date:${dateKey(run.completedAt || run.createdAt)}`;
    const group = ensureGroup(
      key,
      batchId
        ? {
            key,
            kind: "Batch",
            title: run.batchName || batchId,
            sortAt: run.batchStartedAt || run.completedAt || run.createdAt || "",
          }
        : {
            key,
            kind: "Date",
            title: dateKey(run.completedAt || run.createdAt),
            sortAt: run.completedAt || run.createdAt || "",
          },
    );
    group.runs.push(run);
  }

  return [...groups.values()].sort((left, right) => {
    if (left.kind !== right.kind) {
      return left.kind === "Batch" ? -1 : 1;
    }
    return String(right.sortAt || "").localeCompare(String(left.sortAt || ""));
  });
}

function runGroupStats(group) {
  const total = group.runs.length;
  const known = group.runs.filter((run) => run.labelMatched !== null && run.labelMatched !== undefined).length;
  const matched = group.runs.filter((run) => run.labelMatched === true).length;
  const diagnosisOk = group.runs.filter((run) => run.analysisOk === true).length;
  const mismatches = group.runs.filter((run) => run.labelMatched === false).length;
  return { total, known, matched, diagnosisOk, mismatches, accuracy: known ? matched / known : null };
}

function ensureRunGroupDefaults(groups) {
  if (state.runGroupsInitialized) {
    return;
  }
  for (const group of groups) {
    if (group.kind === "Batch") {
      state.expandedRunGroups.add(group.key);
    }
    if (group.runs.some((run) => run.dirName === state.selectedRunDir)) {
      state.expandedRunGroups.add(group.key);
    }
  }
  if (!state.expandedRunGroups.size && groups[0]) {
    state.expandedRunGroups.add(groups[0].key);
  }
  state.runGroupsInitialized = true;
}

function renderStatusBadge(value) {
  const status = String(value || "unknown");
  return `<span class="pill pill-status ${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

function renderTopbar() {
  const health = state.health || {};
  const activeRun = selectedRun();
  const sourceName =
    state.sourceLabel ||
    activeRun?.runId ||
    activeRun?.traceId ||
    activeRun?.dirName ||
    basename(health.runsIndexPath) ||
    basename(RUNS_INDEX_URL) ||
    "runs/index.json";
  const count = activeRun?.eventCount ?? countEvents(state.allTraces);
  const updated = activeRun?.completedAt || activeRun?.createdAt ? formatDateTime(activeRun.completedAt || activeRun.createdAt) : "--";
  const taskRuns = state.runs.filter((run) => run.taskRepo?.taskId).length;
  const diagnosisOk = state.runs.filter((run) => run.analysisOk === true).length;
  const mismatches = state.runs.filter((run) => run.labelMatched === false).length;

  elements.liveBadge.className = `live-badge ${state.statusBadge}`;
  elements.liveBadge.textContent = state.statusLabel;
  elements.eventCount.textContent = state.runs.length ? `${state.runs.length} runs` : `${count || 0} events`;
  elements.lastUpdated.textContent = state.runs.length
    ? `task runs ${taskRuns} · diagnosis ok ${diagnosisOk}/${state.runs.length} · mismatches ${mismatches}`
    : `最后更新 ${updated}`;
  elements.sourceLine.textContent = sourceName;
  renderRunSelector();
  elements.backToTraces.classList.toggle("hidden", state.view !== VIEW_TIMELINE);
  elements.filterButton.textContent = state.traceFilter === "important" ? "显示当前 run 全部 trace" : "仅重要 trace";
  elements.toggleEvidence.textContent = state.evidenceExpanded ? "收起原始事件与调试信息" : "查看原始事件与调试信息";
}

function renderRunSelector() {
  if (!elements.runSelect) {
    return;
  }
  const runs = state.runs || [];
  if (!runs.length) {
    elements.runSelect.innerHTML = `<option value="">暂无 runs</option>`;
    elements.runSelect.disabled = true;
    return;
  }
  elements.runSelect.disabled = false;
  elements.runSelect.innerHTML = runs
    .map((run) => {
      const label = [run.taskRepo?.taskId || shortId(run.runId || run.traceId || run.dirName), run.status || "unknown"]
        .filter(Boolean)
        .join(" · ");
      return `<option value="${escapeHtml(run.dirName)}">${escapeHtml(label)}</option>`;
    })
    .join("");
  if (!state.selectedRunDir) {
    state.selectedRunDir = runs[0].dirName;
  }
  elements.runSelect.value = state.selectedRunDir || runs[0].dirName;
}

function renderBanner() {
  const notices = [];
  if (state.loadStatus === "error") {
    notices.push(`
      <div class="banner warning">
        <div class="banner-copy">
          <strong>${escapeHtml(state.statusLabel)}</strong>
          <span>${escapeHtml(state.statusMessage)}</span>
        </div>
      </div>
    `);
  }

  const routineOnly =
    state.traceFilter === "important" &&
    state.visibleTraces.length === 0 &&
    state.allTraces.length > 0 &&
    state.allTraces.some((trace) => trace.summary.isRoutine);

  if (routineOnly) {
    notices.push(`
      <div class="banner info">
        <div class="banner-copy">
          <strong>当前仅存在例行 trace，已默认隐藏</strong>
          <span>这些 trace 仍在当前 run 文件中，可一键切换到“显示当前 run 全部 trace”。</span>
        </div>
        <button id="show-all-banner" class="banner-button" type="button">显示当前 run 全部 trace</button>
      </div>
    `);
  }

  elements.bannerArea.innerHTML = notices.join("");
  const showAllButton = document.getElementById("show-all-banner");
  if (showAllButton) {
    showAllButton.addEventListener("click", () => {
      state.traceFilter = "all";
      syncVisibleTraces();
      render();
    });
  }
}

function renderRunExplorer() {
  if (!elements.runGroupList || !elements.runCount) {
    return;
  }
  const runs = state.runs || [];
  const groups = buildRunGroups(runs);
  ensureRunGroupDefaults(groups);
  const taskRuns = runs.filter((run) => run.taskRepo?.taskId).length;
  const mismatches = runs.filter((run) => run.labelMatched === false).length;
  elements.runCount.textContent = `${runs.length} runs · ${taskRuns} task runs · ${mismatches} mismatches`;

  if (!runs.length) {
    elements.runGroupList.innerHTML = `
      <div class="run-empty">暂无 runs</div>
    `;
    return;
  }

  elements.runGroupList.innerHTML = groups
    .map((group) => {
      const expanded = state.expandedRunGroups.has(group.key);
      const stats = runGroupStats(group);
      const statLine = stats.known
        ? `${stats.total} runs · ${stats.matched}/${stats.known} matched · ${formatPercent(stats.accuracy)}`
        : `${stats.total} runs · diagnosis ok ${stats.diagnosisOk}/${stats.total}`;
      return `
        <section class="run-group ${expanded ? "expanded" : ""}">
          <button class="run-group-head" type="button" data-run-group="${escapeHtml(group.key)}">
            <span class="run-group-caret">${expanded ? "−" : "+"}</span>
            <span class="run-group-kind">${escapeHtml(group.kind)}</span>
            <strong class="run-group-title">${escapeHtml(group.title)}</strong>
            <span class="run-group-meta">${escapeHtml(statLine)}</span>
          </button>
          <div class="run-group-body ${expanded ? "" : "hidden"}">
            ${group.runs
              .map((run) => {
                const taskRepo = run.taskRepo || {};
                const issueClass = runIssueClass(run);
                const groupName = taskGroupFromPath(taskRepo.sourcePath);
                const labelPair =
                  taskRepo.expectedLabel !== undefined || (run.predictedLabel !== null && run.predictedLabel !== undefined)
                    ? `${labelText(taskRepo.expectedLabel)} -> ${labelText(run.predictedLabel)}`
                    : "label n/a";
                return `
                  <button
                    class="run-row ${run.dirName === state.selectedRunDir ? "active" : ""} ${escapeHtml(issueClass)}"
                    type="button"
                    data-run-dir="${escapeHtml(run.dirName)}"
                    title="${escapeHtml(run.runId || run.dirName)}"
                  >
                    <div class="run-row-main">
                      <span class="run-issue-dot ${escapeHtml(issueClass)}" aria-hidden="true"></span>
                      <strong class="run-title">${escapeHtml(runTitle(run))}</strong>
                      <span class="run-badge ${escapeHtml(issueClass)}">${escapeHtml(runIssueLabel(run))}</span>
                    </div>
                    <div class="run-row-tags">
                      <span>${escapeHtml(groupName)}</span>
                      <span>${escapeHtml(taskRepo.attackType || "manual")}</span>
                      <span>${escapeHtml(labelPair)}</span>
                      <span>${escapeHtml(run.analysisOk === true ? "diagnosis ok" : run.analysisOk === false ? "diagnosis failed" : "diagnosis n/a")}</span>
                    </div>
                    <div class="run-row-meta">
                      <span>${escapeHtml(formatDateTime(run.completedAt || run.createdAt))}</span>
                      <span>${escapeHtml(formatRunDuration(run))}</span>
                      <span>${escapeHtml(`${run.eventCount || 0} events`)}</span>
                      <span>${escapeHtml(shortId(run.runId || run.dirName))}</span>
                    </div>
                    ${runSubtitle(run) ? `<div class="run-row-subtitle">${escapeHtml(runSubtitle(run))}</div>` : ""}
                  </button>
                `;
              })
              .join("")}
          </div>
        </section>
      `;
    })
    .join("");

  for (const node of elements.runGroupList.querySelectorAll("[data-run-group]")) {
    node.addEventListener("click", () => {
      const key = node.dataset.runGroup;
      if (state.expandedRunGroups.has(key)) {
        state.expandedRunGroups.delete(key);
      } else {
        state.expandedRunGroups.add(key);
      }
      renderRunExplorer();
    });
  }

  for (const node of elements.runGroupList.querySelectorAll("[data-run-dir]")) {
    node.addEventListener("click", async () => {
      await selectRunDir(node.dataset.runDir, { openTimeline: true });
    });
  }
}

function renderTraceList() {
  elements.traceCount.textContent = `${state.visibleTraces.length} traces`;
  if (!state.visibleTraces.length) {
    elements.traceList.innerHTML = `
      <div class="trace-item trace-item-empty">
        <div class="trace-item-title">没有可展示的 trace</div>
        <div class="trace-item-result muted">如果当前 live 里只有 heartbeat，切到“显示全部”后就能看到。</div>
      </div>
    `;
    return;
  }

  elements.traceList.innerHTML = state.visibleTraces
    .map((trace) => {
      const summary = trace.summary;
      return `
        <button
          class="trace-item ${trace.traceId === state.selectedTraceId ? "active" : ""}"
          data-trace-id="${escapeHtml(trace.traceId)}"
          title="${escapeHtml(trace.traceId)}"
          type="button"
        >
          <div class="trace-item-row">
            ${renderStatusBadge(summary.status)}
            <strong class="trace-item-title">${escapeHtml(summary.title)}</strong>
          </div>
          <div class="trace-item-row trace-item-meta">
            <span>${escapeHtml(formatClock(summary.startedAt))}</span>
            <span>&middot;</span>
            <span>${escapeHtml(summary.durationLabel)}</span>
          </div>
          <div class="trace-item-path">${escapeHtml(summary.mainPath)}</div>
          <div class="trace-item-result">${escapeHtml(summary.oneLineResult || summary.rootCause || "暂无摘要")}</div>
        </button>
      `;
    })
    .join("");

  for (const node of elements.traceList.querySelectorAll("[data-trace-id]")) {
    node.addEventListener("click", () => {
      state.selectedTraceId = node.dataset.traceId;
      state.selectedSpanId = null;
      state.view = VIEW_TIMELINE;
      syncVisibleTraces();
      normalizeViewState();
      syncRoute({ push: true });
      render();
    });
  }
}

function renderHeader(trace) {
  if (!trace) {
    elements.heroEmpty.classList.remove("hidden");
    elements.traceHeaderCard.classList.add("hidden");
    elements.timelinePanel.classList.add("hidden");
    return;
  }

  const summary = trace.summary;
  const rootCause = summary.status === "error" ? summary.rootCause || "未提供明确原因" : "无";

  elements.heroEmpty.classList.add("hidden");
  elements.traceHeaderCard.classList.remove("hidden");
  elements.traceHeaderCard.className = `panel trace-header-card ${summary.status}`;
  elements.traceHeaderCard.innerHTML = `
    <div class="trace-summary-title">${escapeHtml(summary.title)}</div>
    <div class="trace-summary-line">
      <span>状态: <strong>${escapeHtml(summary.status)}</strong></span>
      <span>根因: ${escapeHtml(rootCause)}</span>
      <span>主链: ${escapeHtml(summary.mainPath)}</span>
      <span>总耗时: ${escapeHtml(summary.durationLabel)}</span>
    </div>
  `;
}

function buildExpandedRows(nodes, output = []) {
  for (const node of nodes) {
    output.push(node);
    if (!node.children.length || !state.expandedSpanIds.has(node.spanId)) {
      continue;
    }
    buildExpandedRows(node.children, output);
  }
  return output;
}

function descendantSpanIds(node, output = []) {
  for (const child of node.children || []) {
    output.push(child.spanId);
    descendantSpanIds(child, output);
  }
  return output;
}

function siblingKindCounts(trace) {
  const counts = new Map();
  for (const node of trace.visibleNodes) {
    const key = `${node.parentSpanId || "root"}::${node.kind}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

function deriveSemanticNodeName(row, displayKind) {
  const span = row?.span || {};
  const target = span?.target || {};

  if (displayKind === "llm") {
    const provider = String(target.provider || "").trim();
    const model = String(target.model || "").trim();
    if (provider && model) {
      return `${provider}/${model}`;
    }
    if (model) {
      return model;
    }
    if (provider) {
      return provider;
    }
  }

  if (displayKind === "tool") {
    const fromTarget = String(target.toolName || "").trim();
    const fromName = String(span.name || "").replace(/^tool\./, "").trim();
    const toolName = fromTarget || fromName;
    const targetPath = String(target.path || "").trim();
    if (toolName && targetPath) {
      return `${toolName} ${basename(targetPath)}`;
    }
    if (toolName) {
      return toolName;
    }
    if (targetPath) {
      return basename(targetPath);
    }
  }

  return "";
}

function isWeakDisplayName(value, displayKind) {
  const normalized = String(value || "")
    .replace(/\s+/g, " ")
    .trim();
  if (!normalized) {
    return true;
  }
  if (!/[A-Za-z0-9\u4e00-\u9fff]/.test(normalized)) {
    return true;
  }
  if (normalized.length <= 2) {
    return true;
  }
  if (/^[A-Za-z]\.$/.test(normalized)) {
    return true;
  }
  if (displayKind && normalized.toLowerCase() === String(displayKind).toLowerCase()) {
    return true;
  }
  return false;
}

function timelineTicks(trace) {
  const fractions = [0, 0.25, 0.5, 0.75, 1];
  return fractions
    .map((fraction, index) => {
      const ms = trace.timelineDurationMs * fraction;
      const alignClass = index === 0 ? "start" : index === fractions.length - 1 ? "end" : "middle";
      return `<span class="timeline-tick ${alignClass}" style="left:${fraction * 100}%">${escapeHtml(formatDuration(ms))}</span>`;
    })
    .join("");
}

function renderTimeline(trace) {
  if (!trace) {
    elements.timelinePanel.classList.add("hidden");
    elements.timelineList.innerHTML = "";
    return;
  }

  elements.timelinePanel.classList.remove("hidden");
  ensureExpandedRows(trace);
  const rows = buildExpandedRows(trace.visibleRoots);
  const counts = siblingKindCounts(trace);

  const renderRow = (row) => {
    const rowKey = `${row.parentSpanId || "root"}::${row.kind}`;
    const grouped = (counts.get(rowKey) || 0) > 1;
    const selected = row.spanId === state.selectedSpanId;
    const expanded = state.expandedSpanIds.has(row.spanId);
    const offsetPct = Number.isFinite(row.offsetPct) ? row.offsetPct : 0;
    const durationPct = Math.max(row.durationPct || 0, MIN_VISIBLE_WATERFALL_PCT);
    const statusClass = row.status || "unknown";
    const noteLabel = row.isReplaced ? "已替换" : grouped && row.isEffective ? "最终有效" : "";
    const rawKind = String(row.kind || "").trim();
    const displayKind = rawKind || "unknown";
    const rawName = String(row.name || "").trim();
    const semanticName = deriveSemanticNodeName(row, displayKind);
    const fallbackName = `span-${shortId(row.spanId)}`;
    const displayName = isWeakDisplayName(rawName, displayKind) ? semanticName || fallbackName : rawName;
    const summaryText = String(row.summaryLine || "").trim();
    const compactSummary = summaryText.length > 140 ? `${summaryText.slice(0, 139)}…` : summaryText;
    const rowTitle = [displayKind ? `${displayKind} · ${displayName}` : displayName, noteLabel, summaryText].filter(Boolean).join(" | ");
    const depthForIndent = Math.min(Number(row.depth) || 0, 4);
    const hasSubLine = Boolean(noteLabel || compactSummary);
    const subLineClass = noteLabel ? "has-note" : "no-note";

    return `
      <article class="waterfall-row ${selected ? "selected" : ""} ${row.isReplaced ? "replaced" : ""} ${row.isEffective ? "effective" : ""}" style="--depth:${depthForIndent}">
        <div class="waterfall-label">
          <button
            class="row-toggle ${row.children.length ? "" : "hidden"}"
            data-toggle-span="${escapeHtml(row.spanId)}"
            type="button"
            aria-label="${expanded ? "收起子节点" : "展开子节点"}"
          >${expanded ? "−" : "+"}</button>
          <button class="row-select" data-span-id="${escapeHtml(row.spanId)}" type="button" title="${escapeHtml(rowTitle)}">
            <div class="row-text-block">
              <div class="row-main-line">
                <span class="row-status-dot ${escapeHtml(statusClass)}" aria-hidden="true"></span>
                <span class="row-kind-pill">${escapeHtml(displayKind)}</span>
                <span class="row-name-text">${escapeHtml(displayName)}</span>
              </div>
              ${
                hasSubLine
                  ? `<div class="row-sub-line ${subLineClass}">
                       ${noteLabel ? `<span class="row-sub-note">${escapeHtml(noteLabel)}</span>` : ""}
                       ${compactSummary ? `<span class="row-sub-summary">${escapeHtml(compactSummary)}</span>` : ""}
                     </div>`
                  : ""
              }
            </div>
          </button>
        </div>
        <div class="waterfall-duration">${escapeHtml(formatDuration(row.durationMs))}</div>
        <div class="waterfall-bar-cell">
          <div class="waterfall-track">
            <div
              class="waterfall-bar ${escapeHtml(statusClass)} ${row.isReplaced ? "replaced" : ""}"
              style="left:${offsetPct.toFixed(2)}%; width:max(8px, ${durationPct.toFixed(2)}%);"
            ></div>
          </div>
        </div>
      </article>
    `;
  };

  elements.timelineList.innerHTML = `
    <div class="timeline-scale-header">
      <div class="timeline-scale-label">链路</div>
      <div class="timeline-scale-meta">耗时</div>
      <div class="timeline-scale-track">${timelineTicks(trace)}</div>
    </div>
    <div class="timeline-rows">
      ${rows.map(renderRow).join("")}
    </div>
  `;

  for (const node of elements.timelineList.querySelectorAll("[data-span-id]")) {
    node.addEventListener("click", () => {
      state.selectedSpanId = node.dataset.spanId;
      renderTimeline(trace);
    });
  }

  for (const node of elements.timelineList.querySelectorAll("[data-toggle-span]")) {
    node.addEventListener("click", (event) => {
      event.stopPropagation();
      const spanId = node.dataset.toggleSpan;
      if (state.expandedSpanIds.has(spanId)) {
        state.expandedSpanIds.delete(spanId);
        const collapsedNode = trace.visibleNodes.find((item) => item.spanId === spanId);
        const descendants = collapsedNode ? descendantSpanIds(collapsedNode) : [];
        if (descendants.includes(state.selectedSpanId)) {
          state.selectedSpanId = spanId;
        }
      } else {
        state.expandedSpanIds.add(spanId);
      }
      renderTimeline(trace);
    });
  }
}

function renderEvidence(trace) {
  if (!state.evidenceExpanded || !trace) {
    elements.evidenceDrawer.classList.add("hidden");
    elements.evidenceDrawer.innerHTML = "";
    return;
  }

  const rawEntries = buildRawEventEntries(trace);
  elements.evidenceDrawer.classList.remove("hidden");
  elements.evidenceDrawer.innerHTML = `
    <div class="drawer-toolbar">
      <span class="drawer-title">调试证据</span>
      <span class="drawer-meta">${escapeHtml(shortId(trace.traceId))}</span>
    </div>
    <div class="raw-event-list">
      ${rawEntries
        .map(
          (entry) => `
            <details class="raw-event">
              <summary>
                <div class="drawer-meta">
                  <span>${escapeHtml(formatClock(entry.ts))}</span>
                  <span class="event-chip">${escapeHtml(entry.label)}</span>
                  <span>${escapeHtml(entry.name)}</span>
                </div>
                <div class="event-summary">${escapeHtml(entry.summary)}</div>
              </summary>
              <pre>${escapeHtml(prettyJson(entry.raw))}</pre>
            </details>
          `,
        )
        .join("")}
    </div>
  `;
}

function render() {
  renderTopbar();
  renderBanner();
  renderRunExplorer();
  renderTraceList();

  const isTimelineView = state.view === VIEW_TIMELINE;
  elements.tracesPage.classList.toggle("hidden", isTimelineView);
  elements.timelinePage.classList.toggle("hidden", !isTimelineView);

  if (!isTimelineView) {
    elements.heroEmpty.classList.add("hidden");
    elements.traceHeaderCard.classList.add("hidden");
    elements.timelinePanel.classList.add("hidden");
    renderEvidence(null);
    return;
  }

  const trace = selectedTrace();
  renderHeader(trace);
  renderTimeline(trace);
  renderEvidence(trace);
}

function applyEvents(events, options = {}) {
  const { sourceLabel = "", health = null, runs = null, selectedRunDir = null } = options;
  state.allTraces = buildTraces(events);
  if (health) {
    state.health = health;
  }
  if (Array.isArray(runs)) {
    state.runs = runs;
  }
  if (selectedRunDir) {
    state.selectedRunDir = selectedRunDir;
  }
  state.sourceLabel = sourceLabel;
  state.loadStatus = "ready";
  state.statusBadge = "connected";
  state.statusLabel = "Runs 已连接";
  state.statusMessage = "";
  syncVisibleTraces();
  normalizeViewState();
  syncRoute();
  render();
}

async function loadRunSnapshot(runEntry, options = {}) {
  if (!runEntry?.eventsPath) {
    throw new Error("run events path missing");
  }
  const text = await fetchRunText(runEntry.eventsPath);
  const events = parseJsonl(text, runEntry.eventsPath);
  state.view = state.view || VIEW_TRACES;
  applyEvents(events, {
    sourceLabel: runEntry.runId || runEntry.traceId || runEntry.dirName || runEntry.eventsPath,
    health: options.health || state.health,
    runs: options.runs || state.runs,
    selectedRunDir: runEntry.dirName,
  });
}

async function selectRunDir(nextRunDir, options = {}) {
  const { push = true, openTimeline = false } = options;
  if (!nextRunDir) {
    return;
  }
  if (nextRunDir === state.selectedRunDir && state.allTraces.length) {
    if (openTimeline) {
      state.view = VIEW_TIMELINE;
      syncVisibleTraces();
      normalizeViewState();
      syncRoute({ push });
      render();
    }
    return;
  }
  state.selectedRunDir = nextRunDir;
  state.selectedTraceId = null;
  state.selectedSpanId = null;
  state.view = openTimeline ? VIEW_TIMELINE : VIEW_TRACES;
  const nextRun = selectedRun();
  if (!nextRun) {
    return;
  }
  await loadRunSnapshot(nextRun, { health: state.health, runs: state.runs });
  if (push) {
    window.history.pushState({}, "", buildRouteHref(state.view, state.selectedRunDir, state.selectedTraceId, state.evidenceExpanded));
  }
}

async function loadLive() {
  state.loadStatus = "loading";
  state.statusBadge = "empty";
  state.statusLabel = "正在加载";
  state.statusMessage = "正在重新读取 runs/index.json";
  state.sourceLabel = "";
  renderTopbar();

  const [healthResult, runsResult] = await Promise.allSettled([fetchHealth(), fetchRunsIndex()]);
  if (healthResult.status === "fulfilled") {
    state.health = healthResult.value;
  }

  if (runsResult.status === "rejected") {
    const view = classifyLoadError(runsResult.reason);
    state.allTraces = [];
    state.visibleTraces = [];
    state.runs = [];
    state.selectedRunDir = null;
    state.selectedTraceId = null;
    state.selectedSpanId = null;
    state.view = VIEW_TRACES;
    state.loadStatus = "error";
    state.statusBadge = view.badge;
    state.statusLabel = view.label;
    state.statusMessage = view.message;
    syncRoute();
    render();
    return;
  }

  try {
    const runsPayload = runsResult.value || {};
    const runs = Array.isArray(runsPayload.runs) ? runsPayload.runs : [];
    if (!runs.length) {
      throw new Error("runs index 文件为空");
    }
    const activeRun = runs.find((item) => item.dirName === state.selectedRunDir) || runs[0];
    await loadRunSnapshot(activeRun, {
      health: state.health,
      runs,
    });
  } catch (error) {
    const view = classifyLoadError(error);
    state.allTraces = [];
    state.visibleTraces = [];
    state.runs = [];
    state.selectedRunDir = null;
    state.selectedTraceId = null;
    state.selectedSpanId = null;
    state.view = VIEW_TRACES;
    state.loadStatus = "error";
    state.statusBadge = view.badge;
    state.statusLabel = view.label;
    state.statusMessage = view.message;
    syncRoute();
    render();
  }
}

async function loadUploadedJsonl(file) {
  if (!file) {
    return;
  }
  state.statusBadge = "empty";
  state.statusLabel = "正在加载";
  state.statusMessage = `正在读取上传文件 ${file.name}`;
  renderTopbar();

  try {
    const text = await file.text();
    const events = parseJsonl(text, `upload:${file.name}`);
    state.view = VIEW_TRACES;
    state.runs = [];
    state.selectedRunDir = null;
    state.selectedTraceId = null;
    state.selectedSpanId = null;
    applyEvents(events, { sourceLabel: `upload:${file.name}` });
  } catch (error) {
    const view = classifyLoadError(error);
    state.loadStatus = "error";
    state.statusBadge = "schema_error";
    state.statusLabel = view.label;
    state.statusMessage = view.message;
    render();
  }
}

elements.refreshButton.addEventListener("click", loadLive);
if (elements.runSelect) {
  elements.runSelect.addEventListener("change", async (event) => {
    await selectRunDir(event.target.value || null);
  });
}
elements.backToTraces.addEventListener("click", () => {
  state.view = VIEW_TRACES;
  syncRoute({ push: true });
  render();
});
elements.filterButton.addEventListener("click", () => {
  state.traceFilter = state.traceFilter === "important" ? "all" : "important";
  syncVisibleTraces();
  normalizeViewState();
  syncRoute();
  render();
});
elements.toggleEvidence.addEventListener("click", () => {
  state.evidenceExpanded = !state.evidenceExpanded;
  syncRoute({ push: true });
  renderEvidence(selectedTrace());
  renderTopbar();
});
elements.traceJsonlInput.addEventListener("change", async (event) => {
  const file = event.target.files?.[0] || null;
  await loadUploadedJsonl(file);
  event.target.value = "";
});

window.addEventListener("popstate", async () => {
  const route = parseRouteFromUrl();
  const runChanged = route.run !== state.selectedRunDir;
  state.view = route.view;
  state.evidenceExpanded = route.evidenceExpanded;
  state.selectedRunDir = route.run;
  if (route.traceId !== null) {
    state.selectedTraceId = route.traceId;
  }
  if (runChanged) {
    await loadLive();
    return;
  }
  syncVisibleTraces();
  normalizeViewState();
  syncRoute();
  render();
});

loadLive();
