import {
  LIVE_URL,
  MIN_VISIBLE_WATERFALL_PCT,
  buildRawEventEntries,
  buildTraces,
  chooseDefaultSpan,
  chooseDefaultTrace,
  escapeHtml,
  fetchHealth,
  fetchLiveText,
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
  const traceId = params.get("traceId");
  return {
    view,
    traceId: traceId && traceId.trim() ? traceId.trim() : null,
    evidenceExpanded: view === VIEW_TIMELINE && parseBooleanFlag(params.get("evidence")),
  };
}

const initialRoute = parseRouteFromUrl();

const state = {
  health: null,
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
  statusMessage: "正在读取 live JSONL",
};

const elements = {
  liveBadge: document.getElementById("live-badge"),
  eventCount: document.getElementById("event-count"),
  lastUpdated: document.getElementById("last-updated"),
  sourceLine: document.getElementById("source-line"),
  backToTraces: document.getElementById("back-to-traces"),
  refreshButton: document.getElementById("refresh-button"),
  filterButton: document.getElementById("filter-button"),
  bannerArea: document.getElementById("banner-area"),
  tracesPage: document.getElementById("traces-page"),
  timelinePage: document.getElementById("timeline-page"),
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

function basename(value) {
  const text = String(value || "");
  if (!text) {
    return "";
  }
  const parts = text.split(/[\\/]/);
  return parts[parts.length - 1] || text;
}

function buildRouteHref(view, traceId = null, evidenceExpanded = false) {
  const url = new URL(window.location.href);
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
  const href = buildRouteHref(state.view, state.selectedTraceId, state.evidenceExpanded);
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
      label: "Live 缺失",
      message: "默认 live 文件还不存在，当前页面暂时没有可展示的数据。",
    };
  }
  if (message.includes("文件为空")) {
    return {
      badge: "empty",
      label: "Live 为空",
      message: "当前 behavior-events.jsonl 为空，等待下一次写入后会出现 trace。",
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

function selectedTrace() {
  return findTraceById(state.visibleTraces, state.selectedTraceId);
}

function countEvents(traces) {
  return traces.reduce((sum, trace) => sum + trace.events.length, 0);
}

function renderStatusBadge(value) {
  const status = String(value || "unknown");
  return `<span class="pill pill-status ${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

function renderTopbar() {
  const health = state.health || {};
  const sourceName = state.sourceLabel || basename(health.liveJsonlPath) || basename(LIVE_URL) || "behavior-events.jsonl";
  const count = health.eventCount ?? countEvents(state.allTraces);
  const updated = health.liveMtime ? formatDateTime(health.liveMtime) : "--";

  elements.liveBadge.className = `live-badge ${state.statusBadge}`;
  elements.liveBadge.textContent = state.statusLabel;
  elements.eventCount.textContent = `${count || 0} events`;
  elements.lastUpdated.textContent = `最后更新 ${updated}`;
  elements.sourceLine.textContent = sourceName;
  elements.backToTraces.classList.toggle("hidden", state.view !== VIEW_TIMELINE);
  elements.filterButton.textContent = state.traceFilter === "important" ? "显示全部" : "仅重要";
  elements.toggleEvidence.textContent = state.evidenceExpanded ? "收起原始事件与调试信息" : "查看原始事件与调试信息";
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
          <span>这些 trace 仍在 live 文件中，可一键切换到“显示全部”。</span>
        </div>
        <button id="show-all-banner" class="banner-button" type="button">显示全部</button>
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
  const { sourceLabel = "", health = null } = options;
  state.allTraces = buildTraces(events);
  if (health) {
    state.health = health;
  }
  state.sourceLabel = sourceLabel;
  state.loadStatus = "ready";
  state.statusBadge = "connected";
  state.statusLabel = "Live 已连接";
  state.statusMessage = "";
  syncVisibleTraces();
  normalizeViewState();
  syncRoute();
  render();
}

async function loadLive() {
  state.loadStatus = "loading";
  state.statusBadge = "empty";
  state.statusLabel = "正在加载";
  state.statusMessage = "正在重新读取 behavior-events.jsonl";
  state.sourceLabel = "";
  renderTopbar();

  const [healthResult, liveResult] = await Promise.allSettled([fetchHealth(), fetchLiveText()]);
  if (healthResult.status === "fulfilled") {
    state.health = healthResult.value;
  }

  if (liveResult.status === "rejected") {
    const view = classifyLoadError(liveResult.reason);
    state.allTraces = [];
    state.visibleTraces = [];
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
    const events = parseJsonl(liveResult.value, LIVE_URL);
    applyEvents(events);
  } catch (error) {
    const view = classifyLoadError(error);
    state.allTraces = [];
    state.visibleTraces = [];
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

window.addEventListener("popstate", () => {
  const route = parseRouteFromUrl();
  state.view = route.view;
  state.evidenceExpanded = route.evidenceExpanded;
  if (route.traceId !== null) {
    state.selectedTraceId = route.traceId;
  }
  syncVisibleTraces();
  normalizeViewState();
  syncRoute();
  render();
});

loadLive();
