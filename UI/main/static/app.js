/**
 * Triagent Main UI - Application Logic
 *
 * Security & Styling Rules:
 * - Strictly textContent and DOM node creation only (NEVER innerHTML)
 * - Meta CSRF token sent in X-CSRF-Token header
 * - Fixed class allowlists: data values never directly become class names or attributes
 * - Amber element (.needs-you) ONLY on "waiting for you" chips or pending indicators
 * - Red (.v-attack) ONLY on confirmed "Real attack" verdicts
 * - Neutral buttons and quiet status chips
 * - Polling with visibility awareness and scroll preservation
 * - URL Hash routing: #/thread/<id>
 */

(function () {
  "use strict";

  // Fixed Allowlists
  const VERDICT_CLASS_MAP = {
    "true_positive": "v-attack",
    "false_positive": "v-safe",
    "needs_more_info": "v-unsure"
  };

  const VERDICT_LABEL_MAP = {
    "true_positive": "Real attack",
    "false_positive": "False alarm",
    "needs_more_info": "Needs more info"
  };

  const STATUS_CLASS_MAP = {
    "working": "st-working",
    "waiting_human": "st-waiting needs-you",
    "done": "st-done",
    "incomplete": "st-incomplete"
  };

  const TOOL_STATUS_MAP = {
    "ok": "chip-ok",
    "error": "chip-error",
    "rejected": "chip-rejected",
    "not_executed": "chip-skipped",
    "waiting": "chip-waiting"
  };

  const DIRECTION_CLASS_MAP = {
    "suspicious": "ev-suspicious",
    "benign": "ev-benign",
    "neutral": "ev-neutral"
  };

  const SENDER_CLASS_MAP = {
    "user": "bubble-user",
    "agent": "bubble-agent"
  };

  // State
  let currentThreadId = null;
  let currentRunState = "idle";
  let threadListPollTimer = null;
  let threadDetailPollTimer = null;
  let renderedItemIds = new Set();
  let detailsOpenState = new Map();
  let allThreads = [];
  let currentFilter = "all";
  let currentSearchQuery = "";
  let currentTimelineTab = "all";

  // Read CSRF Token and HITL port from meta tags
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";

  const hitlMeta = document.querySelector('meta[name="hitl-port"]');
  const hitlPort = hitlMeta ? hitlMeta.getAttribute("content") : "8765";

  // Elements
  const threadListEl = document.getElementById("thread-list");
  const activeRunsBadge = document.getElementById("active-runs-badge");
  const noThreadSelectedEl = document.getElementById("no-thread-selected");
  const emptyStateTitleEl = document.getElementById("empty-state-title");
  const threadViewEl = document.getElementById("thread-view");

  const threadSearchInput = document.getElementById("thread-search-input");
  const filterPillsEl = document.getElementById("filter-pills");
  const countAllEl = document.getElementById("count-all");
  const countWaitingEl = document.getElementById("count-waiting");
  const countAttackEl = document.getElementById("count-attack");
  const countSafeEl = document.getElementById("count-safe");

  const headerTitleEl = document.getElementById("header-title");
  const headerLevelEl = document.getElementById("header-level");
  const headerStatusEl = document.getElementById("header-status");
  const headerHostEl = document.getElementById("header-host");
  const headerUserEl = document.getElementById("header-user");
  const headerTimeEl = document.getElementById("header-time");
  const headerThreadIdEl = document.getElementById("header-thread-id");

  const timelineContainerEl = document.getElementById("timeline-container");
  const timelineItemsEl = document.getElementById("timeline-items");
  const timelineCountBadge = document.getElementById("timeline-count-badge");
  const timelineTabs = document.querySelectorAll(".timeline-tab");

  const inputStatusBanner = document.getElementById("input-status-banner");
  const inputStatusText = document.getElementById("input-status-text");
  const hitlLink = document.getElementById("hitl-link");
  const chatForm = document.getElementById("chat-form");
  const chatInput = document.getElementById("chat-input");
  const chatSendBtn = document.getElementById("chat-send-btn");

  // Helper: DOM Safe Text Element Creator
  function createEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined && text !== null) {
      el.textContent = text;
    }
    return el;
  }

  // Helper: Copy to Clipboard Button
  function createCopyButton(textToCopy) {
    const btn = createEl("button", "copy-btn", "Copy");
    btn.type = "button";
    btn.title = "Copy to clipboard";
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      if (!textToCopy) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textToCopy).then(function () {
          btn.textContent = "✓ Copied";
          btn.classList.add("copied");
          setTimeout(function () {
            btn.textContent = "Copy";
            btn.classList.remove("copied");
          }, 1800);
        }).catch(function () {
          btn.textContent = "Error";
        });
      }
    });
    return btn;
  }

  // Format Level Badge (Neutral: label only, no color)
  function setLevelBadge(el, level) {
    el.textContent = (level || "UNKNOWN").toUpperCase();
    el.className = "level-chip";
  }

  // Format Status Badge (Allowlist lookup only)
  function setStatusBadge(el, status, verdict) {
    el.className = "st-chip";

    if (status === "working") {
      el.textContent = "working";
      el.classList.add("st-working");
    } else if (status === "waiting_human") {
      el.textContent = "waiting for you";
      el.classList.add("st-waiting", "needs-you");
    } else if (status === "done") {
      if (verdict === "true_positive") {
        el.textContent = "Real attack";
        el.classList.add("v-attack");
      } else if (verdict === "false_positive") {
        el.textContent = "False alarm";
        el.classList.add("v-safe");
      } else if (verdict === "needs_more_info") {
        el.textContent = "Needs more info";
        el.classList.add("v-unsure");
      } else {
        el.textContent = "done";
        el.classList.add("st-done");
      }
    } else if (status === "incomplete") {
      el.textContent = "incomplete";
      el.classList.add("st-incomplete");
    } else {
      el.textContent = status || "unknown";
      el.classList.add("st-incomplete");
    }
  }

  // Parse Relative Time
  function formatRelativeTime(isoString) {
    if (!isoString) return "";
    try {
      const date = new Date(isoString);
      if (isNaN(date.getTime())) return isoString;
      const now = new Date();
      const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
      if (diffSec < 10) return "just now";
      if (diffSec < 60) return `${diffSec}s ago`;
      const diffMin = Math.floor(diffSec / 60);
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr}h ago`;
      const diffDay = Math.floor(diffHr / 24);
      return `${diffDay}d ago`;
    } catch (e) {
      return isoString;
    }
  }

  // Hash Navigation: #/thread/<id>
  function getThreadIdFromHash() {
    const hash = window.location.hash || "";
    const match = hash.match(/^#\/thread\/([a-zA-Z0-9_\-]+)$/);
    return match ? match[1] : null;
  }

  function setThreadHash(threadId) {
    if (threadId) {
      window.location.hash = `#/thread/${threadId}`;
    } else {
      window.location.hash = "";
    }
  }

  window.addEventListener("hashchange", function () {
    const newThreadId = getThreadIdFromHash();
    if (newThreadId !== currentThreadId) {
      selectThread(newThreadId, false);
    }
  });

  // Polling: Thread List
  async function fetchThreads() {
    try {
      const resp = await fetch("/api/threads");
      if (!resp.ok) return;
      const threads = await resp.json();
      renderThreadList(threads);
    } catch (e) {
      console.warn("Thread list fetch failed:", e);
    }
  }

  function renderThreadList(threads) {
    allThreads = threads || [];
    applyThreadFilters();
  }

  function applyThreadFilters() {
    let activeCount = 0;
    let waitingHumanCount = 0;
    let attackCount = 0;
    let safeCount = 0;

    allThreads.forEach((t) => {
      if (t.status === "working") activeCount++;
      if (t.status === "waiting_human" || (t.pending_hitl_count && t.pending_hitl_count > 0)) waitingHumanCount++;
      if (t.verdict === "true_positive") attackCount++;
      if (t.verdict === "false_positive") safeCount++;
    });

    if (countAllEl) countAllEl.textContent = allThreads.length ? `(${allThreads.length})` : "";
    if (countWaitingEl) countWaitingEl.textContent = waitingHumanCount ? `(${waitingHumanCount})` : "";
    if (countAttackEl) countAttackEl.textContent = attackCount ? `(${attackCount})` : "";
    if (countSafeEl) countSafeEl.textContent = safeCount ? `(${safeCount})` : "";

    const query = (currentSearchQuery || "").toLowerCase().trim();

    const filtered = allThreads.filter((t) => {
      if (currentFilter === "waiting" && t.status !== "waiting_human" && !(t.pending_hitl_count && t.pending_hitl_count > 0)) {
        return false;
      }
      if (currentFilter === "attack" && t.verdict !== "true_positive") {
        return false;
      }
      if (currentFilter === "safe" && t.verdict !== "false_positive") {
        return false;
      }

      if (query) {
        const titleMatch = (t.title || "").toLowerCase().includes(query);
        const hostMatch = (t.host || "").toLowerCase().includes(query);
        const userMatch = (t.user || "").toLowerCase().includes(query);
        const idMatch = (t.thread_id || "").toLowerCase().includes(query);
        if (!titleMatch && !hostMatch && !userMatch && !idMatch) {
          return false;
        }
      }

      return true;
    });

    renderFilteredThreadList(filtered, activeCount, waitingHumanCount);
  }

  function renderFilteredThreadList(threads, activeCount, waitingHumanCount) {
    if (!threads || threads.length === 0) {
      threadListEl.textContent = "";
      const msg = allThreads.length === 0 ? "No alert threads found." : "No matching alerts found.";
      threadListEl.appendChild(createEl("div", "empty-state", msg));
      if (activeRunsBadge) activeRunsBadge.textContent = `${activeCount} active`;
      return;
    }

    const fragment = document.createDocumentFragment();

    threads.forEach((t) => {
      const card = createEl("a", "thread-card");
      card.href = `#/thread/${t.thread_id}`;
      card.dataset.threadId = t.thread_id;
      if (t.thread_id === currentThreadId) {
        card.setAttribute("aria-current", "true");
        card.classList.add("active");
      }

      card.addEventListener("click", function (e) {
        e.preventDefault();
        setThreadHash(t.thread_id);
      });

      const title = createEl("div", "thread-card-title", t.title || "Untitled Alert");
      card.appendChild(title);

      const meta = createEl("div", "thread-card-meta");
      const hostSpan = createEl("span", null, t.host || "Unknown host");
      const timeSpan = createEl("span", null, formatRelativeTime(t.updated_at));
      meta.appendChild(hostSpan);
      meta.appendChild(timeSpan);
      card.appendChild(meta);

      const badges = createEl("div", "thread-card-badges");
      const lvl = createEl("span");
      setLevelBadge(lvl, t.level);
      badges.appendChild(lvl);

      const st = createEl("span");
      setStatusBadge(st, t.status, t.verdict);
      badges.appendChild(st);

      card.appendChild(badges);
      fragment.appendChild(card);
    });

    if (activeRunsBadge) activeRunsBadge.textContent = `${activeCount} active`;
    threadListEl.textContent = "";
    threadListEl.appendChild(fragment);

    // Update empty state banner according to waiting status
    if (emptyStateTitleEl) {
      emptyStateTitleEl.textContent = "";
      if (waitingHumanCount > 0) {
        const span = createEl("span", "needs-you", `${waitingHumanCount} thing${waitingHumanCount === 1 ? "" : "s"} need${waitingHumanCount === 1 ? "s" : ""} you`);
        emptyStateTitleEl.appendChild(span);
      } else {
        emptyStateTitleEl.textContent = "Watching. Nothing needs you right now.";
      }
    }
  }

  // Select and Open Thread
  async function selectThread(threadId, updateHash = true) {
    if (!threadId) {
      currentThreadId = null;
      noThreadSelectedEl.classList.remove("hidden");
      threadViewEl.classList.add("hidden");
      return;
    }

    currentThreadId = threadId;
    if (updateHash) {
      setThreadHash(threadId);
    }

    // Highlight in sidebar
    document.querySelectorAll(".thread-card").forEach((c) => {
      if (c.getAttribute("href") === `#/thread/${threadId}`) {
        c.setAttribute("aria-current", "true");
        c.classList.add("active");
      } else {
        c.removeAttribute("aria-current");
        c.classList.remove("active");
      }
    });

    noThreadSelectedEl.classList.add("hidden");
    threadViewEl.classList.remove("hidden");

    // Reset items tracking for this thread
    renderedItemIds.clear();
    timelineItemsEl.textContent = "";

    await fetchThreadDetail();
  }

  // Polling: Thread Details
  async function fetchThreadDetail() {
    if (!currentThreadId) return;

    try {
      const resp = await fetch(`/api/threads/${encodeURIComponent(currentThreadId)}`);
      if (resp.status === 404) {
        timelineItemsEl.textContent = "";
        timelineItemsEl.appendChild(createEl("div", "empty-state", "Thread not found or deleted."));
        return;
      }
      if (!resp.ok) return;

      const data = await resp.json();
      renderThreadDetail(data);
    } catch (e) {
      console.warn("Thread detail fetch error:", e);
    } finally {
      scheduleThreadDetailPoll();
    }
  }

  function scheduleThreadDetailPoll() {
    if (threadDetailPollTimer) clearTimeout(threadDetailPollTimer);
    if (!currentThreadId || document.hidden) return;

    const interval = currentRunState === "running" ? 1500 : 5000;
    threadDetailPollTimer = setTimeout(fetchThreadDetail, interval);
  }

  // Render Thread Details and Timeline
  function renderThreadDetail(data) {
    const thread = data.thread || {};
    const items = data.items || [];
    const run = data.run || {};

    currentRunState = run.state || "idle";

    // Header values
    headerTitleEl.textContent = thread.title || "Investigation";
    setLevelBadge(headerLevelEl, thread.level);
    setStatusBadge(headerStatusEl, thread.status, thread.verdict);
    headerHostEl.textContent = `Host: ${thread.host || "unknown"}`;
    headerUserEl.textContent = `User: ${thread.user || "unknown"}`;
    headerTimeEl.textContent = formatRelativeTime(thread.updated_at);
    headerThreadIdEl.textContent = thread.thread_id || "";

    // Input box state
    updateInputBoxState(run);

    // Save scroll position before updating items
    const isAtBottom =
      timelineContainerEl.scrollHeight - timelineContainerEl.scrollTop - timelineContainerEl.clientHeight <= 40;

    // Render items by item ID (preserve open details & scroll)
    items.forEach((item) => {
      const itemId = item.id;
      let existing = document.getElementById(`item_${itemId}`);

      if (existing) {
        updateTimelineItemNode(existing, item);
      } else {
        const itemNode = createTimelineItemNode(item);
        if (itemNode) {
          itemNode.id = `item_${itemId}`;
          timelineItemsEl.appendChild(itemNode);
          renderedItemIds.add(itemId);
        }
      }
    });

    filterAllTimelineItems();

    if (isAtBottom) {
      timelineContainerEl.scrollTop = timelineContainerEl.scrollHeight;
    }
  }

  function applyTimelineTabFilter(node) {
    if (!node || !node.dataset) return;
    const type = node.dataset.itemType;
    let visible = true;
    if (currentTimelineTab === "tools") {
      visible = (type === "tool");
    } else if (currentTimelineTab === "decisions") {
      visible = (type === "verdict" || type === "action" || type === "ask_user" || type === "verdict_rejected");
    } else if (currentTimelineTab === "chat") {
      visible = (type === "chat_bubble" || type === "ask_user");
    }
    if (visible) {
      node.classList.remove("hidden");
    } else {
      node.classList.add("hidden");
    }
  }

  function filterAllTimelineItems() {
    const children = timelineItemsEl.querySelectorAll(".item-card, .chat-bubble-container, .verdict-superseded-container, .timeline-note");
    let visibleCount = 0;
    children.forEach((child) => {
      applyTimelineTabFilter(child);
      if (!child.classList.contains("hidden")) {
        visibleCount++;
      }
    });
    if (timelineCountBadge) {
      timelineCountBadge.textContent = `${visibleCount} item${visibleCount === 1 ? "" : "s"}`;
    }
  }

  function updateInputBoxState(run) {
    const state = run.state || "idle";

    if (state === "running") {
      chatInput.disabled = true;
      chatSendBtn.disabled = true;
      inputStatusBanner.classList.remove("hidden");
      inputStatusText.textContent = "Agent investigation in progress... (waiting for response)";
      hitlLink.classList.add("hidden");
    } else if (state === "waiting_human") {
      chatInput.disabled = true;
      chatSendBtn.disabled = true;
      inputStatusBanner.classList.remove("hidden");
      inputStatusText.textContent = "Waiting for human approval on a sensitive operation.";
      hitlLink.href = `http://127.0.0.1:${hitlPort}/`;
      hitlLink.classList.remove("hidden");
    } else {
      chatInput.disabled = false;
      chatSendBtn.disabled = false;
      inputStatusBanner.classList.add("hidden");
      hitlLink.classList.add("hidden");
    }
  }

  // Create Specific Timeline Items
  function createTimelineItemNode(item) {
    let node = null;
    switch (item.type) {
      case "alert":
        node = renderAlertCard(item);
        break;
      case "plan":
        node = renderPlanCard(item);
        break;
      case "tool":
        node = renderToolCard(item);
        break;
      case "action":
        node = renderActionCard(item);
        break;
      case "ask_user":
        node = renderAskUserCard(item);
        break;
      case "chat_bubble":
        node = renderChatBubble(item);
        break;
      case "verdict_rejected":
        node = renderVerdictRejectedChip(item);
        break;
      case "verdict":
        node = renderVerdictCard(item);
        break;
      case "note":
        node = renderNoteItem(item);
        break;
      default:
        return null;
    }
    if (node) {
      node.dataset.itemType = item.type;
      applyTimelineTabFilter(node);
    }
    return node;
  }

  function updateTimelineItemNode(node, item) {
    const replacement = createTimelineItemNode(item);
    if (replacement && node.parentNode) {
      replacement.id = node.id;
      const oldDetails = node.querySelector("details");
      const newDetails = replacement.querySelector("details");
      if (oldDetails && newDetails && oldDetails.open) {
        newDetails.open = true;
      }
      node.parentNode.replaceChild(replacement, node);
    }
  }

  // 1. Alert Card
  function renderAlertCard(item) {
    const card = createEl("div", "item-card alert-card");

    const header = createEl("div", "alert-card-header");
    const title = createEl("strong", null, item.title || "Triggered Security Alert");
    const lvl = createEl("span");
    setLevelBadge(lvl, item.level);
    header.appendChild(title);
    header.appendChild(lvl);
    card.appendChild(header);

    const grid = createEl("div", "alert-card-grid");
    const hostBox = createEl("div", "alert-grid-item");
    hostBox.appendChild(createEl("span", null, "Host:"));
    hostBox.appendChild(createEl("span", null, item.host || "unknown"));
    grid.appendChild(hostBox);

    const userBox = createEl("div", "alert-grid-item");
    userBox.appendChild(createEl("span", null, "User:"));
    userBox.appendChild(createEl("span", null, item.user || "unknown"));
    grid.appendChild(userBox);

    const procBox = createEl("div", "alert-grid-item");
    procBox.appendChild(createEl("span", null, "Process:"));
    procBox.appendChild(createEl("span", null, item.process_name || "unknown"));
    grid.appendChild(procBox);

    card.appendChild(grid);

    if (item.command_line) {
      const cmdRow = createEl("div", "code-header-row");
      cmdRow.appendChild(createEl("span", "meta-item", "Command:"));
      cmdRow.appendChild(createCopyButton(item.command_line));
      card.appendChild(cmdRow);

      const cmd = createEl("div", "alert-cmd", item.command_line);
      card.appendChild(cmd);
    }

    if (item.raw_alert) {
      const det = createEl("details", "tool-details");
      det.appendChild(createEl("summary", null, "Raw Alert Event"));

      const rawRow = createEl("div", "code-header-row");
      rawRow.appendChild(createEl("span", "meta-item", "Event data"));
      rawRow.appendChild(createCopyButton(item.raw_alert));
      det.appendChild(rawRow);

      const body = createEl("pre", "tool-result-body", item.raw_alert);
      det.appendChild(body);
      card.appendChild(det);
    }

    return card;
  }

  // 2. Plan Card
  function renderPlanCard(item) {
    const card = createEl("div", "item-card plan-card");
    card.appendChild(createEl("div", "plan-title", "Investigation Plan"));

    const stepsList = createEl("ol", "plan-steps");
    (item.steps || []).forEach((st) => {
      stepsList.appendChild(createEl("li", null, st));
    });
    card.appendChild(stepsList);
    return card;
  }

  // 3. Compact Tool Card (Quiet, neutral status chip)
  function renderToolCard(item) {
    const card = createEl("div", "item-card tool-card");

    const header = createEl("div", "tool-card-header");
    const nameSpan = createEl("span", "tool-name", item.tool_name);
    header.appendChild(nameSpan);

    const rawStatus = item.status || "ok";
    const statusClass = TOOL_STATUS_MAP[rawStatus] || "chip-neutral";
    const chip = createEl("span", "chip " + statusClass, rawStatus);

    header.appendChild(chip);
    card.appendChild(header);

    if (item.args && Object.keys(item.args).length > 0) {
      const argsBox = createEl("div", "tool-args-box");
      const argsRow = createEl("div", "code-header-row");
      argsRow.appendChild(createEl("span", null, "Arguments:"));
      let argsText = "";
      for (const [k, v] of Object.entries(item.args)) {
        argsText += `${k}: ${v}\n`;
      }
      argsRow.appendChild(createCopyButton(argsText.trim()));
      argsBox.appendChild(argsRow);

      for (const [k, v] of Object.entries(item.args)) {
        const line = createEl("div", null, `${k}: ${v}`);
        argsBox.appendChild(line);
      }
      card.appendChild(argsBox);
    }

    if (item.result_preview || item.result_full) {
      const resText = item.result_full || item.result_preview;
      const det = createEl("details", "tool-details");
      det.addEventListener("toggle", function () {
        detailsOpenState.set(item.id, det.open);
      });
      if (detailsOpenState.get(item.id)) {
        det.open = true;
      }
      det.appendChild(createEl("summary", null, "View tool output"));

      const outRow = createEl("div", "code-header-row");
      outRow.appendChild(createEl("span", "meta-item", "Output text"));
      outRow.appendChild(createCopyButton(resText));
      det.appendChild(outRow);

      const body = createEl("pre", "tool-result-body", resText);
      det.appendChild(body);
      card.appendChild(det);
    }

    return card;
  }

  // 4. Action Card (Human Decision: neutral styling)
  function renderActionCard(item) {
    const card = createEl("div", "item-card action-card");

    const header = createEl("div", "action-header");
    const title = createEl("span", "action-target", `${item.tool_name}: ${item.target}`);
    header.appendChild(title);

    const dec = item.decision || "pending";
    let decisionText = "Pending decision";
    if (dec === "approved") decisionText = "You approved";
    else if (dec === "rejected" || dec === "blocked") decisionText = "You rejected";
    else if (dec === "dry_run") decisionText = "Dry run";
    else if (dec === "expired") decisionText = "Expired";

    const badge = createEl("span", "chip", decisionText);
    header.appendChild(badge);
    card.appendChild(header);

    if (item.reason) {
      card.appendChild(createEl("div", "tool-card-meta", `Reason: ${item.reason}`));
    }
    if (item.details) {
      const detRow = createEl("div", "code-header-row");
      detRow.appendChild(createEl("span", "meta-item", "Action payload"));
      detRow.appendChild(createCopyButton(item.details));
      card.appendChild(detRow);
      card.appendChild(createEl("div", "alert-cmd", item.details));
    }
    return card;
  }

  // 5. Ask User Card
  function renderAskUserCard(item) {
    const card = createEl("div", "item-card ask-user-card");
    card.appendChild(createEl("div", "ask-user-question", `Question: ${item.question}`));

    if (item.choices && item.choices.length > 0) {
      const ul = createEl("ul", "ask-user-choices");
      item.choices.forEach((c) => {
        ul.appendChild(createEl("li", null, c));
      });
      card.appendChild(ul);
    }

    const answerDiv = createEl("div", null);
    if (item.status === "answered" && item.answer) {
      answerDiv.appendChild(createEl("span", "ask-user-answer", `Answer: ${item.answer}`));
    } else {
      const waitChip = createEl("span", "chip", `Status: ${item.status || "pending"}`);
      answerDiv.appendChild(waitChip);
    }
    card.appendChild(answerDiv);
    return card;
  }

  // 6. Chat Bubbles
  function renderChatBubble(item) {
    const sender = item.sender === "user" ? "user" : "agent";
    const senderClass = SENDER_CLASS_MAP[sender] || "bubble-agent";

    const container = createEl("div", "chat-bubble-container " + senderClass);
    const bubble = createEl("div", "chat-bubble " + senderClass);

    if (item.unstructured) {
      bubble.appendChild(createEl("span", "unstructured-tag", "Unstructured reply"));
    }

    const textNode = document.createTextNode(item.text || "");
    bubble.appendChild(textNode);
    container.appendChild(bubble);
    return container;
  }

  // 7. Verdict Rejected Chip
  function renderVerdictRejectedChip(item) {
    const chip = createEl("div", "verdict-rejected-chip");
    const errText = (item.errors || []).join("; ") || "Verdict submission rejected, agent retrying";
    chip.textContent = `Verdict rejected: ${errText}`;
    return chip;
  }

  // 8. Verdict Card (Prominent & Complete)
  function renderVerdictCard(item) {
    const isSuperseded = Boolean(item.superseded);
    let wrapper = null;

    if (isSuperseded) {
      wrapper = createEl("details", "verdict-superseded-container");
      wrapper.appendChild(createEl("summary", null, `Revision ${item.revision} (Superseded - click to view)`));
    }

    const vClass = VERDICT_CLASS_MAP[item.verdict] || "v-unsure";
    const vLabel = VERDICT_LABEL_MAP[item.verdict] || "Needs more info";

    const card = createEl("div", "verdict-card " + vClass);

    // Header: Headline Badge & Classification Badges
    const header = createEl("div", "verdict-header");

    const headlineBadge = createEl("span", "verdict-headline-badge " + vClass, vLabel);
    header.appendChild(headlineBadge);

    const rightBadges = createEl("div", "thread-card-badges");
    if (item.severity) {
      const sevBadge = createEl("span");
      setLevelBadge(sevBadge, item.severity);
      rightBadges.appendChild(sevBadge);
    }
    if (item.confidence) {
      rightBadges.appendChild(createEl("span", "chip", `Confidence: ${item.confidence}`));
    }
    if (item.category) {
      rightBadges.appendChild(createEl("span", "chip", `Category: ${item.category}`));
    }
    header.appendChild(rightBadges);
    card.appendChild(header);

    // Summary Headline
    card.appendChild(createEl("h3", "verdict-summary", item.summary));

    // Explanation
    if (item.explanation) {
      card.appendChild(createEl("p", "verdict-explanation", item.explanation));
    }

    // Evidence Section
    if (item.evidence && item.evidence.length > 0) {
      const evSec = createEl("div", "verdict-section");
      evSec.appendChild(createEl("div", "verdict-section-title", "Verified Evidence"));
      const evList = createEl("ul", "evidence-list");

      item.evidence.forEach((ev) => {
        const li = createEl("li", "evidence-item");
        const rawDir = (ev.direction || "neutral").toLowerCase();
        const dirClass = DIRECTION_CLASS_MAP[rawDir] || "ev-neutral";
        const dirLabel = rawDir === "suspicious" ? "[SUSPICIOUS]" : rawDir === "benign" ? "[BENIGN]" : "[NEUTRAL]";

        const dirBadge = createEl("span", "direction-badge " + dirClass, dirLabel);
        li.appendChild(dirBadge);
        li.appendChild(createEl("span", null, `${ev.finding} (source: ${ev.source_tool || "unknown"})`));
        evList.appendChild(li);
      });

      evSec.appendChild(evList);
      card.appendChild(evSec);
    }

    // What AI Couldn't Verify (Assumptions + Not Checked)
    const unverified = [
      ...(item.assumptions || []).map((a) => `Assumption: ${a}`),
      ...(item.not_checked || []).map((nc) => `Not checked: ${nc}`),
    ];
    if (unverified.length > 0) {
      const unvSec = createEl("div", "verdict-section");
      unvSec.appendChild(createEl("div", "verdict-section-title", "What Triagent Couldn't Verify"));
      const ul = createEl("ul", "evidence-list");
      unverified.forEach((u) => {
        ul.appendChild(createEl("li", "evidence-item", u));
      });
      unvSec.appendChild(ul);
      card.appendChild(unvSec);
    }

    // Recommended Next Steps
    if (item.recommended_next_steps && item.recommended_next_steps.length > 0) {
      const recSec = createEl("div", "verdict-section");
      recSec.appendChild(createEl("div", "verdict-section-title", "Recommended Next Steps"));
      const ol = createEl("ol", "plan-steps");
      item.recommended_next_steps.forEach((r) => {
        ol.appendChild(createEl("li", null, r));
      });
      recSec.appendChild(ol);
      card.appendChild(recSec);
    }

    // Conditional Fields
    if (item.benign_explanation) {
      const benSec = createEl("div", "verdict-section");
      benSec.appendChild(createEl("div", "verdict-section-title", "Benign Explanation"));
      benSec.appendChild(createEl("p", null, item.benign_explanation));
      card.appendChild(benSec);
    }
    if (item.remaining_risk || item.threat_active) {
      const riskSec = createEl("div", "verdict-section");
      riskSec.appendChild(createEl("div", "verdict-section-title", "Remaining Risk & Threat Status"));
      if (item.threat_active) {
        riskSec.appendChild(createEl("p", null, `Threat Active: ${item.threat_active}`));
      }
      if (item.remaining_risk) {
        riskSec.appendChild(createEl("p", null, `Remaining Risk: ${item.remaining_risk}`));
      }
      card.appendChild(riskSec);
    }
    if (item.missing_info) {
      const misSec = createEl("div", "verdict-section");
      misSec.appendChild(createEl("div", "verdict-section-title", "Missing Information"));
      misSec.appendChild(createEl("p", null, item.missing_info));
      card.appendChild(misSec);
    }

    // Room for future Agree/Disagree buttons
    const placeholder = createEl("div", "verdict-actions-placeholder");
    card.appendChild(placeholder);

    // Footer: Revision, Duration, Turns, Tool Count
    const footer = createEl("div", "verdict-footer");
    const ftData = item.footer || {};
    footer.appendChild(createEl("span", null, `Revision: ${item.revision || 1}`));
    if (ftData.duration_seconds !== null && ftData.duration_seconds !== undefined) {
      footer.appendChild(createEl("span", null, `Duration: ${ftData.duration_seconds}s`));
    }
    footer.appendChild(createEl("span", null, `Turns: ${ftData.turns || 0}`));
    footer.appendChild(createEl("span", null, `Tools Used: ${ftData.tool_count || 0}`));
    card.appendChild(footer);

    if (wrapper) {
      wrapper.appendChild(card);
      return wrapper;
    }
    return card;
  }

  // 9. Note Item
  function renderNoteItem(item) {
    return createEl("div", "timeline-note", item.text || "Note");
  }

  // User Chat Submission
  chatForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    await submitChatMessage();
  });

  chatInput.addEventListener("keydown", async function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      await submitChatMessage();
    }
  });

  if (chatInput) {
    chatInput.addEventListener("input", function () {
      chatInput.style.height = "auto";
      chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + "px";
    });
  }

  async function submitChatMessage() {
    if (!currentThreadId) return;
    const text = chatInput.value.trim();
    if (!text) return;

    chatInput.disabled = true;
    chatSendBtn.disabled = true;

    try {
      const resp = await fetch(`/api/threads/${encodeURIComponent(currentThreadId)}/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        body: JSON.stringify({ text: text }),
      });

      if (resp.status === 202) {
        chatInput.value = "";
        chatInput.style.height = "auto";
        currentRunState = "running";
        updateInputBoxState({ state: "running" });
        scheduleThreadDetailPoll();
      } else if (resp.status === 409) {
        const err = await resp.json();
        alert(`Cannot send message: ${err.reason === "waiting_human" ? "waiting for human decision" : "investigation currently running"}`);
      } else if (resp.status === 429) {
        alert("Cannot send message: thread has reached the maximum allowed resumes.");
      } else {
        const err = await resp.json().catch(() => ({}));
        alert(`Failed to send message (${resp.status}): ${err.error || "Server error"}`);
      }
    } catch (e) {
      alert(`Network error: ${e.message}`);
    } finally {
      if (currentRunState !== "running") {
        chatInput.disabled = false;
        chatSendBtn.disabled = false;
        chatInput.focus();
      }
    }
  }

  // Search Input Listener
  if (threadSearchInput) {
    threadSearchInput.addEventListener("input", function () {
      currentSearchQuery = threadSearchInput.value;
      applyThreadFilters();
    });
  }

  // Filter Pills Listener
  if (filterPillsEl) {
    filterPillsEl.addEventListener("click", function (e) {
      const btn = e.target.closest(".filter-pill");
      if (!btn) return;
      filterPillsEl.querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.dataset.filter || "all";
      applyThreadFilters();
    });
  }

  // Timeline Tab Filters Listener
  timelineTabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      timelineTabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      currentTimelineTab = tab.dataset.tab || "all";
      filterAllTimelineItems();
    });
  });

  // Global Keyboard Shortcuts (/, Esc, Arrow keys, j/k)
  window.addEventListener("keydown", function (e) {
    const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : "";
    const isTyping = activeTag === "input" || activeTag === "textarea";

    if (e.key === "/" && !isTyping) {
      if (threadSearchInput) {
        e.preventDefault();
        threadSearchInput.focus();
        threadSearchInput.select();
      }
      return;
    }

    if (e.key === "Escape") {
      if (threadSearchInput && document.activeElement === threadSearchInput) {
        threadSearchInput.value = "";
        currentSearchQuery = "";
        threadSearchInput.blur();
        applyThreadFilters();
        return;
      }
    }

    if (!isTyping && (e.key === "ArrowDown" || e.key === "j" || e.key === "ArrowUp" || e.key === "k")) {
      const visibleCards = Array.from(threadListEl.querySelectorAll(".thread-card"));
      if (visibleCards.length === 0) return;

      let currentIndex = visibleCards.findIndex((c) => c.dataset.threadId === currentThreadId);
      let nextIndex = currentIndex;

      if (e.key === "ArrowDown" || e.key === "j") {
        nextIndex = currentIndex < visibleCards.length - 1 ? currentIndex + 1 : 0;
      } else if (e.key === "ArrowUp" || e.key === "k") {
        nextIndex = currentIndex > 0 ? currentIndex - 1 : visibleCards.length - 1;
      }

      if (nextIndex >= 0 && nextIndex < visibleCards.length) {
        e.preventDefault();
        const nextCard = visibleCards[nextIndex];
        const nextId = nextCard.dataset.threadId;
        if (nextId) {
          setThreadHash(nextId);
          nextCard.scrollIntoView({ block: "nearest", behavior: "smooth" });
        }
      }
    }
  });

  // Visibility Change Handling: Pause polling when tab is hidden
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      fetchThreads();
      if (currentThreadId) {
        fetchThreadDetail();
      }
    }
  });

  // Initialization
  function init() {
    const initThreadId = getThreadIdFromHash();
    if (initThreadId) {
      selectThread(initThreadId, false);
    }

    fetchThreads();
    threadListPollTimer = setInterval(function () {
      if (!document.hidden) {
        fetchThreads();
      }
    }, 2000);
  }

  init();
})();
