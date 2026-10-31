/**
 * BlueTeamingAI Main UI - Application Logic
 *
 * Security:
 * - Strictly textContent and createTextNode only (NEVER innerHTML)
 * - Meta CSRF token sent in X-CSRF-Token header
 * - Polling with visibility awareness and scroll preservation
 * - URL Hash routing: #/thread/<id>
 */

(function () {
  "use strict";

  // State
  let currentThreadId = null;
  let currentRunState = "idle";
  let threadListPollTimer = null;
  let threadDetailPollTimer = null;
  let renderedItemIds = new Set();
  let detailsOpenState = new Map();

  // Read CSRF Token and HITL port from meta tags
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";

  const hitlMeta = document.querySelector('meta[name="hitl-port"]');
  const hitlPort = hitlMeta ? hitlMeta.getAttribute("content") : "8765";

  // Elements
  const threadListEl = document.getElementById("thread-list");
  const activeRunsBadge = document.getElementById("active-runs-badge");
  const noThreadSelectedEl = document.getElementById("no-thread-selected");
  const threadViewEl = document.getElementById("thread-view");

  const headerTitleEl = document.getElementById("header-title");
  const headerLevelEl = document.getElementById("header-level");
  const headerStatusEl = document.getElementById("header-status");
  const headerHostEl = document.getElementById("header-host");
  const headerUserEl = document.getElementById("header-user");
  const headerTimeEl = document.getElementById("header-time");
  const headerThreadIdEl = document.getElementById("header-thread-id");

  const timelineContainerEl = document.getElementById("timeline-container");
  const timelineItemsEl = document.getElementById("timeline-items");

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

  // Format Level Badge
  function setLevelBadge(el, level) {
    el.textContent = (level || "UNKNOWN").toUpperCase();
    el.className = "badge";
    const l = (level || "").toLowerCase();
    if (l === "critical" || l === "high") {
      el.classList.add("badge-danger");
    } else if (l === "medium") {
      el.classList.add("badge-warning");
    } else if (l === "low") {
      el.classList.add("badge-info");
    } else {
      el.classList.add("badge-subtle");
    }
  }

  // Format Status Badge
  function setStatusBadge(el, status, verdict) {
    el.className = "badge";
    if (status === "working") {
      el.textContent = "Working...";
      el.classList.add("badge-warning");
    } else if (status === "waiting_human") {
      el.textContent = "Waiting for you";
      el.classList.add("badge-danger");
    } else if (status === "done") {
      if (verdict === "true_positive") {
        el.textContent = "Real attack";
        el.classList.add("badge-danger");
      } else if (verdict === "false_positive") {
        el.textContent = "False alarm";
        el.classList.add("badge-success");
      } else if (verdict === "needs_more_info") {
        el.textContent = "Needs more info";
        el.classList.add("badge-warning");
      } else {
        el.textContent = "Done";
        el.classList.add("badge-success");
      }
    } else if (status === "incomplete") {
      el.textContent = "Incomplete";
      el.classList.add("badge-subtle");
    } else {
      el.textContent = status || "Unknown";
      el.classList.add("badge-subtle");
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
    if (!threads || threads.length === 0) {
      threadListEl.textContent = "";
      threadListEl.appendChild(createEl("div", "empty-state", "No alert threads found."));
      activeRunsBadge.textContent = "0 active";
      return;
    }

    let activeCount = 0;
    const fragment = document.createDocumentFragment();

    threads.forEach((t) => {
      if (t.status === "working") activeCount++;

      const card = createEl("a", "thread-card");
      card.href = `#/thread/${t.thread_id}`;
      if (t.thread_id === currentThreadId) {
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

    activeRunsBadge.textContent = `${activeCount} active`;
    threadListEl.textContent = "";
    threadListEl.appendChild(fragment);
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
        c.classList.add("active");
      } else {
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

    // 1.5s while working, 5s otherwise
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
        // If changed, update content
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

    // Auto-scroll to bottom only if user was already at bottom
    if (isAtBottom) {
      timelineContainerEl.scrollTop = timelineContainerEl.scrollHeight;
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
    switch (item.type) {
      case "alert":
        return renderAlertCard(item);
      case "plan":
        return renderPlanCard(item);
      case "tool":
        return renderToolCard(item);
      case "action":
        return renderActionCard(item);
      case "ask_user":
        return renderAskUserCard(item);
      case "chat_bubble":
        return renderChatBubble(item);
      case "verdict_rejected":
        return renderVerdictRejectedChip(item);
      case "verdict":
        return renderVerdictCard(item);
      case "note":
        return renderNoteItem(item);
      default:
        return null;
    }
  }

  function updateTimelineItemNode(node, item) {
    const replacement = createTimelineItemNode(item);
    if (replacement && node.parentNode) {
      replacement.id = node.id;
      // Preserve open details state
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
      const cmd = createEl("div", "alert-cmd", item.command_line);
      card.appendChild(cmd);
    }

    if (item.raw_alert) {
      const det = createEl("details", "tool-details");
      det.appendChild(createEl("summary", null, "Raw Alert Event"));
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

  // 3. Compact Tool Card
  function renderToolCard(item) {
    const card = createEl("div", "item-card tool-card");

    const header = createEl("div", "tool-card-header");
    const nameSpan = createEl("span", "tool-name", item.tool_name);
    header.appendChild(nameSpan);

    const chip = createEl("span", "badge");
    const st = item.status || "ok";
    chip.textContent = st;
    if (st === "ok") chip.classList.add("badge-success");
    else if (st === "error" || st === "rejected") chip.classList.add("badge-danger");
    else if (st === "not_executed" || st === "waiting") chip.classList.add("badge-warning");
    else chip.classList.add("badge-subtle");

    header.appendChild(chip);
    card.appendChild(header);

    // Args box
    if (item.args && Object.keys(item.args).length > 0) {
      const argsBox = createEl("div", "tool-args-box");
      for (const [k, v] of Object.entries(item.args)) {
        const line = createEl("div", null, `${k}: ${v}`);
        argsBox.appendChild(line);
      }
      card.appendChild(argsBox);
    }

    // Collapsible Result
    if (item.result_preview || item.result_full) {
      const det = createEl("details", "tool-details");
      det.addEventListener("toggle", function () {
        detailsOpenState.set(item.id, det.open);
      });
      if (detailsOpenState.get(item.id)) {
        det.open = true;
      }
      det.appendChild(createEl("summary", null, "View Tool Output"));
      const body = createEl("pre", "tool-result-body", item.result_full || item.result_preview);
      det.appendChild(body);
      card.appendChild(det);
    }

    return card;
  }

  // 4. Action Card (kill_process / quarantine_file)
  function renderActionCard(item) {
    const card = createEl("div", "item-card action-card");

    const header = createEl("div", "action-header");
    const title = createEl("span", "action-target", `${item.tool_name}: ${item.target}`);
    header.appendChild(title);

    const badge = createEl("span", "badge");
    const dec = item.decision || "pending";
    badge.textContent = `Decision: ${dec}`;
    if (dec === "approved") badge.classList.add("badge-success");
    else if (dec === "rejected" || dec === "blocked") badge.classList.add("badge-danger");
    else if (dec === "dry_run") badge.classList.add("badge-info");
    else badge.classList.add("badge-warning");

    header.appendChild(badge);
    card.appendChild(header);

    if (item.reason) {
      card.appendChild(createEl("div", "tool-card-meta", `Reason: ${item.reason}`));
    }
    if (item.details) {
      card.appendChild(createEl("div", "alert-cmd", item.details));
    }
    return card;
  }

  // 5. Ask User Card
  function renderAskUserCard(item) {
    const card = createEl("div", "item-card ask-user-card");
    card.appendChild(createEl("div", "ask-user-question", `Human Question: ${item.question}`));

    if (item.choices && item.choices.length > 0) {
      const ul = createEl("ul", "ask-user-choices");
      item.choices.forEach((c) => {
        ul.appendChild(createEl("li", null, c));
      });
      card.appendChild(ul);
    }

    const answerDiv = createEl("div", null);
    if (item.status === "answered" && item.answer) {
      answerDiv.appendChild(createEl("span", "ask-user-answer", `User Answer: ${item.answer}`));
    } else {
      const waitChip = createEl("span", "badge badge-warning", `Status: ${item.status || "pending"}`);
      answerDiv.appendChild(waitChip);
    }
    card.appendChild(answerDiv);
    return card;
  }

  // 6. Chat Bubbles
  function renderChatBubble(item) {
    const container = createEl("div", `chat-bubble-container ${item.sender}`);
    const bubble = createEl("div", `chat-bubble ${item.sender}`);

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
    chip.textContent = `Verdict submission rejected: ${errText}`;
    return chip;
  }

  // 8. Verdict Card (Prominent & Complete)
  function renderVerdictCard(item) {
    const isSuperseded = Boolean(item.superseded);

    // If superseded, wrap in a collapsed details element
    let wrapper = null;
    let cardParent = null;

    if (isSuperseded) {
      wrapper = createEl("details", "verdict-superseded-container");
      wrapper.appendChild(createEl("summary", null, `Revision ${item.revision} (Superseded - click to view)`));
      cardParent = wrapper;
    }

    const card = createEl("div", `verdict-card ${item.verdict || "needs_more_info"}`);

    // Header: Headline Badge & Classification Badges
    const header = createEl("div", "verdict-header");

    const headlineBadge = createEl("span", "badge verdict-headline-badge");
    const badgeText = item.headline_badge || "Verdict";
    headlineBadge.textContent = badgeText;
    if (item.verdict === "true_positive") {
      headlineBadge.classList.add("badge-danger");
    } else if (item.verdict === "false_positive") {
      headlineBadge.classList.add("badge-success");
    } else {
      headlineBadge.classList.add("badge-warning");
    }
    header.appendChild(headlineBadge);

    const rightBadges = createEl("div", "thread-card-badges");
    if (item.severity) {
      const sevBadge = createEl("span");
      setLevelBadge(sevBadge, item.severity);
      rightBadges.appendChild(sevBadge);
    }
    if (item.confidence) {
      rightBadges.appendChild(createEl("span", "badge badge-subtle", `Confidence: ${item.confidence}`));
    }
    if (item.category) {
      rightBadges.appendChild(createEl("span", "badge badge-subtle", `Category: ${item.category}`));
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
        const dir = ev.direction || "neutral";
        const dirBadge = createEl("span", `direction-badge direction-${dir}`, `[${dir}]`);
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
      unvSec.appendChild(createEl("div", "verdict-section-title", "What AI Couldn't Verify"));
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
        body: jsonSafeStringify({ text: text }),
      });

      if (resp.status === 202) {
        chatInput.value = "";
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

  function jsonSafeStringify(obj) {
    return JSON.stringify(obj);
  }

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
