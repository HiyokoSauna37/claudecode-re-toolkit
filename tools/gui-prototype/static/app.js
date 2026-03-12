/* ── State ──────────────────────────────────────── */
const state = {
  ws: null,
  executing: false,
  currentAssistantMsg: null,
  currentAssistantBuf: "",
  sessions: [{ id: 0, name: "Session 1", messages: [], log: [], claudeSessionId: "" }],
  activeSession: 0,
  sessionCounter: 1,
  skills: [],
  wsConnected: false,
  autoScroll: true,
  promptHistory: [],
  historyIndex: -1,
  spinnerInterval: null,
  toolTimers: {},
  sessionToolCount: 0,
  sessionStartTime: null,
  statusRefreshInterval: null,
  contextMenuTarget: null,
  slashMenuIndex: -1,
  slashMenuItems: [],
  lastMessageTime: 0,
  vmPollInterval: null,
  vmActive: false,
  execInterval: null,
  activeAgents: {},  // toolId -> description
  wsReconnectDelay: 1000,
  cmdPaletteIndex: -1,
  cmdPaletteItems: [],
  pendingNextStep: null,
  currentPipelineStage: null,
  previewedFile: null,
};

const THEMES = ["default", "claude", "cyber", "arctic", "amethyst", "light"];
const THEME_LABELS = { default: "Default", claude: "Claude", cyber: "Cyber", arctic: "Arctic", amethyst: "Amethyst", light: "Light" };

/* ── Init ──────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  loadTheme();
  refreshStatus();
  fetchSkills();
  fetchReports();
  fetchQuarantine();
  fetchGhidraLogs();
  connectWebSocket();
  loadChatHistory();
  setupDragDrop();
  setupTemplateButtons();
  setupSkillTooltip();
  setupKeyboardShortcuts();
  setupTextareaAutoResize();
  setupSlashMenu();
  setupResizablePanels();
  setupCommandPalette();
  setupHashDetection();
  setupCollapsibleAria();
  setupAutoScrollDetection();

  state.statusRefreshInterval = setInterval(refreshStatus, 30000);

  document.querySelector("header h1").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
  });

  document.addEventListener("click", () => {
    document.getElementById("tab-context-menu").classList.add("hidden");
  });

  updateWelcomeScreen();
});

/* ── Theme ─────────────────────────────────────── */
function loadTheme() {
  const saved = localStorage.getItem("mat_theme") || "default";
  document.body.setAttribute("data-theme", saved);
}

function cycleTheme() {
  const current = document.body.getAttribute("data-theme") || "default";
  const idx = THEMES.indexOf(current);
  const next = THEMES[(idx + 1) % THEMES.length];
  document.body.setAttribute("data-theme", next);
  localStorage.setItem("mat_theme", next);
  const btn = document.getElementById("theme-btn");
  btn.title = `Theme: ${THEME_LABELS[next]}`;
  showToast(`Theme: ${THEME_LABELS[next]}`, "info");
}

/* ── REST calls ────────────────────────────────── */
async function refreshStatus() {
  const list = document.getElementById("status-list");
  if (!list) return;
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    renderStatus(data);
  } catch (e) {
    list.innerHTML = '<div class="status-item"><span class="dot error"></span>Failed</div>';
  }
}

function renderStatus(data) {
  const list = document.getElementById("status-list");
  list.innerHTML = "";
  const items = [
    ["env_file", ".env"], ["docker", "Docker"], ["proxy_web_image", "proxy-web"],
    ["ghidra_container", "Ghidra"], ["vmware", "VMware"],
    ["claude_cli", "Claude CLI"], ["yara_rules", "YARA"],
  ];
  let allOk = true;
  for (const [key, label] of items) {
    const info = data[key];
    if (!info) continue;
    if (info.status !== "ok" && info.status !== "running") allOk = false;
    const el = document.createElement("div");
    el.className = "status-item";
    el.innerHTML = `<span class="dot ${info.status}"></span><span class="label">${label}</span><span class="detail" title="${esc(info.detail)}">${esc(info.detail)}</span>`;
    list.appendChild(el);
  }
  // Auto-collapse if all green
  if (allOk) {
    const section = document.getElementById("status-panel");
    const body = section.querySelector(".section-body");
    const h2 = section.querySelector("h2.collapsible");
    if (body && !body.classList.contains("collapsed")) {
      body.classList.add("collapsed");
      h2.classList.add("is-collapsed");
    }
  }
}

async function fetchSkills() {
  try {
    const res = await fetch("/api/skills");
    state.skills = await res.json();
    const sel = document.getElementById("skill-select");
    while (sel.options.length > 1) sel.remove(1);
    for (const s of state.skills) {
      const opt = document.createElement("option");
      opt.value = s.name;
      opt.textContent = s.name;
      opt.dataset.description = s.description;
      sel.appendChild(opt);
    }
  } catch (e) {
    console.warn("fetchSkills failed:", e);
  }
}

async function fetchReports() {
  const list = document.getElementById("report-list");
  list.innerHTML = "";
  try {
    const res = await fetch("/api/reports");
    const reports = await res.json();
    if (reports.length === 0) {
      list.innerHTML = '<div style="font-size:10px;color:var(--text-dim)">No reports</div>';
      return;
    }
    for (const r of reports) {
      const el = document.createElement("div");
      el.className = "report-item";
      el.onclick = () => openReport(r.path);
      const dateStr = r.modified ? new Date(r.modified * 1000).toLocaleDateString("ja-JP", { month: "2-digit", day: "2-digit" }) : "";
      el.innerHTML = `<span class="report-date">${esc(dateStr)}</span><span class="report-name" title="${esc(r.path)}">${esc(r.name)}</span>`;
      list.appendChild(el);
    }
  } catch (e) {
    console.warn("fetchReports failed:", e);
  }
}

/* ── Quarantine Browser ───────────────────────── */
async function fetchQuarantine() {
  const tree = document.getElementById("quarantine-tree");
  if (!tree) return;
  tree.innerHTML = "";
  try {
    const res = await fetch("/api/quarantine");
    const hosts = await res.json();
    if (!hosts.length) {
      tree.innerHTML = '<div class="q-empty">No files</div>';
      return;
    }
    for (const host of hosts) {
      const hostEl = document.createElement("div");
      hostEl.className = "q-host";

      const hostName = document.createElement("div");
      hostName.className = "q-host-name";
      hostName.innerHTML = `<span class="q-arrow">&#9654;</span>${esc(host.name)}`;

      const sessionsEl = document.createElement("div");
      sessionsEl.style.display = "none";

      hostName.onclick = () => {
        const open = sessionsEl.style.display !== "none";
        sessionsEl.style.display = open ? "none" : "block";
        hostName.querySelector(".q-arrow").classList.toggle("open", !open);
      };

      for (const session of host.sessions) {
        const sessionEl = document.createElement("div");
        sessionEl.className = "q-session";

        const sessionName = document.createElement("div");
        sessionName.className = "q-session-name";
        // Parse date from session name (format: YYYYMMDD_HHMMSS)
        const dateMatch = session.name.match(/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})/);
        const sessionDate = dateMatch ? `${dateMatch[2]}/${dateMatch[3]} ${dateMatch[4]}:${dateMatch[5]}` : "";
        const statusClass = session.analyzed ? "q-analyzed" : "q-unanalyzed";
        sessionName.innerHTML = `<span class="q-arrow">&#9654;</span><span class="${statusClass}">${esc(session.name)}</span>${sessionDate ? `<span class="q-session-date">${sessionDate}</span>` : ""}`;

        const filesEl = document.createElement("div");
        filesEl.className = "q-files collapsed";

        sessionName.onclick = () => {
          filesEl.classList.toggle("collapsed");
          sessionName.querySelector(".q-arrow").classList.toggle("open");
        };

        for (const file of session.files) {
          const fileEl = document.createElement("div");
          fileEl.className = "q-file";

          const icon = file.is_encrypted ? "&#x1F512;" : file.name.endsWith(".json") ? "&#x1F4C4;" : file.name.endsWith(".png") ? "&#x1F5BC;" : file.name.endsWith(".html") ? "&#x1F310;" : "&#x1F4C1;";
          const sizeStr = file.size > 1024 * 1024 ? `${(file.size / 1024 / 1024).toFixed(1)}MB` : `${(file.size / 1024).toFixed(1)}KB`;

          let actionBtn = "";
          const escapedPath = esc(file.path.replace(/\\/g, "\\\\").replace(/'/g, "\\'"));
          if (file.is_encrypted) {
            actionBtn = `<button class="q-analyze-btn" onclick="analyzeQuarantineFile(event, '${escapedPath}', '${esc(host.name)}', 'ghidra')">Ghidra</button><button class="q-analyze-btn q-vmware-btn" onclick="analyzeQuarantineFile(event, '${escapedPath}', '${esc(host.name)}', 'vmware')">VMware</button>`;
          }

          const isPreviewable = /\.(html|png|jpg|jpeg|json|csv|txt)$/i.test(file.name);
          let nameClass = isPreviewable ? "q-file-name q-previewable" : "q-file-name";
          if (file.is_encrypted) {
            nameClass += session.analyzed ? " q-analyzed" : " q-unanalyzed";
          }

          fileEl.innerHTML = `<span class="q-file-icon">${icon}</span><span class="${nameClass}" title="${esc(file.path)}" ${isPreviewable ? `onclick="previewQuarantineFile(event, '${escapedPath}', '${esc(file.name)}')"` : ""}>${esc(file.name)}</span><span class="q-file-size">${sizeStr}</span>${actionBtn}`;
          // Drag & drop to chat
          fileEl.draggable = true;
          fileEl.addEventListener("dragstart", (e) => {
            e.dataTransfer.setData("text/plain", file.path);
            e.dataTransfer.setData("application/x-quarantine", JSON.stringify({ path: file.path, name: file.name, encrypted: file.is_encrypted }));
            fileEl.classList.add("q-dragging");
          });
          fileEl.addEventListener("dragend", () => fileEl.classList.remove("q-dragging"));
          filesEl.appendChild(fileEl);
        }

        sessionEl.appendChild(sessionName);
        sessionEl.appendChild(filesEl);
        sessionsEl.appendChild(sessionEl);
      }

      hostEl.appendChild(hostName);
      hostEl.appendChild(sessionsEl);
      tree.appendChild(hostEl);
    }
  } catch (e) {
    tree.innerHTML = '<div class="q-empty">Load failed</div>';
  }
}

function analyzeQuarantineFile(event, filePath, hostName, skill = "ghidra") {
  event.stopPropagation();
  const cmd = skill === "vmware" ? "/vmware-sandbox" : "/ghidra-headless";
  insertPrompt(`${cmd} ${filePath}`);
  document.getElementById("prompt-input").focus();
}

function highlightAnalyzingFile(prompt) {
  clearAnalyzingHighlight();
  // Match file paths in the prompt against quarantine file titles
  document.querySelectorAll("#quarantine-tree .q-file-name").forEach(el => {
    const filePath = el.getAttribute("title") || "";
    if (filePath && prompt.includes(filePath)) {
      // Highlight the file
      el.closest(".q-file")?.classList.add("q-analyzing");
      // Highlight and expand parent session
      const session = el.closest(".q-session");
      if (session) {
        session.querySelector(".q-session-name")?.classList.add("q-analyzing");
        const files = session.querySelector(".q-files");
        if (files) files.classList.remove("collapsed");
        const arrow = session.querySelector(".q-session-name .q-arrow");
        if (arrow) arrow.classList.add("open");
      }
      // Expand parent host
      const host = el.closest(".q-host");
      if (host) {
        const sessionsContainer = host.querySelector(".q-host-name + div");
        if (sessionsContainer) sessionsContainer.style.display = "block";
        const arrow = host.querySelector(".q-host-name .q-arrow");
        if (arrow) arrow.classList.add("open");
      }
    }
  });
}

function clearAnalyzingHighlight() {
  document.querySelectorAll(".q-analyzing").forEach(el => el.classList.remove("q-analyzing"));
}

function previewQuarantineFile(event, filePath, fileName) {
  event.stopPropagation();
  const url = `/api/quarantine/file?path=${encodeURIComponent(filePath)}`;
  const modal = document.getElementById("report-modal");
  const title = document.getElementById("report-modal-title");
  const body = document.getElementById("report-modal-body");

  title.textContent = fileName;

  if (/\.(png|jpg|jpeg)$/i.test(fileName)) {
    body.innerHTML = `<img src="${url}" style="max-width:100%;border-radius:4px;" alt="${esc(fileName)}">`;
  } else if (/\.html$/i.test(fileName)) {
    body.innerHTML = `<iframe src="${url}" style="width:100%;height:70vh;border:1px solid var(--border);border-radius:4px;background:#fff;" sandbox="allow-same-origin"></iframe>`;
  } else if (/\.json$/i.test(fileName)) {
    fetch(url).then(r => r.text()).then(text => {
      try { text = JSON.stringify(JSON.parse(text), null, 2); } catch(e) {}
      body.innerHTML = `<pre style="white-space:pre-wrap;font-family:var(--font-mono);font-size:11px;">${esc(text)}</pre>`;
    }).catch(() => { body.innerHTML = '<p>Load failed</p>'; });
  } else {
    fetch(url).then(r => r.text()).then(text => {
      body.innerHTML = `<pre style="white-space:pre-wrap;font-family:var(--font-mono);font-size:11px;">${esc(text)}</pre>`;
    }).catch(() => { body.innerHTML = '<p>Load failed</p>'; });
  }

  modal.showModal();
}

/* ── Ghidra Logs ──────────────────────────────── */
async function fetchGhidraLogs() {
  const list = document.getElementById("ghidra-log-list");
  if (!list) return;
  list.innerHTML = "";
  try {
    const res = await fetch("/api/ghidra-logs");
    const logs = await res.json();
    if (!logs.length) {
      list.innerHTML = '<div style="font-size:10px;color:var(--text-dim)">No logs</div>';
      return;
    }
    for (const log of logs) {
      const el = document.createElement("div");
      el.className = "ghidra-log-item";
      const sizeStr = log.size > 1024 ? `${(log.size / 1024).toFixed(1)}KB` : `${log.size}B`;
      el.innerHTML = `<span class="gl-name" title="${esc(log.path)}">${esc(log.name)}</span><span class="gl-size">${sizeStr}</span>`;
      el.onclick = () => previewQuarantineFile(new Event("click"), log.path, log.name);
      list.appendChild(el);
    }
  } catch (e) {}
}

async function openReport(path) {
  try {
    const res = await fetch(`/api/reports/${encodeURIComponent(path)}`);
    const data = await res.json();
    document.getElementById("report-modal-title").textContent = path;
    document.getElementById("report-modal-body").innerHTML = renderMarkdown(data.content);
    document.getElementById("report-modal").showModal();
  } catch (e) {
    showToast("Failed to load report", "error");
  }
}

function closeReportModal() {
  document.getElementById("report-modal").close();
}

/* ── Sidebar ──────────────────────────────────── */
function toggleSection(h2) {
  h2.nextElementSibling.classList.toggle("collapsed");
  h2.classList.toggle("is-collapsed");
  const expanded = !h2.classList.contains("is-collapsed");
  h2.setAttribute("aria-expanded", String(expanded));
}

function setupSkillTooltip() {
  const sel = document.getElementById("skill-select");
  const tip = document.getElementById("skill-tooltip");
  sel.addEventListener("change", () => {
    const opt = sel.options[sel.selectedIndex];
    const desc = opt.dataset.description;
    if (desc) {
      tip.textContent = desc;
      tip.classList.add("visible");
      setTimeout(() => tip.classList.remove("visible"), 3000);
    } else {
      tip.classList.remove("visible");
    }
  });
}

function setupTemplateButtons() {
  document.querySelectorAll(".tpl-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      insertPrompt(btn.dataset.prompt);
      if (btn.dataset.focus !== "true") executePrompt();
    });
  });
}

/* ── Welcome Screen ───────────────────────────── */
function updateWelcomeScreen() {
  const welcome = document.getElementById("welcome-screen");
  if (!welcome) return;
  // Only toggle welcome screen; never hide #chat-messages
  if (getChatEl().children.length > 0) {
    welcome.classList.add("hidden");
  } else {
    welcome.classList.remove("hidden");
  }
}

function insertPrompt(text) {
  const input = document.getElementById("prompt-input");
  input.value = text;
  input.focus();
  autoResizeTextarea(input);
}

/* ── Slash Command Autocomplete ───────────────── */
function setupSlashMenu() {
  const input = document.getElementById("prompt-input");
  input.addEventListener("input", () => {
    const val = input.value;
    if (val.startsWith("/") && !val.includes(" ")) {
      const query = val.slice(1).toLowerCase();
      state.slashMenuItems = state.skills.filter(s =>
        s.name.toLowerCase().includes(query)
      );
      if (state.slashMenuItems.length > 0) {
        showSlashMenu();
        return;
      }
    }
    hideSlashMenu();
  });
}

function showSlashMenu() {
  const menu = document.getElementById("slash-menu");
  menu.innerHTML = "";
  state.slashMenuIndex = -1;
  for (let i = 0; i < state.slashMenuItems.length; i++) {
    const s = state.slashMenuItems[i];
    const el = document.createElement("div");
    el.className = "slash-item";
    el.innerHTML = `<span class="slash-item-name">/${esc(s.name)}</span><span class="slash-item-desc">${esc(s.description)}</span>`;
    el.onclick = () => selectSlashItem(i);
    menu.appendChild(el);
  }
  menu.classList.remove("hidden");
}

function hideSlashMenu() {
  document.getElementById("slash-menu").classList.add("hidden");
  state.slashMenuItems = [];
  state.slashMenuIndex = -1;
}

function selectSlashItem(idx) {
  const item = state.slashMenuItems[idx];
  if (!item) return;
  const input = document.getElementById("prompt-input");
  input.value = `/${item.name} `;
  input.focus();
  autoResizeTextarea(input);
  hideSlashMenu();
}

function navigateSlashMenu(dir) {
  if (state.slashMenuItems.length === 0) return false;
  state.slashMenuIndex += dir;
  if (state.slashMenuIndex < 0) state.slashMenuIndex = state.slashMenuItems.length - 1;
  if (state.slashMenuIndex >= state.slashMenuItems.length) state.slashMenuIndex = 0;
  const items = document.querySelectorAll(".slash-item");
  items.forEach((el, i) => el.classList.toggle("selected", i === state.slashMenuIndex));
  return true;
}

/* ── Chat Search (Ctrl+F) ─────────────────────── */
function openChatSearch() {
  document.getElementById("chat-search").classList.remove("hidden");
  document.getElementById("chat-search-input").focus();
}

function closeChatSearch() {
  document.getElementById("chat-search").classList.add("hidden");
  document.getElementById("chat-search-input").value = "";
  getChatEl().querySelectorAll("mark.search-highlight").forEach(m => {
    m.replaceWith(document.createTextNode(m.textContent));
  });
  document.getElementById("chat-search-count").textContent = "";
}

function searchChat(query) {
  const chatEl = getChatEl();
  chatEl.querySelectorAll("mark.search-highlight").forEach(m => {
    m.replaceWith(document.createTextNode(m.textContent));
  });
  if (!query) {
    document.getElementById("chat-search-count").textContent = "";
    return;
  }
  let count = 0;
  chatEl.querySelectorAll(".msg").forEach(msg => {
    const walker = document.createTreeWalker(msg, NodeFilter.SHOW_TEXT);
    const textNodes = [];
    while (walker.nextNode()) textNodes.push(walker.currentNode);
    for (const node of textNodes) {
      const idx = node.textContent.toLowerCase().indexOf(query.toLowerCase());
      if (idx >= 0) {
        const range = document.createRange();
        range.setStart(node, idx);
        range.setEnd(node, idx + query.length);
        const mark = document.createElement("mark");
        mark.className = "search-highlight";
        range.surroundContents(mark);
        count++;
      }
    }
  });
  document.getElementById("chat-search-count").textContent = `${count} found`;
}

/* ── Tool Visibility / Collapse / Expand ──────── */
function toggleToolVisibility() {
  const chat = getChatEl();
  const btn = document.getElementById("hide-tools-btn");
  const hidden = chat.classList.toggle("hide-tools");
  btn.classList.toggle("active", !hidden);
  btn.title = hidden ? "Show tool calls" : "Hide tool calls";
}

function collapseAllTools() {
  getChatEl().querySelectorAll(".tool-call-body.open").forEach(b => b.classList.remove("open"));
}

function expandAllTools() {
  getChatEl().querySelectorAll(".tool-call-body").forEach(b => b.classList.add("open"));
}

/* ── Textarea auto resize ─────────────────────── */
function setupTextareaAutoResize() {
  const input = document.getElementById("prompt-input");
  input.addEventListener("input", () => autoResizeTextarea(input));
}

function autoResizeTextarea(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 120) + "px";
}

/* ── Keyboard Shortcuts ───────────────────────── */
function setupKeyboardShortcuts() {
  const input = document.getElementById("prompt-input");

  input.addEventListener("keydown", (e) => {
    // Slash menu navigation
    if (!document.getElementById("slash-menu").classList.contains("hidden")) {
      if (e.key === "ArrowUp") { e.preventDefault(); navigateSlashMenu(-1); return; }
      if (e.key === "ArrowDown") { e.preventDefault(); navigateSlashMenu(1); return; }
      if (e.key === "Enter" || e.key === "Tab") {
        if (state.slashMenuIndex >= 0) { e.preventDefault(); selectSlashItem(state.slashMenuIndex); return; }
        if (e.key === "Tab") { e.preventDefault(); selectSlashItem(0); return; }
      }
      if (e.key === "Escape") { e.preventDefault(); hideSlashMenu(); return; }
    }

    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      executePrompt();
    }

    if (e.key === "ArrowUp" && input.value === "") {
      e.preventDefault();
      navigateHistory(-1);
    }
    if (e.key === "ArrowDown" && state.historyIndex >= 0) {
      e.preventDefault();
      navigateHistory(1);
    }
  });

  document.addEventListener("keydown", (e) => {
    // Command palette takes priority
    if (e.ctrlKey && e.key === "k") { e.preventDefault(); toggleCommandPalette(); return; }

    if (e.key === "Escape") {
      const palette = document.getElementById("command-palette");
      if (palette.open) { palette.close(); return; }
      if (!document.getElementById("chat-search").classList.contains("hidden")) {
        closeChatSearch();
        return;
      }
      const modal = document.getElementById("report-modal");
      if (modal.open) { closeReportModal(); return; }
      if (state.executing) { cancelExecution(); return; }
    }
    if (e.ctrlKey && e.key === "l") { e.preventDefault(); clearChat(); }
    if (e.ctrlKey && e.key === "n") { e.preventDefault(); createSession(); }
    if (e.ctrlKey && e.key === "s") { e.preventDefault(); exportChat(); }
    if (e.ctrlKey && e.key === "f") { e.preventDefault(); openChatSearch(); }
  });
}

function navigateHistory(dir) {
  const input = document.getElementById("prompt-input");
  const newIdx = state.historyIndex + dir;
  if (newIdx < -1 || newIdx >= state.promptHistory.length) return;
  state.historyIndex = newIdx;
  input.value = newIdx === -1 ? "" : state.promptHistory[state.promptHistory.length - 1 - newIdx];
  autoResizeTextarea(input);
}

function clearChat() {
  if (getChatEl().children.length === 0) return;
  if (!confirm("チャットをクリアしますか？")) return;
  getChatEl().innerHTML = "";
  currentSession().messages = [];
  state.currentAssistantMsg = null;
  state.currentAssistantBuf = "";
  saveChatHistory();
  updateWelcomeScreen();
}

function toggleAutoScroll() {
  state.autoScroll = !state.autoScroll;
  document.getElementById("autoscroll-btn").classList.toggle("active", state.autoScroll);
  if (state.autoScroll) scrollChat();
}

function setupAutoScrollDetection() {
  const chat = getChatEl();
  chat.addEventListener("scroll", () => {
    // Bottom threshold: within 30px of the bottom = "at bottom"
    const atBottom = chat.scrollHeight - chat.scrollTop - chat.clientHeight < 30;
    if (atBottom && !state.autoScroll) {
      state.autoScroll = true;
      document.getElementById("autoscroll-btn").classList.add("active");
    } else if (!atBottom && state.autoScroll) {
      state.autoScroll = false;
      document.getElementById("autoscroll-btn").classList.remove("active");
    }
  });
}

function exportChat() {
  const session = currentSession();
  let md = `# ${session.name}\n\nExported: ${new Date().toLocaleString("ja-JP")}\n\n`;
  for (const msg of session.messages) {
    if (msg.type === "user") md += `## User\n\n${msg.content}\n\n`;
    else if (msg.type === "assistant") md += `## Assistant\n\n${msg.content}\n\n`;
  }
  const blob = new Blob([md], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${session.name.replace(/\s+/g, "_")}_${new Date().toISOString().slice(0, 10)}.md`;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast("Chat exported", "success");
}

/* ── Resizable Panels ─────────────────────────── */
function setupResizablePanels() {
  const sidebarHandle = document.getElementById("sidebar-resize");
  if (sidebarHandle) {
    let startX, startW;
    sidebarHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startX = e.clientX;
      startW = document.getElementById("sidebar").offsetWidth;
      sidebarHandle.classList.add("active");
      const onMove = (e) => {
        const w = Math.max(160, Math.min(400, startW + (e.clientX - startX)));
        document.querySelector("main").style.gridTemplateColumns = `${w}px 4px 1fr`;
      };
      const onUp = () => {
        sidebarHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  }

  const logHandle = document.getElementById("log-resize");
  if (logHandle) {
    let startY, startH;
    logHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startY = e.clientY;
      startH = document.getElementById("tool-log-panel").offsetHeight;
      logHandle.classList.add("active");
      const onMove = (e) => {
        const h = Math.max(60, Math.min(400, startH - (e.clientY - startY)));
        document.getElementById("tool-log-panel").style.height = h + "px";
      };
      const onUp = () => {
        logHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  }
}

/* ── WebSocket ─────────────────────────────────── */
function connectWebSocket() {
  const wsEl = document.getElementById("ws-status");
  wsEl.textContent = "Connecting...";
  wsEl.className = "ws-reconnecting";

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  state.ws = new WebSocket(`${proto}//${location.host}/ws/chat`);

  state.ws.onopen = () => {
    state.wsConnected = true;
    state.wsReconnectDelay = 1000; // Reset on success
    wsEl.textContent = "Connected";
    wsEl.className = "ws-connected";
    showToast("Connected", "success");
  };

  state.ws.onclose = () => {
    state.wsConnected = false;
    wsEl.textContent = "Disconnected";
    wsEl.className = "ws-disconnected";
    if (state.executing) { addErrorMsg("Connection lost"); setExecuting(false); }
    // Exponential backoff: 1s, 2s, 4s, 8s, max 30s
    const delay = state.wsReconnectDelay;
    state.wsReconnectDelay = Math.min(delay * 2, 30000);
    setTimeout(connectWebSocket, delay);
  };

  state.ws.onerror = () => { wsEl.textContent = "Error"; wsEl.className = "ws-disconnected"; };
  state.ws.onmessage = (event) => handleMessage(JSON.parse(event.data));
}

/* ── Message handling ──────────────────────────── */
function handleMessage(msg) {
  state.lastMessageTime = Date.now();
  updateExecStatus();

  switch (msg.type) {
    case "system":
      if (msg.subtype !== "start") addSystemMsg(`[${msg.subtype}]`);
      break;
    case "text": appendAssistantText(msg.content); break;
    case "tool_use":
      addToolCall(msg);
      addLogEntry(msg.name, summarizeInput(msg.name, msg.input), msg.id);
      state.sessionToolCount++;
      updateSessionStats();
      // Track active Agent sub-agents
      if (msg.name === "Agent") {
        state.activeAgents[msg.id] = msg.input?.description || msg.input?.prompt?.slice(0, 40) || "Sub-agent";
      }
      // Detect VMware tool usage
      if (msg.name === "Skill" && msg.input?.skill?.includes("vmware")) {
        startVmLiveView();
        setPipelineStage("dynamic");
        autoExpandPanel("ghidra-logs-panel"); // Useful during dynamic too
      }
      // Detect Ghidra usage
      if (msg.name === "Skill" && msg.input?.skill?.includes("ghidra")) {
        setPipelineStage("static");
        autoExpandPanel("ghidra-logs-panel");
      }
      // Detect proxy-web / triage
      if (msg.name === "Skill" && (msg.input?.skill?.includes("proxy") || msg.input?.skill?.includes("url"))) {
        setPipelineStage("triage");
      }
      // Track tool info for result-based refresh
      state._toolNames = state._toolNames || {};
      state._toolNames[msg.id] = { name: msg.name, skill: msg.input?.skill || "", path: msg.input?.file_path || "" };
      break;
    case "tool_result":
      updateToolResult(msg);
      // Remove completed agent from active list
      if (msg.tool_use_id && state.activeAgents[msg.tool_use_id]) {
        delete state.activeAgents[msg.tool_use_id];
      }
      // Auto-refresh after proxy-web completes (new quarantine files)
      {
        const info = state._toolNames?.[msg.tool_use_id];
        if (info) {
          const sk = info.skill.toLowerCase();
          if (info.name === "Skill" && (sk.includes("proxy") || sk.includes("url"))) {
            fetchQuarantine();
          }
          // Auto-refresh after Write/Edit to reports directory (new/updated reports)
          if ((info.name === "Write" || info.name === "Edit") && info.path.includes("report")) {
            fetchReports();
          }
          delete state._toolNames[msg.tool_use_id];
        }
      }
      break;
    case "result":
      // Save Claude Code session ID for resume
      if (msg.session_id) {
        currentSession().claudeSessionId = msg.session_id;
      }
      addResultFooter(msg);
      setExecuting(false);
      saveChatHistory();
      notifyCompletion();
      // Auto-refresh reports & quarantine after execution
      fetchReports();
      fetchQuarantine();
      // Suggest next steps based on pipeline stage
      suggestNextStep();
      // Auto-rename session tab based on analysis
      autoRenameSession();
      // Mark current stage as completed
      if (state.currentPipelineStage) {
        completePipelineStage(state.currentPipelineStage);
      }
      // Execute queued prompts
      processPromptQueue();
      break;
    case "error":
      addErrorMsg(friendlyError(msg.message));
      setExecuting(false);
      processPromptQueue();
      break;
  }
}

/* ── Chat rendering ────────────────────────────── */
function getChatEl() { return document.getElementById("chat-messages"); }

function now() { return new Date().toLocaleTimeString("ja-JP", { hour12: false }); }

function addUserMsg(text) {
  updateWelcomeScreen();
  const trimmed = text.replace(/\n+$/, "");
  const el = document.createElement("div");
  el.className = "msg user";
  el.innerHTML = `<div class="msg-text">${esc(trimmed).replace(/\n/g, "<br>")}</div><div class="msg-time">${now()}</div>`;
  getChatEl().appendChild(el);
  state.currentAssistantMsg = null;
  state.currentAssistantBuf = "";
  currentSession().messages.push({ type: "user", content: trimmed });
  const w = document.getElementById("welcome-screen");
  if (w) w.classList.add("hidden");
  // Scroll after layout settles so the full message is visible
  requestAnimationFrame(() => {
    el.scrollIntoView({ behavior: "smooth", block: "end" });
  });
}

function appendAssistantText(text) {
  const chatEl = getChatEl();
  if (!state.currentAssistantMsg) {
    state.currentAssistantMsg = document.createElement("div");
    state.currentAssistantMsg.className = "msg assistant typing-cursor";
    chatEl.appendChild(state.currentAssistantMsg);
    state.currentAssistantBuf = "";
  }
  state.currentAssistantBuf += text;
  state.currentAssistantMsg.innerHTML = renderMarkdown(state.currentAssistantBuf);
  addCopyButtons(state.currentAssistantMsg);
  scrollChat();
}

function finalizeAssistantMsg() {
  if (state.currentAssistantMsg) {
    state.currentAssistantMsg.classList.remove("typing-cursor");
    const timeDiv = document.createElement("div");
    timeDiv.className = "msg-time";
    timeDiv.textContent = now();
    state.currentAssistantMsg.appendChild(timeDiv);
    addCopyButtons(state.currentAssistantMsg);
    if (state.currentAssistantBuf) {
      currentSession().messages.push({ type: "assistant", content: state.currentAssistantBuf });
    }
    state.currentAssistantMsg = null;
    state.currentAssistantBuf = "";
  }
}

function addSystemMsg(text) {
  finalizeAssistantMsg();
  const el = document.createElement("div");
  el.className = "msg system-msg";
  el.textContent = text;
  getChatEl().appendChild(el);
  scrollChat();
}

function addErrorMsg(text) {
  finalizeAssistantMsg();
  const el = document.createElement("div");
  el.className = "msg error";
  el.textContent = text;
  getChatEl().appendChild(el);
  scrollChat();
}

function addToolCall(msg) {
  finalizeAssistantMsg();
  state.toolTimers[msg.id] = Date.now();
  const el = document.createElement("div");
  el.className = "tool-call running";
  el.dataset.toolId = msg.id;
  const inputPreview = summarizeInput(msg.name, msg.input);
  el.innerHTML = `
    <div class="tool-call-header" onclick="toggleToolBody(this)">
      <span class="tool-badge ${msg.name}">${esc(msg.name)}</span>
      <span class="tool-summary">${esc(inputPreview)}</span>
      <span class="tool-elapsed" data-elapsed-for="${msg.id}"></span>
      <span class="tool-result-badge" data-result-for="${msg.id}"></span>
    </div>
    <div class="tool-call-body">${esc(JSON.stringify(msg.input, null, 2))}</div>`;
  getChatEl().appendChild(el);
  scrollChat();
}

function toggleToolBody(header) {
  const body = header.nextElementSibling;
  body.classList.toggle("open");
  if (body.classList.contains("open") && body.textContent.length > 500 && !body.parentElement.querySelector(".tool-result-search")) {
    const sd = document.createElement("div");
    sd.className = "tool-result-search";
    sd.innerHTML = '<input type="text" placeholder="Search..." oninput="searchToolResult(this)">';
    body.parentElement.appendChild(sd);
  }
}

function searchToolResult(input) {
  const body = input.closest(".tool-call").querySelector(".tool-call-body");
  const q = input.value.toLowerCase();
  if (!q) { body.innerHTML = body.dataset.original || body.innerHTML; return; }
  if (!body.dataset.original) body.dataset.original = body.innerHTML;
  body.innerHTML = esc(body.textContent).replace(
    new RegExp(escapeRegex(esc(q)), "gi"),
    m => `<mark style="background:var(--warning);color:#000">${m}</mark>`
  );
}

function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function updateToolResult(msg) {
  const startTime = state.toolTimers[msg.tool_use_id];
  if (startTime) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const el = document.querySelector(`[data-elapsed-for="${msg.tool_use_id}"]`);
    if (el) el.textContent = `${elapsed}s`;
    const logEl = document.querySelector(`[data-log-elapsed="${msg.tool_use_id}"]`);
    if (logEl) logEl.textContent = `${elapsed}s`;
    delete state.toolTimers[msg.tool_use_id];
  }
  const badge = document.querySelector(`[data-result-for="${msg.tool_use_id}"]`);
  if (badge) {
    badge.textContent = msg.is_error ? "ERROR" : "OK";
    badge.className = `tool-result-badge ${msg.is_error ? "err" : "ok"}`;
  }
  const tc = document.querySelector(`[data-tool-id="${msg.tool_use_id}"]`);
  if (tc) {
    tc.classList.remove("running");
    tc.classList.add(msg.is_error ? "completed-error" : "completed-ok");
    const body = tc.querySelector(".tool-call-body");
    if (body) body.textContent += "\n--- Result ---\n" + msg.content;
  }
}

function addResultFooter(msg) {
  finalizeAssistantMsg();
  const el = document.createElement("div");
  el.className = "result-footer";
  const dur = msg.duration_ms ? `${(msg.duration_ms / 1000).toFixed(1)}s` : "---";
  el.innerHTML = `${dur} | ${state.sessionToolCount} tools`;
  getChatEl().appendChild(el);
  scrollChat();
}

/* ── Copy buttons ─────────────────────────────── */
function addCopyButtons(container) {
  container.querySelectorAll("pre").forEach(pre => {
    if (pre.querySelector(".copy-btn")) return;
    const btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.onclick = (e) => {
      e.stopPropagation();
      navigator.clipboard.writeText((pre.querySelector("code") || pre).textContent).then(() => {
        btn.textContent = "Copied!";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1500);
      });
    };
    pre.style.position = "relative";
    pre.appendChild(btn);
  });
}

/* ── Sessions ─────────────────────────────────── */
function currentSession() {
  return state.sessions.find(s => s.id === state.activeSession) || state.sessions[0];
}

function createSession() {
  const id = state.sessionCounter++;
  state.sessions.push({ id, name: `Session ${id + 1}`, messages: [], log: [], claudeSessionId: "" });
  renderSessionTabs();
  switchSession(id);
}

function switchSession(id) {
  // Save current session state
  const cs = currentSession();
  cs._chatHTML = getChatEl().innerHTML;
  cs._logHTML = document.getElementById("tool-log").innerHTML;
  cs._welcomeHidden = document.getElementById("welcome-screen")?.classList.contains("hidden");

  state.activeSession = id;
  state.currentAssistantMsg = null;
  state.currentAssistantBuf = "";

  // Restore target session state (empty string for new sessions)
  const target = currentSession();
  getChatEl().innerHTML = target._chatHTML || "";
  document.getElementById("tool-log").innerHTML = target._logHTML || "";

  // Show welcome screen for empty sessions (never hide #chat-messages)
  if (target._chatHTML) {
    document.getElementById("welcome-screen")?.classList.add("hidden");
  } else {
    document.getElementById("welcome-screen")?.classList.remove("hidden");
  }

  renderSessionTabs();
  if (state.executing) setExecuting(false);
}

function renderSessionTabs() {
  const tabsEl = document.getElementById("session-tabs");
  tabsEl.querySelectorAll(".tab").forEach(t => t.remove());
  const btn = document.getElementById("new-session-btn");
  for (const s of state.sessions) {
    const tab = document.createElement("div");
    tab.className = `tab ${s.id === state.activeSession ? "active" : ""}`;
    tab.textContent = s.name;
    tab.onclick = () => switchSession(s.id);
    tab.oncontextmenu = (e) => { e.preventDefault(); state.contextMenuTarget = s.id; const m = document.getElementById("tab-context-menu"); m.style.left = e.clientX + "px"; m.style.top = e.clientY + "px"; m.classList.remove("hidden"); };
    tab.ondblclick = () => { state.contextMenuTarget = s.id; renameSession(); };
    tabsEl.insertBefore(tab, btn);
  }
}

function renameSession() {
  document.getElementById("tab-context-menu").classList.add("hidden");
  const s = state.sessions.find(s => s.id === state.contextMenuTarget);
  if (!s) return;
  const name = prompt("Session name:", s.name);
  if (name?.trim()) { s.name = name.trim(); renderSessionTabs(); }
}

function closeSession() {
  document.getElementById("tab-context-menu").classList.add("hidden");
  if (state.sessions.length <= 1) return;
  const idx = state.sessions.findIndex(s => s.id === state.contextMenuTarget);
  if (idx < 0) return;
  state.sessions.splice(idx, 1);
  if (state.activeSession === state.contextMenuTarget) switchSession(state.sessions[0].id);
  renderSessionTabs();
}

function updateSessionStats() {
  const el = document.getElementById("session-stats");
  if (!el) return;
  const elapsed = state.sessionStartTime ? ((Date.now() - state.sessionStartTime) / 1000).toFixed(0) : 0;
  el.textContent = `Tools: ${state.sessionToolCount} | ${elapsed}s`;
}

/* ── Tool activity log ─────────────────────────── */
function addLogEntry(toolName, detail, toolId) {
  const logEl = document.getElementById("tool-log");
  const el = document.createElement("div");
  el.className = "log-entry";
  el.dataset.toolName = toolName.toLowerCase();
  el.dataset.detail = detail.toLowerCase();
  if (toolId) el.dataset.toolId = toolId;
  el.innerHTML = `
    <span class="log-time">${now()}</span>
    <span class="log-tool" style="color:${toolColor(toolName)}">${esc(toolName)}</span>
    <span class="log-detail" title="${esc(detail)}">${esc(detail)}</span>
    <span class="log-elapsed" data-log-elapsed="${toolId || ""}">...</span>`;
  // Click to scroll, double-click to scroll + expand
  if (toolId) {
    el.style.cursor = "pointer";
    el.addEventListener("click", () => scrollToToolCall(toolId));
    el.addEventListener("dblclick", () => scrollToToolCall(toolId, true));
  }
  logEl.appendChild(el);
  logEl.scrollTop = logEl.scrollHeight;

  // Apply active filter
  const filter = document.getElementById("tool-log-filter").value.toLowerCase();
  if (filter && !toolName.toLowerCase().includes(filter) && !detail.toLowerCase().includes(filter)) {
    el.classList.add("filtered-out");
  }
}

function scrollToToolCall(toolId, expand = false) {
  const toolEl = document.querySelector(`.tool-call[data-tool-id="${toolId}"]`);
  if (!toolEl) return;
  // Expand body on double-click
  if (expand) {
    const body = toolEl.querySelector(".tool-call-body");
    if (body) body.classList.add("open");
  }
  toolEl.scrollIntoView({ behavior: "smooth", block: "center" });
  // Highlight briefly
  toolEl.classList.add("highlight-flash");
  setTimeout(() => toolEl.classList.remove("highlight-flash"), 2000);
}

function filterToolLog(query) {
  const q = query.toLowerCase();
  document.querySelectorAll("#tool-log .log-entry").forEach(el => {
    const match = !q || (el.dataset.toolName || "").includes(q) || (el.dataset.detail || "").includes(q);
    el.classList.toggle("filtered-out", !match);
  });
}

function clearToolLog() {
  document.getElementById("tool-log").innerHTML = "";
}

function exportToolLog() {
  const entries = [];
  document.querySelectorAll("#tool-log .log-entry").forEach(el => {
    entries.push(el.textContent.trim());
  });
  const blob = new Blob([entries.join("\n")], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `tool_log_${new Date().toISOString().slice(0, 10)}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ── Execution Status Bar ─────────────────────── */
function showExecStatus() {
  const bar = document.getElementById("exec-status-bar");
  bar.classList.remove("hidden", "stale");
  state.lastMessageTime = Date.now();
}

function hideExecStatus() {
  document.getElementById("exec-status-bar").classList.add("hidden");
  clearInterval(state.execInterval);
  state.execInterval = null;
}

function updateExecStatus() {
  if (!state.executing) return;
  const bar = document.getElementById("exec-status-bar");
  const elapsed = Math.floor((Date.now() - state.sessionStartTime) / 1000);
  const min = Math.floor(elapsed / 60);
  const sec = elapsed % 60;
  document.getElementById("exec-elapsed").textContent = `${min}:${sec.toString().padStart(2, "0")}`;
  document.getElementById("exec-tool-count").textContent = `${state.sessionToolCount} tools`;

  // Active agents info
  const agentNames = Object.values(state.activeAgents);
  const agentInfo = agentNames.length > 0 ? ` | Agents: ${agentNames.join(", ")}` : "";

  // Detect staleness (no message for 30s)
  const sinceLast = Date.now() - state.lastMessageTime;
  if (sinceLast > 30000) {
    bar.classList.add("stale");
    const waitText = agentNames.length > 0
      ? `Waiting for ${agentNames.length} agent(s): ${agentNames.join(", ")}`
      : `Waiting... (${Math.floor(sinceLast / 1000)}s since last activity)`;
    document.getElementById("exec-phase").textContent = waitText;
  } else {
    bar.classList.remove("stale");
    const lastTool = document.querySelector("#tool-log .log-entry:last-child .log-tool");
    const phaseText = lastTool ? `Running: ${lastTool.textContent}` : "Processing...";
    document.getElementById("exec-phase").textContent = phaseText + agentInfo;
  }
}

/* ── VM Live View ─────────────────────────────── */
function startVmLiveView() {
  if (state.vmActive) return;
  state.vmActive = true;
  const view = document.getElementById("vm-live-view");
  view.classList.remove("hidden");
  view.classList.remove("minimized");
  document.getElementById("vm-live-placeholder").classList.add("hidden");
  document.getElementById("vm-live-img").classList.remove("hidden");
  pollVmScreenshot();
  state.vmPollInterval = setInterval(pollVmScreenshot, 3000);
  setupVmDrag();
}

function closeVmLiveView() {
  state.vmActive = false;
  document.getElementById("vm-live-view").classList.add("hidden");
  clearInterval(state.vmPollInterval);
}

function toggleVmLiveView() {
  document.getElementById("vm-live-view").classList.toggle("minimized");
}

function toggleVmLiveViewVisibility() {
  const view = document.getElementById("vm-live-view");
  if (view.classList.contains("hidden")) {
    // Reopen - start polling again
    state.vmActive = true;
    view.classList.remove("hidden");
    view.classList.remove("minimized");
    document.getElementById("vm-live-placeholder").classList.remove("hidden");
    document.getElementById("vm-live-img").classList.add("hidden");
    pollVmScreenshot();
    state.vmPollInterval = setInterval(pollVmScreenshot, 3000);
    setupVmDrag();
  } else {
    closeVmLiveView();
  }
}

function setupVmDrag() {
  const view = document.getElementById("vm-live-view");
  const header = document.getElementById("vm-live-header");
  if (view._dragSetup) return;
  view._dragSetup = true;

  let isDragging = false, startX, startY, startLeft, startTop;

  header.addEventListener("mousedown", (e) => {
    if (e.target.tagName === "BUTTON") return;
    isDragging = true;
    const rect = view.getBoundingClientRect();
    startX = e.clientX;
    startY = e.clientY;
    startLeft = rect.left;
    startTop = rect.top;
    view.style.position = "fixed";
    view.style.right = "auto";
    view.style.left = rect.left + "px";
    view.style.top = rect.top + "px";
    e.preventDefault();
  });

  document.addEventListener("mousemove", (e) => {
    if (!isDragging) return;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;
    view.style.left = (startLeft + dx) + "px";
    view.style.top = (startTop + dy) + "px";
  });

  document.addEventListener("mouseup", () => {
    isDragging = false;
  });
}

async function pollVmScreenshot() {
  try {
    const res = await fetch("/api/vm/screenshot?t=" + Date.now());
    if (res.ok) {
      const blob = await res.blob();
      if (blob.size > 0) {
        const url = URL.createObjectURL(blob);
        const img = document.getElementById("vm-live-img");
        const oldUrl = img.src;
        img.src = url;
        img.classList.remove("hidden");
        document.getElementById("vm-live-placeholder").classList.add("hidden");
        if (oldUrl.startsWith("blob:")) URL.revokeObjectURL(oldUrl);
      }
    } else {
      // VM might not be running - show placeholder
      document.getElementById("vm-live-img").classList.add("hidden");
      document.getElementById("vm-live-placeholder").classList.remove("hidden");
    }
  } catch (e) {
    document.getElementById("vm-live-img").classList.add("hidden");
    document.getElementById("vm-live-placeholder").classList.remove("hidden");
  }
}

/* ── Execution ─────────────────────────────────── */
function executePrompt() {
  if (!state.wsConnected) { addErrorMsg("Not connected"); return; }

  const input = document.getElementById("prompt-input");
  let prompt = input.value.trim();
  if (!prompt) return;

  hideSlashMenu();

  const skill = document.getElementById("skill-select").value;
  if (skill) prompt = `/${skill} ${prompt}`;

  state.promptHistory.push(prompt);
  if (state.promptHistory.length > 50) state.promptHistory.shift();
  state.historyIndex = -1;

  // Queue follow-up if already executing
  if (state.executing) {
    addUserMsg(prompt);
    state._pendingPrompts = state._pendingPrompts || [];
    state._pendingPrompts.push(prompt);
    input.value = "";
    autoResizeTextarea(input);
    showToast("Queued — will execute after current task", "info");
    return;
  }

  addUserMsg(prompt);
  highlightAnalyzingFile(prompt);
  input.value = "";
  autoResizeTextarea(input);
  setExecuting(true);
  state.sessionToolCount = 0;
  state.sessionStartTime = Date.now();
  state.lastMessageTime = Date.now();
  showSpinner();
  showExecStatus();

  // Start periodic exec status update
  state.execInterval = setInterval(updateExecStatus, 1000);

  const claudeSessionId = currentSession().claudeSessionId || "";
  state.ws.send(JSON.stringify({ type: "execute", prompt, session_id: claudeSessionId }));
}

function cancelExecution() {
  state.ws.send(JSON.stringify({ type: "cancel" }));
  setExecuting(false);
  state._pendingPrompts = [];
}

function processPromptQueue() {
  if (!state._pendingPrompts?.length) return;
  const next = state._pendingPrompts.shift();
  // Small delay to let the UI settle
  setTimeout(() => {
    highlightAnalyzingFile(next);
    setExecuting(true);
    state.sessionToolCount = 0;
    state.sessionStartTime = Date.now();
    state.lastMessageTime = Date.now();
    showSpinner();
    showExecStatus();
    state.execInterval = setInterval(updateExecStatus, 1000);
    const claudeSessionId = currentSession().claudeSessionId || "";
    state.ws.send(JSON.stringify({ type: "execute", prompt: next, session_id: claudeSessionId }));
  }, 500);
}

function setExecuting(v) {
  state.executing = v;
  document.getElementById("execute-btn").disabled = false;
  document.getElementById("cancel-btn").style.display = v ? "inline-block" : "none";
  if (!v) {
    document.getElementById("prompt-input").focus();
    finalizeAssistantMsg();
    hideSpinner();
    hideExecStatus();
    // Don't auto-close VM Live View - user can close it manually
    updateSessionStats();
    state.activeAgents = {};
    clearAnalyzingHighlight();
  }
}

function showSpinner() {
  const el = document.getElementById("loading-spinner");
  el.classList.remove("hidden");
  const t = Date.now();
  state.spinnerInterval = setInterval(() => {
    document.getElementById("spinner-elapsed").textContent = `${((Date.now() - t) / 1000).toFixed(0)}s`;
  }, 1000);
}

function hideSpinner() {
  document.getElementById("loading-spinner").classList.add("hidden");
  clearInterval(state.spinnerInterval);
}

function notifyCompletion() {
  if (document.hidden && "Notification" in window) {
    if (Notification.permission === "granted") {
      new Notification("Analysis Complete", { body: "Processing finished." });
    } else if (Notification.permission !== "denied") {
      Notification.requestPermission();
    }
  }
}

/* ── File Upload ──────────────────────────────── */
function setupDragDrop() {
  const cp = document.getElementById("chat-panel");
  const dz = document.getElementById("drop-zone");
  cp.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.remove("hidden"); });
  cp.addEventListener("dragleave", (e) => { if (!cp.contains(e.relatedTarget)) dz.classList.add("hidden"); });
  cp.addEventListener("drop", (e) => {
    e.preventDefault();
    dz.classList.add("hidden");
    // Quarantine file drag
    const qData = e.dataTransfer.getData("application/x-quarantine");
    if (qData) {
      try {
        const info = JSON.parse(qData);
        const input = document.getElementById("prompt-input");
        const val = input.value;
        const pos = input.selectionStart || val.length;
        const sep = val && !val.endsWith(" ") ? " " : "";
        input.value = val.slice(0, pos) + sep + info.path + val.slice(pos);
        input.focus();
        const newPos = pos + sep.length + info.path.length;
        input.setSelectionRange(newPos, newPos);
        autoResizeTextarea(input);
      } catch (_) {}
      return;
    }
    // Regular file upload
    if (e.dataTransfer.files.length) uploadAndAnalyze(e.dataTransfer.files[0]);
  });
}

function handleFileSelect(event) {
  if (event.target.files[0]) uploadAndAnalyze(event.target.files[0]);
  event.target.value = "";
}

async function uploadAndAnalyze(file) {
  const MAX_SIZE = 100 * 1024 * 1024; // 100MB
  if (file.size > MAX_SIZE) {
    showToast(`File too large (${(file.size / 1024 / 1024).toFixed(1)}MB, max 100MB)`, "error");
    return;
  }
  // Show file preview before upload
  showFilePreview(file);
}

async function doUpload(file) {
  addSystemMsg(`Uploading: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
  const fd = new FormData();
  fd.append("file", file);
  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) { addErrorMsg(`Upload: ${data.error}`); return; }
    showToast(`Uploaded: ${data.name}`, "success");
    addSystemMsg(`Uploaded: ${data.name}`);
    insertPrompt(`このファイルを解析して: ${data.path}`);
  } catch (e) { addErrorMsg(`Upload: ${e.message}`); }
}

function showFilePreview(file) {
  state.previewedFile = file;
  const body = document.getElementById("file-preview-body");
  const sizeStr = file.size > 1024 * 1024 ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : `${(file.size / 1024).toFixed(1)} KB`;
  body.innerHTML = `
    <div class="preview-row"><span class="preview-label">Name</span><span class="preview-value">${esc(file.name)}</span></div>
    <div class="preview-row"><span class="preview-label">Size</span><span class="preview-value">${sizeStr}</span></div>
    <div class="preview-row"><span class="preview-label">Type</span><span class="preview-value">${esc(file.type || "unknown")}</span></div>
    <div class="preview-row"><span class="preview-label">Modified</span><span class="preview-value">${new Date(file.lastModified).toLocaleString("ja-JP")}</span></div>
  `;
  document.getElementById("file-preview-overlay").classList.remove("hidden");
}

function hideFilePreview() {
  document.getElementById("file-preview-overlay").classList.add("hidden");
  state.previewedFile = null;
}

function analyzePreviewedFile() {
  if (state.previewedFile) {
    doUpload(state.previewedFile);
    hideFilePreview();
  }
}

/* ── Chat History ─────────────────────────────── */
const HISTORY_KEY = "mat_chat_history";

function saveChatHistory() {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(
      state.sessions.map(s => ({ id: s.id, name: s.name, messages: s.messages.slice(-100), claudeSessionId: s.claudeSessionId || "" }))
    ));
  } catch (e) {}
}

function loadChatHistory() {
  try {
    const saved = JSON.parse(localStorage.getItem(HISTORY_KEY));
    if (!Array.isArray(saved) || !saved.length) return;
    state.sessions = saved.map(s => ({ ...s, log: [], claudeSessionId: s.claudeSessionId || "" }));
    state.activeSession = saved[0].id;
    state.sessionCounter = Math.max(...saved.map(s => s.id)) + 1;
    const chatEl = getChatEl();
    for (const msg of currentSession().messages) {
      const el = document.createElement("div");
      el.className = `msg ${msg.type}`;
      if (msg.type === "assistant") { el.innerHTML = renderMarkdown(msg.content); addCopyButtons(el); }
      else el.textContent = msg.content;
      chatEl.appendChild(el);
    }
    renderSessionTabs();
    updateWelcomeScreen();
    scrollChat();
  } catch (e) {}
}

/* ── Markdown ─────────────────────────────────── */
function renderMarkdown(text) {
  if (!text) return "";
  try {
    if (typeof marked !== "undefined") {
      marked.setOptions({ breaks: true, gfm: true });
      return marked.parse(text);
    }
  } catch (e) {}
  return esc(text).replace(/\n/g, "<br>");
}

function friendlyError(msg) {
  if (!msg) return "Unknown error";
  if (msg.includes("exit code 1")) return "Claude CLIエラー。claude --version で確認してください。";
  if (msg.includes("ECONNREFUSED")) return "Claude CLIに接続できません。";
  if (msg.includes("timeout")) return "タイムアウトしました。";
  if (msg.includes("permission")) return "権限エラーです。";
  const lines = msg.split("\n");
  return lines.length > 5 ? lines.slice(0, 3).join("\n") + "\n..." : msg;
}

/* ── Helpers ───────────────────────────────────── */
function scrollChat() {
  if (!state.autoScroll) return;
  getChatEl().scrollTop = getChatEl().scrollHeight;
}

function esc(s) {
  if (!s) return "";
  const d = document.createElement("div");
  d.textContent = String(s);
  return d.innerHTML;
}

function summarizeInput(toolName, input) {
  if (!input) return "";
  if (typeof input === "string") return input.slice(0, 80);
  if (toolName === "Bash") return (input.command || "").slice(0, 80);
  if (toolName === "Read") return input.file_path || "";
  if (toolName === "Write" || toolName === "Edit") return input.file_path || "";
  if (toolName === "Grep") return `/${input.pattern || ""}/ in ${input.path || "."}`;
  if (toolName === "Glob") return input.pattern || "";
  if (toolName === "Skill") return input.skill || "";
  if (toolName === "Agent") return (input.description || "").slice(0, 60);
  return JSON.stringify(input).slice(0, 80);
}

function toolColor(name) {
  return { Bash: "#2563eb", Read: "#059669", Write: "#d97706", Edit: "#d97706", Grep: "#7c3aed", Glob: "#7c3aed", Skill: "#e94560", Agent: "#db2777", WebFetch: "#0891b2", WebSearch: "#0891b2", ToolSearch: "#0891b2", TodoWrite: "#e67e22", TodoRead: "#e67e22", NotebookEdit: "#8b5cf6", MultiTool: "#6366f1" }[name] || "#888";
}

/* ── Toast Notifications ─────────────────────── */
function showToast(message, type = "info", duration = 3000) {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  const icons = { success: "\u2714", error: "\u2718", warning: "\u26A0", info: "\u2139" };
  toast.innerHTML = `<span>${icons[type] || ""}</span><span>${esc(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("toast-out");
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

/* ── Command Palette (Ctrl+K) ────────────────── */
const CMD_PALETTE_COMMANDS = [
  { category: "Analysis", icon: "\uD83D\uDD0E", label: "URL Analyze", action: () => insertPrompt("このURLを解析して: "), shortcut: "" },
  { category: "Analysis", icon: "\uD83D\uDD0D", label: "Ghidra Static Analysis", action: () => insertPrompt("/ghidra-headless "), shortcut: "" },
  { category: "Analysis", icon: "\uD83D\uDCBB", label: "VMware Dynamic Analysis", action: () => insertPrompt("/vmware-sandbox "), shortcut: "" },
  { category: "Analysis", icon: "\uD83C\uDF10", label: "Proxy Web", action: () => insertPrompt("/proxy-web "), shortcut: "" },
  { category: "Lookup", icon: "\uD83D\uDD0E", label: "VirusTotal Search", action: () => insertPrompt("VTでこのハッシュを調べて: "), shortcut: "" },
  { category: "Setup", icon: "\u2699", label: "Toolkit Setup", action: () => insertPrompt("/toolkit-setup"), shortcut: "" },
  { category: "Actions", icon: "\u25B2", label: "Collapse All Tools", action: () => collapseAllTools(), shortcut: "" },
  { category: "Actions", icon: "\u25BC", label: "Expand All Tools", action: () => expandAllTools(), shortcut: "" },
  { category: "Actions", icon: "\uD83D\uDCBB", label: "Toggle VM Live View", action: () => toggleVmLiveViewVisibility(), shortcut: "" },
  { category: "Actions", icon: "\u2193", label: "Toggle Auto Scroll", action: () => toggleAutoScroll(), shortcut: "" },
  { category: "Session", icon: "\u2795", label: "New Session", action: () => createSession(), shortcut: "Ctrl+N" },
  { category: "Session", icon: "\uD83D\uDDD1", label: "Clear Chat", action: () => clearChat(), shortcut: "Ctrl+L" },
  { category: "Session", icon: "\u2913", label: "Export Chat", action: () => exportChat(), shortcut: "Ctrl+S" },
  { category: "Session", icon: "\uD83D\uDD0D", label: "Search Chat", action: () => openChatSearch(), shortcut: "Ctrl+F" },
  { category: "UI", icon: "\uD83C\uDFA8", label: "Switch Theme", action: () => cycleTheme(), shortcut: "" },
  { category: "UI", icon: "\u21BB", label: "Refresh Status", action: () => { refreshStatus(); fetchReports(); fetchQuarantine(); fetchGhidraLogs(); showToast("Refreshed", "info"); }, shortcut: "" },
];

function setupCommandPalette() {
  const palette = document.getElementById("command-palette");
  const input = document.getElementById("cmd-palette-input");
  const results = document.getElementById("cmd-palette-results");

  input.addEventListener("input", () => renderCommandResults(input.value));

  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); navigateCmdPalette(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); navigateCmdPalette(-1); }
    else if (e.key === "Enter") {
      e.preventDefault();
      const item = state.cmdPaletteItems[state.cmdPaletteIndex];
      if (item) { palette.close(); item.action(); }
    }
    else if (e.key === "Escape") { palette.close(); }
  });

  // Close on backdrop click
  palette.addEventListener("click", (e) => {
    if (e.target === palette) palette.close();
  });
}

function toggleCommandPalette() {
  const palette = document.getElementById("command-palette");
  if (palette.open) {
    palette.close();
  } else {
    palette.showModal();
    const input = document.getElementById("cmd-palette-input");
    input.value = "";
    input.focus();
    renderCommandResults("");
  }
}

function renderCommandResults(query) {
  const results = document.getElementById("cmd-palette-results");
  const q = query.toLowerCase();
  state.cmdPaletteItems = CMD_PALETTE_COMMANDS.filter(c =>
    !q || c.label.toLowerCase().includes(q) || c.category.toLowerCase().includes(q)
  );
  state.cmdPaletteIndex = state.cmdPaletteItems.length > 0 ? 0 : -1;

  results.innerHTML = "";
  let lastCategory = "";
  for (let i = 0; i < state.cmdPaletteItems.length; i++) {
    const cmd = state.cmdPaletteItems[i];
    if (cmd.category !== lastCategory) {
      lastCategory = cmd.category;
      const sep = document.createElement("div");
      sep.className = "cmd-separator";
      sep.textContent = cmd.category;
      results.appendChild(sep);
    }
    const el = document.createElement("div");
    el.className = `cmd-item ${i === 0 ? "selected" : ""}`;
    el.innerHTML = `<span class="cmd-item-icon">${cmd.icon}</span><span class="cmd-item-label">${esc(cmd.label)}</span>${cmd.shortcut ? `<span class="cmd-item-shortcut">${cmd.shortcut}</span>` : ""}`;
    el.onclick = () => { document.getElementById("command-palette").close(); cmd.action(); };
    results.appendChild(el);
  }
}

function navigateCmdPalette(dir) {
  if (state.cmdPaletteItems.length === 0) return;
  state.cmdPaletteIndex += dir;
  if (state.cmdPaletteIndex < 0) state.cmdPaletteIndex = state.cmdPaletteItems.length - 1;
  if (state.cmdPaletteIndex >= state.cmdPaletteItems.length) state.cmdPaletteIndex = 0;
  const items = document.querySelectorAll("#cmd-palette-results .cmd-item");
  items.forEach((el, i) => {
    el.classList.toggle("selected", i === state.cmdPaletteIndex);
    if (i === state.cmdPaletteIndex) el.scrollIntoView({ block: "nearest" });
  });
}

/* ── Pipeline Indicator ──────────────────────── */
function setPipelineStage(stage) {
  state.currentPipelineStage = stage;
  document.querySelectorAll(".pipeline-stage").forEach(el => {
    if (el.dataset.stage === stage) {
      el.classList.add("active");
      el.classList.remove("completed");
    }
  });
}

function completePipelineStage(stage) {
  document.querySelectorAll(".pipeline-stage").forEach(el => {
    if (el.dataset.stage === stage) {
      el.classList.remove("active");
      el.classList.add("completed");
    }
  });
}

function resetPipeline() {
  state.currentPipelineStage = null;
  document.querySelectorAll(".pipeline-stage").forEach(el => {
    el.classList.remove("active", "completed");
  });
}

/* ── Context-Aware Panel Auto-Expand ─────────── */
function autoExpandPanel(panelId) {
  const section = document.getElementById(panelId);
  if (!section) return;
  const body = section.querySelector(".section-body");
  const h2 = section.querySelector("h2.collapsible");
  if (body && body.classList.contains("collapsed")) {
    body.classList.remove("collapsed");
    h2.classList.remove("is-collapsed");
    h2.setAttribute("aria-expanded", "true");
  }
}

/* ── Next Step Suggestion ────────────────────── */
function suggestNextStep() {
  const msgs = currentSession().messages;
  const lastAssistant = [...msgs].reverse().find(m => m.type === "assistant");
  if (!lastAssistant) return;

  const content = lastAssistant.content.toLowerCase();
  let suggestion = null;

  // Detect packed/obfuscated
  if (content.includes("pack") || content.includes("obfuscat") || content.includes("upx") || content.includes("themida") || content.includes("vmprotect")) {
    if (state.currentPipelineStage === "static") {
      suggestion = { text: "Packed binary detected. Run dynamic analysis to unpack.", action: "/vmware-sandbox ", label: "Dynamic Analysis" };
    }
  }
  // Detect need for deeper static analysis after dynamic
  if ((content.includes("unpack") || content.includes("dump")) && state.currentPipelineStage === "dynamic") {
    suggestion = { text: "Unpacked binary available. Re-analyze with Ghidra.", action: "/ghidra-headless ", label: "Re-analyze" };
  }
  // Detect IOCs found
  if (content.includes("ioc") || content.includes("c2") || content.includes("indicator")) {
    if (!content.includes("report")) {
      suggestion = { text: "IOCs detected. Generate a report.", action: "この解析結果をレポートにまとめて", label: "Generate Report" };
    }
  }

  if (suggestion) {
    showNextStep(suggestion);
  }
}

function showNextStep(suggestion) {
  state.pendingNextStep = suggestion;
  document.getElementById("next-step-text").textContent = suggestion.text;
  document.getElementById("next-step-action").textContent = suggestion.label;
  document.getElementById("next-step-bar").classList.remove("hidden");
}

function hideNextStep() {
  document.getElementById("next-step-bar").classList.add("hidden");
  state.pendingNextStep = null;
}

function applyNextStep() {
  if (state.pendingNextStep) {
    insertPrompt(state.pendingNextStep.action);
    hideNextStep();
  }
}

/* ── Auto-Rename Session Tab ─────────────────── */
function autoRenameSession() {
  const session = currentSession();
  if (!session.name.startsWith("Session ")) return; // Only rename default names

  const msgs = session.messages;
  // Look for hash or family name in recent messages
  const allText = msgs.map(m => m.content || "").join(" ");

  // Try to find SHA256 hash
  const sha256Match = allText.match(/\b([a-fA-F0-9]{64})\b/);
  if (sha256Match) {
    session.name = sha256Match[1].slice(0, 12) + "...";
    renderSessionTabs();
    return;
  }

  // Try to find malware family
  const familyPatterns = [
    /family[:\s]+["']?(\w+)/i,
    /malware[:\s]+["']?(\w+)/i,
    /(lumma|redline|raccoon|vidar|amadey|asyncrat|remcos|formbook|agenttesla|lokibot|njrat|emotet|trickbot|qakbot|icedid|cobalt\s*strike)/i,
  ];
  for (const pat of familyPatterns) {
    const m = allText.match(pat);
    if (m) {
      session.name = m[1].slice(0, 20);
      renderSessionTabs();
      return;
    }
  }
}

/* ── Hash Auto-Detection ─────────────────────── */
function setupHashDetection() {
  const input = document.getElementById("prompt-input");
  let debounceTimer;
  input.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => detectHash(input.value), 300);
  });
}

function detectHash(text) {
  const hashSuggest = document.getElementById("hash-suggest");
  if (!hashSuggest) return;

  const trimmed = text.trim();
  // MD5
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) {
    showHashSuggestion(trimmed, "MD5");
    return;
  }
  // SHA1
  if (/^[a-fA-F0-9]{40}$/.test(trimmed)) {
    showHashSuggestion(trimmed, "SHA1");
    return;
  }
  // SHA256
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
    showHashSuggestion(trimmed, "SHA256");
    return;
  }

  hideHashSuggestion();
}

function showHashSuggestion(hash, type) {
  let el = document.getElementById("hash-suggest");
  if (!el) {
    el = document.createElement("div");
    el.id = "hash-suggest";
    document.getElementById("chat-input-row").style.position = "relative";
    document.getElementById("chat-input-row").appendChild(el);
  }
  el.innerHTML = `<span>${type} detected: ${hash.slice(0, 16)}...</span><button onclick="insertPrompt('VTでこのハッシュを調べて: ${hash}'); hideHashSuggestion()">VT Search</button>`;
  el.classList.remove("hidden");
}

function hideHashSuggestion() {
  const el = document.getElementById("hash-suggest");
  if (el) el.classList.add("hidden");
}

/* ── Collapsible ARIA setup ──────────────────── */
function setupCollapsibleAria() {
  document.querySelectorAll("h2.collapsible").forEach(h2 => {
    h2.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleSection(h2);
      }
    });
  });
}
