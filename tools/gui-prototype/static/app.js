/* ── State ──────────────────────────────────────── */
const state = {
  ws: null,
  executing: false,
  currentAssistantMsg: null,
};

/* ── Init ──────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  refreshStatus();
  fetchSkills();
  fetchMode();
  connectWebSocket();
});

/* ── REST calls ────────────────────────────────── */
async function refreshStatus() {
  const list = document.getElementById("status-list");
  list.innerHTML = '<div class="status-item loading">Checking...</div>';

  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    renderStatus(data);
  } catch (e) {
    list.innerHTML = `<div class="status-item"><span class="dot error"></span>Failed to fetch status</div>`;
  }
}

function renderStatus(data) {
  const list = document.getElementById("status-list");
  list.innerHTML = "";

  const items = [
    ["env_file", ".env"],
    ["docker", "Docker Desktop"],
    ["proxy_web_image", "proxy-web image"],
    ["ghidra_container", "ghidra-headless"],
    ["vmware", "VMware"],
    ["claude_cli", "Claude CLI"],
    ["agent_sdk", "Agent SDK"],
    ["api_key", "API Key"],
    ["yara_rules", "YARA Rules"],
  ];

  for (const [key, label] of items) {
    const info = data[key];
    if (!info) continue;
    const el = document.createElement("div");
    el.className = "status-item";
    el.innerHTML = `
      <span class="dot ${info.status}"></span>
      <span class="label">${label}</span>
      <span class="detail" title="${esc(info.detail)}">${esc(info.detail)}</span>
    `;
    list.appendChild(el);
  }
}

async function fetchSkills() {
  try {
    const res = await fetch("/api/skills");
    const skills = await res.json();
    const sel = document.getElementById("skill-select");
    for (const s of skills) {
      const opt = document.createElement("option");
      opt.value = s.name;
      opt.textContent = s.name;
      opt.title = s.description;
      sel.appendChild(opt);
    }
  } catch (e) {
    console.error("Failed to fetch skills:", e);
  }
}

async function fetchMode() {
  try {
    const res = await fetch("/api/mode");
    const data = await res.json();
    document.getElementById("mode-label").textContent = data.mode;
  } catch (e) {
    document.getElementById("mode-label").textContent = "error";
  }
}

async function toggleMode() {
  const current = document.getElementById("mode-label").textContent;
  const next = current === "sdk" ? "subprocess" : "sdk";
  try {
    const res = await fetch(`/api/mode/${next}`, { method: "POST" });
    const data = await res.json();
    document.getElementById("mode-label").textContent = data.mode || data.error;
  } catch (e) {
    console.error("Failed to switch mode:", e);
  }
}

/* ── WebSocket ─────────────────────────────────── */
function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  state.ws = new WebSocket(`${proto}//${location.host}/ws/chat`);

  state.ws.onopen = () => console.log("WS connected");
  state.ws.onclose = () => {
    console.log("WS disconnected, reconnecting in 2s...");
    setTimeout(connectWebSocket, 2000);
  };
  state.ws.onerror = (e) => console.error("WS error:", e);
  state.ws.onmessage = (event) => handleMessage(JSON.parse(event.data));
}

/* ── Message handling ──────────────────────────── */
function handleMessage(msg) {
  switch (msg.type) {
    case "system":
      addSystemMsg(`[${msg.subtype}] mode=${msg.data?.mode || ""}`);
      break;

    case "text":
      appendAssistantText(msg.content);
      break;

    case "tool_use":
      addToolCall(msg);
      addLogEntry(msg.name, summarizeInput(msg.name, msg.input));
      break;

    case "tool_result":
      updateToolResult(msg);
      break;

    case "result":
      addResultFooter(msg);
      setExecuting(false);
      break;

    case "error":
      addErrorMsg(msg.message);
      setExecuting(false);
      break;
  }
}

/* ── Chat rendering ────────────────────────────── */
const chatEl = document.getElementById("chat-messages");

function addUserMsg(text) {
  const el = document.createElement("div");
  el.className = "msg user";
  el.textContent = text;
  chatEl.appendChild(el);
  state.currentAssistantMsg = null;
  scrollChat();
}

function appendAssistantText(text) {
  if (!state.currentAssistantMsg) {
    state.currentAssistantMsg = document.createElement("div");
    state.currentAssistantMsg.className = "msg assistant";
    chatEl.appendChild(state.currentAssistantMsg);
  }
  state.currentAssistantMsg.textContent += text;
  scrollChat();
}

function addSystemMsg(text) {
  const el = document.createElement("div");
  el.className = "msg system-msg";
  el.textContent = text;
  chatEl.appendChild(el);
  state.currentAssistantMsg = null;
  scrollChat();
}

function addErrorMsg(text) {
  const el = document.createElement("div");
  el.className = "msg error";
  el.textContent = text;
  chatEl.appendChild(el);
  state.currentAssistantMsg = null;
  scrollChat();
}

function addToolCall(msg) {
  state.currentAssistantMsg = null;

  const el = document.createElement("div");
  el.className = "tool-call";
  el.dataset.toolId = msg.id;

  const inputPreview = summarizeInput(msg.name, msg.input);

  el.innerHTML = `
    <div class="tool-call-header" onclick="this.nextElementSibling.classList.toggle('open')">
      <span class="tool-badge ${msg.name}">${esc(msg.name)}</span>
      <span>${esc(inputPreview)}</span>
      <span class="tool-result-badge" data-result-for="${msg.id}"></span>
    </div>
    <div class="tool-call-body">${esc(JSON.stringify(msg.input, null, 2))}</div>
  `;
  chatEl.appendChild(el);
  scrollChat();
}

function updateToolResult(msg) {
  const badge = document.querySelector(`[data-result-for="${msg.tool_use_id}"]`);
  if (badge) {
    badge.textContent = msg.is_error ? "ERROR" : "OK";
    badge.className = `tool-result-badge ${msg.is_error ? "err" : "ok"}`;
  }
  // Add result content to the tool call body
  const toolCall = document.querySelector(`[data-tool-id="${msg.tool_use_id}"]`);
  if (toolCall) {
    const body = toolCall.querySelector(".tool-call-body");
    if (body) {
      body.textContent += "\n--- Result ---\n" + msg.content;
    }
  }
}

function addResultFooter(msg) {
  const el = document.createElement("div");
  el.className = "result-footer";
  const cost = msg.cost_usd ? `$${msg.cost_usd.toFixed(4)}` : "---";
  const dur = msg.duration_ms ? `${(msg.duration_ms / 1000).toFixed(1)}s` : "---";
  el.innerHTML = `<span class="cost">${cost}</span> | <span class="duration">${dur}</span>`;
  chatEl.appendChild(el);
  state.currentAssistantMsg = null;
  scrollChat();
}

/* ── Tool activity log ─────────────────────────── */
const logEl = document.getElementById("tool-log");

function addLogEntry(toolName, detail) {
  const el = document.createElement("div");
  el.className = "log-entry";
  const time = new Date().toLocaleTimeString("ja-JP", { hour12: false });
  el.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-tool" style="color:${toolColor(toolName)}">${esc(toolName)}</span>
    <span class="log-detail" title="${esc(detail)}">${esc(detail)}</span>
  `;
  logEl.appendChild(el);
  logEl.scrollTop = logEl.scrollHeight;
}

/* ── Execution ─────────────────────────────────── */
function executePrompt() {
  if (state.executing) return;
  const input = document.getElementById("prompt-input");
  let prompt = input.value.trim();
  if (!prompt) return;

  const skill = document.getElementById("skill-select").value;
  if (skill) {
    prompt = `/${skill} ${prompt}`;
  }

  addUserMsg(prompt);
  input.value = "";
  setExecuting(true);

  state.ws.send(JSON.stringify({ type: "execute", prompt }));
}

function cancelExecution() {
  state.ws.send(JSON.stringify({ type: "cancel" }));
  setExecuting(false);
}

function setExecuting(v) {
  state.executing = v;
  document.getElementById("execute-btn").disabled = v;
  document.getElementById("cancel-btn").style.display = v ? "inline-block" : "none";
  document.getElementById("prompt-input").disabled = v;
  if (!v) document.getElementById("prompt-input").focus();
}

/* ── Helpers ───────────────────────────────────── */
function scrollChat() {
  chatEl.scrollTop = chatEl.scrollHeight;
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
  const colors = {
    Bash: "#2563eb", Read: "#059669", Write: "#d97706", Edit: "#d97706",
    Grep: "#7c3aed", Glob: "#7c3aed", Skill: "#e94560", Agent: "#db2777",
    WebFetch: "#0891b2", WebSearch: "#0891b2",
  };
  return colors[name] || "#888";
}
