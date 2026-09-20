const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) n.setAttribute(k, v);
  }
  // Teclado en nodos con onclick (no en celdas ni overlays).
  if (typeof attrs.onclick === "function") {
    const t = n.tagName;
    const native = t === "A" || t === "BUTTON" || t === "INPUT" || t === "SELECT" || t === "TEXTAREA" || t === "LABEL";
    const skip = t === "TD" || t === "TH" || /(^|\s)modal-bg(\s|$)/.test(n.className || "");
    if (!native && !skip) {
      if (!n.hasAttribute("tabindex")) n.setAttribute("tabindex", "0");
      if (!n.hasAttribute("role")) n.setAttribute("role", "button");
      n.addEventListener("keydown", (e) => {
        if ((e.key === "Enter" || e.key === " ") && e.target === n) { e.preventDefault(); n.click(); }
      });
    }
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    n.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
};
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

// CSI del PTY: redibuja pantalla, no concatena.
function ansiScreen(rows = 28, cols = 100) {
  let grid = Array.from({ length: rows }, () => Array(cols).fill(" "));
  let r = 0, c = 0;
  const clamp = () => { r = Math.max(0, Math.min(rows - 1, r)); c = Math.max(0, Math.min(cols - 1, c)); };
  const eraseEOL = () => { for (let x = c; x < cols; x++) grid[r][x] = " "; };
  const eraseLine = () => { for (let x = 0; x < cols; x++) grid[r][x] = " "; };
  const eraseEOS = () => { eraseEOL(); for (let y = r + 1; y < rows; y++) for (let x = 0; x < cols; x++) grid[y][x] = " "; };
  const eraseAll = () => { grid = Array.from({ length: rows }, () => Array(cols).fill(" ")); r = 0; c = 0; };
  const put = (ch) => {
    if (ch === "\n") { r++; c = 0; if (r >= rows) { grid.shift(); grid.push(Array(cols).fill(" ")); r = rows - 1; } return; }
    if (ch === "\r") { c = 0; return; }
    if (ch === "\b") { c = Math.max(0, c - 1); return; }
    if (ch === "\t") { c = Math.min(cols - 1, c + (8 - (c % 8))); return; }
    if (ch === "\x07") return;
    grid[r][c] = ch;
    c++;
    if (c >= cols) { c = 0; r++; if (r >= rows) { grid.shift(); grid.push(Array(cols).fill(" ")); r = rows - 1; } }
  };
  const csi = (params, inter, cmd) => {
    const n = (i, d) => { const v = parseInt(params[i], 10); return Number.isFinite(v) && v > 0 ? v : d; };
    if (inter === "?") return;
    if (cmd === "A") { r -= n(0, 1); clamp(); return; }
    if (cmd === "B") { r += n(0, 1); clamp(); return; }
    if (cmd === "C") { c += n(0, 1); clamp(); return; }
    if (cmd === "D") { c -= n(0, 1); clamp(); return; }
    if (cmd === "H" || cmd === "f") { r = n(0, 1) - 1; c = n(1, 1) - 1; clamp(); return; }
    if (cmd === "G") { c = n(0, 1) - 1; clamp(); return; }
    if (cmd === "J") { const m = parseInt(params[0], 10) || 0; if (m === 2 || m === 3) eraseAll(); else eraseEOS(); return; }
    if (cmd === "K") { const m = parseInt(params[0], 10) || 0; if (m === 2) eraseLine(); else eraseEOL(); return; }
    if (cmd === "m" || cmd === "h" || cmd === "l" || cmd === "n" || cmd === "s" || cmd === "u") return;
  };
  const apply = (raw) => {
    let i = 0;
    const s = String(raw);
    while (i < s.length) {
      const ch = s[i];
      if (ch === "\x1b") {
        const n1 = s[i + 1];
        if (n1 === "[") {
          i += 2;
          let inter = "";
          if (s[i] === "?") { inter = "?"; i++; }
          let p = "";
          while (i < s.length && /[0-9;]/.test(s[i])) p += s[i++];
          const cmd = s[i++] || "";
          csi(p.split(";"), inter, cmd);
          continue;
        }
        if (n1 === "]") {
          i += 2;
          while (i < s.length && s[i] !== "\x07" && !(s[i] === "\x1b" && s[i + 1] === "\\")) i++;
          if (s[i] === "\x07") i++;
          else if (s[i] === "\x1b") i += 2;
          continue;
        }
        i += n1 ? 2 : 1;
        continue;
      }
      put(ch);
      i++;
    }
  };
  const render = () => grid.map((row) => row.join("").replace(/\s+$/, "")).join("\n").replace(/\n+$/, "");
  return { apply, render };
}

// AEGIS_WEB_TOKEN: ?token= → localStorage. Header en fetch; query en SSE (EventSource no lleva headers).
const TOKEN = (() => {
  try {
    const q = new URL(location.href).searchParams.get("token");
    if (q) { localStorage.setItem("aegis_token", q); return q; }
    return localStorage.getItem("aegis_token") || "";
  } catch { return ""; }
})();
const authHeaders = (h = {}) => (TOKEN ? { ...h, "X-Aegis-Token": TOKEN } : h);
const withTok = (url) => (TOKEN ? url + (url.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(TOKEN) : url);
const evtSource = (url) => new EventSource(withTok(url));
function evidencePath(rel) {
  return String(rel || "").split("/").filter((p) => p !== "").map(encodeURIComponent).join("/");
}
function evidenceUrl(runId, rel, query) {
  let url = `/api/runs/${runId}/files/${evidencePath(rel)}`;
  if (query) url += query;
  return url;
}
function evidenceIsFile(rel) {
  const s = String(rel || "").trim().replace(/^\.\//, "");
  if (!s || s.length > 200 || /[\n\r]/.test(s)) return false;
  if (/\s=>\s/.test(s) || /\s\([^)]+\)\s/.test(s)) return false;
  if (/^(nxc|netexec|crackmapexec|cme|smbclient|curl|nmap|ldapsearch|impacket)\b/i.test(s)) return false;
  const base = s.split("/").pop() || "";
  if (s.includes(" ") && !/\.[A-Za-z0-9]{1,8}$/.test(base)) return false;
  return s.includes("/") || /\.[A-Za-z0-9]{1,8}$/.test(s);
}

const _getInflight = new Map();
const api = {
  async get(p) {
    const hit = _getInflight.get(p);
    if (hit) return hit;
    const job = (async () => {
      const r = await fetch(p, { headers: authHeaders() });
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.status);
      return r.json();
    })();
    _getInflight.set(p, job);
    try { return await job; }
    finally { if (_getInflight.get(p) === job) _getInflight.delete(p); }
  },
  async getText(p) { const r = await fetch(p, { headers: authHeaders() }); if (!r.ok) throw new Error(r.status); return r.text(); },
  async post(p, body, opts = {}) {
    const r = await fetch(p, { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(body || {}), signal: opts.signal });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || r.status);
    return j;
  },
  async upload(p, file, name) {
    const r = await fetch(p, { method: "POST", headers: authHeaders({ "X-Aegis-Name": encodeURIComponent(name || file.name) }), body: file });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || r.status);
    return j;
  },
  async del(p, body) {
    const headers = body ? authHeaders({ "Content-Type": "application/json" }) : authHeaders();
    const r = await fetch(p, { method: "DELETE", headers, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || r.status);
    return j;
  },
  async patch(p, body) { const r = await fetch(p, { method: "PATCH", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(body || {}) }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.status); return j; },
};

const ICON = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.2-2.8 7.7-7 9-4.2-1.3-7-4.8-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
  play: '<svg viewBox="0 0 24 24" class="ic"><path d="M7 5l12 7-12 7z"/></svg>',
  pause: '<svg viewBox="0 0 24 24" class="ic"><path d="M8 5v14M16 5v14"/></svg>',
  stop: '<svg viewBox="0 0 24 24" class="ic"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>',
  doc: '<svg viewBox="0 0 24 24" class="ic"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/></svg>',
  download: '<svg viewBox="0 0 24 24" class="ic"><path d="M12 4v11M7 11l5 5 5-5M5 20h14"/></svg>',
  copy: '<svg viewBox="0 0 24 24" class="ic"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5h10"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" class="ic"><path d="M20 11a8 8 0 1 0-2 5"/><path d="M20 5v6h-6"/></svg>',
  plus: '<svg viewBox="0 0 24 24" class="ic"><path d="M12 5v14M5 12h14"/></svg>',
  trash: '<svg viewBox="0 0 24 24" class="ic"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>',
  edit: '<svg viewBox="0 0 24 24" class="ic"><path d="M4 20h4l10-10-4-4L4 16v4z"/><path d="M13 7l4 4"/></svg>',
  terminal: '<svg viewBox="0 0 24 24" class="fic"><path d="M4 5h16v14H4z"/><path d="M8 10l3 2-3 2M13 14h4"/></svg>',
  code: '<svg viewBox="0 0 24 24" class="fic"><path d="M9 8l-4 4 4 4M15 8l4 4-4 4"/></svg>',
  file: '<svg viewBox="0 0 24 24" class="fic"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/></svg>',
  flag: '<svg viewBox="0 0 24 24" class="fic"><path d="M5 21V4M5 4h11l-2 4 2 4H5"/></svg>',
  net: '<svg viewBox="0 0 24 24" class="ic"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
};
const heroShield = '<svg viewBox="0 0 24 24"><defs><linearGradient id="ashield" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#e59a3f"/><stop offset="1" stop-color="#b4d15f"/></linearGradient></defs><path d="M12 2l7 3v6c0 4.5-3 8.3-7 9-4-.7-7-4.5-7-9V5l7-3z" fill="none" stroke="url(#ashield)" stroke-width="1.4"/><path d="M9 12l2 2 4-4" fill="none" stroke="url(#ashield)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';

const state = { view: "operar", catalog: null, catalogTs: 0, doctor: null, liveId: null, runs: null, runsTs: 0, queue: [], operarFace: "", liveWatch: null, es: {}, tabCleanup: null, viewRun: null, followLive: false, launchAt: 0, expectQid: "" };
const VIEW_TITLES = { operar: "Operar", lanzar: "Lanzar engagement", historial: "Historial", cuentas: "Modelos" };
const KPI_HELP = {
  tiempo: "Tiempo en marcha del agente. No cuenta pausas ni el cierre (revisión, corrección e informe).",
  tokens: "Tokens de entrada + salida consumidos por el modelo.",
  hyps: "Hipótesis del cuaderno: vivas / total.",
  findings: "Hallazgos: P=demostrados, S=sospechados.",
  cmds: "Comandos que ha ejecutado el agente.",
  conscience: "Auditor interno: revisa cada turno y decide SIGUE / AVISA / SALVAGUARDA.",
  cuentas: "Cuentas identificadas (login, SSH…).",
  flags: "Flags capturadas frente al contrato CTF.",
  sev: "Reparto de hallazgos por severidad (C/H/M/L/I).",
};

const runTitle = (r) => String((r && r.title) || "").trim() || (r && r.run_id) || "";
function runTargetValues(r) {
  return ((r && r.targets) || []).map((t) => String((t && t.value) || "").trim()).filter(Boolean);
}
function cardTitle(r) {
  let title = String((r && r.title) || "").trim();
  for (const t of runTargetValues(r)) {
    const esc = t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    title = title.replace(new RegExp(`(?:^|[\\s,;|/]+)${esc}(?=$|[\\s,;|/])`, "gi"), " ");
  }
  title = title.replace(/\s+/g, " ").trim();
  return title;
}
function cardTarget(r) {
  return runTargetValues(r).join(", ");
}

function toast(msg, kind = "") {
  const t = el("div", { class: "toast " + kind }, msg);
  $("#toast-root").appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transform = "translateX(20px)"; setTimeout(() => t.remove(), 300); }, 3200);
}

function closeStreams() {
  if (state.tabCleanup) { try { state.tabCleanup(); } catch {} state.tabCleanup = null; }
  for (const k of Object.keys(state.es)) { try { state.es[k].close(); } catch {} delete state.es[k]; }
}

function fmtDur(s) { s = Math.max(0, Number(s || 0)); const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60); return (h ? `${h}h ` : "") + `${m}m ${String(sec).padStart(2,"0")}s`; }
function fmtDurShort(s) {
  s = Math.max(0, Number(s || 0));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h && m) return `${h}h ${m}m`;
  if (h) return `${h}h`;
  return `${m}m`;
}
// Transcurrido / máximo (si hay timeout): "12m 03s / 30m 00s". Sin máximo, solo el transcurrido.
function fmtDurMax(s, max) { const t = fmtDur(s); const m = Number(max || 0); return m > 0 ? t + " / " + fmtDur(m) : t; }
function fmtBytes(n) { n = Number(n || 0); if (n < 1024) return n + " B"; if (n < 1048576) return (n / 1024).toFixed(1) + " KB"; return (n / 1048576).toFixed(1) + " MB"; }
function fmtTs(ts) {
  if (ts == null || ts === "") return "";
  try {
    let d;
    if (typeof ts === "number" || (typeof ts === "string" && /^\d+(\.\d+)?$/.test(String(ts).trim()))) {
      const n = Number(ts);
      d = new Date(n < 1e12 ? n * 1000 : n);
    } else {
      d = new Date(String(ts).replace(/(\.\d{3})\d+Z$/, "$1Z"));
    }
    if (isNaN(d.getTime())) return "";
    return d.toLocaleTimeString("es-ES", { hour12: false });
  } catch { return ""; }
}
function num(n) {
  const x = Math.round(Number(n || 0));
  return x.toLocaleString("es-ES").replace(/\./g, "\u202f");
}
function toolArgs(args) {
  if (args == null || args === "" || args === "{}" || args === "[]") return "—";
  if (typeof args === "object") {
    const d = args.command || args.cmd || args.filePath || args.path || args.pattern || args.url || args.query || "";
    if (d) return String(d);
    const keys = Object.keys(args);
    if (!keys.length) return "—";
    try { const s = JSON.stringify(args); return s.length > 280 ? s.slice(0, 280) + "…" : s; } catch { return "—"; }
  }
  const s = String(args);
  return (!s || s === "{}" || s === "[]") ? "—" : (s.length > 280 ? s.slice(0, 280) + "…" : s);
}

function navActive(view) {
  for (const b of document.querySelectorAll("#nav button")) b.classList.toggle("active", b.dataset.view === view);
}
function paintTopbar() {
  const host = $("#page-title");
  if (!host) return;
  host.replaceChildren();
  if (state.view === "operar" && state.viewRun) {
    host.appendChild(el("button", { class: "crumb-link", onclick: () => setView("operar") }, "Operar"));
    host.appendChild(el("span", { class: "crumb-sep" }, "/"));
    host.appendChild(el("span", { class: "crumb-cur", id: "crumb-run" }, state._runLabel || "Run"));
  } else {
    host.appendChild(document.createTextNode(VIEW_TITLES[state.view] || state.view));
  }
}
function setView(v, opts) {
  opts = opts || {};
  if (!opts.fromRoute) { const h = "#/" + v; if (location.hash !== h) history.pushState(null, "", h); }
  state.view = v;
  state.viewRun = null;
  state.routeTab = null;
  navActive(v);
  paintTopbar();
  closeStreams();
  render();
}
function parseHash() {
  const parts = (location.hash || "").replace(/^#\/?/, "").split("/").filter(Boolean);
  if (!parts.length) return { view: "operar" };
  if (parts[0] === "run" && parts[1]) return { view: "operar", runId: decodeURIComponent(parts[1]), tab: parts[2] || null };
  if (parts[0] === "modelos") return { view: "cuentas" };
  if (["operar", "lanzar", "historial", "cuentas"].includes(parts[0])) return { view: parts[0] };
  return { view: "operar" };
}
function applyRoute() {
  const r = parseHash();
  if (r.runId) openRun(r.runId, { tab: r.tab, fromRoute: true });
  else setView(r.view, { fromRoute: true });
}
window.addEventListener("popstate", applyRoute);
for (const b of document.querySelectorAll("#nav button")) b.addEventListener("click", () => setView(b.dataset.view));

async function render() {
  const gen = (state.renderGen = (state.renderGen || 0) + 1);
  const view = $("#view");
  view.dataset.view = state.viewRun ? "run" : state.view;
  try {
    if (state.view === "operar") await renderOperar(view, gen);
    else if (state.view === "lanzar") await renderLanzar(view, gen);
    else if (state.view === "historial") await renderHistorial(view, gen);
    else if (state.view === "cuentas") await renderCuentas(view, gen);
  } catch (e) {
    if (state.renderGen !== gen) return;
    view.innerHTML = "";
    view.appendChild(el("div", { class: "empty" }, el("div", { class: "em-title" }, "Error"), e.message));
  }
}

function dropCatalog() { state.catalog = null; state.catalogTs = 0; }

const HARNESS_CHOICES = [
  { id: "opencode", label: "OpenCode — Grok, ChatGPT, gateway, local" },
  { id: "codex", label: "Codex CLI — tu login de ChatGPT" },
  { id: "claude", label: "Claude Code — tu login de Claude.ai" },
];

function harnessReady(cat, h) {
  const hs = ((cat && cat.harnesses) || {})[h] || {};
  if (h === "opencode") return !!(cat && (cat.opencode || hs.available || hs.binary));
  return !!(hs.available || hs.binary);
}
function dropRuns() { state.runsTs = 0; }
function runsFresh() { return Array.isArray(state.runs) && Date.now() - (state.runsTs || 0) < 4000; }
function catalogFresh() { return state.catalog && Date.now() - (state.catalogTs || 0) < 20000; }
function rememberRuns(runs) {
  if (!Array.isArray(runs)) return state.runs || [];
  state.runs = runs;
  state.runsTs = Date.now();
  return state.runs;
}
async function loadRuns() {
  if (runsFresh()) return state.runs;
  try {
    return rememberRuns(await api.get("/api/runs"));
  } catch {
    return state.runs || [];
  }
}
function queueIsStarting(it) {
  if (!it || (it.state !== "launching" && it.state !== "running")) return false;
  if (!it.run_id) return true;
  const r = (state.runs || []).find((x) => x.run_id === it.run_id);
  if (r && (r.status === "ended" || !r.live)) return false;
  return true;
}
function operarFace() {
  if (state.viewRun) return "run:" + state.viewRun;
  if (state.followLive && !state.liveId) return "launching";
  if (state.liveId) return "live:" + state.liveId;
  if ((state.queue || []).some(queueIsStarting)) return "launching";
  return "idle";
}
function syncOperarFromHeader() {
  if (state.view !== "operar") return;
  if (state.viewRun) return;
  const face = operarFace();
  if (face === state.operarFace) return;
  closeStreams();
  render();
}
function listedLive(runs) {
  return (runs || []).find((r) => r.live && r.status !== "ended") || null;
}
function isFreshLaunch(r) {
  if (!r || r.status === "ended") return false;
  if (state.expectQid) {
    const it = (state.queue || []).find((x) => x.qid === state.expectQid);
    if (it && it.run_id) return r.run_id === it.run_id;
    if (it) return false;
  }
  if (!state.followLive || !state.launchAt) return !!r.live;
  const t = Date.parse(r.started_at || "");
  return Number.isFinite(t) && t >= state.launchAt - 15000;
}
function launchTarget(runs) {
  if (state.expectQid) {
    const it = (state.queue || []).find((x) => x.qid === state.expectQid);
    if (it && it.run_id) {
      const hit = (runs || []).find((x) => x.run_id === it.run_id && x.status !== "ended");
      if (hit) return hit;
    }
    if (it && !it.run_id) return null;
  }
  return (runs || []).find((r) => r.live && isFreshLaunch(r)) || null;
}
function stopLiveWatch() {
  if (!state.liveWatch) return;
  clearInterval(state.liveWatch);
  state.liveWatch = null;
}
function rememberLaunch(item) {
  state.followLive = true;
  state.launchAt = Date.now();
  state.expectQid = (item && item.qid) || "";
  state.viewRun = null;
  if (item && item.qid && !(state.queue || []).some((x) => x.qid === item.qid)) {
    state.queue = (state.queue || []).concat([item]);
  }
}
function watchUntilLive() {
  stopLiveWatch();
  const started = Date.now();
  const tick = async () => {
    dropRuns();
    await refreshHeader({ force: true });
    let live = launchTarget(state.runs || []);
    if (!live) {
      const listed = listedLive(state.runs || []);
      const waiting = !!(state.expectQid && (state.queue || []).some((x) => x.qid === state.expectQid && !x.run_id));
      const t = listed ? Date.parse(listed.started_at || "") : NaN;
      const fresh = Number.isFinite(t) && state.launchAt && t >= state.launchAt - 15000;
      if (listed && fresh && (!waiting || Date.now() - started > 4000)) live = listed;
    }
    if (live) {
      state.liveId = live.run_id;
      stopLiveWatch();
      state.followLive = false;
      state.launchAt = 0;
      state.expectQid = "";
      if (state.view === "operar" && !state.viewRun) {
        closeStreams();
        render();
      }
      return;
    }
    if (Date.now() - started > 200000) {
      stopLiveWatch();
      state.followLive = false;
      state.launchAt = 0;
      state.expectQid = "";
    }
  };
  tick();
  state.liveWatch = setInterval(tick, 750);
}
async function loadCatalog(force) {
  if (!force && catalogFresh()) return state.catalog;
  const cat = await api.get("/api/models");
  state.catalog = cat;
  state.catalogTs = Date.now();
  return cat;
}

let _headerInflight = null;
let _headerSeq = 0;
async function refreshHeader(opts) {
  const forceDoctor = !!(opts && opts.refreshDoctor);
  const force = !!(opts && opts.force);
  if (_headerInflight && !forceDoctor && !force) return _headerInflight;
  const job = _refreshHeader(opts || {});
  _headerInflight = job;
  try {
    const result = await job;
    if (_headerInflight && _headerInflight !== job) return await _headerInflight;
    return result;
  } finally {
    if (_headerInflight === job) _headerInflight = null;
  }
}
async function _refreshHeader(opts) {
  const seq = ++_headerSeq;
  const forceDoctor = !!(opts && opts.refreshDoctor);
  const doctorUrl = forceDoctor ? "/api/doctor?refresh=1" : "/api/doctor";
  const [doctor, runs, q] = await Promise.all([
    api.get(doctorUrl).catch(() => state.doctor),
    api.get("/api/runs").catch(() => undefined),
    api.get("/api/queue").catch(() => undefined),
  ]);
  if (seq !== _headerSeq) return;
  if (doctor) state.doctor = doctor;
  if (Array.isArray(runs)) rememberRuns(runs);
  if (Array.isArray(q)) state.queue = q;
  const listedRuns = Array.isArray(runs) ? runs : (state.runs || []);
  const followed = state.followLive ? launchTarget(listedRuns) : null;
  const listed = listedLive(listedRuns);
  if (followed) state.liveId = followed.run_id;
  else if (!state.followLive) state.liveId = listed ? listed.run_id : null;
  const live = followed || listed;

  const d = state.doctor || {};
  const mini = $("#doctor-mini");
  mini.innerHTML = "";
  // Texto + punto: el estado no va solo en color.
  const line = (ok, label, extra, title) => {
    const st = extra || (ok ? "ok" : "no");
    return el("div", { class: "dline", title: title || "" },
      el("span", { class: "dot " + (ok ? "ok" : "bad"), "aria-hidden": "true" }),
      el("span", { class: "dname" }, label),
      el("span", { class: "dstate " + (ok ? "ok" : "bad") }, st),
    );
  };
  const cx = d.codex || {};
  const cl = d.claude || {};
  mini.appendChild(line(d.image_ok, "Imagen sandbox", d.image_ok ? "lista" : "falta", `Imagen '${d.image || "aegis-runner:latest"}' construida con Docker (make image): SO + herramientas del agente. Si está lista, Docker está activo.`));
  mini.appendChild(line(!!d.opencode, "OpenCode", d.opencode ? "listo" : "falta", "Binario de OpenCode en el host (el harness/cerebro que corre en el sandbox)."));
  mini.appendChild(line(!!cx.logged_in, "Codex", cx.logged_in ? (cx.auth_mode || "ChatGPT") : (cx.binary ? "sin login" : "ausente"), "Codex CLI en el host (harness). Login: Sign in with ChatGPT. Ausente = no hay binario; instálalo y refresca Modelos."));
  mini.appendChild(line(!!cl.logged_in, "Claude Code", cl.logged_in ? (cl.auth_mode || "suscripción") : (cl.expired ? "caducado" : (cl.binary ? "sin login" : "ausente")), "Claude Code nativo en el host (harness). Login: claude auth login. «Logueado» si el access vale o el refresh aún sirve (se renueva al lanzar). Caducado = hay que hacer login otra vez."));

  const warn = $("#warnings");
  warn.innerHTML = "";
  if (d && d.docker_ok && !d.image_ok) warn.appendChild(el("div", { class: "warnbadge" }, "Falta imagen (make image)"));

  paintLiveChip(live);

  renderQueueWidget(Array.isArray(q) ? q : (state.queue || []));
  if (!(opts && opts.skipSync)) syncOperarFromHeader();
}

function renderQueueWidget(q) {
  const w = $("#queue-widget");
  w.innerHTML = "";
  // Cola = waiting. El run vivo no entra.
  const waiting = (q || []).filter((it) => (it.state === "queued" || it.state === "launching") && !(state.liveId && it.run_id === state.liveId));
  w.className = "queue-widget" + (waiting.length ? "" : " qw-idle");
  w.appendChild(el("div", { class: "qw-head" },
    el("span", { class: "qw-title" }, "Cola"),
    el("span", { class: "qw-count" + (waiting.length ? " hot" : "") }, String(waiting.length)),
  ));
  if (!waiting.length) { w.appendChild(el("div", { class: "qw-empty" }, "sin runs en cola")); return; }
  const list = el("div", { class: "qw-list" });
  for (const it of waiting) {
    list.appendChild(el("div", { class: "qw-item" },
      el("div", { class: "qi-main" },
        el("div", { class: "qi-t" }, it.title || it.target),
        el("div", { class: "qi-sub" }, `${it.ctf ? "CTF · " : ""}${it.title ? it.target + " · " : ""}${it.harness || "opencode"} · ${it.mode} · ${(it.model || "").split("/").pop()}${it.backup_model ? ` → backup ${(it.backup_model || "").split("/").pop()}` : ""}${sshBit(it)}`),
      ),
      el("button", { class: "qi-x", title: "Quitar de la cola", onclick: async () => { try { await api.del(`/api/queue/${it.qid}`); refreshHeader(); } catch (e) { toast(e.message || "No se pudo quitar", "err"); } } }, "\u00d7"),
    ));
  }
  w.appendChild(list);
}

async function renderOperar(view, gen) {
  const had = runsFresh();
  if (!had) { view.innerHTML = ""; view.appendChild(loadingBox()); }
  const runs = await loadRuns();
  if (gen && state.renderGen !== gen) return;
  let target;
  const wantId = state.followLive ? "" : (state.viewRun || state.liveId);
  if (state.followLive) {
    target = launchTarget(runs);
  } else {
    target = wantId ? runs.find((r) => r.run_id === wantId) : runs.find((r) => r.live && r.status !== "ended");
    if (target && !state.viewRun && target.status === "ended" && !target.live) {
      target = runs.find((r) => r.live && r.status !== "ended") || null;
    }
  }
  if (wantId && !target) {
    target = await api.get(`/api/runs/${wantId}`).catch(() => null);
    if (gen && state.renderGen !== gen) return;
  }
  if (target) {
    const detail = await api.get(`/api/runs/${target.run_id}`).catch(() => target);
    if (gen && state.renderGen !== gen) return;
    state.operarFace = state.viewRun ? "run:" + target.run_id : "live:" + target.run_id;
    view.innerHTML = "";
    renderRunDetail(view, detail);
    return;
  }
  state.operarFace = operarFace();
  view.innerHTML = "";
  if (state.operarFace === "launching") {
    renderOperarLaunching(view);
    return;
  }
  renderOperarIdle(view, runs);
}

function renderOperarLaunching(view) {
  view.appendChild(el("div", { class: "hero" },
    el("div", { class: "hero-shield", html: heroShield }),
    el("h1", {}, "Arrancando el sandbox…"),
    el("p", {}, "El engagement ya está en marcha. En unos segundos verás la consola aquí, sin recargar."),
    el("div", { class: "wait-bar", style: "width:min(360px,100%)" }, el("div", { class: "wait-bar-fill" })),
  ));
}

function renderOperarIdle(view, runs) {
  const hero = el("div", { class: "hero" },
    el("div", { class: "hero-shield", html: heroShield }),
    el("h1", {}, "Sin engagement activo"),
    el("p", {}, "No hay ningún run en marcha. Lanza un engagement autorizado para desplegar el sandbox y el agente. Aquí verás la consola en vivo, los comandos, la red y las evidencias."),
    el("div", { class: "hero-actions" },
      el("button", { class: "btn icon", html: ICON.play + "<span>Lanzar engagement</span>", onclick: () => setView("lanzar") }),
      el("button", { class: "btn ghost", onclick: () => setView("historial") }, "Ver historial"),
    ),
  );
  view.appendChild(hero);

  view.appendChild(el("div", { class: "section-title" }, el("h2", {}, "Runs recientes")));
  if (!runs.length) { view.appendChild(el("div", { class: "empty" }, "Todavía no hay runs.")); return; }
  const grid = el("div", { class: "recent-grid" });
  for (const r of runs.slice(0, 6)) {
    const s = r._stats || {};
    const sev = s.findings_by_severity || {};
    const tgt = cardTarget(r);
    grid.appendChild(el("div", { class: "run-card", onclick: () => openRun(r.run_id) },
      el("div", { class: "rc-top" },
        el("div", { class: "rc-name" },
          el("span", { class: "rc-title" }, cardTitle(r)),
          ctfChip(r, { compact: true }),
          sshChip(r, { compact: true }),
        ),
        statusBadge(r),
      ),
      el("div", { class: "rc-id" }, r.run_id),
      el("div", { class: "rc-target" }, tgt || "(sin target)"),
      el("div", { class: "rc-meta" }, `${r.harness || "opencode"} · ${r.mode || "?"} · ${(r.model || "").split("/").pop()}${r.backup_model ? ` → ${(r.backup_model || "").split("/").pop()}` : ""}${sshBit(r)}`),
      el("div", { class: "rc-foot" },
        el("div", { class: "sev-row" }, ...sevMini(sev)),
        el("button", { class: "btn ghost small", onclick: (e) => { e.stopPropagation(); openReport(r.run_id); } }, "Informe"),
      ),
    ));
  }
  view.appendChild(grid);
}

function sevMini(sev) {
  const out = [];
  for (const k of ["critical", "high", "medium", "low"]) {
    if (sev[k]) out.push(el("span", { class: "sev " + k }, k[0].toUpperCase(), el("b", {}, String(sev[k]))));
  }
  if (!out.length) out.push(el("span", { class: "mono-small" }, "sin findings"));
  return out;
}

const REASON_LABEL = { completed: "completado", timeout: "fin de tiempo", abort: "cancelado", error: "error", ended: "terminado", stalled: "estancado", quota: "sin crédito", session: "límite de sesión", refused: "salvaguardas", refuse: "salvaguardas" };
const reasonLabel = (x) => REASON_LABEL[x] || x || "";

function pauseUntilBit(run) {
  const u = run && run.pause_until;
  if (!u) return "";
  const d = new Date(typeof u === "number" ? u * 1000 : u);
  if (Number.isNaN(d.getTime())) return "";
  const hhmm = d.toLocaleTimeString("es-ES", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "Europe/Madrid",
  });
  return ` · ${hhmm}`;
}

function pauseReasonLabel(reason, short) {
  if (reason === "quota") return short ? "SIN CRÉDITO" : "sin crédito";
  if (reason === "session") return short ? "LÍMITE DE SESIÓN" : "límite de sesión";
  if (reason === "refuse") return short ? "SALVAGUARDAS" : "salvaguardas";
  return short ? "EN PAUSA" : "en pausa";
}

function isSubscriptionRun(run) {
  const h = String((run && run.harness) || "");
  if (h === "claude" || h === "codex") return true;
  const model = String((run && run.model) || "");
  if (h === "opencode" && /grok|xai/i.test(model)) return true;
  return false;
}
function numCompact(n) {
  const x = Number(n || 0);
  if (x >= 1e6) return (x / 1e6).toFixed(x >= 1e7 ? 0 : 1).replace(".", ",") + "M";
  if (x >= 1e4) return Math.round(x / 1e3) + "k";
  return num(x);
}
function tokenCaption(tok) {
  return `${numCompact(tok.in)} / ${numCompact(tok.out)}`;
}
function ctfFlagScore(r) {
  const prog = r && r.mission && r.mission.ctf;
  if (prog && prog.total) return (prog.got || 0) + "/" + prog.total;
  if (r && r.ctf_total) return (r.ctf_got || 0) + "/" + r.ctf_total;
  const n = ((r && r.ctf_flags) || []).length;
  return n ? "0/" + n : "—";
}
function costCaption(run, s) {
  if (!Number((s && s.cost) || 0)) return "sin dato del modelo";
  const harness = String((run && run.harness) || "");
  const model = String((run && run.model) || "");
  if (harness === "claude" || /claude|opus|sonnet|haiku/i.test(model)) return "Claude / Anthropic";
  if (harness === "codex" || /codex|gpt-/i.test(model)) return "Codex / OpenAI";
  if (/xai|grok/i.test(model)) return "OpenCode / xAI";
  if (harness === "opencode") return "OpenCode";
  return harness || "modelo";
}
const MONTHS_ES = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];

function parseRunDate(r) {
  if (r && r.started_at) {
    const d = new Date(r.started_at);
    if (!Number.isNaN(d.getTime())) return d;
  }
  const m = String((r && r.run_id) || "").match(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/);
  if (!m) return null;
  return new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`);
}

function fmtRunWhen(r) {
  const d = parseRunDate(r);
  if (!d) return "—";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getDate()} ${MONTHS_ES[d.getMonth()]} ${d.getFullYear()}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function operatorNote(r) {
  return String((r && (r.operator_note || r.note)) || "").trim();
}

function canContinue(r) {
  return !!(r && r.live && r.paused);
}
function canResume(r) {
  return !!(r && r.run_id && !r.live && r.status === "ended");
}
async function resumeEndedRun(r) {
  if (!canResume(r)) return;
  const body = { authorized: true };
  if (sshUsed(r)) {
    const pass = await openPrompt({
      title: "Retomar con SSH",
      message: "Contraseña de " + (sshLabel(r) || r.ssh_host) + ". No se guarda en cola.",
      okLabel: "Retomar",
      password: true,
      maxlength: 200,
    });
    if (pass == null) return;
    if (!String(pass).trim()) { toast("SSH necesita contraseña", "err"); return; }
    body.ssh_host = r.ssh_host;
    body.ssh_user = r.ssh_user || "";
    body.ssh_pass = pass;
  }
  const out = await api.post(`/api/runs/${r.run_id}/resume`, body);
  toast(out && out.live ? "Run relanzado" : "Retomar en cola", "ok");
  dropRuns();
  rememberLaunch(out && out.item);
  setView("operar");
  watchUntilLive();
}

function canDeleteRun(r) {
  return !!(r && r.run_id && !r.live);
}

async function deleteRuns(ids, labels) {
  const list = [...new Set((ids || []).map((x) => String(x || "").trim()).filter(Boolean))];
  if (!list.length) return null;
  const names = (labels && labels.length) ? labels : list;
  const preview = names.slice(0, 8).map((t) => "· " + t).join("\n");
  const extra = names.length > 8 ? "\n· y " + (names.length - 8) + " más" : "";
  const many = list.length > 1;
  const msg = many
    ? `Se borrarán ${list.length} runs y todos sus artefactos en disco. Esta acción no se puede deshacer.\n\n${preview}${extra}`
    : `Se borrará el run ${names[0] || list[0]} y todos sus artefactos en disco. Esta acción no se puede deshacer.`;
  if (!(await openConfirm({
    title: many ? "Borrar runs" : "Borrar run",
    message: msg,
    okLabel: many ? ("Sí, borrar " + list.length) : "Sí, borrar",
    cancelLabel: "Volver",
    danger: true,
  }))) return null;
  const out = await api.del("/api/runs", { ids: list });
  const gone = (out && out.deleted) || [];
  if (gone.length) toast(gone.length === 1 ? "Run borrado" : gone.length + " runs borrados", "ok");
  const skipped = (out && out.skipped) || [];
  if (skipped.length) toast(skipped.length === 1 ? "Uno sigue en curso" : skipped.length + " en curso, no se borraron", "err");
  if (out && out.errors && out.errors.length) toast("Algunos no se pudieron borrar", "err");
  if (!gone.length && !skipped.length && !(out && out.errors && out.errors.length)) toast("No se borró ninguno", "err");
  if (state.viewRun && gone.includes(state.viewRun)) state.viewRun = null;
  if (gone.length && Array.isArray(state.runs)) {
    state.runs = state.runs.filter((r) => !gone.includes(r.run_id));
  }
  state.runsTs = 0;
  await refreshHeader({ force: true });
  return out;
}

function runElapsed(r) {
  if (!r) return 0;
  if (r.stats && r.stats.elapsed != null && r.stats.elapsed !== "") return Number(r.stats.elapsed) || 0;
  if (r._stats && r._stats.elapsed != null && r._stats.elapsed !== "") return Number(r._stats.elapsed) || 0;
  return 0;
}

function isDocGrace(r) {
  return !!(r && r.live && r.doc_grace && r.doc_grace.active);
}

function isClosing(r) {
  if (!(r && r.live)) return false;
  if (isDocGrace(r) || r._closingTick) return true;
  const max = Number(r.timeout_s) || 0;
  return max > 0 && runElapsed(r) >= max;
}

function displayElapsed(r, extra) {
  const raw = runElapsed(r) + (Number(extra) || 0);
  const max = Number(r && r.timeout_s) || 0;
  if (r && r.live && max > 0) return Math.min(raw, max);
  return raw;
}

function timeCaption(r) {
  if (isClosing(r)) return "finalizando";
  if (r && r.paused) return "en pausa";
  const max = r && r.timeout_s ? "máx " + fmtDurShort(r.timeout_s) : "";
  if (r && r.live) return max || "en marcha";
  return max;
}

async function copyText(e, text, ok = "Copiado") {
  if (e) e.stopPropagation();
  const t = String(text || "").trim();
  if (!t) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(t);
    } else {
      const ta = el("textarea", { style: "position:fixed;left:-9999px" });
      ta.value = t;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    toast(ok, "ok");
  } catch {
    toast("No se pudo copiar", "err");
  }
}

function copyPrompt(e, text) {
  return copyText(e, text, "Prompt copiado");
}

function isFlagPath(rel) {
  return /(^|\/)(user|root|proof|local|flag)\.txt$/i.test(String(rel || ""));
}

function copyableFileText(text) {
  const t = String(text || "");
  if (!t.trim() || t.includes("\x00")) return "";
  return t.trim();
}

function copyFileBtn(text, ok = "Copiado") {
  const payload = copyableFileText(text);
  if (!payload) return "";
  return el("button", {
    type: "button",
    class: "btn ghost small icon",
    html: ICON.copy + "<span>Copiar</span>",
    onclick: (e) => copyText(e, payload, ok),
  });
}

function noteMark(note) {
  const t = String(note || "").trim();
  if (!t) return "";
  return el("button", {
    type: "button",
    class: "prompt-mark",
    title: t,
    onclick: (e) => copyPrompt(e, t),
  }, "Prompt");
}

function isCtf(r) {
  return !!(r && r.ctf);
}
function isNet(r) {
  return String((r && r.mode) || "") === "net";
}
function showAccounts(r) {
  return !isNet(r) || !!(r && r.exploit_mgmt);
}
function ctfChip(r, { compact } = {}) {
  if (!isCtf(r)) return false;
  const flags = (r.ctf_flags || []).filter(Boolean);
  const tot = Number(r.ctf_total || flags.length || 0);
  const got = r.ctf_got;
  const tip = tot ? `contrato ${tot} flags: ${flags.join(" · ")}` : "Modo CTF: contrato de flags";
  const score = (got != null && tot) ? `${got}/${tot}` : (tot ? String(tot) : "");
  const label = compact ? (score ? `CTF ${score}` : "CTF") : (score ? `CTF ${score}` : "CTF");
  return el("span", { class: "chip ctf", title: tip }, label);
}
function sshUsed(r) {
  return !!(r && String(r.ssh_host || "").trim());
}
function sshLabel(r) {
  const host = String((r && r.ssh_host) || "").trim();
  if (!host) return "";
  const user = String((r && r.ssh_user) || "").trim();
  return user ? `${user}@${host}` : host;
}
function sshChip(r, { compact } = {}) {
  if (!sshUsed(r)) return false;
  const who = sshLabel(r);
  const tip = who
    ? `Salto SSH al lanzar: ${who}. Credencial de operador, no descubierta en el target.`
    : "Este run se lanzó con salto SSH.";
  return el("span", { class: "chip ssh", title: tip }, compact ? "SSH" : ("SSH " + who));
}
function sshBit(r) {
  return sshUsed(r) ? ` · SSH ${sshLabel(r)}` : "";
}

function paintLiveChip(live) {
  const ind = $("#live-indicator");
  if (!ind) return;
  if (live && live.status !== "ended") {
    const chipId = live.run_id || state.liveId;
    const closing = isClosing(live);
    ind.classList.remove("hidden");
    ind.classList.toggle("paused", !!live.paused);
    ind.classList.toggle("closing", !!(closing && !live.paused));
    const pauseLbl = live.paused
      ? (pauseReasonLabel(live.pause_reason, true) + pauseUntilBit(live))
      : (closing ? "FINALIZANDO" : "RUN VIVO");
    const cons = live.conscience;
    const consBit = cons && (cons.phase === "overdue" || cons.phase === "dead") ? ' · <span class="chip" title="La conciencia no ha revisado: el reloj del host no está vivo">conciencia atrasada</span>' : (cons && cons.phase === "stuck" ? ' · <span class="chip">conciencia: corte</span>' : "");
    ind.innerHTML = `<span class="blink"></span> ${pauseLbl} · ${esc(runTitle(live))}${live.ctf ? ' <span class="chip ctf">CTF</span>' : ""}${live.ssh_host ? ' <span class="chip ssh">SSH</span>' : ""}${consBit}`;
    ind.title = closing && !live.paused
      ? "Comprobador de cierre: revisa, corrige e informa. Abrir en Operar"
      : "Abrir en Operar";
    ind.setAttribute("role", "button");
    ind.setAttribute("tabindex", "0");
    ind.onclick = () => {
      if (!chipId) return;
      if (state.view === "operar" && !state.viewRun && state.operarFace === "live:" + chipId) return;
      openRun(chipId);
    };
    ind.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); ind.click(); } };
  } else {
    ind.classList.add("hidden");
    ind.classList.remove("paused", "closing");
    ind.onclick = null;
    ind.onkeydown = null;
    ind.removeAttribute("title");
    ind.removeAttribute("tabindex");
    ind.removeAttribute("role");
  }
}

function statusBadge(r) {
  if (r.live) {
    if (r.paused) return el("span", { class: "statusbadge paused" }, el("span", { class: "d" }), pauseReasonLabel(r.pause_reason) + pauseUntilBit(r));
    if (isClosing(r)) {
      const left = Number((r.doc_grace && r.doc_grace.left_s) || 0);
      const sub = left > 0 ? ` · ${Math.ceil(left / 60)} min` : "";
      return el("span", { class: "statusbadge closing", title: "Finalizando: el comprobador revisa consola y disco, corrige e informa. Cierra al terminar o al tope. Cancelar otra vez corta ya." }, el("span", { class: "d" }), "Finalizando" + sub);
    }
    return el("span", { class: "statusbadge running" }, el("span", { class: "d" }), "en curso");
  }
  const reason = r.reason || r.status || "ended";
  const cls = ["error", "timeout", "abort"].includes(reason) ? reason : "ended";
  return el("span", { class: "statusbadge " + cls, title: reason === "timeout" ? "Se agotó el timeout (el agente insistió hasta el final)" : "" }, el("span", { class: "d" }), reasonLabel(reason));
}

function renderRunDetail(view, run) {
  const runId = run.run_id;
  const isLive = !!run.live;
  state._ctfView = isCtf(run);
  const wrap = el("div", { class: "run-detail" });
  const head = el("div", { class: "rd-chrome" });
  const missionHost = el("div", { class: "mission-stack" });
  const tabsHost = el("div", { class: "tabs" });
  wrap.appendChild(head); wrap.appendChild(missionHost); wrap.appendChild(tabsHost);
  view.appendChild(wrap);

  const paintHead = (r) => {
    head.innerHTML = "";
    state._runLabel = runTitle(r);
    const crumb = $("#crumb-run");
    if (crumb) crumb.textContent = state._runLabel;
    const targets = (r.targets || []).map((t) => t.value).join(", ");
    const controls = el("div", { class: "rd-controls" });
    if (r.live) {
      if (r.paused) {
        controls.appendChild(el("button", { class: "btn small icon", html: ICON.play + "<span>Reanudar</span>", onclick: async () => { try { await api.post(`/api/runs/${runId}/unpause`); toast("Run reanudado", "ok"); refreshHeader(); reload(); } catch (e) { toast(e.message, "err"); } } }));
      } else {
        controls.appendChild(el("button", { class: "btn small warnbtn icon", html: ICON.pause + "<span>Pausar</span>", onclick: async () => { try { await api.post(`/api/runs/${runId}/pause`); toast("Run en pausa", "ok"); refreshHeader(); reload(); } catch (e) { toast(e.message, "err"); } } }));
      }
      const closing = isDocGrace(r);
      controls.appendChild(el("button", { class: "btn small danger icon", html: ICON.stop + "<span>" + (closing ? "Cortar ya" : "Cancelar") + "</span>", onclick: async () => {
        const msg = closing
          ? `Se corta ya el run ${runId}: se destruye el contenedor y se genera el informe con lo que haya en disco.`
          : `Comprobador (cualquier modelo): revisa consola y disco, corrige o borra fichas y cuentas, y redacta el informe. Cierra al terminar (tope 8 min). Cancelar otra vez corta ya.`;
        if (await openConfirm({ title: closing ? "Cortar ya" : "Cancelar run", message: msg, okLabel: closing ? "Sí, cortar ya" : "Sí, cerrar y documentar", cancelLabel: "Volver", danger: true })) {
          await abortRunWithReport(runId, { force: closing });
        }
      } }));
      if (r.conscience && r.conscience.phase === "dead") {
        controls.appendChild(el("button", { class: "btn small icon", html: ICON.refresh + "<span>Reenganchar</span>", onclick: async () => { try { const out = await api.post(`/api/runs/${runId}/watch`); toast(out && out.already ? "El reloj ya estaba vivo" : "Reloj reenganchado", "ok"); refreshHeader(); reload(); } catch (e) { toast(e.message, "err"); } } }));
      }
    } else {
      if (canResume(r)) {
        controls.appendChild(el("button", { class: "btn small icon", html: ICON.play + "<span>Retomar</span>", onclick: async () => { try { await resumeEndedRun(r); } catch (e) { toast(e.message, "err"); } } }));
      }
      controls.appendChild(el("button", { class: "btn small danger icon", html: ICON.trash + "<span>Borrar</span>", onclick: async (e) => { e.stopPropagation(); try { const out = await deleteRuns([runId], [runTitle(r) || runId]); if (out && (out.deleted || []).includes(runId)) setView("operar"); } catch (err) { toast(err.message, "err"); } } }));
    }
    controls.appendChild(el("button", { class: "btn ghost small icon", html: ICON.edit + "<span>Renombrar</span>", onclick: async () => { if (await renameRun(runId, r.title || "")) { refreshHeader(); reload(); } } }));
    controls.appendChild(el("button", { class: "btn ghost small icon", html: ICON.doc + "<span>Informe</span>", onclick: () => openReport(runId) }));

    head.appendChild(el("div", { class: "rd-head" },
      el("div", {},
        el("div", { class: "rd-title" }, el("h1", {}, runTitle(r)), statusBadge(r)),
        el("div", { class: "rd-meta" },
          el("span", { class: "rd-id" }, fmtRunWhen(r) + " · " + runId + (targets && targets !== runTitle(r) ? " · " + targets : "")),
          el("span", { class: "chip", title: "Harness: el cerebro que corre en el sandbox (OpenCode / Codex / Claude Code)." }, "harness ", el("b", {}, r.harness || "opencode")),
          r.harness === "codex" ? el("span", { class: "chip" }, "stateless: vive del disco") : false,
          el("span", { class: "chip", title: "Modo de operación: full / assess / recon / net (marca hasta dónde puede llegar el agente)." }, "modo ", el("b", {}, r.mode || "?")),
          ctfChip(r),
          sshChip(r),
          el("span", { class: "chip accent" }, r.model || "?"),
          r.rescue_model ? el("span", { class: "chip" }, "salvaguarda ", el("b", {}, (r.rescue_harness && r.rescue_harness !== r.harness ? r.rescue_harness + "/" : "") + (r.rescue_model || "").split("/").pop())) : false,
          r.backup_model ? el("span", { class: "chip" }, r.backup_used ? "usando backup " : "backup ", el("b", {}, (r.backup_model || "").split("/").pop())) : false,
          operatorNote(r) ? el("button", { type: "button", class: "chip note-chip", title: operatorNote(r), onclick: (e) => copyPrompt(e, operatorNote(r)) }, "Prompt") : false,
          (r.inbox_count > 0) ? el("button", { type: "button", class: "chip", title: "Archivos que se adjuntaron al lanzar este run. Abre la pestaña Archivos.", onclick: () => { try { ctl.show("archivos"); } catch (e) {} } }, `${r.inbox_count} ${r.inbox_count === 1 ? "anexo" : "anexos"}`) : false,
        ),
      ),
      controls,
    ));
    if (r.live) {
      const inp = el("input", { type: "text", placeholder: "Dirigir al agente (una frase)…", id: "steer-in" });
      const sel = el("select", { class: "steer-sel", id: "steer-model", title: "Con qué modelo continuar. «auto» respeta el modelo actual; elegir uno lo fuerza y luego sigue la lógica de salvaguardas." },
        el("option", { value: "" }, "auto"),
        el("option", { value: "primary" }, (r.model || "?").split("/").pop()),
      );
      if (r.rescue_model) {
        sel.appendChild(el("option", { value: "rescue" }, "salvaguarda: " + (r.rescue_model || "").split("/").pop()));
      }
      const send = async () => {
        const t = (inp.value || "").trim();
        if (!t) return;
        try {
          await api.post(`/api/runs/${runId}/steer`, { text: t, model: sel.value || "" });
          inp.value = "";
          const how = sel.value === "primary" ? " (sigo en principal)" : sel.value === "rescue" ? " (paso a salvaguarda)" : "";
          toast("Orden enviada — corto el turno y entra ahora" + how, "ok");
        } catch (e) { toast(e.message, "err"); }
      };
      inp.addEventListener("keydown", (e) => { if (e.key === "Enter") send(); });
      head.appendChild(el("div", { class: "steer-row" },
        sel,
        inp,
        el("button", { class: "btn small", title: "Corta el turno del agente y le mete tu orden ahora mismo.", onclick: send }, "Steer"),
      ));
    }
  };

  const fmtMem = (b) => {
    b = Number(b) || 0;
    if (b >= 1073741824) {
      const g = b / 1073741824;
      const nice = Math.abs(g - Math.round(g)) < 0.05 ? String(Math.round(g)) : g.toFixed(1);
      return nice + " GiB";
    }
    if (b >= 1048576) return Math.round(b / 1048576) + " MiB";
    if (b >= 1024) return Math.round(b / 1024) + " KiB";
    return b ? String(b) : "—";
  };
  const fmtRam = (s) => {
    const used = fmtMem(s.mem_bytes);
    const lim = Number(s.mem_limit_bytes) || 0;
    return lim ? used + " / " + fmtMem(lim) : used;
  };
  const fmtCpu = (s) => {
    // cpu_cores; si no, cpu_pct/100 (100 = 1 núcleo). Formato used / techo.
    const lim = Number(s.cpu_limit) > 0 ? Number(s.cpu_limit) : 4;
    let cores;
    if (s.cpu_cores != null && s.cpu_cores !== "") cores = Number(s.cpu_cores);
    else cores = (Number(s.cpu_pct) || 0) / 100;
    if (!Number.isFinite(cores) || cores < 0) cores = 0;
    const used = cores < 0.05 ? "0" : (cores < 1 ? cores.toFixed(2) : cores.toFixed(1));
    return used + " / " + String(Math.round(lim)) + " CPU";
  };
  const paintCtfPanel = (r) => {
    if (!isCtf(r)) return null;
    const prog = (r.mission && r.mission.ctf) || null;
    const slots = (prog && prog.slots) || [];
    const box = el("div", { class: "ctf-progress" });
    box.appendChild(el("div", { class: "ctf-progress-head" },
      el("span", { class: "ctf-progress-title" }, "Contrato CTF"),
      el("span", { class: "ctf-progress-count" }, (prog ? prog.got : 0) + "/" + (prog ? prog.total : (r.ctf_flags || []).length || 2)),
    ));
    const row = el("div", { class: "ctf-progress-slots" });
    const fallback = (r.ctf_flags || []).map((m) => ({ match: m, found: false, value: "", ts: "", finding: "", kind: /root|proof/i.test(m) ? "root" : "user" }));
    for (const s of (slots.length ? slots : fallback)) {
      row.appendChild(el("div", { class: "ctf-slot" + (s.found ? " got" : "") },
        el("div", { class: "ctf-slot-mark" }, s.found ? "✓" : "✗"),
        el("div", {},
          el("div", { class: "ctf-slot-name" }, s.match || s.kind || "flag"),
          s.found && s.value ? el("div", { class: "ctf-slot-val" }, s.value) : el("div", { class: "ctf-slot-val muted" }, "pendiente"),
          el("div", { class: "ctf-slot-meta" }, [s.ts ? fmtTs(s.ts) : "", s.finding || ""].filter(Boolean).join(" · ") || "—"),
        ),
      ));
    }
    box.appendChild(row);
    return box;
  };

  const paintIdentities = (r) => {
    if (!showAccounts(r)) return null;
    const items = (((r.mission && r.mission.notebook) || {}).identities || []).filter((i) => i.status === "compromised");
    if (!items.length) return null;
    const box = el("div", { class: "id-progress" });
    box.appendChild(el("div", { class: "ctf-progress-head" },
      el("span", { class: "id-progress-title" }, "Cuentas identificadas"),
      el("span", { class: "ctf-progress-count" }, String(items.length)),
    ));
    const row = el("div", { class: "id-progress-slots" });
    for (const it of items.slice(0, 8)) {
      row.appendChild(el("div", {
        class: "id-slot clickable",
        title: "Ver el detalle" + (it.has_secret ? " y la contraseña" : ""),
        onclick: () => openIdentity(it),
      },
        el("div", { class: "id-slot-name" }, it.principal || "—"),
        el("div", { class: "id-slot-val" }, identityWhere(it)),
        el("div", { class: "ctf-slot-meta" }, [it.via, it.priv, it.finding].filter(Boolean).join(" · ") || "—"),
      ));
    }
    box.appendChild(row);
    return box;
  };

  const paintTimeline = (r) => {
    const steps = (r.mission && r.mission.timeline) || [];
    if (!steps.length) return null;
    const bar = el("div", { class: "chain" });
    for (const st of steps) {
      bar.appendChild(el("div", { class: "chain-step" + (st.ok ? " ok" : "") },
        el("div", { class: "chain-dot" }),
        el("div", { class: "chain-lab" }, st.label),
        el("div", { class: "chain-sub" }, st.ok ? (st.detail ? String(st.detail).slice(0, 28) : (st.ts ? fmtTs(st.ts) : "hecho")) : "—"),
      ));
    }
    return bar;
  };

  const paintKpis = (s, r) => {
    s = s || {};
    r = r || run;
    const tok = s.tokens || {};
    const sev = s.findings_by_severity || {};
    const jobs = s.jobs || r.jobs || {};
    const jobKeys = Object.keys(jobs).filter((k) => jobs[k] && (typeof jobs[k] !== "object" || jobs[k].status));
    const jobLabel = jobKeys.length
      ? jobKeys.slice(0, 3).map((k) => {
          const v = jobs[k];
          const st = (v && v.status) || v;
          return k + (st && st !== true ? "=" + st : "");
        }).join(" · ")
      : "ninguno";
    const orphans = s.orphans || [];
    const showCost = Number(s.cost || 0) > 0 && !isSubscriptionRun(r);
    const nb = (r.mission && r.mission.notebook) || {};
    const hyps = nb.hypotheses || [];
    const viva = hyps.filter((h) => (h.status || "viva") === "viva").length;
    const missionRows = [
      ["tiempo", "Tiempo", fmtDur(displayElapsed(r)), timeCaption(r)],
      ["tokens", "Tokens", num((tok.in || 0) + (tok.out || 0)), tokenCaption(tok)],
      showCost ? ["coste", "Coste", "$" + Number(s.cost || 0).toFixed(3), costCaption(r, s)] : null,
      isCtf(r) ? ["flags", "Flags", ctfFlagScore(r), "contrato"] : null,
      showAccounts(r) ? (() => {
        const ids = nb.identities || [];
        const nComp = ids.filter((i) => i.status === "compromised").length;
        const nEnum = ids.filter((i) => i.status !== "compromised").length;
        return ["cuentas", "Cuentas", nEnum ? (nComp + " · " + nEnum) : num(nComp), nEnum ? "enum." : ""];
      })() : null,
      ["hyps", "Hipótesis", hyps.length ? (viva + "/" + hyps.length) : "0", viva ? "vivas" : ""],
      ["findings", "Findings", num((s.findings_proven || 0) + (s.findings_suspected || 0)), `P${s.findings_proven || 0} · S${s.findings_suspected || 0}`],
      ["cmds", "Comandos", num(s.commands_count), ""],
      conscienceKpi(r.conscience, !r.live),
    ].filter(Boolean);
    const sysRows = [
      ["ram", "RAM / CPU", fmtRam(s), [fmtCpu(s), s.pids ? s.pids + " pids" : ""].filter(Boolean).join(" · ")],
      ["jobs", "Jobs", String(jobKeys.length || "0"), jobLabel],
      ["orphans", "Huérfanos", String(orphans.length || "0"), orphans.length ? orphans.length + " procesos" : "ninguno"],
      ["red", "Red", num(s.net_destinations_unique), "destinos"],
    ];
    const applyTiles = (host, rows) => {
      if (!host) return;
      for (const [key, , val, sub, extraCls] of rows) {
        if (key === "tiempo" && isLive) continue;
        const node = host.querySelector(`[data-kpi="${key}"]`);
        if (!node) continue;
        node.classList.toggle("conscience-overdue", key === "conscience" && extraCls === "conscience-overdue");
        const v = node.querySelector(".k-val");
        if (v) v.textContent = String(val);
        const sn = node.querySelector(".k-sub");
        if (sn && sub) sn.textContent = sub;
        if (key === "conscience" && sub) {
          node.title = (KPI_HELP.conscience || "") + " " + String(sub).replace(/\n/g, " · ");
        }
      }
    };
    if (missionHost.dataset.ready === "1") {
      applyTiles(missionHost.querySelector("[data-band=mission]"), missionRows);
      applyTiles(missionHost.querySelector("[data-band=system]"), sysRows);
      const sevRow = missionHost.querySelector("[data-kpi=sev] .sev-row");
      if (sevRow) {
        for (const k of ["critical", "high", "medium", "low", "info"]) {
          const b = sevRow.querySelector(".sev." + k + " b");
          if (b) b.textContent = String(sev[k] || 0);
        }
      }
      const ctfBox = missionHost.querySelector(".ctf-progress");
      if (isCtf(r)) {
        const next = paintCtfPanel(r);
        if (ctfBox && next) ctfBox.replaceWith(next);
        else if (!ctfBox && next) missionHost.insertBefore(next, missionHost.firstChild);
      } else if (ctfBox) ctfBox.remove();
      const chain = missionHost.querySelector(".chain");
      const nextChain = paintTimeline(r);
      if (chain && nextChain) chain.replaceWith(nextChain);
      else if (!chain && nextChain) {
        const after = missionHost.querySelector(".ctf-progress");
        if (after && after.nextSibling) missionHost.insertBefore(nextChain, after.nextSibling);
        else missionHost.insertBefore(nextChain, missionHost.firstChild);
      }
      const idBox = missionHost.querySelector(".id-progress");
      const nextIds = paintIdentities(r);
      if (idBox && nextIds) idBox.replaceWith(nextIds);
      else if (!idBox && nextIds) {
        const after = missionHost.querySelector(".chain") || missionHost.querySelector(".ctf-progress");
        if (after && after.nextSibling) missionHost.insertBefore(nextIds, after.nextSibling);
        else if (after) after.after(nextIds);
        else missionHost.insertBefore(nextIds, missionHost.firstChild);
      } else if (idBox && !nextIds) idBox.remove();
      return;
    }
    missionHost.innerHTML = "";
    missionHost.dataset.ready = "1";
    const ctfEl = paintCtfPanel(r);
    if (ctfEl) missionHost.appendChild(ctfEl);
    const chainEl = paintTimeline(r);
    if (chainEl) missionHost.appendChild(chainEl);
    const idEl = paintIdentities(r);
    if (idEl) missionHost.appendChild(idEl);
    const tile = (key, label, val, sub, extraCls) => el("div", { class: "kpi" + (extraCls ? " " + extraCls : ""), "data-kpi": key, title: key === "conscience" && sub ? ((KPI_HELP[key] || "") + " " + String(sub).replace(/\n/g, " · ")) : (KPI_HELP[key] || "") }, el("div", { class: "k-label" }, label), el("div", { class: "k-val" }, String(val)), sub ? el("div", { class: "k-sub" }, sub) : null);
    const sevTile = () => el("div", { class: "kpi", "data-kpi": "sev" }, el("div", { class: "k-label" }, "Severidad"), el("div", { class: "sev-row" },
      ...["critical", "high", "medium", "low", "info"].map((k) => el("span", { class: "sev " + k }, k[0].toUpperCase(), el("b", {}, String(sev[k] || 0))))));
    const missionBand = el("div", { class: "kpi-band", "data-band": "mission" });
    missionBand.appendChild(el("div", { class: "kpi-band-lab" }, "Misión"));
    const grid = el("div", { class: "kpis" });
    for (const row of missionRows) grid.appendChild(tile(row[0], row[1], row[2], row[3] || null, row[4] || null));
    grid.appendChild(sevTile());
    missionBand.appendChild(grid);
    missionHost.appendChild(missionBand);
    const sysBand = el("div", { class: "kpi-band system collapsed", "data-band": "system" });
    const sysHead = el("button", { type: "button", class: "kpi-band-lab toggle" }, "Sistema");
    sysHead.addEventListener("click", () => sysBand.classList.toggle("collapsed"));
    sysBand.appendChild(sysHead);
    const sysGrid = el("div", { class: "kpis" });
    for (const row of sysRows) sysGrid.appendChild(tile(row[0], row[1], row[2], row[3] || null, row[4] || null));
    sysBand.appendChild(sysGrid);
    missionHost.appendChild(sysBand);
  };

  paintHead(run);
  paintKpis(run.stats || {}, run);

  const tabs = [
    { id: "consola", label: "Consola", render: (p) => tabConsole(p, runId, isLive) },
    { id: "cadena", label: "Cadena", render: (p) => tabChain(p, run) },
    showAccounts(run) ? { id: "cuentas", label: "Cuentas", render: (p) => tabIdentities(p, run) } : null,
    { id: "cuaderno", label: "Cuaderno", render: (p) => tabNotebook(p, run) },
    { id: "comandos", label: "Comandos", render: (p) => tabCommands(p, runId) },
    { id: "red", label: "Red", render: (p) => tabNetwork(p, runId, run) },
    { id: "archivos", label: "Archivos", render: (p) => tabFiles(p, runId, isCtf(run)) },
    { id: "findings", label: "Findings", render: (p) => tabFindings(p, runId, isCtf(run)) },
    { id: "informe", label: "Informe", render: (p) => tabReport(p, runId) },
    { id: "estado", label: "Estado", render: (p) => tabState(p, runId, run) },
  ].filter(Boolean);
  const ctl = makeTabs(tabsHost, tabs);
  if (run.inbox_count > 0) ctl.setExtra("archivos", String(run.inbox_count));
  const wantTab = state.routeTab && tabs.some((t) => t.id === state.routeTab) ? state.routeTab : "consola";
  ctl.show(wantTab);

  let lastLive = !!run.live;
  let lastPaused = !!(run.paused || run.pause_reason);
  let lastClosing = isClosing(run);
  let elapsedBase = Number((run.stats && run.stats.elapsed) || 0);
  let elapsedAt = Date.now();

  const tickClock = () => {
    const node = missionHost.querySelector("[data-kpi=tiempo] .k-val");
    if (!node) return;
    const max = Number(run.timeout_s) || 0;
    const extra = (lastPaused || lastClosing) ? 0 : Math.max(0, (Date.now() - elapsedAt) / 1000);
    const raw = elapsedBase + extra;
    const closingNow = lastClosing || isClosing(run) || (max > 0 && lastLive && !lastPaused && raw >= max);
    if (closingNow && !lastClosing) {
      lastClosing = true;
      run._closingTick = true;
      paintHead(run);
      const sub0 = missionHost.querySelector("[data-kpi=tiempo] .k-sub");
      if (sub0) sub0.textContent = "finalizando";
      if (state.liveId === runId) paintLiveChip(run);
    }
    const elapsed = (max > 0 && lastLive) ? Math.min(raw, max) : raw;
    node.textContent = fmtDur(elapsed);
    const sn = missionHost.querySelector("[data-kpi=tiempo] .k-sub");
    if (sn) sn.textContent = lastClosing ? "finalizando" : (lastPaused ? "en pausa" : timeCaption(run));
  };

  // Tras pausar/reanudar/renombrar: refresca cabecera y KPIs.
  async function reload() {
    const r = await api.get(`/api/runs/${runId}`).catch(() => null);
    if (!r) return;
    run.doc_grace = r.doc_grace;
    lastLive = !!r.live;
    lastPaused = !!(r.paused || r.pause_reason);
    lastClosing = isClosing(r);
    run.paused = lastPaused;
    run.pause_reason = r.pause_reason;
    run.pause_until = r.pause_until;
    run.stats = r.stats || run.stats;
    elapsedBase = Number((run.stats && run.stats.elapsed) || 0);
    elapsedAt = Date.now();
    run.jobs = r.jobs || run.jobs;
    run.conscience = r.conscience || run.conscience;
    run.conscience_md = r.conscience_md;
    run.mission = r.mission || run.mission;
    run.ctf = r.ctf;
    paintHead(r);
    paintKpis(r.stats || {}, r);
    if (state.liveId === runId) paintLiveChip(r);
  }

  const poll = async () => {
    const r = await api.get(`/api/runs/${runId}`).catch(() => null);
    if (!r) return;
    run.doc_grace = r.doc_grace;
    const pausedNow = !!(r.paused || r.pause_reason);
    if (!!r.live !== lastLive || pausedNow !== lastPaused || isClosing(r) !== lastClosing || (r.conscience && r.conscience.phase) !== (run.conscience && run.conscience.phase)) {
      lastLive = !!r.live;
      lastPaused = pausedNow;
      lastClosing = isClosing(r);
      run.paused = pausedNow;
      run.pause_reason = r.pause_reason;
      run.pause_until = r.pause_until;
      paintHead(r);
      if (state.liveId === runId) paintLiveChip(r);
    }
    paintKpis(r.stats || {}, r);
    run.stats = r.stats || run.stats;
    elapsedBase = Number((run.stats && run.stats.elapsed) || 0);
    elapsedAt = Date.now();
    run.jobs = r.jobs || run.jobs;
    run.conscience = r.conscience || run.conscience;
    run.conscience_md = r.conscience_md;
    run.mission = r.mission || run.mission;
    run.ctf = r.ctf;
    const s = run.stats || {};
    const fn = (s.findings_proven || 0) + (s.findings_suspected || 0);
    if (typeof ctl.setExtra === "function") ctl.setExtra("findings", fn || "");
    if (!r.live && isLive) {
      // No remountar: la consola viva ya tiene el stream parseado. Un render()
      // volvería a pedir el snapshot y se veía distinto (más recortado).
      // Guard GLOBAL por run_id: el aviso "run terminado" sale UNA sola vez aunque el
      // detalle se re-monte (cada re-montaje creaba un poll nuevo con el guard local
      // reseteado → el toast se repetía cada 4s).
      state.endedToasted = state.endedToasted || {};
      if (!state.endedToasted[runId]) {
        state.endedToasted[runId] = true;
        toast("El run ha terminado", "ok");
        lastLive = false;
        run.live = false;
        run.reason = r.reason || run.reason;
        run.status = r.status || "ended";
        paintHead(r);
        paintKpis(r.stats || {}, r);
        if (state.liveId === runId) paintLiveChip(r);
        // El informe se escribe al cierre: refresca la pestaña activa unas veces para
        // que aparezca, y DETÉN el poll (no seguir sondeando un run terminado).
        const soft = () => {
          if (typeof state.tabSoftRefresh === "function" && state.activeTab && state.activeTab !== "consola") state.tabSoftRefresh();
        };
        soft();
        setTimeout(soft, 4000);
        setTimeout(soft, 12000);
        if (state.es && state.es._tick) { try { state.es._tick.close(); } catch {} }
      }
      return;
    }
    if (typeof state.tabSoftRefresh === "function" && state.activeTab && state.activeTab !== "consola") {
      state.tabSoftRefresh();
    }
  };

  if (isLive) {
    const clock = setInterval(() => { if (state.view !== "operar") { clearInterval(clock); return; } tickClock(); }, 1000);
    const iv = setInterval(() => { if (state.view !== "operar") { clearInterval(iv); return; } poll(); }, 4000);
    state.es._tick = { close: () => { clearInterval(clock); clearInterval(iv); } };
  }
}

function makeTabs(host, tabs) {
  const nav = el("div", { class: "tabnav" });
  const panel = el("div", { class: "tabpanel" });
  const btns = {};
  let current = null;
  const show = (id) => {
    if (state.tabCleanup) { try { state.tabCleanup(); } catch {} state.tabCleanup = null; }
    state.tabSoftRefresh = null;
    // cierra SSE de consola al cambiar de pestaña
    for (const k of ["console", "events"]) { if (state.es[k]) { try { state.es[k].close(); } catch {} delete state.es[k]; } }
    current = id;
    state.activeTab = id;
    // pestaña en el hash (replaceState: recarga / deep-link)
    if (state.viewRun) { const h = "#/run/" + encodeURIComponent(state.viewRun) + "/" + id; if (location.hash !== h) history.replaceState(null, "", h); }
    // seq: un fetch tardío no pinta en otra pestaña.
    state.tabSeq = (state.tabSeq || 0) + 1;
    for (const k in btns) btns[k].classList.toggle("active", k === id);
    panel.innerHTML = "";
    panel.classList.add("anim");
    const t = tabs.find((x) => x.id === id);
    state.tabCleanup = t.render(panel) || null;
    setTimeout(() => panel.classList.remove("anim"), 280);
  };
  const refresh = () => { if (current) show(current); };
  for (const t of tabs) {
    const b = el("button", { onclick: () => show(t.id) }, t.label);
    btns[t.id] = b; nav.appendChild(b);
  }
  host.appendChild(nav); host.appendChild(panel);
  const setExtra = (id, extra) => {
    const b = btns[id];
    if (!b) return;
    let n = b.querySelector(".tcount");
    if (!extra) { if (n) n.remove(); return; }
    if (!n) { n = el("span", { class: "tcount" }); b.appendChild(n); }
    n.textContent = String(extra);
  };
  return { show, refresh, panel, setExtra };
}

function loadingBox(text) { return el("div", { class: "loading" }, el("span", { class: "spin" }), text || "cargando…"); }

const CONSOLE_GUTTER = { "c-agent": "agente", "c-conscience": "conciencia", "c-guard": "guarda", "c-sys": "sys", "c-find": "hallazgo", "c-err": "err", "c-cmd": "cmd", "c-out": "out" };

function stripAnsi(s) {
  return String(s)
    .replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    .replace(/\r/g, "");
}

function stripAgentMd(s) {
  let t = String(s || "");
  t = t.replace(/\*\*([^*]+)\*\*/g, "$1");
  t = t.replace(/__([^_]+)__/g, "$1");
  t = t.replace(/`([^`\n]+)`/g, "$1");
  t = t.replace(/\*\*/g, "");
  return t;
}

// Nombre corto del modelo para etiquetar cada línea del agente: quita el proveedor
// (xai/…) y el prefijo claude-. p.ej. claude-opus-4-8 → opus-4-8, xai/grok-4.6 → grok-4.6.
function shortModel(m) {
  return String(m || "").split("/").pop().replace(/^claude-/, "");
}

const CONSOLE_FIND_SPEECH_RE = /FLAG\{|CTF\{|HTB\{|(?:user|root|proof|local)\.txt\s*=|findings\/F-\d+/i;
const CONSOLE_FIND_CMD_RE = /^\$\s+(?:read|write|writefile)\s+\S*(?:findings\/F-\d+|(?:user|root|proof|local)\.txt)/i;

function consoleFindCls(cls, text) {
  if (cls === "c-guard" || cls === "c-err" || cls === "c-conscience" || cls === "c-sys") return cls;
  const t = String(text || "");
  if (cls === "c-cmd") return CONSOLE_FIND_CMD_RE.test(t) ? "c-find" : cls;
  return CONSOLE_FIND_SPEECH_RE.test(t) ? "c-find" : cls;
}

function classifyRaw(line) {
  const t = line.trim();
  if (/^\[aegis\] — conciencia:/i.test(t) || /^(SIGUE \(|AVISA \(|SALVAGUARDA\.|CONCIENCIA \()/i.test(t)) return "c-conscience";
  if (/salvaguarda/i.test(t)) return "c-guard";
  if (/^\[(aegis|opencode|runner|sandbox)\b/i.test(t)) return "c-sys";
  if (/(^|\s)(fatal|traceback|exception|segfault|permission denied|connection refused|no route to host)\b/i.test(t) || /\berror\b/i.test(t)) return "c-err";
  return consoleFindCls("c-agent", t);
}

const CONSOLE_CYBER_RE = /safeguards flagged|cyber-related safeguards|api_refusal_category|intentionally broad|legitimate cybersecurity|this request triggered|model_refusal|capabilities faster|trusted access for cyber|chatgpt\.com\/cyber|offensive exploitation/i;
const CONSOLE_PROMPT_LEAK_RE = /^(STEER \(obligatorio\)|Target y avance en |Este es un laboratorio de ciberseguridad autorizado|Lab autorizado del operador|Instrucción del operador \(obligatoria\)|Sesión nueva\.( Sigue| No abras)|SALVAGUARDA\.|No abras (STATE\.md|BRIEF\.md|john)|No leas findings\/\*\.json|No reescribas RESUME\.md|Narra en castellano\. No pares|YA HAY ACCESO al objetivo|El vector de entrada YA cumplió|Empieza ahora\. No preguntes|Sigue solo RESUME\.md|Si hay hold=, es usuario y vía|No rehagas ids cubiertos|DOCUMENTA el impacto en findings)/i;
const CONSOLE_ARGV_RE = /^\[aegis\] (claude --print --|claude print exit=|codex exec --|foothold detectado →|foothold presente →|de-escala salvaguarda →|— conciencia: salvaguarda)|--dangerously-skip-permissions|--dangerously-bypass-approvals/i;
const CONSOLE_CYBER_SHORT = "SALVAGUARDA · cyber — el modelo cortó este turno.";

function polishConsoleRow(r) {
  if (!r) return null;
  const t = String(r.text || "").trim();
  if (!t) return null;
  if (CONSOLE_CYBER_RE.test(t)) return { ...r, cls: "c-guard", text: CONSOLE_CYBER_SHORT };
  if (CONSOLE_PROMPT_LEAK_RE.test(t) || CONSOLE_ARGV_RE.test(t)) return null;
  if (/salvaguarda/i.test(t) && r.cls === "c-sys") return { ...r, cls: "c-guard" };
  const find = consoleFindCls(r.cls, t);
  return find === r.cls ? r : { ...r, cls: find };
}

function polishConsoleRows(row) {
  if (!row) return null;
  const out = [];
  for (const r of (Array.isArray(row) ? row : [row])) {
    const p = polishConsoleRow(r);
    if (!p) continue;
    const prev = out[out.length - 1];
    if (prev && prev.cls === p.cls && prev.text === p.text) continue;
    out.push(p);
  }
  if (!out.length) return null;
  return out.length === 1 ? out[0] : out;
}

function consoleLegend() {
  const items = [
    ["var(--console-agent)", "agente"], ["var(--console-conscience)", "agente — conciencia"], ["var(--console-guard)", "salvaguarda"],
    ["var(--console-cmd)", "comando"], ["var(--console-sys)", "sistema"], ["var(--console-find)", "hallazgo"], ["var(--console-err)", "error"],
  ];
  return el("div", { class: "console-legend" },
    el("span", { class: "cl-note" }, "Cronología con hora. Sin el JSON interno; desplaza para todo el run. La salida de cada comando está en Comandos."),
    ...items.map(([c, t]) => el("span", {}, el("i", { style: `background:${c}` }), t)));
}

function evTime(ev) {
  return normalizeConsoleTs(ev && (ev.timestamp || ev.ts || ev.time));
}

function claudeToolDetail(inp) {
  inp = inp || {};
  return inp.command || inp.file_path || inp.filePath || inp.path || inp.pattern || inp.url || inp.description || "";
}

function formatOpevent(ev) {
  if (ev && ev.cls && ev.text != null && !ev.type) {
    return { cls: ev.cls, text: ev.text, ts: ev.ts || ev.timestamp || evTime(ev), model: ev.model || "" };
  }
  const type = ev.type || "";
  const part = ev.part || {};
  const ts = evTime(ev);
  if (type === "aegis_conscience" || type === "aegis_claimcheck") {
    const text = String(ev.text || "").trim();
    if (!text) return null;
    return { cls: "c-conscience", text, ts: ev.timestamp || ts };
  }
  if (type === "step_start" || type === "step_finish") return null;
  if (type === "assistant" && ev.message) {
    const rows = [];
    const model = String(ev.message.model || "");
    const list = Array.isArray(ev.message.content) ? ev.message.content : [];
    for (const b of list) {
      if (!b || typeof b !== "object") continue;
      if (b.type === "text" && String(b.text || "").trim()) {
        const text = stripAgentMd(String(b.text).trim());
        rows.push({ cls: classifyRaw(text), text, ts, model });
      }
      if (b.type === "tool_use") {
        const name = b.name || "tool";
        const detail = claudeToolDetail(b.input);
        rows.push({ cls: "c-cmd", text: `$ ${name}${detail ? "  " + String(detail).slice(0, 360) : ""}`, ts });
      }
    }
    return rows.length ? rows : null;
  }
  if (type === "system" && ev.subtype === "init") {
    return { cls: "c-sys", text: `claude listo · ${ev.model || "claude"}`, ts: ev.timestamp || ts };
  }
  if (type === "result" && ev.is_error) {
    const text = String(ev.result || ev.error || "").trim();
    if (!text || /interrupted by user|request interrupted/i.test(text)) return null;
    return { cls: "c-err", text, ts: ev.timestamp || ts };
  }
  if (type === "rate_limit_event") {
    const info = ev.rate_limit_info || {};
    if (String(info.status || "").startsWith("allowed")) return null;
    if (info.status) {
      return { cls: "c-err", text: `cuota Claude: ${info.status}`, ts: ev.timestamp || ts };
    }
    return null;
  }
  if (type === "text" || part.type === "text") {
    const text = stripAgentMd(String(part.text || "").trim());
    if (!text) return null;
    const model = String(ev.model || part.model || (ev.message && ev.message.model) || "");
    return { cls: classifyRaw(text), text, ts, model };
  }
  if (type === "tool_use" || part.type === "tool") {
    const st = part.state || {};
    if (st.status === "pending" || st.status === "running") return null;
    const tool = part.tool || "tool";
    const inp = st.input || part.input || {};
    const detail = inp.command || inp.filePath || inp.path || inp.pattern || inp.url || st.title || "";
    const err = st.error || st.status === "error";
    const tail = err ? ` — ${st.error || "error"}` : "";
    return { cls: err ? "c-err" : "c-cmd", text: `$ ${tool}${detail ? "  " + String(detail).slice(0, 360) : ""}${tail}`, ts };
  }
  if (type === "thread.started" || type === "turn.started" || type === "turn.completed") return null;
  if (type === "item.started" || type === "item.updated" || type === "item.completed") {
    return formatCodexItem(ev, ts);
  }
  if (type === "error" || ev.error) return { cls: "c-err", text: String(ev.error || ev.message || "error"), ts };
  return null;
}

function formatCodexItem(ev, ts) {
  const item = ev && ev.item && typeof ev.item === "object" ? ev.item : {};
  const kind = String(item.type || "");
  const typ = String(ev && ev.type || "");
  if (typ === "item.started" || typ === "item.updated") return null;
  if (kind === "agent_message") {
    const text = stripAgentMd(String(item.text || "").trim());
    if (!text) return null;
    return { cls: classifyRaw(text), text, ts };
  }
  if (kind === "command_execution") {
    const cmd = String(item.command || "").trim();
    if (!cmd) return null;
    const status = String(item.status || "");
    const code = item.exit_code;
    const failed = status === "failed" || status === "error" || (Number.isInteger(code) && code !== 0);
    const tail = failed ? (Number.isInteger(code) ? ` — exit ${code}` : " — error") : "";
    return { cls: failed ? "c-err" : "c-cmd", text: `$ bash${cmd ? "  " + cmd.slice(0, 360) : ""}${tail}`, ts };
  }
  return null;
}

let _consoleLastTs = "";
// Modelo activo del turno en curso. Lo fija la línea de turno "[aegis] T{N}: <modelo>"
// (y el arranque "harness=… model=…"), que el orquestador imprime para TODOS los
// harness. Sirve para etiquetar las líneas "agente" que no traen modelo propio
// (p. ej. Grok/OpenCode, que narra en texto plano "[agente] …" sin JSON con model).
let _consoleCurModel = "";

// Extrae el modelo activo de una línea de turno/arranque del orquestador.
function _modelFromAegisLine(t) {
  let m = t.match(/^\[aegis\]\s+T\d+:\s*(\S+)/i);
  if (m) return m[1];
  m = t.match(/^\[aegis\]\s+harness=\S*\s+model=(\S+)/i);
  if (m) return m[1];
  return "";
}

// Estampa el modelo del turno en filas "agente" sin modelo propio (y usa el de las
// filas que sí lo traen —Claude, JSON— para mantener el estado al día).
function _stampConsoleModel(r) {
  if (!r) return;
  if (r.model) { _consoleCurModel = r.model; return; }
  if (r.cls === "c-agent" && _consoleCurModel) r.model = _consoleCurModel;
}

function formatConsoleLine(raw) {
  let t = stripAnsi(String(raw || ""));
  let ts = "";
  const iso = t.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s*/);
  if (iso) {
    ts = iso[1];
    t = t.slice(iso[0].length);
  }
  t = t.trim();
  if (!t) return null;
  if (CONSOLE_CYBER_RE.test(t)) {
    ts = ts || _consoleLastTs;
    if (ts) _consoleLastTs = ts;
    return { cls: "c-guard", text: CONSOLE_CYBER_SHORT, ts };
  }
  // Actualiza el modelo activo del turno con las líneas del orquestador (todos
  // los harness). Va antes del parseo para que las filas siguientes ya lo tengan.
  const cur = _modelFromAegisLine(t);
  if (cur) _consoleCurModel = cur;
  const i = t.indexOf("{");
  const j = t.lastIndexOf("}");
  if (i >= 0 && j > i) {
    try {
      const row = formatOpevent(JSON.parse(t.slice(i, j + 1)));
      if (!row) return null;
      const out = Array.isArray(row) ? row : [row];
      for (const r of out) {
        r.ts = r.ts || ts || _consoleLastTs;
        if (r.ts) _consoleLastTs = r.ts;
        // Snapshot compactado: la línea T{N} viene en r.text, no en el raw.
        const fromText = _modelFromAegisLine(String(r.text || ""));
        if (fromText) _consoleCurModel = fromText;
        _stampConsoleModel(r);
      }
      return polishConsoleRows(out.length === 1 ? out[0] : out);
    } catch { return null; }
  }
  if (t.startsWith("{")) return null;
  if (/aegis-entrypoint:|unexpected EOF|syntax error/i.test(t)) {
    ts = ts || _consoleLastTs;
    if (ts) _consoleLastTs = ts;
    return { cls: "c-err", text: t, ts };
  }
  ts = ts || _consoleLastTs;
  if (ts) _consoleLastTs = ts;
  const cls = classifyRaw(t);
  const row = { cls, text: cls === "c-agent" ? stripAgentMd(t) : t, ts };
  _stampConsoleModel(row);
  return polishConsoleRows(row);
}

function utf8len(s) { return new TextEncoder().encode(String(s)).length; }

function normalizeConsoleTs(ts) {
  if (ts == null || ts === "") return "";
  if (typeof ts === "number" && Number.isFinite(ts)) {
    const ms = ts < 1e12 ? ts * 1000 : ts;
    return new Date(ms).toISOString();
  }
  const s = String(ts).trim();
  if (/^\d{10,13}$/.test(s)) {
    const n = Number(s);
    const ms = n < 1e12 ? n * 1000 : n;
    return new Date(ms).toISOString();
  }
  return s;
}

function consoleTsMs(ts) {
  const iso = normalizeConsoleTs(ts);
  const n = Date.parse(iso || "");
  return Number.isFinite(n) ? n : 0;
}

function sortConsoleItems(items) {
  return items
    .map((it, i) => ({ it, i }))
    .sort((a, b) => {
      const d = consoleTsMs(a.it.ts) - consoleTsMs(b.it.ts);
      return d || a.i - b.i;
    })
    .map((x) => x.it);
}

function dedupeConscience(items) {
  const out = [];
  for (const it of items) {
    const prev = out[out.length - 1];
    if (
      prev && prev.cls === "c-conscience" && it.cls === "c-conscience"
      && consoleTsMs(prev.ts) === consoleTsMs(it.ts)
    ) {
      if ((it.text || "").length > (prev.text || "").length) out[out.length - 1] = it;
      continue;
    }
    out.push(it);
  }
  return out;
}

function tabConsole(panel, runId, isLive) {
  const cache = (state.consoleCache = state.consoleCache || {});
  const buf = cache[runId] || (cache[runId] = { items: [], bytes: 0, ver: 0 });
  if (buf.ver !== 13) { buf.items = []; buf.bytes = 0; buf.ver = 13; }
  _consoleLastTs = "";
  const ROW = 30;
  const OVER = 16;
  const box = el("div", { class: "console" });
  const virt = el("div", { class: "console-virt" });
  box.appendChild(virt);
  panel.appendChild(el("div", { class: "console-wrap" }, consoleLegend(), box));

  const atBottom = () => box.scrollTop + box.clientHeight >= box.scrollHeight - 2;
  let follow = true;
  let paintRaf = 0;
  let measuring = false;
  const isSpeech = (cls) => cls === "c-agent" || cls === "c-conscience" || cls === "c-guard" || cls === "c-find";
  const rowH = (item) => {
    if (item._h) return item._h;
    if (!isSpeech(item.cls)) return ROW;
    let lines = 0;
    for (const part of String(item.text || "").split("\n")) {
      lines += Math.max(1, Math.ceil((part.length || 1) / 64));
    }
    return Math.max(ROW, 12 + lines * 18);
  };
  const offsetsOf = (items) => {
    const off = new Array(items.length + 1);
    off[0] = 0;
    for (let i = 0; i < items.length; i++) off[i + 1] = off[i] + rowH(items[i]);
    return off;
  };
  const idxAt = (off, y) => {
    let lo = 0, hi = off.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (off[mid + 1] <= y) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  const paintLine = (item, i, top, h) => {
    const speech = isSpeech(item.cls);
    const line = el("span", {
      class: "ln " + item.cls + (speech ? " ln-speech" : ""),
      style: speech ? ("top:" + top + "px;min-height:" + h + "px") : ("top:" + top + "px;height:" + ROW + "px"),
      "data-i": String(i),
    });
    line.appendChild(el("span", { class: "c-ts" }, item.ts ? fmtTs(item.ts) : ""));
    line.appendChild(el("span", { class: "gt" }, CONSOLE_GUTTER[item.cls] || ""));
    const tx = el("span", { class: "c-tx", title: speech ? "" : item.text });
    // Chip con el modelo que produjo la línea, junto a la etiqueta "agente".
    if (item.cls === "c-agent" && item.model) {
      tx.appendChild(el("span", { class: "c-model", title: String(item.model) }, shortModel(item.model)));
    }
    tx.appendChild(document.createTextNode(item.text));
    line.appendChild(tx);
    return line;
  };
  const paintWindow = (stick) => {
    const n = buf.items.length;
    const off = offsetsOf(buf.items);
    virt.style.height = Math.max(off[n] || 1, 1) + "px";
    const view = box.clientHeight || 400;
    const y = box.scrollTop;
    const start = Math.max(0, idxAt(off, y) - OVER);
    const end = Math.min(n, idxAt(off, y + view) + 1 + OVER);
    const frag = document.createDocumentFragment();
    for (let i = start; i < end; i++) {
      frag.appendChild(paintLine(buf.items[i], i, off[i], off[i + 1] - off[i]));
    }
    virt.replaceChildren(frag);
    if (stick && follow) box.scrollTop = off[n] || virt.scrollHeight;
    if (measuring) return;
    measuring = true;
    requestAnimationFrame(() => {
      measuring = false;
      let changed = false;
      for (const node of virt.children) {
        const i = Number(node.dataset.i);
        const item = buf.items[i];
        if (!item || !isSpeech(item.cls)) continue;
        const h = node.offsetHeight;
        if (h && Math.abs((item._h || 0) - h) > 3) {
          item._h = h;
          changed = true;
        }
      }
      if (changed) paintWindow(false);
    });
  };
  const relayout = () => {
    buf.items = dedupeConscience(sortConsoleItems(buf.items));
    paintWindow(true);
  };
  box.addEventListener("wheel", (e) => {
    if (e.deltaY < 0) follow = false;
  }, { passive: true });
  box.addEventListener("scroll", () => {
    follow = atBottom();
    if (paintRaf) return;
    paintRaf = requestAnimationFrame(() => {
      paintRaf = 0;
      paintWindow(false);
    });
  }, { passive: true });
  paintWindow(true);

  const push = (cls, text, ts) => {
    const stamp = ts || _consoleLastTs || new Date().toISOString();
    _consoleLastTs = stamp;
    buf.items.push({ cls, text, ts: stamp });
    paintWindow(true);
  };
  const emit = (chunk, countBytes, quiet) => {
    for (const l of String(chunk).split("\n")) {
      if (countBytes) buf.bytes += utf8len(l) + 1;
      const row = formatConsoleLine(l);
      if (!row) continue;
      for (const r of (Array.isArray(row) ? row : [row])) {
        const stamp = r.ts || _consoleLastTs || new Date().toISOString();
        if (r.ts) _consoleLastTs = stamp;
        const last = buf.items[buf.items.length - 1];
        if (last && last.text === CONSOLE_CYBER_SHORT && r.text === CONSOLE_CYBER_SHORT) continue;
        buf.items.push({ cls: r.cls, text: r.text, ts: stamp, model: r.model || "" });
      }
    }
    if (!quiet) paintWindow(true);
  };

  let alive = true;
  const ac = new AbortController();
  (async () => {
    if (!buf.items.length) {
      try {
        const r = await fetch(`/api/runs/${runId}/console?snapshot=1&plain=1`, { headers: authHeaders(), signal: ac.signal });
        if (!alive) return;
        const raw = r.ok ? await r.text() : "";
        if (!alive) return;
        buf.bytes = Number(r.headers.get("X-Aegis-Bytes") || utf8len(raw)) || utf8len(raw);
        if (raw.trim()) { emit(raw, false, true); relayout(); }
        else push("c-sys", isLive ? "esperando salida del agente\u2026" : "este run no dejó consola", "");
      } catch {
        if (!alive) return;
        if (!buf.items.length) push("c-sys", isLive ? "esperando salida del agente\u2026" : "este run no dejó consola", "");
      }
    }
    if (!alive || !isLive) return;
    buf.watching = true;
    let backoff = 800;  // ms; sube con cada fallo hasta 15s y se resetea al recibir datos
    const openES = () => {
      if (!alive || !buf.watching) return;
      const cES = evtSource(`/api/runs/${runId}/console?from=${buf.bytes || 0}`);
      state.es.console = cES;
      cES.addEventListener("line", (e) => { backoff = 800; emit(e.data, true); });
      cES.addEventListener("end", () => { buf.watching = false; push("c-sys", "\u2500\u2500 fin de consola", ""); });
      cES.onerror = () => {
        try { cES.close(); } catch {}
        if (state.es.console === cES) delete state.es.console;
        if (alive && buf.watching) { setTimeout(openES, backoff); backoff = Math.min(backoff * 2, 15000); }
      };
    };
    openES();
  })();
  return () => {
    alive = false;
    buf.watching = false;
    try { ac.abort(); } catch {}
    if (state.es.console) { try { state.es.console.close(); } catch {} delete state.es.console; }
  };
}

function tabCommands(panel, runId) {
  let sig = "";
  let gen = 0;
  const load = (first) => {
    const my = ++gen;
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${runId}/activity?part=commands`).then((a) => {
    if (my !== gen || state.activeTab !== "comandos") return;
    const cmds = a.commands || [];
    const next = cmds.map((c) => [c.argv || "", c.exit ?? "", c.count || 1, c.ts || ""].join("|")).join(";");
    if (!first && next === sig) return;
    sig = next;
    panel.innerHTML = "";
    if (!cmds.length) { panel.appendChild(el("div", { class: "empty" }, "Sin comandos registrados todavía.")); return; }
    const tbl = el("table", { class: "dtable" }, el("thead", {}, el("tr", {}, ...["Hora", "Comando", "Exit", ""].map((h) => el("th", {}, h)))));
    const tb = el("tbody", {});
    for (const c of cmds.slice().reverse()) {
      const out = (c.stdout || "").trim();
      const err = (c.stderr || "").trim();
      const hasIO = out || err;
      const exit = c.exit;
      const excls = exit === 0 || exit === "0" || exit === "completed" ? "ok" : (exit == null || exit === "" || exit === "pending" || exit === "running" ? "na" : "bad");
      const bodyInner = el("div", { class: "exp-body" });
      bodyInner.appendChild(el("span", { class: "lbl" }, "exit"));
      bodyInner.appendChild(document.createTextNode(exit == null || exit === "" ? "(sin código)" : String(exit)));
      if (hasIO) {
        if (out) { bodyInner.appendChild(el("span", { class: "lbl" }, "stdout")); bodyInner.appendChild(document.createTextNode(c.stdout)); }
        if (err) { bodyInner.appendChild(el("span", { class: "lbl" }, "stderr")); bodyInner.appendChild(document.createTextNode(c.stderr)); }
        if (c.truncated) {
          bodyInner.appendChild(el("span", { class: "lbl" }, "recorte"));
          bodyInner.appendChild(el("span", { class: "muted" }, "Salida recortada. El resto está en Consola o en la evidencia del finding."));
        }
      } else {
        bodyInner.appendChild(el("span", { class: "lbl" }, "salida"));
        bodyInner.appendChild(el("span", { class: "muted" }, "Sin captura de salida (comando silencioso o aún en curso)."));
      }
      const bodyRow = el("tr", { class: "hidden" }, el("td", { colspan: 4 }, bodyInner));
      const row = el("tr", { class: "exp", onclick: () => bodyRow.classList.toggle("hidden") },
        el("td", { class: "muted" }, fmtTs(c.ts)),
        el("td", { class: "wrapcell" }, c.argv || "", (c.count > 1) ? el("span", { class: "muted" }, ` ×${c.count}`) : null),
        el("td", {}, el("span", { class: "exitcode " + excls }, exit == null || exit === "" ? "—" : String(exit))),
        el("td", { class: "muted" }, "▾"),
      );
      tb.appendChild(row); tb.appendChild(bodyRow);
    }
    tbl.appendChild(tb);
    panel.appendChild(tbl);
  }).catch((e) => { if (first) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { gen++; state.tabSoftRefresh = null; };
}

function tabChain(panel, run) {
  const seq = state.tabSeq;
  const draw = (steps) => {
    panel.innerHTML = "";
    if (!steps.length) {
      panel.appendChild(el("div", { class: "empty" }, "Aún no hay cadena. Aparece al haber recon, acceso o findings."));
      return;
    }
    const list = el("div", { class: "chain-list" });
    for (const st of steps) {
      list.appendChild(el("div", { class: "chain-row" + (st.ok ? " ok" : "") },
        el("div", { class: "chain-dot" }),
        el("div", {},
          el("div", { class: "chain-lab" }, st.label),
          el("div", { class: "muted" }, [st.ts ? fmtTs(st.ts) : "", st.detail || "", st.finding || ""].filter(Boolean).join(" · ") || "pendiente"),
        ),
      ));
    }
    panel.appendChild(list);
  };
  const paint = () => draw((run.mission && run.mission.timeline) || []);
  const load = (first) => {
    if (run.mission) { paint(); return; }
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${run.run_id}`).then((r) => {
      if (state.tabSeq !== seq) return;
      run.mission = r.mission || run.mission;
      paint();
    }).catch((e) => { if (first) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { state.tabSoftRefresh = null; };
}

function identityWhere(it) {
  const host = String((it && it.host) || "").trim();
  const ip = String((it && it.ip) || "").trim();
  if (host && ip && host !== ip) return host + " · " + ip;
  return host || ip || "—";
}

function openIdentity(it) {
  it = it || {};
  const has = !!String(it.secret || "").trim();
  const via = String(it.via || "");
  const body = el("div", { class: "identity-detail" },
    el("p", { class: "id-how" }, it.how || "Sin detalle de la vía."),
    el("div", { class: "rd-meta", style: "margin-bottom:12px" },
      el("span", { class: "chip" }, it.principal || "—"),
      via ? el("span", { class: "chip accent" }, via) : null,
      el("span", { class: "badge " + (it.priv === "root" || it.priv === "admin" ? "proven" : "") }, it.priv || "user"),
      it.finding ? el("span", { class: "chip" }, it.finding) : null,
    ),
    el("div", { class: "f-block" },
      el("div", { class: "lbl" }, "Dónde"),
      el("div", { class: "f-explain" }, identityWhere(it) + (it.scope ? " · " + it.scope : "")),
    ),
  );
  const sec = el("div", { class: "f-block" }, el("div", { class: "lbl" }, "Contraseña"));
  if (has) {
    sec.appendChild(el("pre", { class: "f-proof secret-val" }, it.secret));
    sec.appendChild(el("div", { class: "toolbar", style: "margin-top:8px" },
      el("button", {
        class: "btn ghost small icon",
        html: ICON.copy + "<span>Copiar</span>",
        onclick: (e) => copyText(e, it.secret, "Contraseña copiada"),
      }),
    ));
  } else {
    const noPass = (via === "webshell" || via === "privesc")
      ? "No hay contraseña: el acceso fue por ejecución o sesión, no por login."
      : "No consta contraseña en disco (la cuenta se registró sin capturar el secreto).";
    sec.appendChild(el("div", { class: "empty" }, noPass));
  }
  body.appendChild(sec);
  openModal("Cuenta " + (it.principal || ""), body);
}

function identityTable(items) {
  const tbl = el("table", { class: "dtable" }, el("thead", {}, el("tr", {},
    ...["Principal", "Host / IP", "Vía", "Priv", "Ámbito", "Finding"].map((h) => el("th", {}, h)),
  )));
  const tb = el("tbody", {});
  for (const it of items) {
    tb.appendChild(el("tr", {
      class: "clickable",
        title: "Ver el detalle" + (it.has_secret ? " y la contraseña" : ""),
      onclick: () => openIdentity(it),
    },
      el("td", { class: "wrapcell" }, it.principal || "—", it.has_secret ? el("span", { class: "muted" }, " · cred") : null, it.reviewed ? el("span", { class: "badge reviewed", title: "Contrastado con consola y disco" }, "revisado") : null),
      el("td", { class: "wrapcell" }, identityWhere(it)),
      el("td", {}, it.via || "—"),
      el("td", {}, el("span", { class: "badge " + (it.priv === "root" || it.priv === "admin" ? "proven" : "") }, it.priv || "user")),
      el("td", { class: "muted" }, it.scope || ""),
      el("td", { class: "muted" }, it.finding || "—"),
    ));
  }
  tbl.appendChild(tb);
  return tbl;
}

function tabIdentities(panel, run) {
  const seq = state.tabSeq;
  const draw = (items) => {
    panel.innerHTML = "";
    const rows = items || [];
    const got = rows.filter((i) => i.status === "compromised");
    const enumed = rows.filter((i) => i.status !== "compromised");
    if (!rows.length) {
      panel.appendChild(el("div", { class: "empty" }, "Aún no hay cuentas. Aparecen al haber login, SSH o un hallazgo con usuario (también en AD: varios principals en la misma IP)."));
      return;
    }
    if (got.length) {
      panel.appendChild(el("h3", { class: "tabsec" }, "Confirmadas (" + got.length + ")"));
      panel.appendChild(identityTable(got));
    }
    if (enumed.length) {
      panel.appendChild(el("h3", { class: "tabsec", style: "margin-top:22px" }, "Enumeradas (" + enumed.length + ")"));
      panel.appendChild(identityTable(enumed));
    }
  };
  const paint = () => draw(((run.mission && run.mission.notebook) || {}).identities || []);
  const load = (first) => {
    if (run.mission) { paint(); return; }
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${run.run_id}`).then((r) => {
      if (state.tabSeq !== seq) return;
      run.mission = r.mission || run.mission;
      paint();
    }).catch((e) => { if (first) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { state.tabSoftRefresh = null; };
}

function tabNotebook(panel, run) {
  const seq = state.tabSeq;
  const draw = (nb, cons) => {
    panel.innerHTML = "";
    if (!nb) { panel.appendChild(el("div", { class: "empty" }, "Sin engagement.json todavía.")); return; }
    if (nb.next_move) {
      panel.appendChild(el("div", { class: "nb-next" }, el("div", { class: "lbl" }, "Siguiente paso"), el("p", {}, nb.next_move)));
    }
    panel.appendChild(el("div", { class: "nb-meta muted" }, [nb.phase && ("fase " + nb.phase), nb.layer && ("capa " + nb.layer), nb.updated && fmtTs(nb.updated)].filter(Boolean).join(" · ")));
    const hyps = nb.hypotheses || [];
    panel.appendChild(el("h3", { class: "tabsec" }, "Hipótesis (" + hyps.length + ")"));
    if (!hyps.length) panel.appendChild(el("div", { class: "empty" }, "El critic aún no ha sembrado hipótesis."));
    else {
      const ul = el("div", { class: "nb-hyps" });
      for (const h of hyps) {
        ul.appendChild(el("div", { class: "nb-hyp " + (h.status || "") },
          el("span", { class: "badge" }, h.status || "viva"),
          el("span", {}, h.text || ""),
          h.fails ? el("span", { class: "muted" }, "fallos " + h.fails) : null,
        ));
      }
      panel.appendChild(ul);
    }
    const loops = nb.loops || [];
    if (loops.length) {
      panel.appendChild(el("h3", { class: "tabsec" }, "Bucles"));
      panel.appendChild(el("div", { class: "muted" }, loops.map((l) => (l.cls || "?") + " ×" + (l.count || 0)).join(" · ")));
    }
    const tried = nb.tried || [];
    panel.appendChild(el("h3", { class: "tabsec" }, "Tried (" + tried.length + ")"));
    if (tried.length) {
      const tbl = el("table", { class: "dtable" }, el("thead", {}, el("tr", {}, ...["Hora", "Clase", "Comando"].map((h) => el("th", {}, h)))));
      const tb = el("tbody", {});
      for (const t of tried.slice().reverse()) {
        tb.appendChild(el("tr", {},
          el("td", { class: "muted" }, fmtTs(t.ts)),
          el("td", {}, t.kind || ""),
          el("td", { class: "wrapcell" }, t.argv || ""),
        ));
      }
      tbl.appendChild(tb);
      panel.appendChild(tbl);
    }
    const idents = (nb.identities || []).filter((i) => i.status === "compromised");
    if (idents.length) {
      panel.appendChild(el("h3", { class: "tabsec" }, "Cuentas (" + idents.length + ")"));
      panel.appendChild(identityTable(idents));
    }
    if (isCtf(run) && (nb.flags || []).length) {
      panel.appendChild(el("h3", { class: "tabsec" }, "Flags"));
      for (const f of nb.flags) {
        panel.appendChild(el("div", { class: "muted" }, [f.kind, f.value, f.path].filter(Boolean).join(" · ")));
      }
    }
    if (cons && (cons.history || []).length) {
      panel.appendChild(el("h3", { class: "tabsec" }, "Conciencia"));
      const hist = el("div", { class: "conscience-hist" });
      for (const h of (cons.history || []).slice().reverse()) {
        hist.appendChild(el("div", { class: "conscience-hist-row" },
          el("span", { class: "muted" }, fmtTs(h.iso || h.ts)),
          el("b", {}, (h.action || h.verdict || "").toUpperCase()),
          el("span", {}, [h.kind, h.what].filter(Boolean).join(" — ")),
        ));
      }
      panel.appendChild(hist);
    }
  };
  const paint = () => draw((run.mission && run.mission.notebook) || {}, run.conscience);
  const load = (first) => {
    if (run.mission) { paint(); return; }
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${run.run_id}`).then((r) => {
      if (state.tabSeq !== seq) return;
      run.mission = r.mission || run.mission;
      run.conscience = r.conscience || run.conscience;
      paint();
    }).catch((e) => { if (first) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { state.tabSoftRefresh = null; };
}

function drawNetGraph(graph) {
  const nodes = (graph && graph.nodes) || [];
  const edges = (graph && graph.edges) || [];
  if (!nodes.length) return null;
  const w = 720, h = Math.max(220, 80 + nodes.length * 36);
  const cols = { host: 0, access: 1, service: 2 };
  const buckets = { 0: [], 1: [], 2: [] };
  nodes.forEach((n) => {
    const k = String(n.kind || "host");
    buckets[cols[k] != null ? cols[k] : 0].push(n);
  });
  const pos = {};
  for (const [col, list] of Object.entries(buckets)) {
    list.forEach((n, i) => {
      pos[n.id] = { x: 90 + Number(col) * 220, y: 40 + i * 48 };
    });
  }
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("class", "net-graph");
  for (const e of edges) {
    const a = pos[e.from || e.src], b = pos[e.to || e.dst];
    if (!a || !b) continue;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("class", "net-edge");
    svg.appendChild(line);
  }
  for (const n of nodes) {
    const p = pos[n.id] || { x: 40, y: 40 };
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", p.x); c.setAttribute("cy", p.y); c.setAttribute("r", 8);
    c.setAttribute("class", "net-node" + (graph.current === n.id ? " current" : "") + (n.reachable === false ? " dark" : ""));
    const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
    t.setAttribute("x", p.x + 14); t.setAttribute("y", p.y + 4);
    t.setAttribute("class", "net-label");
    t.textContent = (n.label || n.id || "").slice(0, 28);
    g.appendChild(c); g.appendChild(t); svg.appendChild(g);
  }
  return svg;
}

function tabNetwork(panel, runId, run) {
  let sig = "";
  let gen = 0;
  const load = (first) => {
    const my = ++gen;
    if (first) panel.appendChild(loadingBox());
    Promise.all([
      api.get(`/api/runs/${runId}/activity?part=network`),
      run && run.mission ? Promise.resolve(null) : api.get(`/api/runs/${runId}`).catch(() => null),
    ]).then(([a, detail]) => {
    if (my !== gen || state.activeTab !== "red") return;
    if (detail && detail.mission) run.mission = detail.mission;
    const net = a.network || [];
    const dns = a.dns || [];
    const dl = a.downloads || [];
    const g = (run && run.mission && run.mission.graph) || {};
    const next = net.length + ":" + dns.length + ":" + dl.length + ":" + ((dl[dl.length - 1] || {}).ts || "") + ":" + ((g.nodes || []).length);
    if (!first && next === sig) return;
    sig = next;
    panel.innerHTML = "";
    // destinos fuera de scope primero
    const oos = net.filter((x) => x.out_of_scope);
    if (oos.length) {
      const dests = [...new Set(oos.map((x) => x.dst_ip + (x.dst_port ? ":" + x.dst_port : "")))].slice(0, 8).join(", ");
      panel.appendChild(el("div", { class: "oos-banner", role: "alert" },
        el("span", { class: "oos-ico", "aria-hidden": "true" }, "⚠"),
        el("div", {},
          el("div", { class: "oos-title" }, `${oos.length} destino(s) fuera de scope`),
          el("div", { class: "oos-sub" }, dests),
        ),
      ));
    }
    const graph = run && run.mission && run.mission.graph;
    const svg = drawNetGraph(graph);
    if (svg) {
      panel.appendChild(el("h3", { class: "tabsec" }, "Mapa"));
      panel.appendChild(svg);
    }
    if (!net.length && !dns.length && !dl.length && !svg) { panel.appendChild(el("div", { class: "empty" }, "Sin actividad de red registrada.")); return; }

    if (net.length) {
      panel.appendChild(el("h3", { class: "tabsec" }, `Destinos (${net.length})`));
      const tbl = el("table", { class: "dtable" }, el("thead", {}, el("tr", {}, ...["Destino", "Puerto", "Proto", "Ámbito", "Host", "Vía", "Veces"].map((h) => el("th", {}, h)))));
      const tb = el("tbody", {});
      for (const r of net) {
        tb.appendChild(el("tr", {},
          el("td", {}, r.dst_ip),
          el("td", { class: "num" }, r.dst_port || ""),
          el("td", { class: "muted" }, r.proto || "tcp"),
          el("td", {}, el("span", { class: "scope " + r.scope }, r.scope), r.out_of_scope ? el("span", { class: "oos", title: "fuera de scope" }, " ⚠") : null),
          el("td", { class: "muted" }, r.host || "—"),
          el("td", { class: "muted" }, r.via || r.result || "—"),
          el("td", { class: "num" }, String(r.count)),
        ));
      }
      tbl.appendChild(tb);
      panel.appendChild(tbl);
    }

    if (dns.length) {
      panel.appendChild(el("h3", { class: "tabsec", style: "margin-top:22px" }, `Nombres / DNS (${dns.length})`));
      const chips = el("div", { class: "model-chips" });
      for (const d of dns) chips.appendChild(el("span", { class: "chip", title: "origen: " + d.source }, d.name));
      panel.appendChild(chips);
    }

    if (dl.length) {
      panel.appendChild(el("h3", { class: "tabsec", style: "margin-top:22px" }, `Descargas / fetch (${dl.length})`));
      const tbl = el("table", { class: "dtable" }, el("thead", {}, el("tr", {}, ...["Hora", "Objetivo", "Veces", "Comando"].map((h) => el("th", {}, h)))));
      const tb = el("tbody", {});
      for (const d of dl.slice().reverse()) {
        tb.appendChild(el("tr", {},
          el("td", { class: "muted" }, fmtTs(d.ts)),
          el("td", {}, d.target || ""),
          el("td", { class: "num" }, String(d.count || 1)),
          el("td", { class: "wrapcell muted" }, d.argv || ""),
        ));
      }
      tbl.appendChild(tb);
      panel.appendChild(tbl);
    }
  }).catch((e) => { if (first) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { gen++; state.tabSoftRefresh = null; };
}

const CAT_LABELS = { inbox: "Anexos (tú)", script: "Scripts", finding: "Findings (JSON)", evidence: "Evidencia", report: "Informe", brief: "Brief", state: "Estado", system: "Sistema / logs" };
const CAT_ORDER = ["inbox", "script", "finding", "evidence", "report", "state", "brief", "system"];
function catIcon(cat) { if (cat === "script") return ICON.code; if (cat === "finding") return ICON.flag; if (cat === "report" || cat === "brief" || cat === "state") return ICON.doc; if (cat === "system") return ICON.terminal; return ICON.file; }

function tabFiles(panel, runId, ctf) {
  const seq = state.tabSeq;
  let sig = "";
  const draw = (files) => {
    if (!files.length) { panel.appendChild(el("div", { class: "empty" }, "El agente aún no ha escrito archivos. Aparecerán aquí conforme los cree (STATE.md, findings, scripts…).")); return; }
    const byCat = {};
    for (const f of files) (byCat[f.category] = byCat[f.category] || []).push(f);
    const produced = files.filter((f) => f.category !== "brief" && f.category !== "system");
    if (!produced.length) {
      panel.appendChild(el("div", { class: "empty", style: "margin-bottom:16px" }, "El run acaba de arrancar: de momento solo está el brief y los logs del sistema. STATE.md, scripts y evidencias aparecen aquí en cuanto el agente los escriba."));
    }
    const cats = el("div", { class: "filecats" });
    for (const cat of CAT_ORDER) {
      const list = byCat[cat];
      if (!list || !list.length) continue;
      const block = el("div", { class: "filecat" });
      block.appendChild(el("h3", { html: catIcon(cat) + `<span>${CAT_LABELS[cat] || cat} (${list.length})</span>` }));
      for (const f of list) {
        const dir = f.rel.includes("/") ? f.rel.slice(0, f.rel.lastIndexOf("/") + 1) : "";
        block.appendChild(el("div", { class: "filerow " + cat },
          el("span", { html: catIcon(cat) }),
          el("div", { class: "fname" }, dir ? el("span", { class: "fpath" }, dir) : null, f.name,
            el("span", { class: "forigin " + (f.origin === "agente" ? "agent" : (f.origin === "operador" ? "op" : "sys")), title: f.origin === "agente" ? "Lo escribió el agente en este run" : (f.origin === "operador" ? "Lo adjuntaste tú al lanzar" : "Lo crea Aegis al arrancar el run (brief, meta, logs)") }, f.origin === "agente" ? "agente" : (f.origin === "operador" ? "tú" : "sistema"))),
          el("span", { class: "fsize" }, fmtBytes(f.size)),
          f.previewable ? el("button", { class: "btn ghost small", onclick: () => openFile(runId, f) }, "Ver") : el("span", {}),
          (ctf && isFlagPath(f.rel)) ? el("button", { class: "btn ghost small icon", html: ICON.copy + "<span>Copiar</span>", onclick: async (e) => {
            e.stopPropagation();
            try {
              const text = await api.getText(evidenceUrl(runId, f.rel));
              await copyText(e, text, "Flag copiada");
            } catch { toast("No se pudo copiar", "err"); }
          } }) : "",
          el("a", { class: "btn ghost small icon", href: withTok(evidenceUrl(runId, f.rel, "?download=1")), html: ICON.download + "<span>Descargar</span>" }),
        ));
      }
      cats.appendChild(block);
    }
    panel.appendChild(cats);
  };
  const load = (first) => {
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${runId}/tree`).then((files) => {
      if (state.tabSeq !== seq) return;
      const next = (files || []).map((f) => f.rel + ":" + f.size).join("|");
      if (!first && next === sig) return;
      sig = next;
      panel.innerHTML = "";
      draw(files || []);
    }).catch((e) => { if (first && state.tabSeq === seq) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { state.tabSoftRefresh = null; };
}

const HL_LANGS = {
  py: { lc: /#.*/, kw: ["def", "class", "return", "import", "from", "as", "if", "elif", "else", "for", "while", "try", "except", "finally", "with", "in", "not", "and", "or", "is", "None", "True", "False", "lambda", "pass", "break", "continue", "raise", "yield", "global", "nonlocal", "assert", "del", "async", "await", "self", "print"] },
  sh: { lc: /#.*/, kw: ["if", "then", "else", "elif", "fi", "for", "in", "do", "done", "while", "until", "case", "esac", "function", "return", "export", "local", "set", "read", "echo", "cd", "source", "sudo", "then", "exit", "eval", "trap"] },
  js: { lc: /\/\/.*/, kw: ["const", "let", "var", "function", "return", "if", "else", "for", "while", "do", "try", "catch", "finally", "class", "new", "import", "from", "export", "default", "await", "async", "of", "in", "typeof", "instanceof", "null", "true", "false", "undefined", "this", "yield", "switch", "case", "break", "continue", "throw", "extends", "super"] },
  json: { json: true },
  generic: { lc: /(#|\/\/).*/, kw: ["if", "else", "for", "while", "return", "function", "def", "class", "import", "true", "false", "null", "public", "private", "static", "void", "int", "string"] },
};
function langFor(suffix) {
  const s = String(suffix || "").toLowerCase().replace(/^\./, "");
  if (s === "py") return "py";
  if (["sh", "bash", "zsh", "ksh"].includes(s)) return "sh";
  if (["js", "mjs", "ts", "tsx", "jsx", "go", "c", "cc", "cpp", "h", "hpp", "rs", "java", "php", "lua", "kt", "swift", "scala"].includes(s)) return "js";
  if (s === "json") return "json";
  if (["md", "markdown", "txt", "log", "text", "yaml", "yml", "ini", "conf", "cfg", "toml", "csv", "tsv", "xml", "html", "htm", "nmap", "gnmap", "out", ""].includes(s)) return "text";
  return "generic";
}
const HL_SENT = "\uE000";
function hlEsc(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function hlLine(line, lang) {
  if (lang === "text") return hlEsc(line);
  let s = hlEsc(line);
  const store = [];
  const stash = (html) => { store.push(html); return HL_SENT; };
  if (lang === "json") {
    s = s.replace(/("(?:\\.|[^"\\])*")(\s*:)/g, (m, k, c) => stash(`<span class="hl-key">${k}</span>`) + c);
    s = s.replace(/"(?:\\.|[^"\\])*"/g, (m) => stash(`<span class="hl-str">${m}</span>`));
    s = s.replace(/\b0x[0-9a-fA-F]+\b|-?\b\d[\d_.eE+-]*\b/g, (m) => stash(`<span class="hl-num">${m}</span>`));
    s = s.replace(/\b(true|false|null)\b/g, (m) => `<span class="hl-kw">${m}</span>`);
  } else {
    const rules = HL_LANGS[lang] || HL_LANGS.generic;
    s = s.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, (m) => stash(`<span class="hl-str">${m}</span>`));
    if (rules.lc) s = s.replace(rules.lc, (m) => stash(`<span class="hl-com">${m}</span>`));
    s = s.replace(/\b0x[0-9a-fA-F]+\b|\b\d[\d_.]*\b/g, (m) => stash(`<span class="hl-num">${m}</span>`));
    if (rules.kw && rules.kw.length) {
      const re = new RegExp("\\b(" + rules.kw.join("|") + ")\\b", "g");
      s = s.replace(re, (m) => `<span class="hl-kw">${m}</span>`);
    }
  }
  let i = 0;
  return s.replace(new RegExp(HL_SENT, "g"), () => store[i++]);
}
function renderCode(text, suffix) {
  const lang = langFor(suffix);
  const lines = String(text).replace(/\n$/, "").split("\n");
  const gutter = lines.map((_, i) => i + 1).join("\n");
  return el("div", { class: "codeview" },
    el("pre", { class: "code-gutter" }, gutter),
    el("pre", { class: "code-body", html: lines.map((l) => hlLine(l, lang)).join("\n") }),
  );
}
function suffixOf(name) { const n = String(name || ""); const i = n.lastIndexOf("."); return i > 0 ? n.slice(i) : ""; }

async function openFile(runId, f) {
  let text = "";
  try { text = await api.getText(evidenceUrl(runId, f.rel)); } catch (e) { text = "No se pudo cargar: " + e.message; }
  const suffix = f.suffix || suffixOf(f.name);
  const isMd = /\.(md|markdown)$/i.test(suffix) || /\.(md|markdown)$/i.test(f.name);
  const view = isMd ? el("div", { class: "report md-view", html: miniMarkdown(text) }) : renderCode(text, suffix);
  const body = el("div", {},
    el("div", { class: "toolbar" },
      el("a", { class: "btn ghost small icon", href: withTok(evidenceUrl(runId, f.rel, "?download=1")), html: ICON.download + "<span>Descargar</span>" }),
      (state._ctfView && (isFlagPath(f.rel) || findingKind({ title: f.name, kind: "" }) === "flag")) ? copyFileBtn(text, "Flag copiada") : "",
      el("span", { class: "mono-small" }, f.rel + " · " + fmtBytes(f.size)),
    ),
    view,
  );
  openModal(f.name, body);
}

const KIND_LABEL = { flag: "flag", vuln: "vuln", cve: "CVE", misconfig: "misconfig", info: "info" };
function findingKind(f) {
  const k = String(f.kind || "").toLowerCase();
  if (KIND_LABEL[k]) return k;
  const blob = [f.id, f.title, f.summary, f.asset, f.impact].join(" ");
  if (/(?:user|root|local|flag)(?:_proof)?\.txt|\bproof\.txt\b|FLAG\{|CTF\{/i.test(blob)) return "flag";
  if (/\bCVE-\d{4}-\d{4,}\b/i.test(blob)) return "cve";
  if (/misconfig|default.?cred|anonymous/i.test(blob)) return "misconfig";
  return "vuln";
}
function findingProse(f) {
  let explain = String(f.explain || f.summary || f.description || f.finding || "").trim();
  let proof = String(f.proof || f.reproduction || "").trim();
  const where = String(f.asset || f.vhost || f.host || "").trim();
  const ident = [f.product, f.version].filter(Boolean).join(" ").trim();
  const notes = (f.cve_notes && typeof f.cve_notes === "object" && !Array.isArray(f.cve_notes))
    ? Object.entries(f.cve_notes).map(([k, v]) => k + ": " + v).join("\n")
    : "";
  const leaks = Array.isArray(f.leaks) ? f.leaks.filter(Boolean).join("\n") : "";
  if (!explain) {
    const bits = [];
    if (ident) bits.push(ident + (where ? " en " + where : ""));
    if (notes) bits.push(notes);
    if (leaks) bits.push(leaks);
    explain = bits.join("\n\n").trim();
  }
  if (!proof && notes && !explain.includes(notes)) proof = notes;
  return { explain, proof, notes, leaks, where };
}
function findingRow(runId, f, ctf) {
  const kind = findingKind(f);
  const kindLabel = (kind === "flag" && !ctf) ? "info" : kind;
  const sev = (kind === "flag") ? "info" : (f.severity || "info");
  const draft = !!f.draft;
  const prose = findingProse(f);
  const blurb = draft
    ? "El modelo del run está escribiendo la ficha."
    : prose.explain;
  return el("div", { class: "frow sev-" + sev + (draft ? " draft" : ""), onclick: draft ? undefined : () => openFinding(runId, f, ctf) },
    el("span", { class: "frow-bar" }),
    el("span", { class: "frow-id" }, f.id || "—"),
    el("div", { class: "frow-main" },
      el("span", { class: "frow-title" }, draft ? "Redactando…" : (f.title || "(sin título)")),
      blurb ? el("span", { class: "frow-sum" }, blurb) : null,
      draft ? null : (f.asset ? el("span", { class: "frow-asset" }, f.asset) : null),
      (!draft && pocChip(f)) ? el("span", { class: "frow-asset" }, pocChip(f)) : null,
    ),
    el("span", { class: "frow-tags" },
      el("span", { class: "badge kind " + kindLabel }, KIND_LABEL[kindLabel] || kindLabel),
      el("span", { class: "sev " + sev }, sev),
      el("span", { class: "badge " + (f.status === "proven" ? "proven" : "suspected") }, f.status === "proven" ? "proven" : "suspected"),
      f.reviewed ? el("span", { class: "badge reviewed", title: "Contrastado con consola y disco" }, "revisado") : null,
    ),
  );
}
function tabFindings(panel, runId, ctf) {
  const seq = state.tabSeq;
  let sig = "";
  const load = (first) => {
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${runId}/findings`).then((items) => {
    if (state.tabSeq !== seq) return;
    const next = (items || []).map((f) => [f.id, f.status, f.title, f.severity, f.draft ? "d" : ""].join(":")).join("|");
    if (!first && next === sig) return;
    sig = next;
    panel.innerHTML = "";
    const shown = (items || []).filter((f) => String(f.kind || "").toLowerCase() !== "flag");
    if (!shown.length) {
      panel.appendChild(el("div", { class: "empty" }, ctf
        ? "Las flags van en Contrato CTF. Aquí solo vulns, CVE y misconfigs."
        : "Aquí aparecen los findings que se vayan encontrando."));
      return;
    }
    const list = el("div", { class: "frows" });
    for (const f of shown) list.appendChild(findingRow(runId, f, ctf));
    panel.appendChild(list);
  }).catch((e) => { if (first && state.tabSeq === seq) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { state.tabSoftRefresh = null; };
}

function captionEvidence(rel, text) {
  const name = String(rel || "").split("/").pop();
  const raw = String(text || "").trim();
  try {
    const j = JSON.parse(raw);
    if (j && typeof j === "object") {
      if (j.preview != null) return `Respuesta del servicio: ${j.preview}`;
      if (j.message) return String(j.message);
      if (j.ok === false && j.error) return `Falló: ${j.error}`;
    }
  } catch {}
  if (/^HTTP\/\d/i.test(raw)) return "Cabeceras HTTP (la prueba útil suele estar en el body o en otro archivo).";
  if (!raw) return name;
  return name;
}

function pocChip(f) {
  const p = (f && f.poc) || {};
  const origin = String(p.origin || "");
  if (origin === "searchsploit" || origin === "exploitdb") return p.edb ? "EDB " + p.edb : "Exploit-DB";
  if (origin === "github") return "GitHub";
  if (origin === "gitlab") return "GitLab";
  if (origin === "advisory") return "Advisory";
  if (origin === "inline") return "sin PoC externo";
  return "";
}

function pocBlock(f) {
  const p = (f && f.poc) || {};
  const urls = Array.isArray(p.urls) ? p.urls.filter(Boolean) : [];
  const local = Array.isArray(p.local) ? p.local.filter(Boolean) : [];
  const origin = String(p.origin || "");
  if (!origin && !urls.length && !local.length) return null;
  const box = el("div", { class: "f-block" }, el("div", { class: "lbl" }, "Origen del PoC"));
  box.appendChild(el("div", { class: "f-explain" }, p.label || (origin === "inline"
    ? "No hay rastro de un PoC en GitHub, Exploit-DB ni searchsploit. La prueba es el comando in-line."
    : origin)));
  if (local.length) {
    for (const path of local) box.appendChild(el("pre", { class: "f-proof" }, path));
  }
  if (urls.length) {
    const ul = el("div", { class: "poc-urls" });
    for (const u of urls) {
      ul.appendChild(el("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, u));
    }
    box.appendChild(ul);
  }
  return box;
}

function openFinding(runId, f, ctf) {
  const kind = findingKind(f);
  ctf = !!ctf;
  const prose = findingProse(f);
  const explain = prose.explain;
  const proof = prose.proof;
  const body = el("div", {},
    el("div", { class: "rd-meta", style: "margin-bottom:12px" },
      el("span", { class: "chip" }, f.id || "—"),
      el("span", { class: "badge kind " + ((kind === "flag" && !ctf) ? "info" : kind) }, KIND_LABEL[(kind === "flag" && !ctf) ? "info" : kind] || kind),
      el("span", { class: "sev " + ((kind === "flag") ? "info" : (f.severity || "info")) }, (kind === "flag") ? "info" : (f.severity || "info")),
      el("span", { class: "badge " + (f.status === "proven" ? "proven" : "suspected") }, f.status || "suspected"),
      f.reviewed ? el("span", { class: "badge reviewed" }, "revisado") : null,
      f.asset ? el("span", { class: "chip mono", title: "Activo afectado" }, f.asset) : null,
      pocChip(f) ? el("span", { class: "chip" }, pocChip(f)) : null,
    ),
  );
  const poc = pocBlock(f);
  if (poc) body.appendChild(poc);
  if (explain) {
    body.appendChild(el("div", { class: "f-block" },
      el("div", { class: "lbl" }, "Qué se observó"),
      el("div", { class: "f-explain" }, explain),
    ));
  }
  if (proof) {
    body.appendChild(el("div", { class: "f-block" },
      el("div", { class: "lbl" }, "Prueba (comando / pasos)"),
      el("pre", { class: "f-proof" }, proof),
    ));
  }
  // no duplicar argv si ya está en proof
  const cmdArgv = f.command && f.command.argv ? String(f.command.argv).trim() : "";
  const proofNorm = proof.replace(/\s+/g, " ").trim();
  const cmdNorm = cmdArgv.replace(/\s+/g, " ").trim();
  const cmdRedundant = cmdNorm && proofNorm && (proofNorm.includes(cmdNorm) || cmdNorm.includes(proofNorm));
  if (cmdArgv && !cmdRedundant) {
    body.appendChild(el("div", { class: "f-block" },
      el("div", { class: "lbl" }, "Comando que lo probó"),
      el("pre", { class: "f-proof" }, (f.command.ts ? fmtTs(f.command.ts) + "  " : "") + cmdArgv),
    ));
  }
  if (f.impact) {
    body.appendChild(el("div", { class: "f-block" },
      el("div", { class: "lbl" }, "Impacto"),
      el("div", { class: "f-explain" }, f.impact),
    ));
  }
  if (prose.leaks && !explain.includes(prose.leaks.split("\n")[0])) {
    body.appendChild(el("div", { class: "f-block" },
      el("div", { class: "lbl" }, "Fugas"),
      el("pre", { class: "f-proof" }, prose.leaks),
    ));
  }
  const ev = Array.isArray(f.evidence) ? f.evidence : [];
  if (ev.length) {
    const box = el("div", { class: "f-block" }, el("div", { class: "lbl" }, "Salida que lo demuestra"));
    for (const rel of ev) {
      const card = el("div", { class: "ev-card" });
      box.appendChild(card);
      if (!evidenceIsFile(rel)) {
        card.appendChild(el("div", { class: "ev-cap" }, "Nota del agente (no es un fichero)"));
        card.appendChild(el("pre", {}, String(rel)));
        continue;
      }
      card.appendChild(el("div", { class: "muted" }, "cargando " + rel + "…"));
      api.getText(evidenceUrl(runId, rel)).then((text) => {
        card.innerHTML = "";
        const clip = text.length > 1200 ? text.slice(0, 1200) + "\n…" : text;
        card.appendChild(el("div", { class: "ev-cap" }, captionEvidence(rel, text)));
        card.appendChild(el("pre", {}, clip || "(vacío)"));
        card.appendChild(el("div", { class: "toolbar", style: "margin-top:8px" },
          el("button", { class: "btn ghost small", onclick: () => openFile(runId, { name: String(rel).split("/").pop(), rel, size: 0 }) }, "Abrir"),
          (ctf && (kind === "flag" || isFlagPath(rel))) ? copyFileBtn(text, "Flag copiada") : "",
          el("a", { class: "btn ghost small icon", href: withTok(evidenceUrl(runId, rel, "?download=1")), html: ICON.download + "<span>Descargar</span>" }),
        ));
      }).catch(() => { card.textContent = "No se pudo leer " + rel; });
    }
    body.appendChild(box);
  }
  openModal(f.title || f.id || "Finding", body);
}

function tabReport(panel, runId) {
  const seq = state.tabSeq;
  let sig = "";
  const load = (first) => {
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${runId}/report`).then((r) => {
    if (state.tabSeq !== seq) return;
    const md = r.markdown || "";
    if (!first && md === sig) return;
    sig = md;
    panel.innerHTML = "";
    if (!md.trim()) { panel.appendChild(el("div", { class: "empty" }, "Aún no hay informe. Se escribe al cerrar el run y se alinea solo con Findings y Cuentas.")); return; }
    const rep = el("div", { class: "report md-view", html: miniMarkdown(md) });
    attachExport(rep, runId);
    panel.appendChild(rep);
  }).catch((e) => { if (first && state.tabSeq === seq) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { state.tabSoftRefresh = null; };
}

function conscienceClock(ts) {
  if (!ts) return "";
  const n = Number(ts);
  if (!n) return "";
  const d = new Date(n < 1e12 ? n * 1000 : n);
  if (isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
}

function conscienceNext(c) {
  if (!c || !c.next_ts) return "";
  const n = Number(c.next_ts);
  const ms = n < 1e12 ? n * 1000 : n;
  const when = conscienceClock(c.next_ts);
  const left = typeof c.next_in_s === "number" ? c.next_in_s : Math.round((ms - Date.now()) / 1000);
  if (left <= 20) return when ? "ahora (tocaba " + when + ")" : "ahora";
  return when ? "próxima " + when : "";
}

function conscienceReviews(c) {
  const n = (c && c.reviews) || 0;
  if (!n) return "";
  return n + (n === 1 ? " revisión" : " revisiones");
}

function conscienceLabel(c, ended) {
  if (!c) return { val: "—", sub: "sin datos" };
  if (c.enabled === false) return { val: "off", sub: "" };
  const next = ended ? "" : conscienceNext(c);
  const reviews = conscienceReviews(c);
  const join = (...parts) => parts.filter(Boolean).join("\n");
  if (ended) {
    if (!c.reviews) return { val: "—", sub: "cerró sin revisiones" };
    const when = conscienceClock(c.last_ts);
    const verdict = c.last_verdict === "ok" ? "SIGUE" : (c.last_verdict === "repeat" ? "AVISA" : (c.last_verdict === "stuck" ? "corte" : (c.last_verdict || "ok")));
    return { val: verdict, sub: join(reviews, when ? "última " + when : "") };
  }
  if (c.phase === "idle") return { val: "—", sub: c.next_ts ? "cerró antes de la 1ª" : "aún no programa" };
  if (c.phase === "pending") {
    const when = conscienceClock(c.next_ts);
    const fail = c.fail_n ? ("falló " + c.fail_n + "×; reintento") : "primera revisión";
    return { val: c.fail_n ? "reintento" : "pendiente", sub: when ? fail + " a las " + when : fail };
  }
  if (c.phase === "dead") {
    return { val: "reloj muerto", sub: join("aegis watch (el contenedor sigue)", reviews), cls: "conscience-overdue" };
  }
  if (c.phase === "overdue") {
    const why = c.watcher
      ? (c.last_error || (c.fail_n ? "el modelo no contestó (" + c.fail_n + "×)" : "el modelo no contestó"))
      : "el reloj del host no está vivo";
    return { val: "atrasada", sub: join(why, next || (conscienceClock(c.next_ts) ? "tocaba " + conscienceClock(c.next_ts) : "")), cls: "conscience-overdue" };
  }
  if (c.phase === "stuck") return { val: "corte", sub: join(reviews, next) };
  if (c.phase === "repeat" || c.last_verdict === "repeat") return { val: "AVISA", sub: join(reviews, next) };
  if (c.reviews) return { val: c.last_verdict === "ok" ? "SIGUE" : (c.last_verdict || "ok"), sub: join(reviews, next) };
  return { val: "—", sub: next };
}

function conscienceKpi(c, ended) {
  const info = conscienceLabel(c, ended);
  return ["conscience", "Conciencia", info.val, info.sub, info.cls || ""];
}

function conscienceCard(c, brief, ended) {
  const info = conscienceLabel(c, ended);
  const card = el("div", { class: "conscience-card" + (!ended && c && (c.phase === "overdue" || c.phase === "dead") ? " overdue" : "") });
  card.appendChild(el("h2", {}, "Conciencia"));
  card.appendChild(el("div", { class: "cc-meta" }, (info.val + (info.sub ? " · " + info.sub : "")) || "sin datos"));
  const hist = (c && c.history) || [];
  if (hist.length) {
    const box = el("div", { class: "conscience-hist" });
    for (const h of hist.slice().reverse()) {
      box.appendChild(el("div", { class: "conscience-hist-row" },
        el("span", { class: "muted" }, fmtTs(h.iso || h.ts)),
        el("b", {}, (h.action || h.verdict || "").toUpperCase()),
        el("span", {}, [h.kind, h.what].filter(Boolean).join(" — ")),
      ));
    }
    card.appendChild(box);
  }
  // quita el H1 "CONSCIENCE" del markdown (ya hay h2 Conciencia)
  const cleanBrief = String(brief || "").replace(/^\s*#{0,6}\s*conscienc[eia]+\s*$/gim, "").replace(/^\s+/, "");
  if (cleanBrief.trim()) {
    card.appendChild(el("div", { class: "report", html: miniMarkdown(cleanBrief) }));
  } else if (ended) {
    card.appendChild(el("p", {}, info.sub || "Sin revisiones en este run."));
  } else if (c && c.phase === "pending") {
    const retry = c.fail_n
      ? ("El juez falló" + (c.last_error ? " (" + c.last_error + ")" : "") + ". Reintento automático en unos minutos.")
      : "La primera revisión es a los 20 minutos. El veredicto sale aquí y en la consola (gutter morado).";
    card.appendChild(el("p", {}, retry));
  } else if (c && (c.phase === "overdue" || c.phase === "dead")) {
    const extra = c.last_error ? " Último error: " + c.last_error + "." : "";
    card.appendChild(el("p", {}, "Debería haber revisado ya." + extra + " Si el reloj del host no está vivo, usa Reenganchar en la cabecera (o aegis watch)."));
  } else {
    card.appendChild(el("p", {}, "Todavía no hay briefing. Cuando salte, el veredicto aparece aquí y en la consola."));
  }
  return card;
}

function tabState(panel, runId, run) {
  const seq = state.tabSeq;
  let sig = "";
  const load = (first) => {
    if (first) panel.appendChild(loadingBox());
    api.get(`/api/runs/${runId}/state`).catch(() => ({ markdown: "" })).then((st) => {
    if (state.tabSeq !== seq) return;
    const md = (st && st.markdown) || "";
    const cons = run && run.conscience;
    const brief = (run && run.conscience_md) || "";
    const next = md + "|" + JSON.stringify(cons || {}) + "|" + brief;
    if (!first && next === sig) return;
    sig = next;
    panel.innerHTML = "";
    panel.appendChild(conscienceCard(cons, brief, run && !run.live));
    if (!md.trim()) { panel.appendChild(el("div", { class: "empty" }, "El agente no ha escrito STATE.md.")); return; }
    panel.appendChild(el("div", { class: "report", html: miniMarkdown(md) }));
  }).catch((e) => { if (first && state.tabSeq === seq) { panel.innerHTML = ""; panel.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); } });
  };
  load(true);
  state.tabSoftRefresh = () => load(false);
  return () => { state.tabSoftRefresh = null; };
}

const MODE_INFO = {
  full: { name: "Full", desc: "Auditoría completa del alcance: inventario, confirmación de hallazgos y documentación con evidencia. Sin denegación de servicio." },
  assess: { name: "Assess", desc: "Identifica y documenta hallazgos con evidencia mínima no destructiva. Sin persistencia ni denegación de servicio." },
  recon: { name: "Recon", desc: "Solo reconocimiento: inventario y superficie. Sin escrituras al objetivo. Entrega mapa e hipótesis." },
  net: { name: "Red", desc: "Auditoría de red: inventario, DNS, segmentación y fugas. CIDR obligatorio. SSH sí, CTF no." },
};

async function renderLanzar(view, gen) {
  if (!catalogFresh()) { view.innerHTML = ""; view.appendChild(loadingBox()); }
  const [cat, runs] = await Promise.all([loadCatalog(true), loadRuns().catch(() => state.runs || [])]);
  if (gen && state.renderGen !== gen) return;
  view.innerHTML = "";
  view.appendChild(el("div", { class: "page-head" },
    el("div", {}, el("h1", {}, "Lanzar engagement"), el("p", { class: "sub" }, "Un solo agente por run. Si hay un run vivo, este entra en cola (FIFO). Al lanzar, confirmas que el engagement está autorizado contra los targets declarados.")),
  ));
  const cloneSel = el("select", { id: "f-clone-run", class: "clone-sel" });
  const list = Array.isArray(runs) ? runs : [];
  cloneSel.appendChild(el("option", { value: "" }, list.length ? "Elige un run…" : "No hay runs que clonar"));
  for (const r of list) {
    const tgt = (r.targets || []).map((t) => t.value).filter(Boolean).join(", ");
    const tipo = r.ctf ? "CTF" : "auditoría";
    const bits = [runTitle(r), fmtRunWhen(r), tipo];
    if (tgt) bits.push(tgt);
    cloneSel.appendChild(el("option", { value: r.run_id }, bits.join(" · ")));
  }
  if (list[0] && list[0].run_id) cloneSel.value = list[0].run_id;
  const cloneBtn = el("button", { class: "btn icon clone-go", type: "button", html: ICON.copy + "<span>Clonar este run</span>" });
  if (!list.length) cloneBtn.setAttribute("disabled", "");
  view.appendChild(el("div", { class: "clone-bar" },
    el("div", { class: "clone-copy" },
      el("div", { class: "clone-title" }, "Clonar un run"),
      el("p", { class: "clone-sub" }, "Copia target, modelo, modo, nota y CTF al formulario. No lanza nada."),
    ),
    cloneSel,
    cloneBtn,
  ));

  const form = el("div", { class: "form" });

  const targetHint = el("span", { class: "hint" }, "IPv4/IPv6, IP:puerto, CIDR, URL http(s), CSV o ruta a un archivo con la lista. Obligatorio: tiene que haber una IP.");
  form.appendChild(el("div", { class: "field" }, el("label", {}, "Target"),
    el("input", { type: "text", id: "f-target", placeholder: "10.0.8.10 · IP:puerto · CIDR · URL · lista CSV" }),
    targetHint));

  form.appendChild(el("div", { class: "field" }, el("label", {}, "Título del run"),
    el("input", { type: "text", id: "f-title", placeholder: "Lab intranet · audit-box…", maxlength: "80" }),
    el("span", { class: "hint" }, "Nombre del engagement. Se puede cambiar después.")));

  let mode = "full";
  let exploitMgmt = false;
  const seg = el("div", { class: "segmented" });
  const segCards = {};
  const noteArea = el("textarea", { id: "f-note", placeholder: "scope extra, credenciales autorizadas, no tocar X, prioridad web…" });
  const exploitMgmtToggle = el("div", { class: "toggle" },
    el("div", { class: "tg-switch" }),
    el("div", {}, el("div", { class: "tg-label" }, "Incluir plano de gestión (fw/switch/AP)"),
      el("div", { class: "tg-desc" }, "Apagado: solo mapa. Encendido: también revisa el plano de gestión de firewall, switch, AP o controlador. Si no entra, sigue la red.")));
  const exploitMgmtField = el("div", { class: "ctf-box hidden" }, exploitMgmtToggle);
  exploitMgmtToggle.addEventListener("click", () => {
    if (mode !== "net") return;
    exploitMgmt = !exploitMgmt;
    exploitMgmtToggle.classList.toggle("on", exploitMgmt);
  });
  const pickMode = (m) => {
    mode = m;
    for (const k in segCards) segCards[k].classList.toggle("active", k === m);
    if (m === "net") {
      if (ctf) ctf = false;
      exploitMgmtField.classList.remove("hidden");
      noteArea.placeholder = "Extras de este lab (no tocar X, no escanear Y). El brief de red ya va en el BRIEF.";
    } else {
      exploitMgmt = false;
      exploitMgmtToggle.classList.remove("on");
      exploitMgmtField.classList.add("hidden");
      noteArea.placeholder = "scope extra, credenciales autorizadas, no tocar X, prioridad web…";
    }
    syncXor();
  };
  for (const m of ["full", "assess", "recon", "net"]) {
    const c = el("div", { class: "seg-card", onclick: () => pickMode(m) },
      el("div", { class: "sc-name" }, el("span", { class: "tick" }), MODE_INFO[m].name),
      el("div", { class: "sc-desc" }, MODE_INFO[m].desc));
    segCards[m] = c; seg.appendChild(c);
  }
  form.appendChild(el("div", { class: "field" }, el("label", {}, "Modo de operación"), seg));
  form.appendChild(exploitMgmtField);

  const harnessSel = el("select", { id: "f-harness" });
  const modelSel = el("select", { id: "f-model" });
  const harnesses = cat.harnesses || {};
  const readyHarnesses = () => HARNESS_CHOICES.filter((o) => harnessReady(cat, o.id));
  const fillHarnessOptions = (sel, { includeEmpty } = {}) => {
    sel.innerHTML = "";
    if (includeEmpty) sel.appendChild(el("option", { value: "" }, "Sin backup — el run no cambia de modelo"));
    const ready = readyHarnesses();
    if (!ready.length && !includeEmpty) {
      sel.appendChild(el("option", { value: "" }, "(ningún harness en el host — instálalo desde Modelos)"));
      sel.disabled = true;
      return;
    }
    sel.disabled = false;
    for (const o of ready) sel.appendChild(el("option", { value: o.id }, o.label));
  };
  fillHarnessOptions(harnessSel);

  const endpointField = el("div", { class: "field hidden" },
    el("label", {}, "Endpoint local (vLLM)"),
    el("input", { type: "text", id: "f-endpoint", placeholder: "127.0.0.1:8000" }),
    el("span", { class: "hint" }, "vLLM: IP:puerto (el /v1 lo añade Aegis)."));
  const modelIdField = el("div", { class: "field hidden" },
    el("label", {}, "model-id manual"),
    el("input", { type: "text", id: "f-modelid", placeholder: "local" }));

  const backupHarnessSel = el("select", { id: "f-backup-harness" });
  fillHarnessOptions(backupHarnessSel, { includeEmpty: true });
  const backupModelSel = el("select", { id: "f-backup-model" });
  const backupModelField = el("div", { class: "field hidden" }, el("label", {}, "Modelo de respaldo"), backupModelSel);
  const rescueSel = el("select", { id: "f-rescue-model" });
  const rescueHint = el("span", { class: "hint" }, "");
  const rescueField = el("div", { class: "field" },
    el("label", {}, "Modelo de relevo"),
    rescueSel,
    rescueHint);

  const ollamaLocal = () => (cat.local || []).find((l) => l.provider === "ollama") || {};
  const onModelChange = () => {
    const v = modelSel.value || "";
    const ollamaPick = v.startsWith("ollama/");
    const vllmPick = v.startsWith("vllm/");
    const ol = ollamaLocal();
    const ollamaReady = ollamaPick && (ol.models || []).length;
    endpointField.classList.toggle("hidden", !vllmPick);
    modelIdField.classList.toggle("hidden", !vllmPick);
    if (ollamaReady) {
      $("#f-endpoint").value = ol.endpoint || "";
      $("#f-modelid").value = v.slice("ollama/".length);
    }
    fillBackupModels();
    fillRescueModels();
  };
  const fillModelSelect = (sel, h, { skipSameAsPrimary } = {}) => {
    sel.innerHTML = "";
    const primaryKey = `${harnessSel.value}::${modelSel.value}`;
    const addOpt = (parent, value, label) => {
      const same = skipSameAsPrimary && `${h}::${value}` === primaryKey;
      const opt = el("option", { value: same ? "" : value }, same ? `${label} (ya es el principal)` : label);
      if (same) opt.disabled = true;
      parent.appendChild(opt);
    };
    if (h === "codex") {
      const cx = harnesses.codex || {};
      if (!cx.logged_in) sel.appendChild(el("option", { value: "" }, "(Codex sin login — ve a Modelos)"));
      for (const m of (cx.models || [])) addOpt(sel, m.id, m.label || m.id);
      if (!(cx.models || []).length && cx.logged_in) addOpt(sel, "gpt-5.6-sol", "gpt-5.6-sol");
      return;
    }
    if (h === "claude") {
      const clh = harnesses.claude || {};
      if (!clh.logged_in) sel.appendChild(el("option", { value: "" }, "(Claude Code sin login — ve a Modelos)"));
      for (const m of (clh.models || [])) addOpt(sel, m.id, m.label || m.id);
      if (!(clh.models || []).length && clh.logged_in) {
        addOpt(sel, "claude-opus-4-8", "Opus 4.8");
        addOpt(sel, "claude-opus-4-7", "Opus 4.7");
        addOpt(sel, "claude-opus-5", "Opus 5");
        addOpt(sel, "claude-sonnet-5", "Sonnet 5");
        addOpt(sel, "claude-sonnet-4-6", "Sonnet 4.6");
        addOpt(sel, "claude-fable-5", "Fable 5");
        addOpt(sel, "claude-haiku-4-5", "Haiku 4.5");
      }
      return;
    }
    for (const g of cat.providers || []) {
      if (!g.models.length || g.access === "logged_out") continue;
      const tag = g.access === "gateway" ? " · gateway" : g.access === "subscription" ? " · suscripción" : g.access === "api" ? " · API" : g.access === "logged_out" ? " · sin login" : "";
      const og = el("optgroup", { label: g.label + tag });
      for (const m of g.models) addOpt(og, m, m);
      sel.appendChild(og);
    }
    for (const lp of cat.local || []) {
      if (lp.provider === "ollama") {
        if (!(lp.models || []).length) continue;
        const og = el("optgroup", { label: lp.label });
        for (const m of lp.models) addOpt(og, `ollama/${m}`, m);
        sel.appendChild(og);
        continue;
      }
      const og = el("optgroup", { label: lp.label + (lp.reachable ? "" : " (sin conexión)") });
      const models = lp.models.length ? lp.models : ["(escribe model-id)"];
      for (const m of models) addOpt(og, `${lp.provider}/${m}`, `${lp.provider}/${m}`);
      sel.appendChild(og);
    }
  };
  const fillBackupModels = () => {
    const h = backupHarnessSel.value;
    backupModelField.classList.toggle("hidden", !h);
    if (!h) { backupModelSel.innerHTML = ""; return; }
    fillModelSelect(backupModelSel, h, { skipSameAsPrimary: true });
  };
  const defaultRescueId = (h) => {
    if (h === "claude") return "claude-sonnet-4-6";
    if (h === "codex") return "gpt-5.4";
    if (h === "opencode") {
      const v = (modelSel.value || "").toLowerCase();
      if (v.includes("grok") || v.includes("xai/")) return "xai/grok-4.3";
      if (v.includes("gpt") || v.includes("openai/") || v.includes("codex")) return "openai/gpt-5.4";
      if (v.includes("claude") || v.includes("anthropic/")) return "anthropic/claude-sonnet-4-6";
    }
    return "";
  };
  const rescueRef = (h, id) => `${h}::${id}`;
  const parseRescueRef = (raw) => {
    const s = String(raw || "");
    const i = s.indexOf("::");
    if (i > 0) return { harness: s.slice(0, i), model: s.slice(i + 2) };
    return { harness: "", model: s };
  };
  const setRescueHint = () => {
    const primaryH = harnessSel.value || "opencode";
    const pv = (modelSel.value || "").toLowerCase();
    const picked = parseRescueRef(rescueSel.value);
    const destH = picked.harness || primaryH;
    const destM = (picked.model || "").toLowerCase();
    const destIsXai = destH === "opencode" && (destM.includes("xai/") || destM.startsWith("grok") || (!destM && (pv.includes("grok") || pv.includes("xai/"))));
    const primaryXai = primaryH === "opencode" && (pv.includes("grok") || pv.includes("xai/"));
    if (primaryXai && destIsXai) {
      rescueHint.textContent = "Suscripción xAI en OpenCode: el relevo empieza un minuto en 4.3 y sigue en 4.6. Go, Zen u otra cuenta no usan ese perfil. El resto de combinaciones abre una ficha nueva. El backup es otra cosa: solo crédito o sesión.";
    } else {
      rescueHint.textContent = "Cualquier modelo: otra sub de OpenCode (Go, Zen, SuperGrok…) u otro harness (Claude Code / Codex). Si el principal no puede seguir, este abre una ficha y luego vuelve. El arranque de 60 s en 4.3 solo aplica de xAI a xAI en OpenCode. El backup es otra cosa: solo crédito o sesión.";
    }
  };
  const fillRescueModels = () => {
    const primaryH = harnessSel.value || "opencode";
    const primaryKey = `${primaryH}::${modelSel.value || ""}`;
    rescueField.classList.toggle("hidden", false);
    rescueSel.innerHTML = "";
    rescueSel.appendChild(el("option", { value: "" }, "Por defecto (automático)"));
    const addOpt = (parent, h, value, label) => {
      const ref = rescueRef(h, value);
      const same = ref === primaryKey;
      const opt = el("option", { value: same ? "" : ref }, same ? `${label} (ya es el principal)` : label);
      if (same) opt.disabled = true;
      parent.appendChild(opt);
    };
    if (harnessReady(cat, "opencode")) {
      for (const g of cat.providers || []) {
        if (!g.models.length || g.access === "logged_out") continue;
        const tag = g.access === "gateway" ? " · gateway" : g.access === "subscription" ? " · suscripción" : g.access === "api" ? " · API" : g.access === "logged_out" ? " · sin login" : "";
        const og = el("optgroup", { label: `OpenCode · ${g.label}${tag}` });
        for (const m of g.models) addOpt(og, "opencode", m, m);
        rescueSel.appendChild(og);
      }
      for (const lp of cat.local || []) {
        if (lp.provider === "ollama") {
          if (!(lp.models || []).length) continue;
          const og = el("optgroup", { label: `OpenCode · ${lp.label}` });
          for (const m of lp.models) addOpt(og, "opencode", `ollama/${m}`, m);
          rescueSel.appendChild(og);
          continue;
        }
        const og = el("optgroup", { label: `OpenCode · ${lp.label}${lp.reachable ? "" : " (sin conexión)"}` });
        const models = lp.models.length ? lp.models : ["(escribe model-id)"];
        for (const m of models) addOpt(og, "opencode", `${lp.provider}/${m}`, `${lp.provider}/${m}`);
        rescueSel.appendChild(og);
      }
    }
    if (harnessReady(cat, "claude")) {
      const clh = harnesses.claude || {};
      const clg = el("optgroup", { label: "Claude Code" });
      if (!clh.logged_in) {
        const opt = el("option", { value: "" }, "(Claude Code sin login — ve a Modelos)");
        opt.disabled = true;
        clg.appendChild(opt);
      }
      const clModels = (clh.models || []).length
        ? clh.models
        : (clh.logged_in
          ? [
            { id: "claude-opus-4-8", label: "Opus 4.8" },
            { id: "claude-opus-4-7", label: "Opus 4.7" },
            { id: "claude-opus-5", label: "Opus 5" },
            { id: "claude-sonnet-5", label: "Sonnet 5" },
            { id: "claude-sonnet-4-6", label: "Sonnet 4.6" },
            { id: "claude-fable-5", label: "Fable 5" },
            { id: "claude-haiku-4-5", label: "Haiku 4.5" },
          ]
          : []);
      for (const m of clModels) addOpt(clg, "claude", m.id || m, m.label || m.id || m);
      rescueSel.appendChild(clg);
    }
    if (harnessReady(cat, "codex")) {
      const cx = harnesses.codex || {};
      const cxg = el("optgroup", { label: "Codex CLI" });
      if (!cx.logged_in) {
        const opt = el("option", { value: "" }, "(Codex sin login — ve a Modelos)");
        opt.disabled = true;
        cxg.appendChild(opt);
      }
      const cxModels = (cx.models || []).length ? cx.models : (cx.logged_in ? [{ id: "gpt-5.6-sol", label: "gpt-5.6-sol" }] : []);
      for (const m of cxModels) addOpt(cxg, "codex", m.id || m, m.label || m.id || m);
      rescueSel.appendChild(cxg);
    }
    const want = defaultRescueId(primaryH);
    const wantRef = want ? rescueRef(primaryH, want) : "";
    const hit = wantRef && [...rescueSel.options].find((o) => o.value === wantRef);
    rescueSel.value = hit ? hit.value : "";
    setRescueHint();
  };
  rescueSel.addEventListener("change", setRescueHint);
  const defaultOpenCodeId = () => {
    const defs = cat.defaults || {};
    const aliases = defs.aliases || {};
    return defs.opencode_id || aliases[defs.model] || aliases.grok || "";
  };
  const applyDefaultModel = (sel, h) => {
    if (h !== "opencode") return;
    const want = defaultOpenCodeId();
    if (!want) return;
    // aegis.yaml (grok) solo si ese proveedor ya está usable. No inventar la opción.
    const prov = want.includes("/") ? want.split("/")[0] : "";
    if (prov && prov !== "opencode") {
      const g = (cat.providers || []).find((x) => x.provider === prov) || {};
      const access = g.access || "";
      if (access !== "subscription" && access !== "api" && access !== "gateway") return;
    }
    const opts = [...sel.options];
    const slug = want.split("/").pop();
    const hit = opts.find((o) => o.value === want)
      || opts.find((o) => (o.value || "").split("/").pop() === slug);
    if (hit) sel.value = hit.value;
  };
  const fillModels = () => {
    const h = harnessSel.value || "";
    if (!h) {
      modelSel.innerHTML = "";
      modelSel.appendChild(el("option", { value: "" }, "(instala un harness desde Modelos)"));
      endpointField.classList.add("hidden");
      modelIdField.classList.add("hidden");
      fillBackupModels();
      fillRescueModels();
      return;
    }
    fillModelSelect(modelSel, h);
    applyDefaultModel(modelSel, h);
    if (h !== "opencode") {
      endpointField.classList.add("hidden");
      modelIdField.classList.add("hidden");
    } else {
      onModelChange();
    }
    fillBackupModels();
    fillRescueModels();
  };
  harnessSel.addEventListener("change", fillModels);
  modelSel.addEventListener("change", onModelChange);
  backupHarnessSel.addEventListener("change", fillBackupModels);

  const harnessHint = el("span", { class: "hint" }, "OpenCode enruta Grok/ChatGPT/gateway/local. Codex CLI usa tu suscripción ChatGPT. Claude Code usa tu login de Claude.ai (claude auth login en el host).");
  const setHarnessHint = () => {
    if (!harnessSel.value) {
      harnessHint.textContent = "Instala OpenCode, Claude Code o Codex en el host y pulsa Refrescar catálogo en Modelos. Lanzar solo lista los que hay.";
    } else if (harnessSel.value === "codex") {
      harnessHint.textContent = "Codex exec no tiene --continue: cada turno es stateless y vive del disco (STATE.md, RECAP.md, engagement.json).";
    } else if (harnessSel.value === "claude") {
      harnessHint.textContent = "Claude Code usa tu login de Claude.ai (claude auth login en el host). El recap del cuaderno entra en cada persist.";
    } else {
      harnessHint.textContent = "OpenCode enruta Grok/ChatGPT/gateway/local. El recap del cuaderno entra en cada persist, para cualquier modelo.";
    }
  };
  harnessSel.addEventListener("change", setHarnessHint);
  setHarnessHint();
  form.appendChild(el("div", { class: "field" }, el("label", {}, "Harness (el cerebro que corre en el sandbox)"), harnessSel, harnessHint));
  form.appendChild(el("div", { class: "field" }, el("label", {}, "Modelo"), modelSel));
  form.appendChild(endpointField); form.appendChild(modelIdField);
  form.appendChild(rescueField);
  form.appendChild(el("div", { class: "backup-box" },
    el("div", { class: "field" },
      el("label", {}, "Modelo de respaldo"),
      backupHarnessSel,
      el("span", { class: "hint" }, "Otro harness o cuenta. Solo si el modelo falla (sin tokens/crédito o sin sesión). No salta por salvaguarda. Vacío = sin backup: sin tokens se pausa.")),
    backupModelField,
  ));

  form.appendChild(el("div", { class: "field" }, el("label", {}, "Timeout"), el("input", { type: "text", id: "f-timeout", value: "6h" }), el("span", { class: "hint" }, "Ej: 90m, 6h, 2h30m")));

  let persist = true;
  const persistToggle = el("div", { class: "toggle on" },
    el("div", { class: "tg-switch" }),
    el("div", {}, el("div", { class: "tg-label" }, "No rendirse hasta el timeout"),
      el("div", { class: "tg-desc" },
        el("b", {}, "Activado (por defecto): "), "si el agente cree que ha terminado antes de tiempo, se le pide que ", el("b", {}, "continúe"), " (re-verifica, prueba vectores nuevos y profundiza) hasta agotar el timeout o hasta que tú lo pares (pausar / abortar). Retoma desde ", el("code", {}, "STATE.md"), ", no reinicia desde cero.",
        el("br", {}),
        el("b", {}, "Desactivado: "), "el run termina en cuanto el agente considere que ha acabado.")));
  persistToggle.addEventListener("click", () => { persist = !persist; persistToggle.classList.toggle("on", persist); });
  form.appendChild(el("div", { class: "ctf-box" }, persistToggle));

  form.appendChild(el("div", { class: "field" }, el("label", {}, "Nota del operador (prevalece sobre el plan)"),
    noteArea));

  const INBOX_MAX_FILES = 20;
  const INBOX_MAX_FILE = 150 * 1024 * 1024;
  const INBOX_MAX_TOTAL = 200 * 1024 * 1024;
  let anexos = [];
  const inboxList = el("div", { class: "inbox-list" });
  const inboxHint = el("span", { class: "hint" }, "El modelo los ve en /run/aegis/inbox (solo lectura) antes de planear. Puedes soltar varios: hasta 20 elementos, 150 MB cada uno, 200 MB en total ya descomprimido. Los .zip / .tar / .rar / .7z se descomprimen solos y se leen también las subcarpetas; si piden contraseña, se ignoran.");
  const paintInbox = () => {
    inboxList.replaceChildren();
    if (!anexos.length) return;
    for (const f of anexos) {
      inboxList.appendChild(el("div", { class: "inbox-row" },
        el("span", { class: "inbox-name", title: f.name }, f.name),
        el("span", { class: "inbox-size" }, fmtBytes(f.size)),
        el("button", { type: "button", class: "btn ghost small", onclick: () => { anexos = anexos.filter((x) => x !== f); paintInbox(); } }, "Quitar"),
      ));
    }
  };
  const addAnexos = (files) => {
    for (const file of files) {
      if (!file || !file.name) continue;
      if (file.size < 1) { toast(`${file.name} está vacío`, "err"); continue; }
      if (file.size > INBOX_MAX_FILE) { toast(`${file.name} supera 150 MB`, "err"); continue; }
      if (anexos.length >= INBOX_MAX_FILES) { toast("como mucho 20 anexos", "err"); break; }
      const total = anexos.reduce((n, x) => n + x.size, 0);
      if (total + file.size > INBOX_MAX_TOTAL) { toast("el lote no puede superar 200 MB", "err"); continue; }
      if (anexos.some((x) => x.name === file.name && x.size === file.size)) continue;
      anexos.push(file);
    }
    paintInbox();
  };
  const fileInput = el("input", { type: "file", multiple: "multiple", class: "inbox-file", "aria-label": "Adjuntar archivos" });
  fileInput.addEventListener("change", () => { addAnexos(fileInput.files || []); fileInput.value = ""; });
  const drop = el("div", { class: "inbox-drop", tabindex: "0", role: "button", "aria-label": "Adjuntar archivos al run" },
    el("div", { class: "inbox-drop-title" }, "Suelta archivos aquí o elige"),
    el("div", { class: "inbox-drop-sub" }, "Starter de un CTF, pcap, diccionario, nmap del cliente, un .zip con todo…"),
    el("button", { type: "button", class: "btn ghost small", onclick: (e) => { e.stopPropagation(); fileInput.click(); } }, "Elegir archivos"),
  );
  drop.addEventListener("click", (e) => { if (e.target === drop || e.target.classList.contains("inbox-drop-title") || e.target.classList.contains("inbox-drop-sub")) fileInput.click(); });
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); addAnexos(e.dataTransfer && e.dataTransfer.files); });
  form.appendChild(el("div", { class: "field" },
    el("label", {}, "Anexos de este run"),
    drop, fileInput, inboxList, inboxHint,
  ));

  let ctf = false;
  let flagCount = 2;
  let sameFormat = true;
  const flagList = el("div", { class: "ctf-flags" });
  const countInput = el("input", { type: "number", id: "f-flag-count", min: "1", max: "32", value: "2" });
  const sameInput = el("input", { type: "text", id: "f-flag-same", placeholder: "FLAG{} · banderita.txt · CTF{}", value: "" });
  const sameField = el("div", { class: "field" },
    el("label", {}, "Formato de todas"),
    sameInput,
    el("span", { class: "hint" }, "Si N≠2 o quieres el mismo tipo en todas: FLAG{}, user.txt, banderita.txt…"));
  const rebuildFlagRows = () => {
    flagList.innerHTML = "";
    const n = Math.max(1, Math.min(32, parseInt(countInput.value, 10) || 2));
    flagCount = n;
    if (n === 2 && sameFormat && !sameInput.value.trim()) {
      flagList.appendChild(el("div", { class: "ctf-row" }, el("input", { type: "text", class: "f-flag", value: "user.txt" })));
      flagList.appendChild(el("div", { class: "ctf-row" }, el("input", { type: "text", class: "f-flag", value: "root.txt" })));
      sameField.classList.add("hidden");
      return;
    }
    if (sameFormat) {
      sameField.classList.remove("hidden");
      return;
    }
    sameField.classList.add("hidden");
    const preset = n === 2 ? ["user.txt", "root.txt"] : [];
    for (let i = 0; i < n; i++) {
      flagList.appendChild(el("div", { class: "ctf-row" },
        el("input", { type: "text", class: "f-flag", placeholder: `flag ${i + 1}`, value: preset[i] || "" })));
    }
  };
  const sameToggle = el("div", { class: "toggle on" },
    el("div", { class: "tg-switch" }),
    el("div", {}, el("div", { class: "tg-label" }, "Mismo formato para todas"),
      el("div", { class: "tg-desc" }, "Activo: un solo tipo (5× FLAG{} o 5× banderita.txt). Inactivo: una caja por flag.")));
  sameToggle.addEventListener("click", (ev) => {
    ev.stopPropagation();
    sameFormat = !sameFormat;
    sameToggle.classList.toggle("on", sameFormat);
    rebuildFlagRows();
  });
  countInput.addEventListener("input", rebuildFlagRows);
  const ctfBody = el("div", { class: "ctf-body hidden" },
    el("div", { class: "field" }, el("label", {}, "Número de flags"), countInput,
      el("span", { class: "hint" }, "2 = clásico (user.txt + root.txt). 1 = un token (FLAG{}). 5 = cinco del tipo que indiques.")),
    sameToggle,
    sameField,
    flagList);
  const ctfToggle = el("div", { class: "toggle" },
    el("div", { class: "tg-switch" }),
    el("div", {}, el("div", { class: "tg-label" }, "Modo CTF"),
      el("div", { class: "tg-desc" },
        el("b", {}, "Desactivado (auditoría): "), "sin contrato de flags. El persist no busca user.txt/root.txt. Vale para web, red y AD.",
        el("br", {}),
        el("b", {}, "Activado: "), "el run termina al tener las N flags en disco, en el formato que indiques.")));
  let ssh = false;
  const sshHost = el("input", { type: "text", id: "f-ssh-host", placeholder: "10.0.0.8", autocomplete: "off" });
  const sshUser = el("input", { type: "text", id: "f-ssh-user", placeholder: "usuario", autocomplete: "username" });
  const sshPass = el("input", { type: "password", id: "f-ssh-pass", placeholder: "contraseña", autocomplete: "current-password" });
  const sshBody = el("div", { class: "ctf-body hidden" },
    el("div", { class: "field" }, el("label", {}, "Host SSH (IP)"), sshHost,
      el("span", { class: "hint" }, "La máquina a la que entras. Tiene que ser IP. Puerto 22.")),
    el("div", { class: "field" }, el("label", {}, "Usuario"), sshUser),
    el("div", { class: "field" }, el("label", {}, "Contraseña"), sshPass,
      el("span", { class: "hint" }, "No va al BRIEF. El agente usa aegis-ssh; no redescubre el login.")),
  );
  const sshToggle = el("div", { class: "toggle" },
    el("div", { class: "tg-switch" }),
    el("div", {}, el("div", { class: "tg-label" }, "Acceso SSH"),
      el("div", { class: "tg-desc" },
        el("b", {}, "Desactivado: "), "auditoría normal. Target con IP, como siempre.",
        el("br", {}),
        el("b", {}, "Activado: "), "entras a esa máquina. Target es el objetivo (vacío = esa caja). No se mezcla con CTF.")));
  const syncXor = () => {
    if (mode === "net" && ctf) ctf = false;
    if (ctf && ssh) ssh = false;
    ctfToggle.classList.toggle("on", ctf);
    ctfToggle.classList.toggle("locked", ssh || mode === "net");
    ctfBody.classList.toggle("hidden", !ctf);
    sshToggle.classList.toggle("on", ssh);
    sshToggle.classList.toggle("locked", ctf);
    sshBody.classList.toggle("hidden", !ssh);
    if (mode === "net") {
      targetHint.textContent = ssh
        ? "CIDR de la VLAN remota. El SSH es el asiento, no sustituye al CIDR."
        : "En Red el Target tiene que ser un CIDR (10.0.0.0/24). IP suelta no vale.";
    } else {
      targetHint.textContent = ssh
        ? "Objetivo. Vacío = la máquina SSH. No pongas el salto otra vez."
        : "IPv4/IPv6, IP:puerto, CIDR, URL http(s), CSV o archivo. Obligatorio: tiene que haber una IP.";
    }
  };
  ctfToggle.addEventListener("click", () => {
    if (ssh || mode === "net") return;
    ctf = !ctf;
    if (ctf) rebuildFlagRows();
    syncXor();
  });
  sshToggle.addEventListener("click", () => {
    if (ctf) return;
    ssh = !ssh;
    syncXor();
  });
  form.appendChild(el("div", { class: "ctf-box" }, ctfToggle, ctfBody));
  form.appendChild(el("div", { class: "ctf-box" }, sshToggle, sshBody));

  const msg = el("div", { class: "mono-small" });
  const btn = el("button", { class: "btn icon", html: ICON.play + "<span>Lanzar / Encolar</span>" });
  btn.addEventListener("click", async () => {
    const v = modelSel.value || "";
    const ollamaPick = v.startsWith("ollama/");
    const vllmPick = v.startsWith("vllm/");
    const local = ollamaPick || vllmPick;
    const ol = ollamaLocal();
    const body = {
      target: $("#f-target").value, mode, harness: harnessSel.value || "", model: v,
      model_id: ollamaPick ? v.slice("ollama/".length) : (vllmPick ? $("#f-modelid").value : ""),
      endpoint: ollamaPick ? (ol.endpoint || "") : (vllmPick ? $("#f-endpoint").value : ""),
      title: $("#f-title").value, note: $("#f-note").value, timeout: $("#f-timeout").value || "6h", persist, authorized: true,
      backup_harness: backupHarnessSel.value || "",
      backup_model: backupHarnessSel.value ? (backupModelSel.value || "") : "",
      rescue_harness: "",
      rescue_model: "",
      ctf, flag_count: flagCount, flags: [],
      ssh_host: ssh ? sshHost.value : "",
      ssh_user: ssh ? sshUser.value : "",
      ssh_pass: ssh ? sshPass.value : "",
      exploit_mgmt: mode === "net" && exploitMgmt,
    };
    if (ctf) {
      const same = (sameInput.value || "").trim();
      if (sameFormat && (flagCount !== 2 || same)) {
        if (!same && flagCount !== 2) { msg.textContent = "indica el formato de las flags (FLAG{}, nombre.txt…)"; return; }
        if (same) body.flags = [same];
      } else {
        body.flags = [...flagList.querySelectorAll(".f-flag")].map((n) => n.value.trim()).filter(Boolean);
        if (body.flags.length && body.flags.length !== flagCount && body.flags.length !== 1) {
          msg.textContent = `indica ${flagCount} flags o activa el mismo formato para todas`;
          return;
        }
      }
    }
    if (!body.harness) { msg.textContent = "ningún harness en el host. Instálalo y refresca Modelos."; return; }
    if (body.harness === "codex" && !v) { msg.textContent = "elige un modelo Codex"; return; }
    if (body.harness === "claude" && !v) { msg.textContent = "elige un modelo Claude"; return; }
    if (body.harness === "opencode" && v && !v.startsWith("ollama/") && !v.startsWith("vllm/")) {
      const prov = v.split("/")[0];
      const pg = (cat.providers || []).find((x) => x.provider === prov) || {};
      const acc = pg.access || "";
      if (acc === "logged_out" || (pg.requires_login && acc !== "subscription" && acc !== "api" && acc !== "gateway")) {
        msg.textContent = `${pg.label || prov} no está logueado. En Modelos pulsa Login.`;
        return;
      }
    }
    if (body.harness === "claude" && !(harnesses.claude || {}).logged_in) {
      msg.textContent = (harnesses.claude || {}).expired
        ? "Claude Code: sesión caducada. En Modelos pulsa Login y termina el flujo (o en el host: claude auth login)."
        : "Claude Code no está logueado. En Modelos pulsa Login (o en el host: claude auth login).";
      return;
    }
    if (body.backup_harness && !body.backup_model) { msg.textContent = "elige el modelo de respaldo o deja Sin backup"; return; }
    if (body.backup_harness === "codex" && !(harnesses.codex || {}).logged_in) {
      msg.textContent = "El backup Codex no está logueado. Ve a Modelos o elige otro.";
      return;
    }
    if (body.backup_harness === "claude" && !(harnesses.claude || {}).logged_in) {
      msg.textContent = "El backup Claude no está logueado. Ve a Modelos o elige otro.";
      return;
    }
    const rescuePick = parseRescueRef(rescueSel.value || "");
    body.rescue_harness = rescuePick.harness || "";
    body.rescue_model = rescuePick.model || "";
    if (body.rescue_harness === "claude" && !(harnesses.claude || {}).logged_in) {
      msg.textContent = (harnesses.claude || {}).expired
        ? "La salvaguarda Claude Code: sesión caducada. En Modelos pulsa Login."
        : "La salvaguarda Claude Code no está logueada. Ve a Modelos o elige otro.";
      return;
    }
    if (body.rescue_harness === "codex" && !(harnesses.codex || {}).logged_in) {
      msg.textContent = "La salvaguarda Codex no está logueada. Ve a Modelos o elige otro.";
      return;
    }
    if (body.ctf && (body.ssh_host || body.ssh_user || body.ssh_pass)) {
      msg.textContent = "SSH y CTF no se mezclan"; return;
    }
    if (mode === "net" && body.ctf) {
      msg.textContent = "Red y CTF no se mezclan"; return;
    }
    if (mode === "net" && !String(body.target || "").includes("/")) {
      msg.textContent = "en Red el Target tiene que ser un CIDR"; return;
    }
    if (ssh) {
      if (!body.ssh_host.trim()) { msg.textContent = "SSH host: pon la IP de la máquina"; return; }
      if (!body.ssh_user.trim() || !body.ssh_pass) { msg.textContent = "SSH necesita usuario y contraseña"; return; }
    } else if (!body.target.trim()) {
      msg.textContent = "target vacío: sin SSH hace falta una IP"; return;
    }
    if (vllmPick && !body.endpoint.trim()) { msg.textContent = "endpoint requerido para vLLM"; return; }
    if (ollamaPick && !body.endpoint.trim()) { msg.textContent = "Ollama: guarda IP:puerto en Cuentas"; return; }
    btn.setAttribute("disabled", "");
    let stagedInbox = "";
    try {
      if (anexos.length) {
        msg.textContent = "Subiendo anexos…";
        const created = await api.post("/api/inbox", {});
        stagedInbox = created.id;
        for (let i = 0; i < anexos.length; i++) {
          msg.textContent = `Subiendo anexos… ${i + 1}/${anexos.length}`;
          await api.upload(`/api/inbox/${stagedInbox}`, anexos[i], anexos[i].name);
        }
        body.inbox = stagedInbox;
      }
      const r = await api.post("/api/runs", body);
      dropRuns();
      if (r.live) {
        toast("Engagement lanzado", "ok");
        rememberLaunch(r.item);
        setView("operar");
        watchUntilLive();
      } else {
        toast("Añadido a la cola", "ok");
        btn.removeAttribute("disabled");
        msg.textContent = "En cola. Se lanzará al terminar el run vivo.";
        refreshHeader({ force: true });
      }
    } catch (e) {
      if (stagedInbox) api.del(`/api/inbox/${stagedInbox}`).catch(() => {});
      msg.textContent = "Error: " + e.message;
      btn.removeAttribute("disabled");
    }
  });
  form.appendChild(el("div", { style: "display:flex;gap:14px;align-items:center" }, btn, msg));

  view.appendChild(form);
  fillModels();
  pickMode("full");

  const applyPreset = (p) => {
    if (!p) return;
    if (p.target) $("#f-target").value = p.target;
    if (p.title) $("#f-title").value = p.title;
    if (p.note) $("#f-note").value = p.note;
    if (p.timeout) $("#f-timeout").value = p.timeout;
    if (p.mode) pickMode(p.mode);
    if (p.mode === "net") {
      exploitMgmt = !!p.exploit_mgmt;
      exploitMgmtToggle.classList.toggle("on", exploitMgmt);
    }
    if (p.harness && [...harnessSel.options].some((o) => o.value === p.harness)) {
      harnessSel.value = p.harness; fillModels(); setHarnessHint();
    }
    if (p.model) {
      modelSel.value = p.model;
      if (!modelSel.value && p.model) {
        modelSel.appendChild(el("option", { value: p.model }, p.model));
        modelSel.value = p.model;
      }
      onModelChange();
    }
    if (p.backup_harness && [...backupHarnessSel.options].some((o) => o.value === p.backup_harness)) {
      backupHarnessSel.value = p.backup_harness;
      fillBackupModels();
      if (p.backup_model) backupModelSel.value = p.backup_model;
    }
    if (p.rescue_model) {
      fillRescueModels();
      const rh = p.rescue_harness || "";
      const want = rh ? `${rh}::${p.rescue_model}` : "";
      const fallback = (p.harness && p.rescue_model) ? `${p.harness}::${p.rescue_model}` : p.rescue_model;
      const opts = [...rescueSel.options];
      const opt = (want && opts.find((o) => o.value === want))
        || opts.find((o) => o.value === p.rescue_model)
        || (fallback && opts.find((o) => o.value === fallback))
        || opts.find((o) => (o.value || "").endsWith("::" + p.rescue_model));
      if (opt) rescueSel.value = opt.value;
      else {
        const v = want || fallback || p.rescue_model;
        rescueSel.appendChild(el("option", { value: v }, v));
        rescueSel.value = v;
      }
      setRescueHint();
    }
    if (p.ctf && !ctf) { ssh = false; ctf = true; rebuildFlagRows(); }
    if (!p.ctf && ctf) ctf = false;
    if (p.ssh && !p.ctf) {
      ssh = true;
      if (p.ssh_host) sshHost.value = p.ssh_host;
      if (p.ssh_user) sshUser.value = p.ssh_user;
    } else if (!p.ssh && ssh) {
      ssh = false;
    }
    syncXor();
    if (p.ctf && p.flag_count) {
      countInput.value = String(p.flag_count);
      rebuildFlagRows();
      const flags = p.flags || [];
      [...flagList.querySelectorAll(".f-flag")].forEach((inp, i) => { if (flags[i]) inp.value = flags[i]; });
    }
    toast("Config de " + (p.title || p.run_id || "ese run") + " cargada", "ok");
  };
  cloneBtn.addEventListener("click", async () => {
    const rid = cloneSel.value;
    if (!rid) { toast("Elige un run", "err"); return; }
    cloneBtn.setAttribute("disabled", "");
    try {
      const p = await api.get(`/api/presets/${rid}`);
      applyPreset(p);
    } catch (e) { toast(e.message || "No se pudo clonar", "err"); }
    cloneBtn.removeAttribute("disabled");
  });
}

let _rowMenuClose = null;

function rowMenu(items, opts) {
  opts = opts || {};
  const list = (items || []).filter(Boolean);
  const label = opts.label || "";
  const wrap = el("div", { class: "rowmenu" });
  const btn = el("button", { class: "btn ghost small rowmenu-btn" + (label ? " icon" : ""), title: opts.title || label || "Más acciones", "aria-haspopup": "true", "aria-expanded": "false" });
  if (label) btn.innerHTML = (opts.icon || "") + `<span>${label}</span>`;
  else btn.textContent = "···";
  const pop = el("div", { class: "rowmenu-pop hidden", role: "menu" });
  const place = () => {
    const r = btn.getBoundingClientRect();
    const gap = 4;
    const margin = 8;
    const pw = pop.offsetWidth;
    const ph = pop.offsetHeight;
    let top = r.bottom + gap;
    if (top + ph > window.innerHeight - margin && r.top - gap - ph >= margin) top = r.top - gap - ph;
    let left = r.right - pw;
    if (left < margin) left = margin;
    if (left + pw > window.innerWidth - margin) left = Math.max(margin, window.innerWidth - margin - pw);
    pop.style.top = `${Math.round(top)}px`;
    pop.style.left = `${Math.round(left)}px`;
  };
  const close = () => {
    if (_rowMenuClose === close) _rowMenuClose = null;
    pop.classList.add("hidden");
    btn.setAttribute("aria-expanded", "false");
    if (wrap.isConnected) wrap.appendChild(pop);
    else pop.remove();
    document.removeEventListener("click", onDoc);
    document.removeEventListener("keydown", onKey);
    window.removeEventListener("scroll", onMove, true);
    window.removeEventListener("resize", onMove);
  };
  const onDoc = (e) => { if (!wrap.contains(e.target) && !pop.contains(e.target)) close(); };
  const onKey = (e) => { if (e.key === "Escape") { close(); btn.focus(); } };
  const onMove = () => { if (!wrap.isConnected) { close(); return; } place(); };
  for (const it of list) {
    pop.appendChild(el("button", { class: "rowmenu-item" + (it.danger ? " danger" : ""), role: "menuitem", onclick: (e) => { e.stopPropagation(); close(); it.onClick(e); } }, it.label));
  }
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (pop.classList.contains("hidden")) {
      if (_rowMenuClose && _rowMenuClose !== close) _rowMenuClose();
      document.body.appendChild(pop);
      pop.classList.remove("hidden");
      btn.setAttribute("aria-expanded", "true");
      place();
      _rowMenuClose = close;
      setTimeout(() => {
        document.addEventListener("click", onDoc);
        document.addEventListener("keydown", onKey);
        window.addEventListener("scroll", onMove, true);
        window.addEventListener("resize", onMove);
      }, 0);
    } else close();
  });
  wrap.appendChild(btn); wrap.appendChild(pop);
  return wrap;
}

async function renderHistorial(view, gen) {
  if (!runsFresh()) { view.innerHTML = ""; view.appendChild(loadingBox()); }
  const runs = await loadRuns();
  if (gen && state.renderGen !== gen) return;
  view.innerHTML = "";
  view.appendChild(el("div", { class: "page-head" }, el("h1", {}, "Historial"), el("p", { class: "sub" }, "Todos los engagements. Haz clic en un run para abrir su detalle.")));
  const search = el("input", { type: "text", "aria-label": "Buscar runs", placeholder: "buscar: título, id, target, modo, modelo, estado…" });
  const count = el("span", { class: "toolbar-count muted" }, "");
  const clearBtn = el("button", { class: "btn ghost small hidden", title: "Limpiar búsqueda", onclick: () => { search.value = ""; draw(); search.focus(); } }, "Limpiar");
  const pickBtn = el("button", { class: "btn ghost small", title: "Elegir varios runs para borrar" }, "Seleccionar");
  const bulkBtn = el("button", { class: "btn small danger icon hidden", html: ICON.trash + "<span>Borrar</span>" });
  view.appendChild(el("div", { class: "toolbar" }, search, clearBtn, count, el("div", { class: "toolbar-end" }, pickBtn, bulkBtn)));
  const container = el("div", { class: "table-wrap" });
  view.appendChild(container);
  const selected = new Set();
  let picking = false;

  const deletable = (list) => list.filter(canDeleteRun);

  const paintBulk = () => {
    pickBtn.textContent = picking ? "Listo" : "Seleccionar";
    pickBtn.classList.toggle("on", picking);
    pickBtn.setAttribute("aria-pressed", picking ? "true" : "false");
    const n = selected.size;
    bulkBtn.classList.toggle("hidden", !picking || n === 0);
    const lab = bulkBtn.querySelector("span");
    if (lab) lab.textContent = n ? ("Borrar " + n) : "Borrar";
  };

  pickBtn.onclick = () => {
    picking = !picking;
    if (!picking) selected.clear();
    draw();
  };

  bulkBtn.onclick = async () => {
    const ids = [...selected];
    if (!ids.length) return;
    const labels = ids.map((id) => {
      const hit = runs.find((r) => r.run_id === id);
      return hit ? (runTitle(hit) || id) : id;
    });
    try {
      const out = await deleteRuns(ids, labels);
      if (!out) return;
      for (const id of (out.deleted || [])) selected.delete(id);
      await renderHistorial($("#view"));
    } catch (err) { toast(err.message, "err"); }
  };

  const draw = () => {
    const q = search.value.toLowerCase().trim();
    const filtered = runs.filter((r) => !q || JSON.stringify([r.title, r.run_id, r.mode, r.model, r.backup_model, r.harness, r.status, r.reason, r.started_at, r.operator_note, r.ctf ? "ctf" : "auditoria", r.ssh_host ? "ssh " + sshLabel(r) : "", (r.ctf_flags || []).join(" "), (r.targets || []).map((t) => t.value)]).toLowerCase().includes(q));
    clearBtn.classList.toggle("hidden", !q);
    count.textContent = q ? `${filtered.length} de ${runs.length}` : `${runs.length} runs`;
    paintBulk();
    container.innerHTML = "";
    if (!filtered.length) { container.appendChild(el("div", { class: "empty" }, "Sin resultados.")); return; }
    const pickable = deletable(filtered);
    const heads = ["Run", "Fecha", "Estado", "Modo", "Tipo", "Modelo", "Target", "Findings", ""].map((h) => el("th", {}, h));
    if (picking) {
      const allBox = el("input", { type: "checkbox", "aria-label": "Seleccionar todos los visibles" });
      allBox.checked = pickable.length > 0 && pickable.every((r) => selected.has(r.run_id));
      allBox.indeterminate = pickable.some((r) => selected.has(r.run_id)) && !allBox.checked;
      allBox.addEventListener("click", (e) => e.stopPropagation());
      allBox.addEventListener("change", () => {
        if (allBox.checked) pickable.forEach((r) => selected.add(r.run_id));
        else pickable.forEach((r) => selected.delete(r.run_id));
        draw();
      });
      heads.unshift(el("th", { class: "cell-check" }, allBox));
    }
    const tbl = el("table", { class: "rtable" + (picking ? " picking" : "") }, el("thead", {}, el("tr", {}, ...heads)));
    const tb = el("tbody", {});
    for (const r of filtered) {
      const s = r._stats || {};
      const fsum = `P${s.findings_proven || 0}/S${s.findings_suspected || 0}`;
      const targets = (r.targets || []).map((t) => t.value).join(", ");
      const prompt = noteMark(operatorNote(r));
      const est = r.reason || r.status || "";
      const okDel = canDeleteRun(r);
      let checkCell = false;
      if (picking) {
        const box = el("input", {
          type: "checkbox",
          "aria-label": "Seleccionar " + (runTitle(r) || r.run_id),
          disabled: okDel ? null : "disabled",
          title: okDel ? "Seleccionar para borrar" : "El run vivo no se puede borrar",
        });
        box.checked = selected.has(r.run_id);
        box.addEventListener("click", (e) => e.stopPropagation());
        box.addEventListener("change", () => {
          if (!okDel) return;
          if (box.checked) selected.add(r.run_id);
          else selected.delete(r.run_id);
          draw();
        });
        checkCell = el("td", { class: "cell-check", onclick: (e) => e.stopPropagation() }, box);
      }
      tb.appendChild(el("tr", { class: "clickable" + (picking && selected.has(r.run_id) ? " picked" : ""), title: "Abrir run", onclick: () => openRun(r.run_id) },
        checkCell,
        el("td", { class: "cell-name" }, el("div", { class: "run-label" }, runTitle(r))),
        el("td", { class: "cell-when" }, fmtRunWhen(r)),
        el("td", {}, el("span", { class: "tag st-" + est }, r.reason ? reasonLabel(r.reason) : (r.status || "?"))),
        el("td", {}, r.mode || ""),
        el("td", { class: "cell-tipo" },
          el("div", { class: "tipo-stack" },
            isCtf(r) ? ctfChip(r, { compact: true }) : el("span", { class: "tipo-audit" }, "auditoría"),
            sshChip(r, { compact: true }),
          ),
        ),
        el("td", {}, (r.model || "").split("/").pop() + (r.backup_model ? " → " + (r.backup_model || "").split("/").pop() : "")),
        el("td", {}, targets),
        el("td", {}, fsum),
        el("td", { class: "row-actions", onclick: (e) => e.stopPropagation() },
          prompt || "",
          el("button", { class: "btn ghost small", onclick: () => openReport(r.run_id) }, "Informe"),
          rowMenu([
            { label: "Renombrar", onClick: async () => { const next = await renameRun(r.run_id, r.title || ""); if (next !== null) { r.title = next; draw(); refreshHeader(); } } },
            canContinue(r) ? { label: "Continuar", onClick: async () => { try { await api.post(`/api/runs/${r.run_id}/unpause`); toast("Run reanudado", "ok"); await refreshHeader(); await renderHistorial($("#view")); } catch (err) { toast(err.message, "err"); } } } : null,
            canResume(r) ? { label: "Retomar", onClick: async () => { try { await resumeEndedRun(r); } catch (err) { toast(err.message, "err"); } } } : null,
            okDel ? { label: "Borrar", danger: true, onClick: async () => { try { const out = await deleteRuns([r.run_id], [runTitle(r) || r.run_id]); if (out) await renderHistorial($("#view")); } catch (err) { toast(err.message, "err"); } } } : null,
          ]),
        ),
      ));
    }
    tbl.appendChild(tb);
    container.appendChild(tbl);
  };
  search.addEventListener("input", draw);
  draw();
}

function openRun(runId, opts) {
  opts = opts || {};
  const tab = opts.tab || null;
  if (!opts.fromRoute) { const h = "#/run/" + encodeURIComponent(runId) + (tab ? "/" + tab : ""); if (location.hash !== h) history.pushState(null, "", h); }
  state.view = "operar";
  state.viewRun = runId;
  state.routeTab = tab;
  state._runLabel = "";
  navActive("operar");
  paintTopbar();
  closeStreams();
  render();
}

function reportHtmlDoc(runId, md) {
  const body = miniMarkdown(md);
  const css = [
    ":root{color-scheme:light}",
    "*{box-sizing:border-box}",
    "body{margin:0;background:#f4f2ec;color:#20242a;font:15px/1.7 'Source Sans 3',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}",
    ".sheet{max-width:820px;margin:0 auto;padding:32px 28px 64px}",
    ".bar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:22px;padding-bottom:12px;border-bottom:2px solid #b8742e}",
    ".bar .who{font:700 18px/1.2 'Archivo Narrow','Arial Narrow',sans-serif;letter-spacing:.14em;text-transform:uppercase;color:#b8742e}",
    ".bar .rid{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#6a6f77}",
    ".bar button{font:600 13px/1 'Source Sans 3',sans-serif;background:#b8742e;color:#fff;border:0;border-radius:6px;padding:9px 14px;cursor:pointer}",
    "h1,h2,h3,h4{font-family:'Archivo Narrow','Arial Narrow',sans-serif;line-height:1.25;margin:22px 0 10px}",
    "h1{font-size:24px}h2{font-size:19px;border-bottom:1px solid #d8d2c4;padding-bottom:5px}h3{font-size:16px}h4{font-size:12.5px;text-transform:uppercase;letter-spacing:.08em;color:#6a6f77}",
    "p{margin:10px 0}ul,ol{margin:10px 0;padding-left:24px}li{margin:5px 0}",
    "code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.86em;background:#ece7db;color:#7a3d12;border:1px solid #ddd6c7;border-radius:4px;padding:.5px 5px;overflow-wrap:anywhere;word-break:break-word}",
    "pre{background:#1b1e17;color:#e9e6dc;border-radius:6px;padding:14px 16px;overflow-x:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.5}",
    "pre code{background:none;border:0;color:inherit;padding:0}",
    "table{border-collapse:collapse;width:100%;margin:14px 0;font-size:13.5px}",
    "th,td{border:1px solid #d8d2c4;padding:7px 11px;text-align:left;vertical-align:top}th{background:#ece7db}",
    "a{color:#b8742e}blockquote{margin:12px 0;padding:8px 14px;border-left:3px solid #d8d2c4;background:#ece7db;color:#4a4f57}",
    "hr{border:0;border-top:1px solid #d8d2c4;margin:22px 0}",
    "@media print{body{background:#fff}.sheet{max-width:none;padding:0}.bar button{display:none}.bar{border-color:#333}pre{border:1px solid #ccc}}",
  ].join("");
  return "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
    + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    + `<title>Aegis · Informe ${esc(runId)}</title><style>${css}</style></head>`
    + "<body><div class=\"sheet\"><div class=\"bar\">"
    + `<span class="who">Aegis</span><span class="rid">${esc(runId)}</span>`
    + "<button onclick=\"window.print()\">Imprimir / Guardar PDF</button>"
    + `</div><main>${body}</main></div></body></html>`;
}

async function _fetchReportMd(runId) {
  try {
    const rep = await api.get(`/api/runs/${runId}/report`);
    return (rep && rep.markdown) || "";
  } catch { return null; }
}
function _downloadBlob(text, mime, filename) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: filename });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
async function downloadReport(runId) {
  const md = await _fetchReportMd(runId);
  if (md === null) { toast("No se pudo cargar el informe", "err"); return; }
  if (!md.trim()) { toast("Sin informe todavía", "err"); return; }
  _downloadBlob(reportHtmlDoc(runId, md), "text/html;charset=utf-8", `aegis-${runId}-informe.html`);
  toast("Informe HTML exportado", "ok");
}
async function downloadReportMd(runId) {
  const md = await _fetchReportMd(runId);
  if (md === null) { toast("No se pudo cargar el informe", "err"); return; }
  if (!md.trim()) { toast("Sin informe todavía", "err"); return; }
  _downloadBlob(md, "text/markdown;charset=utf-8", `aegis-${runId}-informe.md`);
  toast("Markdown exportado", "ok");
}
async function downloadPdf(runId) {
  toast("Generando PDF…");
  try {
    const r = await fetch(`/api/runs/${runId}/report.pdf`, { headers: authHeaders() });
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast(j.error || "No se pudo generar el PDF", "err"); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: `aegis-${runId}-informe.pdf` });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast("PDF descargado", "ok");
  } catch { toast("No se pudo generar el PDF", "err"); }
}
function exportMenu(runId) {
  return rowMenu([
    { label: "PDF", onClick: () => downloadPdf(runId) },
    { label: "Markdown (.md)", onClick: () => downloadReportMd(runId) },
    { label: "HTML", onClick: () => downloadReport(runId) },
  ], { label: "Exportar", icon: ICON.download, title: "Exportar informe" });
}
function attachExport(reportEl, runId) {
  const actions = el("div", { class: "report-actions" }, exportMenu(runId));
  const h = reportEl.querySelector("h1, h2, h3");
  if (h) { h.classList.add("with-actions"); h.appendChild(actions); }
  else { reportEl.prepend(actions); }
}

async function openReport(runId) {
  const rep = await api.get(`/api/runs/${runId}/report`).catch(() => ({ markdown: "" }));
  const body = el("div", { class: "report" });
  if (rep.markdown) { body.innerHTML = miniMarkdown(rep.markdown); attachExport(body, runId); }
  else body.appendChild(el("div", { class: "empty" }, "Sin informe todavía."));
  openModal(`Informe · ${runId}`, body);
}

async function renderCuentas(view, gen) {
  if (!catalogFresh()) { view.innerHTML = ""; view.appendChild(loadingBox()); }
  const cat = await loadCatalog();
  if ((gen && state.renderGen !== gen) || (gen && state.view !== "cuentas")) return;
  view.innerHTML = "";
  const cx = (cat.harnesses && cat.harnesses.codex) || {};
  const clh = (cat.harnesses && cat.harnesses.claude) || {};
  view.appendChild(el("div", { class: "page-head" }, el("div", {}, el("h1", {}, "Modelos"),
    el("p", { class: "sub" }, "Suscripciones, API keys y endpoints. Si un harness está ausente, instálalo en el host y refresca: Lanzar solo lista los que hay."))));
  view.appendChild(el("div", { class: "toolbar" },
    el("button", { class: "btn ghost small icon", html: ICON.refresh + "<span>Refrescar catálogo</span>", onclick: async () => { dropCatalog(); await api.get("/api/models?refresh=1"); await loadCatalog(true); renderCuentas($("#view")); toast("Catálogo actualizado", "ok"); } }),
    el("button", { class: "btn small icon", html: ICON.plus + "<span>Añadir cuenta</span>", onclick: () => openAddAccount(cat) }),
  ));

  const hs = el("div", { class: "acc-section" });
  hs.appendChild(el("div", { class: "section-title" }, el("h2", {}, "Harnesses")));
  const hgrid = el("div", { class: "providers" });
  const cxAvail = !!(cx.available || cx.binary);
  const ocAvail = !!(cat.opencode || (cat.harnesses && cat.harnesses.opencode && (cat.harnesses.opencode.available || cat.harnesses.opencode.binary)));
  hgrid.appendChild(el("div", { class: "prov" },
    el("div", { class: "p-head" }, el("span", { class: "p-name" }, "Codex CLI"), el("span", { class: "status-badge " + (cx.logged_in ? "subscription" : (cxAvail ? "logged_out" : "off")) }, cx.logged_in ? "suscripción ChatGPT" : (cxAvail ? "sin login" : "ausente"))),
    el("div", { class: "model-chips" }, ...(cx.models || []).slice(0, 10).map((m) => el("span", { class: "chip" }, m.id || m))),
    el("div", { class: "mono-small" }, cx.logged_in ? `modo ${cx.auth_mode || "chatgpt"}` : (cxAvail ? "Sign in with ChatGPT. El run montará la sesión sola." : "No encuentro Codex. Luego: curl -fsSL https://chatgpt.com/codex/install.sh | sh  · Refresca el catálogo.")),
    harnessAuthButtons("codex", cx),
  ));
  hgrid.appendChild(el("div", { class: "prov" },
    el("div", { class: "p-head" }, el("span", { class: "p-name" }, "Claude Code"), el("span", { class: "status-badge " + (clh.logged_in ? "subscription" : (clh.available ? "logged_out" : "off")) }, clh.logged_in ? "suscripción Claude.ai" : (clh.expired ? "caducado" : (clh.available ? "sin login" : "ausente")))),
    el("div", { class: "model-chips" }, ...(clh.models || []).map((m) => el("span", { class: "chip", title: m.id || "" }, m.label || m.id || m))),
    el("div", { class: "mono-small" }, clh.logged_in ? `modo ${clh.auth_mode || "subscription"}` : (clh.expired ? "El refresh de esta máquina ya no vale. Pulsa Login y termina el navegador; un access de 8 h caducado no es esto." : (clh.available ? "Binario listo. Login de suscripción Claude.ai." : "No encuentro ~/.local/bin/claude. Luego: curl -fsSL https://claude.ai/install.sh | bash  · Refresca el catálogo."))),
    harnessAuthButtons("claude", clh),
  ));
  hgrid.appendChild(el("div", { class: "prov" },
    el("div", { class: "p-head" }, el("span", { class: "p-name" }, "OpenCode"), el("span", { class: "status-badge " + (ocAvail ? "on" : "off") }, ocAvail ? "instalado" : "ausente")),
    el("div", { class: "mono-small" }, ocAvail ? "Enrutador de modelos. No se loguea aquí: el login va en cada proveedor de abajo (son cuentas de OpenCode)." : "No encuentro OpenCode. Luego: curl -fsSL https://opencode.ai/install | bash  · Refresca el catálogo."),
  ));
  hs.appendChild(hgrid);
  view.appendChild(hs);

  const ps = el("div", { class: "acc-section" });
  ps.appendChild(el("div", { class: "section-title" }, el("h2", {}, "Proveedores de modelos (OpenCode)")));
  ps.appendChild(el("p", { class: "sub" }, "Solo aparecen los que hayas activado al menos una vez. Para conectar otro: Añadir cuenta."));
  const grid = el("div", { class: "providers" });
  const shown = (cat.providers || []).filter((g) => {
    const a = g.access || "";
    return a === "subscription" || a === "api" || a === "gateway" || g.activated;
  });
  if (!shown.length) {
    grid.appendChild(el("div", { class: "empty" }, "Ningún proveedor activado todavía. Usa Añadir cuenta para el primero."));
  }
  for (const g of shown) {
    const access = g.access || "none";
    const label = { subscription: "suscripción", api: "API key", gateway: "gateway libre", logged_out: "sin login", none: "—" }[access] || access;
    const card = el("div", { class: "prov" },
      el("div", { class: "p-head" }, el("span", { class: "p-name" }, `${g.label} (OpenCode)`), el("span", { class: "status-badge " + access }, label)));
    const chips = el("div", { class: "model-chips" });
    for (const m of g.models.slice(0, 12)) chips.appendChild(el("span", { class: "chip" }, m));
    if (g.models.length > 12) chips.appendChild(el("span", { class: "chip" }, `+${g.models.length - 12}`));
    card.appendChild(chips);
    const actions = el("div", { class: "prov-actions" });
    if (g.requires_login) {
      const logged = access === "subscription" || access === "api";
      actions.appendChild(el("button", { class: "btn ghost small", onclick: () => openLogin(g.provider, g.login_method) }, logged ? "Re-login" : "Login"));
      if (logged) actions.appendChild(el("button", { class: "btn danger small", onclick: async () => { await api.post("/api/auth/logout", { provider: g.provider }); dropCatalog(); await api.get("/api/models?refresh=1"); await loadCatalog(true); renderCuentas($("#view")); refreshHeader({ refreshDoctor: true }); } }, "Logout"));
    } else {
      actions.appendChild(el("span", { class: "mono-small" }, "No requiere login."));
    }
    card.appendChild(actions);
    grid.appendChild(card);
  }
  ps.appendChild(grid);
  view.appendChild(ps);

  const ls = el("div", { class: "acc-section" });
  ls.appendChild(el("div", { class: "section-title" }, el("h2", {}, "Locales (OpenCode · Ollama / vLLM)")));
  const lgrid = el("div", { class: "providers" });
  for (const lp of cat.local || []) {
    const isOllama = lp.provider === "ollama";
    const input = el("input", { type: "text", value: lp.endpoint || "", placeholder: isOllama ? "127.0.0.1:11434" : "127.0.0.1:8000" });
    const chips = el("div", { class: "model-chips" }, ...(lp.models || []).map((m) => el("span", { class: "chip" }, m)));
    const empty = !(lp.models || []).length
      ? el("div", { class: "mono-small" }, isOllama
        ? "Escribe IP:puerto y guarda; se probará la conexión (Ollama en 11434)."
        : "Escribe la URL y guarda; se probará la conexión.")
      : null;
    const card = el("div", { class: "prov" },
      el("div", { class: "p-head" }, el("span", { class: "p-name" }, `${lp.label} (OpenCode)`), el("span", { class: "status-badge " + (lp.reachable ? "on" : "off") }, lp.reachable ? "alcanzable" : "sin conexión")),
      el("div", { class: "endpoint-row" }, input,
        el("button", { class: "btn small", onclick: async () => { try { await api.post("/api/local", { provider: lp.provider, endpoint: input.value.trim() }); toast("Endpoint guardado", "ok"); dropCatalog(); await api.get("/api/models?refresh=1"); await loadCatalog(true); renderCuentas($("#view")); } catch (e) { toast(e.message, "err"); } } }, "Guardar")),
      chips, empty,
    );
    lgrid.appendChild(card);
  }
  ls.appendChild(lgrid);
  view.appendChild(ls);
}

function openAddAccount(cat) {
  const popular = (cat.connect_popular && cat.connect_popular.length) ? cat.connect_popular : [
    { id: "opencode", label: "OpenCode Zen", hint: "gateway / modelos free" },
    { id: "opencode-go", label: "OpenCode Go", hint: "suscripción low-cost" },
    { id: "xai", label: "xAI / Grok", hint: "OAuth SuperGrok o API key" },
    { id: "openai", label: "OpenAI / ChatGPT", hint: "OAuth Plus/Pro o API key" },
    { id: "anthropic", label: "Anthropic / Claude", hint: "API key (OpenCode)" },
    { id: "google", label: "Google / Gemini", hint: "OAuth o API key" },
    { id: "groq", label: "Groq", hint: "API key" },
    { id: "openrouter", label: "OpenRouter", hint: "API key" },
  ];
  const rest = (cat.providers || []).filter((g) => !popular.some((p) => p.id === g.provider));
  const provSel = el("select");
  const ogPop = el("optgroup", { label: "Popular (como /connect)" });
  for (const p of popular) {
    ogPop.appendChild(el("option", { value: p.id }, p.hint ? `${p.label} — ${p.hint}` : p.label));
  }
  provSel.appendChild(ogPop);
  if (rest.length) {
    const og = el("optgroup", { label: "Ya vistos en el catálogo" });
    for (const g of rest) og.appendChild(el("option", { value: g.provider }, g.label || g.provider));
    provSel.appendChild(og);
  }
  const localProv = el("select", {}, el("option", { value: "ollama" }, "Ollama"), el("option", { value: "vllm" }, "vLLM"));
  const localUrl = el("input", { type: "text", placeholder: "127.0.0.1:11434" });
  const body = el("div", { class: "form" },
    el("div", { class: "field" }, el("label", {}, "1 · Login de proveedor (consola de OpenCode)"),
      el("span", { class: "hint" }, "Igual que /connect: la consola lista todos los proveedores. Unos piden OAuth (abrir URL), otros solo API key. No pegues la clave aquí; el flujo la pide si toca."),
      el("button", { class: "btn", onclick: () => { closeModal(); openLogin("", "web", { onBack: () => openAddAccount(cat) }); } }, "Abrir lista completa de OpenCode (/connect)"),
      el("div", { class: "endpoint-row", style: "margin-top:10px" }, provSel, el("button", { class: "btn ghost small", onclick: () => { const p = provSel.value; closeModal(); openLogin(p, "web", { onBack: () => openAddAccount(cat) }); } }, "Ir directo a este"))),
    el("hr", { style: "border:0;border-top:1px solid var(--line);width:100%" }),
    el("div", { class: "field" }, el("label", {}, "2 · Local (Ollama / vLLM)"),
      el("span", { class: "hint" }, "Ollama: IP:puerto. vLLM: URL /v1."),
      el("div", { class: "endpoint-row" }, localProv, localUrl, el("button", { class: "btn small", onclick: async () => { const p = localProv.value, u = localUrl.value.trim(); if (!u) return; try { await api.post("/api/local", { provider: p, endpoint: u }); toast("Endpoint guardado", "ok"); closeModal(); dropCatalog(); await api.get("/api/models?refresh=1"); await loadCatalog(true); renderCuentas($("#view")); } catch (e) { toast(e.message, "err"); } } }, "Guardar"))),
  );
  openModal("Añadir cuenta / modelo", body);
}

function harnessAuthButtons(id, st) {
  const actions = el("div", { class: "prov-actions" });
  if (!st || (!st.available && !st.binary && !st.logged_in)) return actions;
  actions.appendChild(el("button", { class: "btn " + (st.logged_in ? "ghost" : "") + " small", onclick: () => openLogin(id) }, st.logged_in ? "Re-login" : "Login"));
  if (st.logged_in) {
    actions.appendChild(el("button", { class: "btn danger small", onclick: () => harnessLogout(id) }, "Logout"));
  }
  return actions;
}

async function harnessLogout(provider) {
  try {
    await api.post("/api/auth/logout", { provider });
    toast("Sesión cerrada", "ok");
    dropCatalog();
    renderCuentas($("#view"));
    refreshHeader({ refreshDoctor: true });
  } catch (e) { toast(e.message, "err"); }
}

async function openLogin(provider, method, opts) {
  opts = opts || {};
  const hint = !provider
    ? "Lista de OpenCode (/connect). Busca o baja con las flechas, Enter para elegir. Unos son OAuth (URL), otros solo API key: el propio flujo lo pide."
    : provider === "claude"
    ? "1) Abre o copia la URL de OAuth. 2) Inicia sesión en Claude.ai. 3) Si te da un código, pégalo abajo y pulsa Enviar. El recuadro negro se puede seleccionar; no hace falta escribir en él."
    : provider === "codex"
      ? "Codex en un servidor no puede abrir el navegador del host (localhost:1455). Usa el enlace de dispositivo (auth.openai.com/codex/device), inicia sesión en ChatGPT en TU PC e introduce el código que salga en el recuadro. Si ChatGPT no tiene «device code» activado, en el host: codex login --device-auth"
      : provider === "xai"
    ? "OpenCode / xAI: SuperGrok. Copia la URL o el device-code, aprueba en el navegador, pega aquí lo que pida."
    : provider === "openai"
      ? "OpenCode / ChatGPT: Plus/Pro. Copia URL o código, aprueba fuera, pega aquí si lo pide."
      : provider === "opencode-go"
        ? "OpenCode Go: suscripción. Elige OAuth o pega la API key cuando el flujo lo pida."
      : "OpenCode: completa el flujo. Si pide API key, pégala abajo.";
  const screen = ansiScreen(28, 108);
  const term = el("div", { class: "term", tabindex: "0" }, "iniciando login…\n");
  const urlBar = el("div", { class: "login-urls hidden" });
  const input = el("input", { type: "text", autocomplete: "off", spellcheck: "false", placeholder: "pega aquí el código (Ctrl+V / Cmd+V) y pulsa Enviar" });
  let sid = null;
  const sendKeys = async (data) => { if (!sid) return; await api.post(`/api/auth/login/${sid}/input`, { data }); };
  // TUI raw: Enter = CR, no LF.
  const ENTER = "\r";
  const sendPaste = async () => { if (!sid) return; const v = input.value; input.value = ""; await sendKeys(v + ENTER); };
  const ttySeq = (e) => {
    if (e.key === "ArrowDown") return "\x1b[B";
    if (e.key === "ArrowUp") return "\x1b[A";
    if (e.key === "ArrowRight") return "\x1b[C";
    if (e.key === "ArrowLeft") return "\x1b[D";
    if (e.key === "Enter") return ENTER;
    if (e.key === "Escape") return "\x1b";
    if (e.key === "Backspace") return "\x7f";
    if (e.key === "Tab") return "\t";
    if (e.key === "Home") return "\x1b[H";
    if (e.key === "End") return "\x1b[F";
    if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) return e.key;
    return null;
  };
  const onModalKey = (e) => {
    if (!sid) return;
    const inPaste = document.activeElement === input;
    if (inPaste) {
      if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); sendPaste(); }
      return;
    }
    const seq = ttySeq(e);
    if (seq == null) return;
    e.preventDefault();
    e.stopPropagation();
    sendKeys(seq);
  };
  document.addEventListener("keydown", onModalKey, true);
  const paintUrlList = (urls) => {
    const list = [...new Set((urls || []).filter((u) => /^https?:\/\//.test(u) && u.length > 20))];
    urlBar.innerHTML = "";
    urlBar.classList.toggle("hidden", !list.length);
    for (const u of list) {
      urlBar.appendChild(el("div", { class: "login-url" },
        el("a", { href: u, target: "_blank", rel: "noopener", title: u }, u),
        el("button", { class: "btn ghost small", onclick: async () => { try { await navigator.clipboard.writeText(u); toast("URL copiada", "ok"); } catch { toast("Selecciona la URL en el recuadro y Ctrl+C", "err"); } } }, "Copiar"),
        el("a", { class: "btn small", href: u, target: "_blank", rel: "noopener" }, "Abrir"),
      ));
    }
  };
  const unwrapLoginUrls = (text) => {
    let cur = String(text || "").replace(/\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\))/g, "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    let prev = "";
    while (cur !== prev) {
      prev = cur;
      cur = cur.replace(/(https?:\/\/[^\s"'<>]+)\n[ \t]*([^\s"'<>]+)/g, (all, a, b) => (/^[&/?#%=+\w.\-~]/.test(b) ? a + b : all));
    }
    const found = [...cur.matchAll(/https?:\/\/[^\s"'<>]+/g)].map((m) => m[0].replace(/[)\].,;]+$/, ""));
    return found.filter((u, i) => u.length > 20 && !found.some((o, j) => j !== i && o.startsWith(u)));
  };
  let rawLogin = "";
  let serverUrls = [];
  const paintUrls = () => {
    paintUrlList(serverUrls.length ? serverUrls : unwrapLoginUrls(rawLogin));
  };
  const paint = (chunk) => {
    rawLogin += chunk;
    screen.apply(chunk);
    const text = screen.render();
    term.textContent = text || "…";
    term.scrollTop = term.scrollHeight;
    paintUrls();
  };
  const arrows = el("div", { style: "display:flex;gap:6px;margin-top:8px" },
    el("button", { class: "btn ghost small", type: "button", onclick: () => sendKeys("\x1b[B") }, "↓"),
    el("button", { class: "btn ghost small", type: "button", onclick: () => sendKeys("\x1b[A") }, "↑"),
    el("button", { class: "btn ghost small", type: "button", onclick: () => sendKeys(ENTER) }, "Enter"),
  );
  let es = null;
  let torn = false;
  const stopKeys = () => document.removeEventListener("keydown", onModalKey, true);
  const teardown = () => { if (torn) return; torn = true; stopKeys(); if (es) { try { es.close(); } catch {} es = null; } if (sid) api.del(`/api/auth/login/${sid}`); };
  const backRow = opts.onBack
    ? el("div", { class: "login-nav" }, el("button", { class: "btn ghost small", type: "button", onclick: () => { teardown(); opts.onBack(); } }, "\u2039 Volver a proveedores"))
    : null;
  const body = el("div", {}, backRow, el("p", { class: "mono-small", style: "margin-top:0" }, hint), term, urlBar, arrows,
    el("div", { class: "term-input" }, input, el("button", { class: "btn small", type: "button", onclick: () => sendPaste() }, "Enviar")));
  openModal(provider ? `Login · ${provider}` : "Login · OpenCode /connect", body, teardown);
  try { const r = await api.post("/api/auth/login", { provider: provider || "", method: method || "" }); sid = r.sid; }
  catch (e) { term.textContent = "Error: " + e.message; stopKeys(); return; }
  term.focus();
  es = evtSource(`/api/auth/login/${sid}/stream`);
  es.addEventListener("out", (e) => {
    let chunk = e.data;
    try { const j = JSON.parse(e.data); if (typeof j === "string") chunk = j; else if (j && typeof j.t === "string") chunk = j.t; } catch { /* texto plano */ }
    paint(chunk);
  });
  es.addEventListener("urls", (e) => {
    try { serverUrls = JSON.parse(e.data) || []; } catch { serverUrls = []; }
    paintUrls();
  });
  es.addEventListener("end", () => { term.textContent = (term.textContent || "") + "\n[login terminó]"; es.close(); stopKeys(); dropCatalog(); refreshHeader({ refreshDoctor: true }); if (state.view === "cuentas") renderCuentas($("#view")); });
}

function showReportWait(msg) {
  const root = $("#modal-root");
  root.innerHTML = "";
  root.appendChild(el("div", { class: "modal-bg wait-bg" },
    el("div", { class: "modal confirm wait-card" },
      el("div", { class: "modal-head" }, el("h2", {}, "Generando informe")),
      el("div", { class: "modal-body" },
        el("p", { class: "confirm-msg" }, msg || "Cerrando el run y redactando el informe. No cierres esta pestaña."),
        el("div", { class: "wait-bar" }, el("div", { class: "wait-bar-fill" }))))));
}

function hideReportWait() {
  const root = $("#modal-root");
  if (root) root.innerHTML = "";
}

async function abortRunWithReport(runId, opts) {
  const force = !!(opts && opts.force);
  showReportWait(force
    ? "Cortando: se tira el contenedor y se arma el informe con lo que hay en disco."
    : "Cierre: el agente revisa, corrige e informa. Para al terminar.");
  try {
    const out = await api.post(`/api/runs/${runId}/abort`, {}, { signal: AbortSignal.timeout(force ? 12000 : 180000) });
    hideReportWait();
    if (out && out.closing) {
      toast("Cierre: un pase de revisión e informe. Cancelar otra vez corta ya.", "ok");
      await refreshHeader();
      openRun(runId);
      return;
    }
    toast(force ? "Cortado. Informe en historial." : "Informe listo. Run en historial.", "ok");
    state.viewRun = null;
    await refreshHeader();
    setView("historial");
  } catch (e) {
    hideReportWait();
    const msg = String(e && (e.message || e.name) || "");
    if (force && (e.name === "TimeoutError" || e.name === "AbortError" || /abort|timeout|timed out/i.test(msg))) {
      toast("Cortado. El contenedor se tira en segundo plano.", "ok");
      state.viewRun = null;
      await refreshHeader();
      setView("historial");
      return;
    }
    toast(e.message || "No se pudo cancelar", "err");
  }
}

function openModal(title, bodyNode, onClose) {
  const root = $("#modal-root");
  const prev = document.activeElement;
  const close = () => {
    if (root._close !== close) return;
    root._close = null;
    window.removeEventListener("keydown", onKey);
    root.innerHTML = "";
    if (onClose) onClose();
    if (prev && typeof prev.focus === "function") { try { prev.focus(); } catch {} }
  };
  const onKey = (e) => { if (e.key === "Escape") { e.preventDefault(); close(); } };
  const dlg = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title, tabindex: "-1" },
    el("div", { class: "modal-head" }, el("h2", {}, title), el("button", { class: "btn ghost small", onclick: close }, "Cerrar")),
    el("div", { class: "modal-body" }, bodyNode));
  const bg = el("div", { class: "modal-bg", onclick: (e) => { if (e.target === bg) close(); } }, dlg);
  root.innerHTML = "";
  root.appendChild(bg);
  root._close = close;
  window.addEventListener("keydown", onKey);
  const closer = dlg.querySelector(".modal-head button");
  setTimeout(() => { try { (closer || dlg).focus(); } catch {} }, 0);
  return { close };
}
function closeModal() {
  const root = $("#modal-root");
  if (typeof root._close === "function") root._close();
  else root.innerHTML = "";
}

function openConfirm(opts) {
  const o = opts || {};
  const title = o.title || "Confirmar";
  const okLabel = o.okLabel || "Aceptar";
  const cancelLabel = o.cancelLabel || "Cancelar";
  const danger = !!o.danger;
  return new Promise((resolve) => {
    const root = $("#modal-root");
    let done = false;
    const onKey = (e) => {
      if (e.key === "Escape") finish(false);
      else if (e.key === "Enter") {
        e.preventDefault();
        if (!danger) finish(true);
      }
    };
    function finish(val) {
      if (done) return;
      done = true;
      window.removeEventListener("keydown", onKey);
      root.innerHTML = "";
      resolve(val);
    }
    const okBtn = el("button", { type: "button", class: "btn small icon" + (danger ? " danger" : ""), html: (danger ? ICON.trash : "") + `<span>${okLabel}</span>` });
    okBtn.addEventListener("click", () => finish(true));
    const cancelBtn = el("button", { type: "button", class: "btn ghost small", onclick: () => finish(false) }, cancelLabel);
    const bg = el("div", { class: "modal-bg", onclick: (e) => { if (e.target === bg) finish(false); } },
      el("div", { class: "modal confirm" },
        el("div", { class: "modal-head" }, el("h2", {}, title), el("button", { class: "btn ghost small", onclick: () => finish(false) }, "Cerrar")),
        el("div", { class: "modal-body" },
          el("div", { class: "confirm-msg" }, o.message || ""),
          el("div", { class: "confirm-actions" }, cancelBtn, okBtn))));
    root.innerHTML = ""; root.appendChild(bg);
    window.addEventListener("keydown", onKey);
    setTimeout(() => (danger ? cancelBtn : okBtn).focus(), 0);
  });
}

function openPrompt(opts) {
  const o = opts || {};
  const title = o.title || "Nombre";
  const okLabel = o.okLabel || "Guardar";
  const cancelLabel = o.cancelLabel || "Cancelar";
  return new Promise((resolve) => {
    const root = $("#modal-root");
    let done = false;
    const inp = el("input", { type: o.password ? "password" : "text", class: "prompt-in", maxlength: String(o.maxlength || 80), value: o.value || "", placeholder: o.placeholder || "" });
    inp.value = o.value || "";
    const onKey = (e) => {
      if (e.key === "Escape") finish(null);
      else if (e.key === "Enter") { e.preventDefault(); finish(inp.value); }
    };
    function finish(val) {
      if (done) return;
      done = true;
      window.removeEventListener("keydown", onKey);
      root.innerHTML = "";
      resolve(val);
    }
    const okBtn = el("button", { class: "btn small" }, okLabel);
    okBtn.addEventListener("click", () => finish(inp.value));
    const cancelBtn = el("button", { class: "btn ghost small", onclick: () => finish(null) }, cancelLabel);
    const bg = el("div", { class: "modal-bg", onclick: (e) => { if (e.target === bg) finish(null); } },
      el("div", { class: "modal confirm" },
        el("div", { class: "modal-head" }, el("h2", {}, title), el("button", { class: "btn ghost small", onclick: () => finish(null) }, "Cerrar")),
        el("div", { class: "modal-body" },
          o.message ? el("div", { class: "confirm-msg" }, o.message) : "",
          inp,
          el("div", { class: "confirm-actions" }, cancelBtn, okBtn))));
    root.innerHTML = ""; root.appendChild(bg);
    window.addEventListener("keydown", onKey);
    setTimeout(() => { inp.focus(); inp.select(); }, 0);
  });
}

async function renameRun(runId, current) {
  const next = await openPrompt({
    title: "Renombrar run",
    message: "Nombre visible en el historial. Déjalo vacío para volver al id.",
    value: current || "",
    placeholder: "Lab-01 · Auditoría · Red-norte",
    okLabel: "Guardar",
  });
  if (next == null) return null;
  try {
    const r = await api.patch(`/api/runs/${runId}`, { title: next });
    toast("Run renombrado", "ok");
    return r.title || "";
  } catch (e) {
    toast(e.message, "err");
    return null;
  }
}

function miniMarkdown(md) {
  const lines = String(md).split("\n");
  let html = "", inCode = false, listTag = "";
  // href: http(s)/mailto/relativo/ancla. Sin comillas (esc() no las escapa). Bloquea javascript:/data:.
  const safeUrl = (u) => {
    const t = String(u).trim();
    if (!(/^(https?:|mailto:)/i.test(t) || /^[/#.]/.test(t))) return "";
    return t.replace(/["'\s]/g, "");
  };
  const inline = (s) => esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<i>$2</i>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (m, text, url) => {
      const href = safeUrl(url);
      return href ? `<a href="${href}" target="_blank" rel="noopener">${text}</a>` : text;
    });
  const closeList = () => { if (listTag) { html += `</${listTag}>`; listTag = ""; } };
  const openList = (tag, cls) => {
    if (listTag && listTag !== tag) closeList();
    if (!listTag) { html += cls ? `<${tag} class="${cls}">` : `<${tag}>`; listTag = tag; }
  };
  const isSep = (s) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(s) && s.includes("-");
  const cells = (s) => s.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.startsWith("```")) { if (inCode) { html += "</code></pre>"; inCode = false; } else { closeList(); html += "<pre><code>"; inCode = true; } continue; }
    if (inCode) { html += esc(raw) + "\n"; continue; }
    // blanco no cierra lista (ítems separados por líneas vacías)
    if (raw.trim() === "") continue;
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(raw)) { closeList(); html += "<hr>"; continue; }
    if (raw.includes("|") && i + 1 < lines.length && isSep(lines[i + 1])) {
      closeList();
      const head = cells(raw);
      let t = '<table class="md-table"><thead><tr>' + head.map((h) => `<th>${inline(h)}</th>`).join("") + "</tr></thead><tbody>";
      i += 2;
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") {
        t += "<tr>" + cells(lines[i]).map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>";
        i++;
      }
      i--;
      html += t + "</tbody></table>";
      continue;
    }
    const h = raw.match(/^(#{1,6})\s+(.*)$/);
    if (h) { closeList(); html += `<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`; continue; }
    const bq = raw.match(/^\s*>\s?(.*)$/);
    if (bq) { closeList(); html += `<blockquote>${inline(bq[1])}</blockquote>`; continue; }
    const task = raw.match(/^\s*[-*]\s+\[([ xX])\]\s+(.*)$/);
    if (task) {
      openList("ul", "md-tasks");
      const done = task[1].toLowerCase() === "x";
      html += `<li class="${done ? "done" : ""}"><span class="chk">${done ? "\u2611" : "\u2610"}</span> ${inline(task[2])}</li>`;
      continue;
    }
    const ol = raw.match(/^\s*\d+[.)]\s+(.*)$/);
    if (ol) { openList("ol", ""); html += `<li>${inline(ol[1])}</li>`; continue; }
    if (/^\s*[-*]\s+/.test(raw)) { openList("ul", ""); html += `<li>${inline(raw.replace(/^\s*[-*]\s+/, ""))}</li>`; continue; }
    closeList();
    html += `<p>${inline(raw)}</p>`;
  }
  if (inCode) html += "</code></pre>";
  closeList();
  return html;
}

async function boot() {
  await refreshHeader({ skipSync: true });
  applyRoute();
  setInterval(refreshHeader, 5000);
}
boot();
