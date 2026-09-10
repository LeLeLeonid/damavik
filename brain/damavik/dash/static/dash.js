/*
 * SPDX-FileCopyrightText: 2026 Leonidas Zervas and Damavik contributors
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * damavik dashboard - hand-rolled, zero dependencies, zero CDN.
 * Polls a localhost JSON API.  Canvas for the graph and timeline, DOM for the
 * trees and tables (they need text selection and accessibility).
 */
"use strict";

const state = {
  token: new URLSearchParams(location.search).get("token") || "",
  view: "tree",
  graph: { nodes: [], edges: [], byId: new Map(), drag: null, zoom: 1, ox: 0, oy: 0 },
  selected: null,
};

/* ------------------------------------------------------------------ api */
async function api(path, params = {}) {
  const qs = new URLSearchParams({ token: state.token, ...params });
  const res = await fetch(`${path}?${qs}`, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
  return res.json();
}

/* --------------------------------------------------------------- colour */
function scoreColor(score) {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  if (s >= 70) return "#d9534f";
  if (s >= 45) return "#e2703a";
  if (s >= 25) return "#d9a441";
  return "#4caf7d";
}

function bar(score) {
  const pct = Math.max(0, Math.min(100, Number(score) || 0));
  return `<span class="bar"><i style="width:${pct}%;background:${scoreColor(pct)}"></i></span>`;
}

function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function base(path) {
  return String(path || "?").replace(/\\/g, "/").split("/").pop() || "?";
}

/* -------------------------------------------------------------- summary */
async function refreshSummary() {
  try {
    const s = await api("/api/summary");
    document.getElementById("summary").textContent =
      `${s.events ?? 0} events · ${s.alerts ?? 0} alerts (${s.open_alerts ?? 0} open) · ` +
      `${s.packages ?? 0} pkgs · top ${Number(s.top_score ?? 0).toFixed(1)}`;
    document.getElementById("offline-flag").textContent =
      s.offline ? "offline mode — no intel providers" : "";
  } catch (err) {
    document.getElementById("summary").textContent = `api error: ${err.message}`;
  }
}

/* ----------------------------------------------------------------- tree */
function renderNode(node, depth, isLast, prefix, out) {
  const connector = isLast ? "└─ " : "├─ ";
  const score = Number(node.score || 0);
  out.push(
    `<div class="node" data-pid="${node.pid}" style="padding-left:${depth * 14 + 4}px">` +
    `<span style="color:#5b6472">${esc(prefix + connector)}</span>` +
    `<span class="dot" style="background:${scoreColor(score)}"></span>` +
    `<span class="pid">${node.pid}</span> ` +
    `<span class="name">${esc(base(node.exe))}</span> ` +
    `<span class="user">${esc(node.user || "-")}</span> ` +
    `${bar(score)} <span style="color:${scoreColor(score)}">${score.toFixed(1)}</span>` +
    `</div>`
  );
  const children = (node.children || []).slice().sort((a, b) => a.pid - b.pid);
  const childPrefix = prefix + (isLast ? "   " : "│  ");
  children.forEach((child, index) => {
    renderNode(child, depth + 1, index === children.length - 1, childPrefix, out);
  });
}

async function refreshTree() {
  const data = await api("/api/tree");
  const out = [];
  const roots = (data.roots || []).slice().sort((a, b) => a.pid - b.pid);
  roots.forEach((root, index) => {
    renderNode(root, 0, index === roots.length - 1, "", out);
  });
  const container = document.getElementById("tree");
  container.innerHTML = out.join("") || '<p class="hint">no processes recorded yet</p>';
  container.querySelectorAll(".node").forEach((el) => {
    el.addEventListener("click", () => showProcess(Number(el.dataset.pid), el));
  });
}

async function showProcess(pid, element) {
  document.querySelectorAll(".node.selected").forEach((el) => el.classList.remove("selected"));
  if (element) element.classList.add("selected");
  const pane = document.getElementById("tree-detail");
  pane.innerHTML = "<h2>detail</h2><p class='hint'>loading…</p>";
  try {
    const [flows, events] = await Promise.all([
      api("/api/flows", { pid, limit: 40 }),
      api("/api/events", { pid, limit: 40 }),
    ]);
    const rows = (flows.edges || []).filter((e) => e.from.startsWith("pid:"));
    const exec = (events.events || []).find((e) => e.type === "proc.exec");
    const proc = (exec && exec.proc) || {};
    const dns = (events.events || []).filter((e) => e.type === "dns.query");
    pane.innerHTML = `<h2>pid ${pid}</h2>
      <table>
        <tr><th>exe</th><td><code>${esc(proc.exe || "?")}</code></td></tr>
        <tr><th>cmd</th><td><code>${esc(proc.cmd || "-")}</code></td></tr>
        <tr><th>user</th><td>${esc(proc.user || "-")}</td></tr>
        <tr><th>parent</th><td>pid ${esc(proc.ppid ?? "-")} <code>${esc(base(proc.parent_exe))}</code></td></tr>
        <tr><th>sha256</th><td><code>${esc((proc.sha256 || "-").slice(0, 32))}…</code></td></tr>
        <tr><th>tags</th><td>${(exec && exec.tags || []).map((t) => `<span class="badge">${esc(t)}</span>`).join("")}</td></tr>
        <tr><th>why</th><td>${esc((exec && exec.reasons || []).join("; ") || "-")}</td></tr>
      </table>
      <h2 style="margin-top:14px">connections <small>dns → ip → flow</small></h2>
      ${dns.length ? `<ul>${dns.slice(0, 12).map((e) => `<li><code>${esc(e.dns.q)}</code> (${esc(e.dns.rtype || "A")})</li>`).join("")}</ul>` : '<p class="hint">no dns recorded</p>'}
      ${rows.length ? `<table><tr><th>dest</th><th>port</th><th>conns</th><th>bytes</th><th>score</th></tr>
        ${rows.map((e) => `<tr><td><code>${esc(e.to)}</code></td><td>${esc(e.dport ?? "-")}</td>
          <td>${e.conns}</td><td>${e.bytes}</td><td style="color:${scoreColor(e.score)}">${Number(e.score).toFixed(0)}</td></tr>`).join("")}</table>`
        : '<p class="hint">no flows recorded</p>'}`;
  } catch (err) {
    pane.innerHTML = `<h2>pid ${pid}</h2><p class="hint">${esc(err.message)}</p>`;
  }
}

/* ---------------------------------------------------------- flow graph */
function layoutGraph(data) {
  const width = 900, height = 560;
  const nodes = (data.nodes || []).map((node, index) => {
    const existing = state.graph.byId.get(node.id);
    const angle = (index / Math.max(1, data.nodes.length)) * Math.PI * 2;
    const radius = node.kind === "host" ? 0 : (node.kind === "process" ? 130 : 240);
    return {
      ...node,
      x: existing ? existing.x : width / 2 + Math.cos(angle) * radius,
      y: existing ? existing.y : height / 2 + Math.sin(angle) * radius,
      vx: 0, vy: 0,
      r: node.kind === "host" ? 14 : (node.kind === "process" ? 9 : 7),
    };
  });
  state.graph.nodes = nodes;
  state.graph.edges = data.edges || [];
  state.graph.byId = new Map(nodes.map((n) => [n.id, n]));
}

function stepGraph() {
  const { nodes, edges, byId } = state.graph;
  const width = 900, height = 560;
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.max(20, Math.hypot(dx, dy));
      const force = 2200 / (dist * dist);
      dx /= dist; dy /= dist;
      a.vx -= dx * force; a.vy -= dy * force;
      b.vx += dx * force; b.vy += dy * force;
    }
  }
  for (const edge of edges) {
    const a = byId.get(edge.from), b = byId.get(edge.to);
    if (!a || !b) continue;
    const dx = b.x - a.x, dy = b.y - a.y;
    const dist = Math.max(20, Math.hypot(dx, dy));
    const target = edge.from.includes("pid:") && !edge.to.includes("pid:") ? 190 : 110;
    const force = (dist - target) * 0.004;
    const ux = dx / dist, uy = dy / dist;
    a.vx += ux * force; a.vy += uy * force;
    b.vx -= ux * force; b.vy -= uy * force;
  }
  for (const node of nodes) {
    if (node.kind === "host") { node.x = width / 2; node.y = height / 2; node.vx = 0; node.vy = 0; continue; }
    node.vx *= 0.82; node.vy *= 0.82;
    node.x = Math.max(14, Math.min(width - 14, node.x + node.vx));
    node.y = Math.max(14, Math.min(height - 14, node.y + node.vy));
  }
}

function drawGraph() {
  const canvas = document.getElementById("graph");
  if (!canvas || state.view !== "graph") return;
  const ctx = canvas.getContext("2d");
  const { nodes, edges, byId, zoom, ox, oy } = state.graph;
  const minScore = Number(document.getElementById("graph-min").value || 0);
  const portFilter = document.getElementById("graph-port").value.trim();
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(ox, oy);
  ctx.scale(zoom, zoom);
  for (const edge of edges) {
    if (edge.score < minScore) continue;
    if (portFilter && String(edge.dport ?? "") !== portFilter) continue;
    const a = byId.get(edge.from), b = byId.get(edge.to);
    if (!a || !b) continue;
    ctx.strokeStyle = scoreColor(edge.score);
    ctx.globalAlpha = 0.55;
    ctx.lineWidth = Math.min(6, 1 + Math.log10(1 + (edge.bytes || 0)) / 1.6);
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    ctx.globalAlpha = 1;
  }
  for (const node of nodes) {
    ctx.fillStyle = node.kind === "host" ? "#5aa9e6"
      : (node.kind === "process" ? "#8892a3" : scoreColor(node.score));
    ctx.beginPath(); ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#a9b4c4";
    ctx.font = "10px ui-monospace, monospace";
    ctx.fillText(String(node.label || node.id).slice(0, 24), node.x + node.r + 4, node.y + 3);
  }
  ctx.restore();
}

function graphLoop() {
  if (state.view === "graph") { stepGraph(); drawGraph(); }
  requestAnimationFrame(graphLoop);
}

async function refreshGraph() {
  const data = await api("/api/flows", { limit: 300 });
  layoutGraph(data);
}

function wireGraph() {
  const canvas = document.getElementById("graph");
  const toLocal = (event) => {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width, scaleY = canvas.height / rect.height;
    return {
      x: ((event.clientX - rect.left) * scaleX - state.graph.ox) / state.graph.zoom,
      y: ((event.clientY - rect.top) * scaleY - state.graph.oy) / state.graph.zoom,
    };
  };
  canvas.addEventListener("mousedown", (event) => {
    const point = toLocal(event);
    const hit = state.graph.nodes.find((n) => Math.hypot(n.x - point.x, n.y - point.y) < n.r + 5);
    state.graph.drag = hit || null;
  });
  canvas.addEventListener("mousemove", (event) => {
    if (!state.graph.drag) return;
    const point = toLocal(event);
    state.graph.drag.x = point.x;
    state.graph.drag.y = point.y;
  });
  window.addEventListener("mouseup", () => { state.graph.drag = null; });
  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    state.graph.zoom = Math.max(0.4, Math.min(3, state.graph.zoom * (event.deltaY < 0 ? 1.1 : 0.9)));
  }, { passive: false });
  document.getElementById("graph-min").addEventListener("input", drawGraph);
  document.getElementById("graph-port").addEventListener("input", drawGraph);
}

/* ------------------------------------------------------------- timeline */
const LANES = [
  { key: "proc.exec", label: "exec", color: "#5aa9e6" },
  { key: "net.flow", label: "flow", color: "#8892a3" },
  { key: "dns.query", label: "dns", color: "#6fc3a0" },
  { key: "pkg.event", label: "pkg", color: "#b48ad6" },
];

function drawTimeline(buckets) {
  const canvas = document.getElementById("timeline");
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!buckets.length) {
    ctx.fillStyle = "#8b95a5";
    ctx.fillText("no events in this window", 20, 30);
    return;
  }
  const left = 60, top = 20, laneH = 44, width = canvas.width - left - 20;
  const step = width / buckets.length;
  const maxCount = Math.max(1, ...buckets.flatMap((b) => LANES.map((l) => b[l.key] || 0)));
  LANES.forEach((lane, index) => {
    const y = top + index * laneH;
    ctx.fillStyle = "#8b95a5";
    ctx.font = "11px ui-monospace, monospace";
    ctx.fillText(lane.label, 8, y + laneH / 2);
    buckets.forEach((bucket, i) => {
      const count = bucket[lane.key] || 0;
      if (!count) return;
      const h = Math.max(2, (count / maxCount) * (laneH - 8));
      ctx.fillStyle = lane.color;
      ctx.globalAlpha = 0.75;
      ctx.fillRect(left + i * step, y + (laneH - 8 - h), Math.max(1, step - 1), h);
      ctx.globalAlpha = 1;
    });
  });
  const alertY = top + LANES.length * laneH;
  ctx.fillStyle = "#8b95a5";
  ctx.fillText("alerts", 8, alertY + 14);
  buckets.forEach((bucket, i) => {
    const score = bucket.max_score || 0;
    if (score < 45) return;
    ctx.fillStyle = scoreColor(score);
    ctx.fillRect(left + i * step, alertY + 4, Math.max(2, step - 1), 14);
  });
  document.getElementById("timeline-legend").innerHTML = LANES
    .map((l) => `<span><span class="dot" style="background:${l.color}"></span>${l.label}</span>`).join("") +
    `<span><span class="dot" style="background:#d9534f"></span>high-score bucket</span>`;
}

async function refreshTimeline() {
  const data = await api("/api/timeline", { hours: 24 });
  drawTimeline(data.buckets || []);
}

/* ------------------------------------------------------------- packages */
async function refreshPackages() {
  const data = await api("/api/packages");
  const vulnerable = new Map((data.vulnerable || []).map((v) => [`${v.manager}:${v.name}`, v]));
  const rows = (data.packages || []).map((pkg) => {
    const hit = vulnerable.get(`${pkg.manager}:${pkg.name}`);
    const isNew = pkg.first_ts === pkg.last_ts;
    return `<tr>
      <td>${esc(pkg.manager)}</td>
      <td><code>${esc(pkg.name)}</code></td>
      <td>${esc(pkg.version)}</td>
      <td>${isNew ? '<span class="badge new">new</span>' : ""}${pkg.removed ? '<span class="badge">removed</span>' : ""}</td>
      <td>${hit ? hit.cves.slice(0, 3).map((c) => `<span class="badge cve">${esc(c)}</span>`).join("") : ""}</td>
      <td>${esc(pkg.first_ts || "")}</td>
    </tr>`;
  });
  document.getElementById("pkg-count").textContent =
    `${rows.length} tracked · ${(data.vulnerable || []).length} vulnerable`;
  document.getElementById("packages").innerHTML = rows.length
    ? `<table><tr><th>manager</th><th>name</th><th>version</th><th>state</th><th>cves</th><th>first seen</th></tr>${rows.join("")}</table>`
    : '<p class="hint">no package inventory yet — run <code>damavik pkg-list --scan</code></p>';
}

/* --------------------------------------------------------------- alerts */
async function refreshAlerts() {
  const data = await api("/api/alerts", { limit: 60 });
  const alerts = data.alerts || [];
  document.getElementById("alerts").innerHTML = alerts.length ? alerts.map((alert) => {
    const sub = alert.subgraph || {};
    const events = (sub.events || []).map((e) =>
      `<li><code>${esc(e.type)}</code> ${esc(base((e.proc && e.proc.exe) || (e.net && e.net.dst) || (e.dns && e.dns.q) || "-"))}</li>`).join("");
    const flows = (sub.flows || []).map((f) =>
      `<li><code>${esc(f.dst)}</code>:${esc(f.dport)} ×${f.conns}</li>`).join("");
    return `<div class="alert level-${esc(alert.level)}" data-id="${esc(alert.id)}">
      <h3>${esc(alert.title)}</h3>
      <div class="meta">${esc(alert.level.toUpperCase())} · ${Number(alert.score).toFixed(1)} ·
        ${esc(alert.ts)} · ${esc(alert.rule || "score-based")} · ${esc(alert.id)}</div>
      <div class="why">${esc(alert.explain)}</div>
      <div class="sub">
        <strong>iocs</strong> <code>${esc(JSON.stringify(alert.iocs || {}))}</code>
        <ul>${events}</ul>
        ${flows ? `<strong>flows</strong><ul>${flows}</ul>` : ""}
      </div>
    </div>`;
  }).join("") : '<p class="hint">no alerts — that is the goal</p>';
  document.querySelectorAll(".alert").forEach((el) => {
    el.addEventListener("click", () => el.classList.toggle("open"));
  });
}

/* ---------------------------------------------------------------- shell */
const REFRESH = {
  tree: refreshTree,
  graph: refreshGraph,
  timeline: refreshTimeline,
  packages: refreshPackages,
  alerts: refreshAlerts,
};

async function refreshCurrent() {
  await refreshSummary();
  try {
    await REFRESH[state.view]();
  } catch (err) {
    document.getElementById(`view-${state.view}`).innerHTML +=
      `<p class="hint">${esc(err.message)}</p>`;
  }
}

function setView(name) {
  state.view = name;
  document.querySelectorAll("nav button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === name);
  });
  document.querySelectorAll(".view").forEach((section) => {
    section.classList.toggle("active", section.id === `view-${name}`);
  });
  refreshCurrent();
}

function boot() {
  document.querySelectorAll("nav button").forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset.view));
  });
  wireGraph();
  graphLoop();
  refreshCurrent();
  setInterval(refreshCurrent, 4000);
}

boot();
