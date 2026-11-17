/*
 * nmap-gui - a modern browser interface for the nmap network scanner
 * Copyright (C) 2026 Denis (https://github.com/agent-denis)
 * SPDX-License-Identifier: GPL-3.0-or-later
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version. It comes WITHOUT ANY WARRANTY.
 * See the LICENSE file or <https://www.gnu.org/licenses/>.
 */
// nmap-gui front end. Talks to server.py through a small JSON API.
"use strict";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = {
  info: null,
  scans: [],
  presetId: "quick",
  current: null,      // full scan object being shown
  events: null,       // live EventSource while a scan runs
  tab: "hosts",
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: opts.body ? { "Content-Type": "application/json" } : {},
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ------------------------------------------------------------------ helpers

function timeAgo(ts) {
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

function duration(sec) {
  if (sec == null) return "–";
  if (sec < 60) return `${sec.toFixed(1)} s`;
  return `${Math.floor(sec / 60)} min ${Math.round(sec % 60)} s`;
}

function ipKey(ip) {
  // Sort IPv4 numerically; anything else alphabetically after.
  const p = ip.split(".");
  return p.length === 4 && p.every((x) => /^\d+$/.test(x))
    ? p.map((x) => x.padStart(3, "0")).join(".") : "~" + ip;
}

const openPorts = (h) => h.ports.filter((p) => p.state === "open");
const statusLabel = { running: "Running", done: "Finished", failed: "Failed", cancelled: "Stopped" };

// ------------------------------------------------------------------ theme

function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem("theme"); } catch (_) {}
  if (saved) document.documentElement.dataset.theme = saved;
  $("#themeBtn").onclick = () => {
    const cur = document.documentElement.dataset.theme ||
      (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch (_) {}
  };
}

// ------------------------------------------------------------------ history

async function loadHistory() {
  try { state.scans = await api("/api/scans"); } catch (_) { return; }
  renderHistory();
}

function renderHistory() {
  const ul = $("#history");
  $("#emptyHistory").hidden = state.scans.length > 0;
  ul.innerHTML = state.scans.map((s) => {
    const bits = [s.preset_name, timeAgo(s.started)];
    if (s.hosts_up != null) bits.push(`${s.hosts_up} up`);
    if (s.open_ports) bits.push(`${s.open_ports} open`);
    const active = state.current && state.current.id === s.id ? "active" : "";
    return `<li class="${active}" data-id="${esc(s.id)}">
      <div class="h-target"><span class="sdot ${esc(s.status)}"></span>${esc(s.target)}</div>
      <div class="h-meta">${esc(bits.join(" · "))}</div></li>`;
  }).join("");
}

$("#history").addEventListener("click", (e) => {
  const li = e.target.closest("li[data-id]");
  if (li) location.hash = `#/scan/${li.dataset.id}`;
});

// ------------------------------------------------------------------ new scan form

function renderPresets() {
  const root = state.info.root;
  $("#presets").innerHTML = state.info.presets.map((p) => {
    const locked = p.root && !root;
    return `<button type="button" class="preset ${p.id === state.presetId ? "selected" : ""}"
      data-id="${p.id}" ${locked ? "disabled title='Start nmap-gui with sudo to use this'" : ""}>
      <div class="preset-name">${esc(p.name)}${p.root ? `<span class="badge">${root ? "admin" : "needs sudo"}</span>` : ""}</div>
      <div class="preset-desc">${esc(p.desc)}</div></button>`;
  }).join("");
  updatePreview();
}

function updatePreview() {
  const p = state.info.presets.find((x) => x.id === state.presetId);
  const target = $("#target").value.trim() || "<target>";
  $("#commandPreview").textContent = ["$ nmap -v", ...p.args, target].join(" ");
}

$("#presets").addEventListener("click", (e) => {
  const b = e.target.closest(".preset");
  if (!b || b.disabled) return;
  state.presetId = b.dataset.id;
  renderPresets();
});
$("#target").addEventListener("input", updatePreview);
document.querySelectorAll("[data-target]").forEach((b) =>
  b.addEventListener("click", () => { $("#target").value = b.dataset.target; updatePreview(); $("#target").focus(); }));

$("#scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  await startScan($("#target").value.trim(), state.presetId);
});

async function startScan(target, preset) {
  const err = $("#formError");
  err.hidden = true;
  $("#startBtn").disabled = true;
  try {
    const s = await api("/api/scans", { method: "POST", body: JSON.stringify({ target, preset }) });
    await loadHistory();
    location.hash = `#/scan/${s.id}`;
  } catch (ex) {
    if (!$("#newView").hidden) { err.textContent = ex.message; err.hidden = false; }
    else alert(ex.message);
  } finally {
    $("#startBtn").disabled = false;
  }
}

function showNew() {
  closeEvents();
  state.current = null;
  $("#scanView").hidden = true;
  $("#newView").hidden = false;
  renderHistory();
  $("#target").focus();
}

// ------------------------------------------------------------------ scan view

function closeEvents() {
  if (state.events) { state.events.close(); state.events = null; }
}

async function showScan(id) {
  closeEvents();
  let s;
  try { s = await api(`/api/scans/${encodeURIComponent(id)}`); }
  catch (_) { location.hash = "#/new"; return; }
  state.current = s;
  $("#newView").hidden = true;
  $("#scanView").hidden = false;
  $("#portFilter").value = "";
  renderHistory();
  renderScan();
  if (s.status === "running") followLive(s);
  onScanShown(s);   // compare.js: fills the Changes tab
}

function followLive(s) {
  const es = new EventSource(`/api/scans/${encodeURIComponent(s.id)}/events`);
  state.events = es;
  let pending = false;
  es.addEventListener("log", (e) => {
    s.log.push(...JSON.parse(e.data));
    // Re-render at most a few times a second while output streams in.
    if (!pending) { pending = true; setTimeout(() => { pending = false; if (state.current === s) renderScan(); }, 300); }
  });
  es.addEventListener("progress", (e) => { s.progress = parseFloat(e.data); renderProgress(); });
  es.addEventListener("end", async () => {
    closeEvents();
    await loadHistory();
    if (state.current && state.current.id === s.id) showScan(s.id);
  });
  es.onerror = () => { /* browser retries automatically */ };
}

// While running, nmap's results file isn't ready yet, so build a live
// preview from its text output.
function liveResult(log) {
  const hosts = new Map();
  const get = (ip, name) => {
    if (!hosts.has(ip)) hosts.set(ip, { ip, hostnames: name ? [name] : [], ports: [], hidden_ports: [], trace: [], scripts: [], live: true });
    return hosts.get(ip);
  };
  for (const line of log) {
    let m = line.match(/^Nmap scan report for (\S+)(?: \(([^)]+)\))?(.*)$/);
    if (m && !/host down/.test(m[3])) { m[2] ? get(m[2], m[1]) : get(m[1]); continue; }
    m = line.match(/^Discovered open port (\d+)\/(\w+) on (\S+)/);
    if (m) get(m[3]).ports.push({ port: +m[1], proto: m[2], state: "open", service: "", product: "", scripts: [] });
  }
  const list = [...hosts.values()];
  return { hosts: list, hosts_up: list.length, live: true };
}

function renderScan() {
  const s = state.current;
  const running = s.status === "running";
  const result = s.result || (running ? liveResult(s.log) : { hosts: [] });
  $("#scanTitle").textContent = s.target;
  $("#scanCommand").textContent = s.command;
  const st = $("#scanStatus");
  st.className = `status ${s.status}`;
  st.textContent = statusLabel[s.status] || s.status;
  $("#cancelBtn").hidden = !running;
  $("#rerunBtn").hidden = running;
  $("#deleteBtn").hidden = running;
  renderProgress();

  const open = result.hosts.reduce((n, h) => n + openPorts(h).length, 0);
  const elapsed = s.finished ? s.finished - s.started : Date.now() / 1000 - s.started;
  const stats = [
    [result.hosts_up ?? result.hosts.length, running ? "Devices found so far" : "Devices up"],
    [open, "Open ports"],
    [duration(result.elapsed || elapsed), running ? "Elapsed" : "Duration"],
    [s.preset_name, "Scan type"],
  ];
  $("#stats").innerHTML = stats.map(([v, l]) =>
    `<div class="card stat"><div class="stat-value ${typeof v === "number" ? "" : "text"}">${esc(v)}</div><div class="stat-label">${esc(l)}</div></div>`).join("") +
    (s.error ? `<div class="card stat" style="grid-column:1/-1;color:var(--danger)">${esc(s.error)}</div>` : "");

  renderHosts(result, running);
  renderPorts(result);
  renderMap(result);
  const out = $("#output");
  const atBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 40;
  out.textContent = s.log.join("\n");
  if (atBottom) out.scrollTop = out.scrollHeight;
  selectTab(state.tab);
}

function renderProgress() {
  const s = state.current;
  if (!s) return;
  const wrap = $("#progressWrap");
  wrap.hidden = s.status !== "running";
  wrap.classList.toggle("indeterminate", s.progress <= 0);
  $("#progressBar").style.width = s.progress > 0 ? `${s.progress}%` : "";
}

function emptyBox(icon, text) {
  return `<div class="empty card"><div class="empty-icon">${icon}</div>${esc(text)}</div>`;
}

function renderHosts(result, running) {
  const panel = $("#tab-hosts");
  const expanded = new Set([...panel.querySelectorAll(".host.expanded")].map((el) => el.dataset.ip));
  const hosts = [...result.hosts].sort((a, b) => ipKey(a.ip).localeCompare(ipKey(b.ip)));
  if (!hosts.length) {
    panel.innerHTML = emptyBox(running ? "⏳" : "🔍", running ? "Scanning… devices will appear here as they are found." : "No devices responded.");
    return;
  }
  panel.innerHTML = `<div class="hosts">${hosts.map((h) => {
    const op = openPorts(h);
    const tags = [
      `<span class="tag ${op.length ? "open" : ""}">${op.length} open port${op.length === 1 ? "" : "s"}</span>`,
      h.vendor ? `<span class="tag">${esc(h.vendor)}</span>` : "",
      h.os ? `<span class="tag">${esc(h.os.name)} (${esc(h.os.accuracy)}%)</span>` : "",
    ].join("");
    const isOpen = expanded.has(h.ip) || hosts.length === 1;
    return `<div class="card host ${isOpen ? "expanded" : ""}" data-ip="${esc(h.ip)}">
      <div class="host-head"><span class="chev">▶</span>
        <span class="host-ip">${esc(h.ip)}</span>
        <span class="host-name">${esc(h.hostnames.join(", "))}</span>
        <div class="host-tags">${tags}</div></div>
      <div class="host-body">${hostDetails(h)}</div></div>`;
  }).join("")}</div>`;
}

function hostDetails(h) {
  const kv = [];
  if (h.hostnames?.length) kv.push(["Hostname", h.hostnames.join(", ")]);
  if (h.ipv6 && h.ipv6 !== h.ip) kv.push(["IPv6", h.ipv6]);
  if (h.mac) kv.push(["MAC", `${h.mac}${h.vendor ? ` (${h.vendor})` : ""}`]);
  if (h.os) kv.push(["OS guess", `${h.os.name} — ${h.os.accuracy}% sure`]);
  if (h.distance) kv.push(["Distance", `${h.distance} hop${h.distance > 1 ? "s" : ""}`]);
  if (h.reason) kv.push(["Detected by", h.reason]);
  for (const x of h.hidden_ports || []) kv.push(["Not shown", `${x.count} ${x.state} ports`]);
  if (h.trace?.length) kv.push(["Route", h.trace.map((t) => t.ip).join(" → ")]);
  let html = kv.length ? `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : "";
  if (h.ports.length) {
    html += `<div class="table-wrap"><table class="table"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Software / version</th></tr></thead><tbody>${
      h.ports.map((p) => `<tr><td class="mono">${p.port}/${esc(p.proto)}</td>
        <td><span class="state ${esc(p.state)}">${esc(p.state)}</span></td>
        <td>${esc(p.service)}</td>
        <td>${esc(p.product)}${p.scripts.map((sc) => `<div class="script-out"><b>${esc(sc.id)}</b>: ${esc(sc.output)}</div>`).join("")}</td></tr>`).join("")
    }</tbody></table></div>`;
  } else if (!h.live) {
    html += `<p class="muted small">No open ports listed for this device${h.hidden_ports?.length ? "" : " (port scan not part of this scan type)"}.</p>`;
  }
  for (const sc of h.scripts || []) html += `<div class="script-out"><b>${esc(sc.id)}</b>: ${esc(sc.output)}</div>`;
  return html;
}

$("#tab-hosts").addEventListener("click", (e) => {
  const head = e.target.closest(".host-head");
  if (head) head.parentElement.classList.toggle("expanded");
});

function renderPorts(result) {
  const q = $("#portFilter").value.trim().toLowerCase();
  const rows = [];
  for (const h of result.hosts) for (const p of h.ports) {
    const text = `${h.ip} ${h.hostnames.join(" ")} ${p.port} ${p.proto} ${p.state} ${p.service} ${p.product}`.toLowerCase();
    if (!q || text.includes(q)) rows.push({ h, p });
  }
  rows.sort((a, b) => ipKey(a.h.ip).localeCompare(ipKey(b.h.ip)) || a.p.port - b.p.port);
  $("#portTable").innerHTML = rows.length
    ? `<thead><tr><th>Device</th><th>Port</th><th>State</th><th>Service</th><th>Software / version</th></tr></thead><tbody>${
      rows.map(({ h, p }) => `<tr><td class="mono">${esc(h.ip)}${h.hostnames[0] ? `<div class="muted small">${esc(h.hostnames[0])}</div>` : ""}</td>
        <td class="mono">${p.port}/${esc(p.proto)}</td><td><span class="state ${esc(p.state)}">${esc(p.state)}</span></td>
        <td>${esc(p.service)}</td><td>${esc(p.product)}</td></tr>`).join("")}</tbody>`
    : `<tbody><tr><td class="empty">${q ? "Nothing matches the filter." : "No ports found in this scan."}</td></tr></tbody>`;
}
$("#portFilter").addEventListener("input", () => state.current && renderPorts(state.current.result || liveResult(state.current.log)));

// ------------------------------------------------------------------ network map

function renderMap(result) {
  const svg = $("#map");
  const hosts = [...result.hosts].sort((a, b) => ipKey(a.ip).localeCompare(ipKey(b.ip)));
  if (!hosts.length) {
    svg.setAttribute("viewBox", "0 0 400 120");
    svg.innerHTML = `<text x="200" y="64" text-anchor="middle" fill="var(--muted)" font-size="14">No devices to draw yet.</text>`;
    return;
  }
  // Place devices on rings around the scanner: ring k holds up to 8*k nodes.
  const placed = [];
  let ring = 1, idx = 0;
  while (idx < hosts.length) {
    const cap = 8 * ring;
    const n = Math.min(cap, hosts.length - idx);
    const r = 140 + (ring - 1) * 100;
    const offset = ring % 2 ? 0 : Math.PI / n;
    for (let i = 0; i < n; i++) {
      const a = -Math.PI / 2 + offset + (2 * Math.PI * i) / n;
      placed.push({ h: hosts[idx + i], x: r * Math.cos(a), y: r * Math.sin(a) });
    }
    idx += n; ring++;
  }
  const R = 140 + (ring - 2) * 100 + 80;
  svg.setAttribute("viewBox", `${-R} ${-R} ${2 * R} ${2 * R}`);
  const showSub = hosts.length <= 40;
  const links = placed.map((p) => `<line class="link" x1="0" y1="0" x2="${p.x.toFixed(1)}" y2="${p.y.toFixed(1)}"/>`).join("");
  const nodes = placed.map(({ h, x, y }) => {
    const n = openPorts(h).length;
    const color = n === 0 ? "var(--node-none)" : n < 5 ? "var(--node-some)" : "var(--node-many)";
    const rad = 10 + Math.min(n, 10);
    const name = h.hostnames[0] || h.vendor || "";
    const tip = [h.ip, name, `${n} open port${n === 1 ? "" : "s"}`,
      ...openPorts(h).slice(0, 12).map((p) => `  ${p.port}/${p.proto} ${p.service}`)].filter(Boolean).join("\n");
    return `<g class="node" data-ip="${esc(h.ip)}" transform="translate(${x.toFixed(1)},${y.toFixed(1)})">
      <title>${esc(tip)}</title>
      <circle r="${rad}" fill="${color}"/>
      <text y="${rad + 14}" text-anchor="middle">${esc(h.ip)}</text>
      ${showSub && name ? `<text class="sub" y="${rad + 27}" text-anchor="middle">${esc(name.length > 22 ? name.slice(0, 21) + "…" : name)}</text>` : ""}
    </g>`;
  }).join("");
  const center = `<g class="node center"><circle r="34"/><text text-anchor="middle" y="-2">Scanner</text>
    <text class="sub" text-anchor="middle" y="13">${hosts.length} device${hosts.length === 1 ? "" : "s"}</text></g>`;
  svg.innerHTML = links + center + nodes;
}

$("#map").addEventListener("click", (e) => {
  const g = e.target.closest(".node[data-ip]");
  if (!g) return;
  selectTab("hosts");
  const card = [...document.querySelectorAll(".host")].find((el) => el.dataset.ip === g.dataset.ip);
  if (card) {
    card.classList.add("expanded", "flash");
    card.scrollIntoView({ behavior: "smooth", block: "center" });
    setTimeout(() => card.classList.remove("flash"), 1300);
  }
});

// ------------------------------------------------------------------ tabs & actions

function selectTab(name) {
  if (!document.getElementById(`tab-${name}`)) name = "hosts";
  state.tab = name;
  if (state.current) history.replaceState(null, "", `#/scan/${state.current.id}/${name}`);
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => { p.hidden = p.id !== `tab-${name}`; });
  if (name === "output") { const o = $("#output"); o.scrollTop = o.scrollHeight; }
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => selectTab(t.dataset.tab)));

$("#cancelBtn").onclick = async () => {
  if (!state.current) return;
  try { await api(`/api/scans/${state.current.id}/cancel`, { method: "POST", body: "{}" }); }
  catch (ex) { alert(ex.message); }
};
$("#rerunBtn").onclick = () => state.current && startScan(state.current.target, state.current.preset);
$("#deleteBtn").onclick = async () => {
  if (!state.current || !confirm("Delete this scan from history?")) return;
  try { await api(`/api/scans/${state.current.id}`, { method: "DELETE" }); }
  catch (ex) { alert(ex.message); return; }
  await loadHistory();
  location.hash = "#/new";
};
$("#newScanBtn").onclick = () => { location.hash = "#/new"; };

$("#quitBtn").onclick = async () => {
  const running = state.scans.some((x) => x.status === "running");
  if (!confirm(running ? "Quit nmap-gui? The running scan will be stopped." : "Quit nmap-gui?")) return;
  closeEvents();
  try { await api("/api/quit", { method: "POST", body: "{}" }); } catch (_) { /* already gone */ }
  clearInterval(state.historyTimer);
  document.querySelector(".layout").innerHTML = `<main class="main">${emptyBox("👋",
    "nmap-gui has stopped. You can close this tab. Start it again from your app menu or with: nmap-gui")}</main>`;
};

// Phone layout: slide-out history panel
$("#menuBtn").onclick = () => document.body.classList.toggle("nav-open");
$("#scrim").onclick = () => document.body.classList.remove("nav-open");

// ------------------------------------------------------------------ routing & start-up

function route() {
  document.body.classList.remove("nav-open");
  const m = location.hash.match(/^#\/scan\/([\w-]+)(?:\/(\w+))?$/);
  if (!m) return showNew();
  state.tab = m[2] || "hosts";
  if (state.current && state.current.id === m[1]) selectTab(state.tab); else showScan(m[1]);
}

async function init() {
  initTheme();
  state.info = await api("/api/info");
  $("#nmapVersion").textContent = state.info.nmap ? `nmap ${state.info.nmap}` : "nmap not found";
  const rc = $("#rootChip");
  rc.hidden = false;
  rc.textContent = state.info.root ? "admin mode" : "normal user";
  rc.className = `chip ${state.info.root ? "warn" : "ok"}`;
  rc.title = state.info.root ? "Running with sudo: all scan types available" : "Some scan types need sudo";
  renderPresets();
  await loadHistory();
  window.addEventListener("hashchange", route);
  route();
  // Keep the history list fresh (status dots, "x min ago").
  // (also tells the server a page is still open, so it doesn't stop when idle)
  state.historyTimer = setInterval(loadHistory, 10000);
}

init().catch((e) => {
  document.querySelector(".main").innerHTML = emptyBox("⚠️", `Could not reach the nmap-gui server: ${e.message}`);
});
