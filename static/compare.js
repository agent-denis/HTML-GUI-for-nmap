/*
 * nmap-gui - a modern browser interface for the nmap network scanner
 * Copyright (C) 2026 Denis (https://github.com/agent-denis)
 * SPDX-License-Identifier: GPL-3.0-or-later
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version. It comes WITHOUT ANY WARRANTY.
 * See the LICENSE file or <https://www.gnu.org/licenses/>.
 */
// nmap-gui: "Changes" tab - compares two scans and builds an email note.
// Uses helpers from app.js ($, esc, api, state).
"use strict";

const MAILTO_LIMIT = 1900;   // longer mailto: links break in some email programs
const PLACEHOLDERS = {
  target: "what was scanned",
  old_time: "date & time of the earlier scan",
  new_time: "date & time of this scan",
  summary: "one-line summary of the changes",
  new_count: "number of new devices",
  new_devices: "list of new devices with details",
  missing_count: "number of devices not seen",
  missing_devices: "list of devices not seen",
  port_changes: "opened/closed ports on known devices",
  other_changes: "changed IP, MAC or hostname",
  warnings: "notes about the comparison (if any)",
};

const cmp = { settings: null, defaults: null, diff: null, candidates: [] };

// ------------------------------------------------------------------ text helpers

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString(undefined, {
    weekday: "short", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const hostLabel = (h) => h.ip + (h.hostnames?.length ? ` (${h.hostnames.join(", ")})` : "");
const portText = (p) => `${p.port}/${p.proto}${p.service ? " " + p.service : ""}${p.product ? ` (${p.product})` : ""}`;

function deviceDetails(h, portsScanned) {
  const bits = [];
  if (h.mac) bits.push(`MAC ${h.mac}${h.vendor ? ` (${h.vendor})` : ""}`);
  if (h.os) bits.push(`OS guess ${h.os.name}`);
  if (portsScanned) {
    const open = h.ports.filter((p) => p.state === "open");
    bits.push(open.length ? `open ports: ${open.map(portText).join(", ")}` : "no open ports found");
  }
  return bits;
}

function summaryLine(d) {
  const parts = [];
  if (d.new_hosts.length) parts.push(plural(d.new_hosts.length, "new device"));
  if (d.missing_hosts.length) parts.push(`${plural(d.missing_hosts.length, "device")} not seen`);
  if (d.port_changes.length) parts.push(`port changes on ${plural(d.port_changes.length, "device")}`);
  if (d.other_changes.length) parts.push(plural(d.other_changes.length, "other change"));
  return parts.length ? parts.join(", ") + "." : "No changes found.";
}

const totalChanges = (d) => d.new_hosts.length + d.missing_hosts.length + d.port_changes.length + d.other_changes.length;

function textList(items, fn) {
  return items.length ? items.map(fn).join("\n") : "  (none)";
}

function placeholderValues(d) {
  const ports = d.ports_compared;
  return {
    target: d.new.target,
    old_time: fmtTime(d.old.started),
    new_time: fmtTime(d.new.started),
    summary: summaryLine(d),
    new_count: String(d.new_hosts.length),
    missing_count: String(d.missing_hosts.length),
    new_devices: textList(d.new_hosts, (h) =>
      [`  • ${hostLabel(h)}`, ...deviceDetails(h, ports).map((b) => `      ${b}`)].join("\n")),
    missing_devices: textList(d.missing_hosts, (h) =>
      `  • ${hostLabel(h)}${h.mac ? ` - MAC ${h.mac}${h.vendor ? ` (${h.vendor})` : ""}` : ""}`),
    port_changes: ports
      ? textList(d.port_changes, (c) => [`  • ${hostLabel(c)}`,
        ...c.opened.map((p) => `      newly open: ${portText(p)}`),
        ...c.closed.map((p) => `      now closed: ${portText(p)}`),
        ...c.changed.map((x) => `      software changed on ${x.port}/${x.proto}: ${x.old} -> ${x.new}`)].join("\n"))
      : "  (not compared - one scan only looked for devices)",
    other_changes: textList(d.other_changes, (c) => `  • ${hostLabel(c)}: ${c.what} changed from ${c.old} to ${c.new}`),
    warnings: d.warnings.length ? "\nPlease note:\n" + d.warnings.map((w) => `  - ${w}`).join("\n") + "\n" : "",
  };
}

const fillTemplate = (tpl, vals) => tpl.replace(/\{(\w+)\}/g, (m, k) => (k in vals ? vals[k] : m));

// ------------------------------------------------------------------ choosing what to compare

function compareCandidates(cur) {
  const usable = state.scans.filter((s) => s.id !== cur.id && s.status !== "running" && s.hosts_up != null);
  const same = usable.filter((s) => s.target === cur.target);
  const other = usable.filter((s) => s.target !== cur.target);
  return { same, other };
}

function defaultCandidate(cur, same) {
  return same.find((s) => s.started < cur.started) || same[0] || null;
}

// Called by app.js whenever a scan is opened.
async function onScanShown(cur) {
  const badge = $("#changesBadge");
  const sel = $("#compareWith");
  cmp.diff = null;
  badge.hidden = true;
  $("#emailCard").hidden = true;
  if (cur.status === "running" || !cur.result) {
    sel.parentElement.hidden = true;
    $("#diffView").innerHTML = emptyBox("⏳", cur.status === "running"
      ? "Changes can be compared when the scan has finished."
      : "This scan has no results to compare.");
    return;
  }
  const { same, other } = compareCandidates(cur);
  const opt = (s) => `<option value="${esc(s.id)}">${esc(fmtTime(s.started))} · ${esc(s.preset_name)}${
    s.target !== cur.target ? ` · ${esc(s.target)}` : ""}${s.started > cur.started ? " (newer)" : ""}</option>`;
  sel.innerHTML = (same.length ? `<optgroup label="Same target (${esc(cur.target)})">${same.map(opt).join("")}</optgroup>` : "") +
    (other.length ? `<optgroup label="Other targets">${other.map(opt).join("")}</optgroup>` : "");
  const def = defaultCandidate(cur, same);
  if (!def) {
    sel.parentElement.hidden = !other.length;
    if (other.length) sel.insertAdjacentHTML("afterbegin", `<option value="" selected>Choose a scan…</option>`);
    $("#diffView").innerHTML = emptyBox("🕒",
      "There is no other scan of this target yet. Run the same scan again later (“Run again”), " +
      "then open this tab to see what changed.");
    return;
  }
  sel.parentElement.hidden = false;
  sel.value = def.id;
  await loadDiff(cur, def.id);
}

$("#compareWith").addEventListener("change", (e) => {
  if (state.current && e.target.value) loadDiff(state.current, e.target.value);
});

async function loadDiff(cur, otherId) {
  let d;
  try {
    d = await api(`/api/compare?old=${encodeURIComponent(otherId)}&new=${encodeURIComponent(cur.id)}`);
  } catch (ex) {
    $("#diffView").innerHTML = emptyBox("⚠️", ex.message);
    return;
  }
  if (state.current !== cur) return;   // user moved on meanwhile
  cmp.diff = d;
  const n = totalChanges(d);
  const badge = $("#changesBadge");
  badge.hidden = false;
  badge.textContent = n;
  badge.classList.toggle("zero", n === 0);
  renderDiff(d);
  fillEmail();
}

// ------------------------------------------------------------------ rendering the comparison

function renderDiff(d) {
  const swapped = d.new.id !== state.current.id;
  const portsHtml = (c) => [
    ...c.opened.map((p) => `<div><span class="plus">+ open</span> ${esc(portText(p))}</div>`),
    ...c.closed.map((p) => `<div><span class="minus">− closed</span> ${esc(portText(p))}</div>`),
    ...c.changed.map((x) => `<div>software on ${x.port}/${esc(x.proto)}: ${esc(x.old)} → ${esc(x.new)}</div>`),
  ].join("");
  const section = (cls, title, items, fn) => items.length
    ? `<div class="card diff-section ${cls}"><h3>${esc(title)} (${items.length})</h3><ul>${items.map(fn).join("")}</ul></div>` : "";
  const label = (h) => `<span class="mono">${esc(h.ip)}</span>${h.hostnames?.length ? ` <span class="muted">${esc(h.hostnames.join(", "))}</span>` : ""}`;

  $("#diffView").innerHTML = `
    <p class="diff-times muted">From <b>${esc(fmtTime(d.old.started))}</b> (${esc(d.old.preset_name)})
      to <b>${esc(fmtTime(d.new.started))}</b> (${esc(d.new.preset_name)})${swapped ? " — the scan you picked is newer, so it is treated as the later one" : ""}.</p>
    ${d.warnings.length ? `<ul class="card warn-list small">${d.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
    ${totalChanges(d) === 0 ? emptyBox("✅", "No changes: the same devices and open ports were found in both scans.") : ""}
    ${section("new", "New devices", d.new_hosts, (h) =>
      `<li>${label(h)}<div class="small muted">${esc(deviceDetails(h, d.ports_compared).join(" · "))}</div></li>`)}
    ${section("missing", "Not seen in the later scan", d.missing_hosts, (h) =>
      `<li>${label(h)}${h.vendor ? ` <span class="small muted">${esc(h.vendor)}</span>` : ""}</li>`)}
    ${section("ports", "Port changes on known devices", d.port_changes, (c) => `<li>${label(c)}<div class="small">${portsHtml(c)}</div></li>`)}
    ${section("other", "Other changes", d.other_changes, (c) =>
      `<li>${label(c)}: ${esc(c.what)} <span class="mono small">${esc(c.old)} → ${esc(c.new)}</span></li>`)}
    ${d.missing_hosts.length ? `<p class="small muted">Phones and laptops often sleep and don't answer, so “not seen” doesn't always mean the device is gone.</p>` : ""}`;
}

// ------------------------------------------------------------------ email note

function fillEmail() {
  const d = cmp.diff;
  if (!d || !cmp.settings) return;
  const vals = placeholderValues(d);
  $("#emailCard").hidden = false;
  $("#mailNotice").hidden = true;
  if (!$("#mailTo").value) $("#mailTo").value = cmp.settings.recipients;
  $("#mailSubject").value = fillTemplate(cmp.settings.subject, vals);
  $("#mailBody").value = fillTemplate(cmp.settings.body, vals);
}

function notice(msg, warn = false) {
  const n = $("#mailNotice");
  n.textContent = msg;
  n.className = `notice small ${warn ? "warn" : ""}`;
  n.hidden = false;
}

function mailtoLink(to, subject, body) {
  const addr = to.split(/[,;\s]+/).filter(Boolean).map(encodeURIComponent).join(",");
  const make = (b) => `mailto:${addr}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(b)}`;
  if (make(body).length <= MAILTO_LIMIT) return { url: make(body), shortened: false };
  const tail = "\n\n[Shortened - the full list is in the attached report.]\n";
  const lines = body.split("\n");
  while (lines.length && make(lines.join("\n") + tail).length > MAILTO_LIMIT) lines.pop();
  return { url: make(lines.join("\n") + tail), shortened: true };
}

$("#sendMailBtn").onclick = () => {
  const { url, shortened } = mailtoLink($("#mailTo").value, $("#mailSubject").value, $("#mailBody").value);
  if (shortened) {
    downloadReport();
    notice("The message was too long for an email link, so it was shortened. The full report was downloaded - " +
      "please attach it to the email.", true);
  } else {
    notice("Opening your email program… If nothing happens, use “Copy text” instead.");
  }
  location.href = url;
};

$("#copyMailBtn").onclick = async () => {
  const text = `Subject: ${$("#mailSubject").value}\n\n${$("#mailBody").value}`;
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const ta = $("#mailBody");
    ta.select();
    document.execCommand("copy");
  }
  notice("Copied - paste it into any email (subject is on the first line).");
};

$("#downloadBtn").onclick = () => { downloadReport(); notice("Report downloaded - you can attach it to an email."); };

function downloadReport() {
  const d = cmp.diff;
  if (!d) return;
  const row = (cells) => `<tr>${cells.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`;
  const table = (title, head, rows) => rows.length ? `<h2>${esc(title)} (${rows.length})</h2>
    <table><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr>${rows.join("")}</table>` : "";
  const ports = (h) => h.ports.filter((p) => p.state === "open").map(portText).join(", ");
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>${esc($("#mailSubject").value)}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:32px auto;padding:0 16px;color:#0f172a}
h1{font-size:22px}h2{font-size:16px;margin-top:28px}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #dde3ec;vertical-align:top}
th{font-size:12px;text-transform:uppercase;color:#5b6b82}.muted{color:#5b6b82}pre{white-space:pre-wrap;background:#f5f7fb;padding:12px;border-radius:8px}</style>
</head><body>
<h1>${esc($("#mailSubject").value)}</h1>
<p>Target <b>${esc(d.new.target)}</b>. Compared the scan on <b>${esc(fmtTime(d.old.started))}</b> (${esc(d.old.preset_name)})
with the scan on <b>${esc(fmtTime(d.new.started))}</b> (${esc(d.new.preset_name)}).</p>
<p><b>${esc(summaryLine(d))}</b></p>
${d.warnings.length ? `<ul>${d.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
${table("New devices", ["IP", "Hostname", "MAC", "Vendor", "OS guess", "Open ports"],
    d.new_hosts.map((h) => row([h.ip, h.hostnames.join(", "), h.mac, h.vendor, h.os?.name || "", d.ports_compared ? ports(h) : "not scanned"])))}
${table("Devices not seen in the later scan", ["IP", "Hostname", "MAC", "Vendor"],
    d.missing_hosts.map((h) => row([h.ip, h.hostnames.join(", "), h.mac, h.vendor])))}
${table("Port changes on known devices", ["IP", "Hostname", "Change", "Port"],
    d.port_changes.flatMap((c) => [
      ...c.opened.map((p) => row([c.ip, c.hostnames.join(", "), "newly open", portText(p)])),
      ...c.closed.map((p) => row([c.ip, c.hostnames.join(", "), "now closed", portText(p)])),
      ...c.changed.map((x) => row([c.ip, c.hostnames.join(", "), "software changed", `${x.port}/${x.proto}: ${x.old} → ${x.new}`])),
    ]))}
${table("Other changes", ["IP", "Hostname", "What", "Before", "After"],
    d.other_changes.map((c) => row([c.ip, c.hostnames.join(", "), c.what, c.old, c.new])))}
<h2>Note</h2><pre>${esc($("#mailBody").value)}</pre>
<p class="muted">Generated by nmap-gui on ${esc(fmtTime(Date.now() / 1000))}.</p>
</body></html>`;
  const stamp = new Date(d.new.started * 1000).toISOString().slice(0, 16).replace(/[T:]/g, "-");
  const name = `network-changes-${d.new.target.replace(/[^\w.-]+/g, "_")}-${stamp}.html`;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([html], { type: "text/html" }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

// ------------------------------------------------------------------ template editor

$("#placeholders").innerHTML = Object.entries(PLACEHOLDERS)
  .map(([k, desc]) => `<button type="button" data-ph="${k}" title="${esc(desc)}">{${k}}</button>`).join("");

// Clicking a placeholder inserts it where the cursor was in subject/message.
let lastTplField = null;
["#tplSubject", "#tplBody"].forEach((id) => $(id).addEventListener("focus", (e) => { lastTplField = e.target; }));
$("#placeholders").addEventListener("mousedown", (e) => e.preventDefault()); // keep focus in the field
$("#placeholders").addEventListener("click", (e) => {
  const b = e.target.closest("[data-ph]");
  if (!b) return;
  const f = lastTplField || $("#tplBody");
  const text = `{${b.dataset.ph}}`;
  const s = f.selectionStart ?? f.value.length, en = f.selectionEnd ?? f.value.length;
  f.value = f.value.slice(0, s) + text + f.value.slice(en);
  f.focus();
  f.selectionStart = f.selectionEnd = s + text.length;
});

function openTemplate(values) {
  $("#tplRecipients").value = values.recipients;
  $("#tplSubject").value = values.subject;
  $("#tplBody").value = values.body;
  $("#templateEditor").hidden = false;
}

$("#editTemplateBtn").onclick = () => {
  if ($("#templateEditor").hidden) openTemplate(cmp.settings); else $("#templateEditor").hidden = true;
};
$("#tplCancel").onclick = () => { $("#templateEditor").hidden = true; };
$("#tplReset").onclick = () => openTemplate({ ...cmp.defaults, recipients: $("#tplRecipients").value });
$("#tplSave").onclick = async () => {
  try {
    const r = await api("/api/settings", { method: "POST", body: JSON.stringify({
      recipients: $("#tplRecipients").value.trim(), subject: $("#tplSubject").value, body: $("#tplBody").value,
    }) });
    cmp.settings = r.settings;
  } catch (ex) { alert(ex.message); return; }
  $("#templateEditor").hidden = true;
  $("#mailTo").value = cmp.settings.recipients;
  fillEmail();
  notice("Template saved. It will be used for every comparison from now on.");
};

(async () => {
  try {
    const r = await api("/api/settings");
    cmp.settings = r.settings;
    cmp.defaults = r.defaults;
    fillEmail();
  } catch (_) { /* server unreachable: app.js shows the error */ }
})();
