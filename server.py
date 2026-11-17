#!/usr/bin/env python3
# nmap-gui - a modern browser interface for the nmap network scanner
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
# This program is free software: you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version. It comes WITHOUT ANY WARRANTY.
# See the LICENSE file or <https://www.gnu.org/licenses/>.
"""nmap-gui: a modern browser interface for nmap.

Runs a tiny web server on THIS computer only (127.0.0.1), starts nmap scans
when you press Start, and serves the page you see in the browser.
Uses only the Python standard library - nothing extra to install.

Usage:  python3 server.py [--port 8642] [--no-browser]
"""
import argparse
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

__version__ = "1.0.0"
APP_ID = "io.github.agent_denis.NmapGui"
DEFAULT_PORT = 8642
IDLE_MINUTES = float(os.environ.get("NMAP_GUI_IDLE_MINUTES", 10))   # --app mode: stop after this long with no page open and no scan running

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "nmap-gui" / "scans"
NMAP = shutil.which("nmap")
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

# Ready-made scan types. "root": True means nmap refuses to run it without sudo.
PRESETS = [
    {"id": "ping", "name": "Find devices", "args": ["-sn"], "root": False,
     "desc": "Lists which devices are online. No port scan, very fast."},
    {"id": "quick", "name": "Quick scan", "args": ["-T4", "-F"], "root": False,
     "desc": "Checks the 100 most common ports."},
    {"id": "noping", "name": "Quick scan, no ping", "args": ["-T4", "-F", "-Pn"], "root": False,
     "desc": "For devices that ignore ping (firewalls, Windows PCs). Treats every address as online, "
             "so it is slow on whole networks."},
    {"id": "regular", "name": "Regular scan", "args": [], "root": False,
     "desc": "Checks the 1000 most common ports."},
    {"id": "services", "name": "Service versions", "args": ["-T4", "-sV"], "root": False,
     "desc": "Top 1000 ports and identifies the software on each open port."},
    {"id": "scripts", "name": "Versions + safe scripts", "args": ["-T4", "-sV", "-sC"], "root": False,
     "desc": "Like Service versions, plus nmap's default scripts: page titles, certificates, "
             "SSH keys, shared folders and more."},
    {"id": "allports", "name": "All TCP ports", "args": ["-T4", "-p-"], "root": False,
     "desc": "Every port from 1 to 65535. Thorough but slow."},
    {"id": "os", "name": "OS detection", "args": ["-T4", "-O", "--osscan-guess"], "root": True,
     "desc": "Top 1000 ports and a guess of each device's operating system."},
    {"id": "udp", "name": "UDP scan", "args": ["-T4", "-sU", "--top-ports", "100"], "root": True,
     "desc": "The 100 most common UDP ports (DNS, DHCP, SNMP, media servers). Slow."},
    {"id": "intense", "name": "Intense scan", "args": ["-T4", "-A"], "root": True,
     "desc": "Versions, operating system, default scripts and traceroute."},
]
PRESET_BY_ID = {p["id"]: p for p in PRESETS}

# A target must start with a letter/digit (so it can never be read as an nmap
# option like "-oN") and may only contain characters used in hosts/IPs/ranges.
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:/_,*\-]{0,252}$")
PROGRESS_RE = re.compile(r"About ([\d.]+)% done")
STATIC_FILES = {"/": "index.html", "/app.js": "app.js", "/compare.js": "compare.js", "/app.css": "app.css", "/icon.svg": "icon.svg"}
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}


def parse_targets(text):
    parts = str(text).split()
    if not parts:
        raise ValueError("Enter a target, e.g. 192.168.1.0/24 or scanme.nmap.org")
    if len(parts) > 32:
        raise ValueError("Too many targets (max 32)")
    for p in parts:
        if not TARGET_RE.match(p):
            raise ValueError(f"Not a valid target: {p}")
    return parts


_VERSION = []


def nmap_version():
    """Asks nmap for its version once, then remembers the answer."""
    if not _VERSION:
        _VERSION.append(_read_nmap_version())
    return _VERSION[0]


def _read_nmap_version():
    if not NMAP:
        return None
    try:
        out = subprocess.run([NMAP, "--version"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"Nmap version (\S+)", out)
        return m.group(1) if m else "unknown"
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------- XML parsing

def _attr(el, name, default=""):
    return el.get(name, default) if el is not None else default


def parse_xml(path):
    """Turn nmap's XML report into simple JSON-friendly data."""
    root = ET.parse(path).getroot()
    hosts = []
    for h in root.findall("host"):
        if _attr(h.find("status"), "state") != "up":
            continue
        ipv4 = ipv6 = mac = vendor = ""
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4":
                ipv4 = a.get("addr", "")
            elif t == "ipv6":
                ipv6 = a.get("addr", "")
            elif t == "mac":
                mac, vendor = a.get("addr", ""), a.get("vendor", "")
        ports = []
        for p in h.findall("ports/port"):
            svc = p.find("service")
            product = " ".join(x for x in (_attr(svc, "product"), _attr(svc, "version"),
                                           _attr(svc, "extrainfo")) if x)
            ports.append({
                "port": int(p.get("portid", 0)),
                "proto": p.get("protocol", ""),
                "state": _attr(p.find("state"), "state"),
                "reason": _attr(p.find("state"), "reason"),
                "service": _attr(svc, "name"),
                "product": product,
                "scripts": [{"id": s.get("id", ""), "output": s.get("output", "")}
                            for s in p.findall("script")],
            })
        hidden = [{"state": e.get("state", ""), "count": int(e.get("count", 0))}
                  for e in h.findall("ports/extraports")]
        osm = h.find("os/osmatch")
        hosts.append({
            "ip": ipv4 or ipv6,
            "ipv6": ipv6,
            "mac": mac,
            "vendor": vendor,
            "hostnames": [n.get("name", "") for n in h.findall("hostnames/hostname")],
            "reason": _attr(h.find("status"), "reason"),
            "ports": ports,
            "hidden_ports": hidden,
            "os": {"name": osm.get("name"), "accuracy": osm.get("accuracy")} if osm is not None else None,
            "distance": int(_attr(h.find("distance"), "value", "0") or 0) or None,
            "trace": [{"ttl": hop.get("ttl"), "ip": hop.get("ipaddr"), "host": hop.get("host", "")}
                      for hop in h.findall("trace/hop")],
            "scripts": [{"id": s.get("id", ""), "output": s.get("output", "")}
                        for s in h.findall("hostscript/script")],
        })
    fin = root.find("runstats/finished")
    hs = root.find("runstats/hosts")
    return {
        "hosts": hosts,
        "summary": _attr(fin, "summary"),
        "elapsed": float(_attr(fin, "elapsed", "0") or 0),
        "hosts_up": int(_attr(hs, "up", "0") or 0),
        "hosts_down": int(_attr(hs, "down", "0") or 0),
        "hosts_total": int(_attr(hs, "total", "0") or 0),
    }


# ---------------------------------------------------------------- comparing two scans

def _open_ports(host):
    return {(p["port"], p["proto"]): p for p in host["ports"] if p["state"] == "open"}


def _brief(host):
    return {k: host.get(k) for k in ("ip", "hostnames", "mac", "vendor", "ports", "os")}


def diff_scans(a, b):
    """What changed between two finished scans. The older one is always 'old'."""
    old, new = (a, b) if a.started <= b.started else (b, a)
    oh = {h["ip"]: h for h in (old.result or {}).get("hosts", [])}
    nh = {h["ip"]: h for h in (new.result or {}).get("hosts", [])}
    new_ips = [ip for ip in nh if ip not in oh]
    gone_ips = [ip for ip in oh if ip not in nh]
    other = []

    # Same physical device (same MAC) that just got a different IP is not "new".
    gone_by_mac = {oh[ip]["mac"]: ip for ip in gone_ips if oh[ip].get("mac")}
    for ip in list(new_ips):
        mac = nh[ip].get("mac")
        if mac and mac in gone_by_mac:
            old_ip = gone_by_mac.pop(mac)
            new_ips.remove(ip)
            gone_ips.remove(old_ip)
            other.append({"ip": ip, "hostnames": nh[ip]["hostnames"], "what": "IP address",
                          "old": old_ip, "new": ip})

    ping_only = "ping" in (old.preset["id"], new.preset["id"])
    warnings = []
    if ping_only:
        warnings.append("One of the scans only looked for devices, so open ports were not compared.")
    elif old.preset["id"] != new.preset["id"]:
        warnings.append(f"The scans used different scan types ({old.preset['name']} vs "
                        f"{new.preset['name']}), so some port differences may come from that.")
    for s in (old, new):
        if s.status != "done":
            warnings.append(f"The scan from {time.strftime('%d %b %Y %H:%M', time.localtime(s.started))} "
                            f"did not finish ({s.status}), so its results may be incomplete.")
    if " ".join(old.targets) != " ".join(new.targets):
        warnings.append("The two scans had different targets.")

    port_changes = []
    for ip in nh:
        if ip not in oh:
            continue
        o, n = oh[ip], nh[ip]
        if not ping_only:
            op, np_ = _open_ports(o), _open_ports(n)
            opened = [np_[k] for k in sorted(np_) if k not in op]
            closed = [op[k] for k in sorted(op) if k not in np_]
            changed = [{"port": k[0], "proto": k[1], "old": op[k]["product"], "new": np_[k]["product"]}
                       for k in sorted(np_) if k in op and op[k]["product"] and np_[k]["product"]
                       and op[k]["product"] != np_[k]["product"]]
            if opened or closed or changed:
                port_changes.append({"ip": ip, "hostnames": n["hostnames"], "opened": opened,
                                     "closed": closed, "changed": changed})
        if o.get("mac") and n.get("mac") and o["mac"] != n["mac"]:
            other.append({"ip": ip, "hostnames": n["hostnames"], "what": "MAC address (different device?)",
                          "old": f"{o['mac']} {o.get('vendor', '')}".strip(),
                          "new": f"{n['mac']} {n.get('vendor', '')}".strip()})
        if o["hostnames"] and n["hostnames"] and o["hostnames"] != n["hostnames"]:
            other.append({"ip": ip, "hostnames": n["hostnames"], "what": "Hostname",
                          "old": ", ".join(o["hostnames"]), "new": ", ".join(n["hostnames"])})

    return {
        "old": old.summary(), "new": new.summary(),
        "new_hosts": [_brief(nh[ip]) for ip in new_ips],
        "missing_hosts": [_brief(oh[ip]) for ip in gone_ips],
        "port_changes": port_changes,
        "other_changes": other,
        "ports_compared": not ping_only,
        "warnings": warnings,
    }


# ---------------------------------------------------------------- settings (email template)

SETTINGS_FILE = DATA.parent / "settings.json"
DEFAULT_SETTINGS = {
    "recipients": "",
    "subject": "Network change detected on {target}",
    "body": (
        "Hello,\n\n"
        "We noticed differences on {target} between the scan on {old_time} "
        "and the scan on {new_time}.\n\n"
        "Summary: {summary}\n\n"
        "New devices detected ({new_count}):\n{new_devices}\n\n"
        "Devices not seen in the latest scan ({missing_count}):\n{missing_devices}\n\n"
        "Port changes on known devices:\n{port_changes}\n\n"
        "Other changes:\n{other_changes}\n"
        "{warnings}\n"
        "Regards,\n"
    ),
}


def load_settings():
    try:
        saved = json.loads(SETTINGS_FILE.read_text())
    except (OSError, ValueError):
        saved = {}
    return {k: str(saved.get(k, v)) for k, v in DEFAULT_SETTINGS.items()}


def save_settings(data):
    clean = {}
    for k, v in DEFAULT_SETTINGS.items():
        val = str(data.get(k, v))
        if len(val) > 20000:
            raise ValueError(f"{k} is too long")
        clean[k] = val
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(clean, indent=2))
    tmp.replace(SETTINGS_FILE)
    return clean


# ---------------------------------------------------------------- scans

class Scan:
    def __init__(self, targets, preset):
        self.id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.targets = targets
        self.preset = preset
        self.args = ["-v", "--stats-every", "2s", *preset["args"]]
        self.status = "running"          # running | done | failed | cancelled
        self.started = time.time()
        self.finished = None
        self.progress = 0.0
        self.log = []
        self.result = None
        self.error = None
        self.proc = None
        self.cond = threading.Condition()

    @property
    def command(self):
        shown = [a for a in self.args if a not in ("--stats-every", "2s")]
        return " ".join(["nmap", *shown, *self.targets])

    def summary(self):
        r = self.result or {}
        return {
            "id": self.id, "target": " ".join(self.targets), "preset": self.preset["id"],
            "preset_name": self.preset["name"], "command": self.command, "status": self.status,
            "started": self.started, "finished": self.finished, "progress": self.progress,
            "hosts_up": r.get("hosts_up"),
            "open_ports": sum(1 for h in r.get("hosts", []) for p in h["ports"] if p["state"] == "open"),
        }

    def full(self):
        return {**self.summary(), "result": self.result, "error": self.error, "log": self.log}

    def _push(self, line):
        with self.cond:
            self.log.append(line)
            self.cond.notify_all()

    def run(self):
        xml_path = DATA / f"{self.id}.xml"
        cmd = [NMAP, *self.args, "-oX", str(xml_path), *self.targets]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, bufsize=1, errors="replace")
            for line in self.proc.stdout:
                line = line.rstrip("\n")
                m = PROGRESS_RE.search(line)
                if m:
                    with self.cond:
                        self.progress = max(self.progress, float(m.group(1)))
                        self.cond.notify_all()
                    continue
                if line.startswith("Stats: "):
                    continue  # periodic timing noise
                self._push(line)
            rc = self.proc.wait()
        except OSError as e:
            rc, self.error = -1, str(e)

        if xml_path.exists():
            try:
                self.result = parse_xml(xml_path)
            except ET.ParseError:
                pass  # cancelled scans leave half-written XML
        with self.cond:
            if self.status == "cancelled":
                pass
            elif rc == 0:
                self.status, self.progress = "done", 100.0
            else:
                self.status = "failed"
                if not self.error:
                    tail = [l for l in self.log if l.strip()][-3:]
                    self.error = " ".join(tail) or f"nmap exited with code {rc}"
            self.finished = time.time()
            self.cond.notify_all()
        self.save()

    def cancel(self):
        with self.cond:
            if self.status != "running":
                return
            self.status = "cancelled"
        if self.proc:
            self.proc.terminate()

    def save(self):
        data = {**self.full(), "targets": self.targets}
        tmp = DATA / f"{self.id}.json.tmp"
        tmp.write_text(json.dumps(data))
        tmp.replace(DATA / f"{self.id}.json")

    @classmethod
    def load(cls, path):
        d = json.loads(path.read_text())
        s = cls.__new__(cls)
        s.id, s.targets = d["id"], d["targets"]
        s.preset = PRESET_BY_ID.get(d["preset"], {"id": d["preset"], "name": d.get("preset_name", ""), "args": []})
        s.args = ["-v", *s.preset["args"]]
        s.status, s.started, s.finished = d["status"], d["started"], d.get("finished")
        s.progress, s.log, s.result, s.error = d.get("progress", 0), d.get("log", []), d.get("result"), d.get("error")
        s.proc, s.cond = None, threading.Condition()
        if s.status == "running":       # server was stopped mid-scan
            s.status, s.error = "failed", "Interrupted (server stopped)"
        return s


class Store:
    def __init__(self):
        DATA.mkdir(parents=True, exist_ok=True)
        self.scans = {}
        self.lock = threading.Lock()
        for f in DATA.glob("*.json"):
            try:
                s = Scan.load(f)
                self.scans[s.id] = s
            except (ValueError, KeyError, OSError):
                pass

    def start(self, targets, preset):
        s = Scan(targets, preset)
        with self.lock:
            self.scans[s.id] = s
        threading.Thread(target=s.run, daemon=True).start()
        return s

    def get(self, sid):
        with self.lock:
            return self.scans.get(sid)

    def list(self):
        with self.lock:
            items = list(self.scans.values())
        return [s.summary() for s in sorted(items, key=lambda s: s.started, reverse=True)]

    def running(self):
        with self.lock:
            return [s for s in self.scans.values() if s.status == "running"]

    def cancel_all(self):
        """Stop running scans and give them a moment to save as 'cancelled'."""
        scans = self.running()
        for s in scans:
            s.cancel()
        deadline = time.time() + 3
        while time.time() < deadline and any(s.finished is None for s in scans):
            time.sleep(0.05)

    def delete(self, sid):
        with self.lock:
            s = self.scans.get(sid)
            if not s or s.status == "running":
                return False
            del self.scans[sid]
        for ext in (".json", ".xml"):
            (DATA / f"{sid}{ext}").unlink(missing_ok=True)
        return True


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "nmap-gui"
    store: Store = None
    allowed_hosts: set = set()
    last_seen = time.time()   # last request from a page; used to stop when idle

    def log_message(self, fmt, *args):
        pass  # keep the terminal quiet

    def _send(self, code, body=b"", ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _guard(self):
        # Blocks other websites from talking to this server (DNS rebinding).
        if self.headers.get("Host", "") not in self.allowed_hosts:
            self._send(403, {"error": "forbidden host"})
            return False
        Handler.last_seen = time.time()
        return True

    def _json_body(self):
        # Requiring a JSON content type means other websites can't silently
        # post to us (browsers block that cross-site without our permission).
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ValueError("expected JSON")
        n = int(self.headers.get("Content-Length", 0) or 0)
        return json.loads(self.rfile.read(min(n, 65536)) or b"{}")

    def do_GET(self):
        if not self._guard():
            return
        path = urlparse(self.path).path
        if path in STATIC_FILES:
            f = STATIC / STATIC_FILES[path]
            return self._send(200, f.read_bytes(), CONTENT_TYPES[f.suffix])
        if path == "/api/info":
            return self._send(200, {"nmap": nmap_version(), "root": IS_ROOT, "presets": PRESETS})
        if path == "/api/scans":
            return self._send(200, self.store.list())
        if path == "/api/settings":
            return self._send(200, {"settings": load_settings(), "defaults": DEFAULT_SETTINGS})
        if path == "/api/compare":
            q = parse_qs(urlparse(self.path).query)
            a = self.store.get(q.get("old", [""])[0])
            b = self.store.get(q.get("new", [""])[0])
            if not a or not b:
                return self._send(404, {"error": "scan not found"})
            if a.id == b.id:
                return self._send(400, {"error": "pick two different scans"})
            if a.status == "running" or b.status == "running" or not a.result or not b.result:
                return self._send(400, {"error": "both scans need results to compare"})
            return self._send(200, diff_scans(a, b))
        m = re.fullmatch(r"/api/scans/([\w-]+)(/events)?", path)
        if m:
            s = self.store.get(m.group(1))
            if not s:
                return self._send(404, {"error": "not found"})
            return self._events(s) if m.group(2) else self._send(200, s.full())
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._guard():
            return
        path = urlparse(self.path).path
        try:
            body = self._json_body()
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        if path == "/api/scans":
            if not NMAP:
                return self._send(500, {"error": "nmap is not installed"})
            preset = PRESET_BY_ID.get(body.get("preset"))
            if not preset:
                return self._send(400, {"error": "Unknown scan type"})
            if preset["root"] and not IS_ROOT:
                return self._send(400, {"error": f"'{preset['name']}' needs administrator rights (sudo)"})
            try:
                targets = parse_targets(body.get("target", ""))
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            return self._send(201, self.store.start(targets, preset).summary())
        if path == "/api/settings":
            try:
                return self._send(200, {"settings": save_settings(body), "defaults": DEFAULT_SETTINGS})
            except ValueError as e:
                return self._send(400, {"error": str(e)})
        if path == "/api/quit":
            self._send(200, {"ok": True})
            self.store.cancel_all()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        m = re.fullmatch(r"/api/scans/([\w-]+)/cancel", path)
        if m and (s := self.store.get(m.group(1))):
            s.cancel()
            return self._send(200, s.summary())
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._guard():
            return
        m = re.fullmatch(r"/api/scans/([\w-]+)", urlparse(self.path).path)
        if m and self.store.delete(m.group(1)):
            return self._send(200, {"ok": True})
        self._send(400, {"error": "cannot delete (missing or still running)"})

    def _events(self, s):
        """Server-sent events: streams new output lines and progress live."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        sent, last_progress = 0, -1
        try:
            while True:
                with s.cond:
                    while (sent == len(s.log) and s.progress == last_progress and s.status == "running"):
                        if not s.cond.wait(timeout=15):
                            break
                    lines, status, progress = s.log[sent:], s.status, s.progress
                sent += len(lines)
                msg = ""
                if lines:
                    msg += f"event: log\ndata: {json.dumps(lines)}\n\n"
                if progress != last_progress:
                    last_progress = progress
                    msg += f"event: progress\ndata: {progress}\n\n"
                if status != "running":
                    msg += f"event: end\ndata: {json.dumps(status)}\n\n"
                self.wfile.write((msg or ": ping\n\n").encode())
                self.wfile.flush()
                if status != "running":
                    return
        except (BrokenPipeError, ConnectionResetError):
            return


def _local(port, method, path, body=None):
    """Talk to an nmap-gui that may already be running on this port."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    headers = {"Host": f"127.0.0.1:{port}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    return r.status, r.read()


def already_running(port):
    try:
        status, data = _local(port, "GET", "/api/info")
        return status == 200 and "presets" in json.loads(data)
    except (OSError, ValueError):
        return False


def notify(msg):
    """Show a message in the terminal and as a desktop notification."""
    print(msg, file=sys.stderr)
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", "--app-name=nmap-gui", f"--icon={APP_ID}", "nmap-gui", msg],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def idle_watchdog(httpd, minutes):
    while True:
        time.sleep(min(15, minutes * 15))
        if not Handler.store.running() and time.time() - Handler.last_seen > minutes * 60:
            print(f"No page open for {minutes} minutes - stopping.")
            httpd.shutdown()
            return


def main():
    ap = argparse.ArgumentParser(description="Browser interface for nmap")
    ap.add_argument("--port", type=int, default=int(os.environ.get("NMAP_GUI_PORT", DEFAULT_PORT)))
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    ap.add_argument("--app", action="store_true",
                    help=f"desktop-launcher mode: stop by itself after {IDLE_MINUTES} minutes with no page open")
    ap.add_argument("--stop", action="store_true", help="stop an nmap-gui that is already running")
    ap.add_argument("--version", action="version", version=f"nmap-gui {__version__}")
    a = ap.parse_args()
    url = f"http://127.0.0.1:{a.port}/"

    if a.stop:
        try:
            _local(a.port, "POST", "/api/quit", "{}")
            print("nmap-gui stopped.")
        except OSError:
            print("nmap-gui is not running.")
        return

    if already_running(a.port):
        print(f"nmap-gui is already running at {url}")
        if not a.no_browser:
            webbrowser.open(url)
        return

    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    except OSError as e:
        notify(f"Can't start: port {a.port} is used by another program ({e.strerror}). "
               f"Try: nmap-gui --port {a.port + 1}")
        sys.exit(1)
    Handler.store = Store()
    port = httpd.server_address[1]
    Handler.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    url = f"http://127.0.0.1:{port}/"
    print(f"nmap-gui {__version__} running at {url}  (press Ctrl+C to stop)")
    if not NMAP:
        notify("nmap was not found. Install it with: sudo dnf install nmap")
    if a.app:
        threading.Thread(target=idle_watchdog, args=(httpd, IDLE_MINUTES), daemon=True).start()
    if not a.no_browser:
        threading.Timer(0.5, webbrowser.open, args=[url]).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        Handler.store.cancel_all()
        httpd.server_close()


if __name__ == "__main__":
    main()
