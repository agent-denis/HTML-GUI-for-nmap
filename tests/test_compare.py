#!/usr/bin/env python3
# nmap-gui - a modern browser interface for the nmap network scanner
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
# This program is free software: you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version. It comes WITHOUT ANY WARRANTY.
# See the LICENSE file or <https://www.gnu.org/licenses/>.
"""Tests for comparing scans and for the email-template settings.

Run:  python3 tests/test_compare.py
Uses made-up scans in a temporary folder; does not run nmap.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="nmap-gui-cmp-")
os.environ["XDG_DATA_HOME"] = TMP
sys.path.insert(0, str(ROOT))
import server  # noqa: E402  (must come after XDG_DATA_HOME is set)
sys.path.insert(0, str(ROOT / "tests"))
from test_smoke import free_port, request  # noqa: E402

failed = False


def check(cond, msg):
    global failed
    print(("  ok    " if cond else "  FAIL  ") + msg)
    failed |= not cond


def port(n, service="", product="", state="open"):
    return {"port": n, "proto": "tcp", "state": state, "reason": "", "service": service,
            "product": product, "scripts": []}


def host(ip, ports=(), mac="", vendor="", names=()):
    return {"ip": ip, "ipv6": "", "mac": mac, "vendor": vendor, "hostnames": list(names), "reason": "",
            "ports": list(ports), "hidden_ports": [], "os": None, "distance": None, "trace": [], "scripts": []}


def make_scan(sid, started, hosts, preset="quick", status="done", target="192.168.1.0/24"):
    d = {"id": sid, "targets": target.split(), "target": target, "preset": preset, "status": status,
         "started": started, "finished": started + 10, "progress": 100, "log": [], "error": None,
         "result": {"hosts": hosts, "summary": "", "elapsed": 10, "hosts_up": len(hosts),
                    "hosts_down": 0, "hosts_total": 256}}
    path = server.DATA / f"{sid}.json"
    path.write_text(json.dumps(d))
    return server.Scan.load(path)


def main():
    server.DATA.mkdir(parents=True, exist_ok=True)
    t = time.time() - 86400

    old = make_scan("20261116-090000-aaaaaa", t, [
        host("192.168.1.1", [port(22, "ssh", "OpenSSH 9.5"), port(80, "http")], "AA:00:00:00:00:01", "TP-Link", ["router.lan"]),
        host("192.168.1.20", [], "AA:00:00:00:00:20", "Apple", ["phone"]),
        host("192.168.1.30", [port(631, "ipp")], "AA:00:00:00:00:30", "HP", ["printer"]),
        host("192.168.1.40", [], "AA:00:00:00:00:40", "Intel", ["laptop"]),
    ])
    new = make_scan("20261117-090000-bbbbbb", t + 86400, [
        host("192.168.1.1", [port(22, "ssh", "OpenSSH 9.6"), port(8080, "http-proxy")], "AA:00:00:00:00:01", "TP-Link", ["router.lan"]),
        host("192.168.1.30", [port(631, "ipp")], "AA:00:00:00:00:99", "Unknown", ["printer"]),
        host("192.168.1.41", [], "AA:00:00:00:00:40", "Intel", ["laptop"]),       # laptop got a new IP
        host("192.168.1.77", [port(80, "http", "lighttpd")], "BB:00:00:00:00:77", "Espressif"),  # genuinely new
    ])

    print("Comparing two scans")
    d = server.diff_scans(new, old)   # wrong order on purpose: must be sorted by time
    check(d["old"]["id"] == old.id and d["new"]["id"] == new.id, "older scan is always 'old'")
    check([h["ip"] for h in d["new_hosts"]] == ["192.168.1.77"], f"new devices: {[h['ip'] for h in d['new_hosts']]}")
    check([h["ip"] for h in d["missing_hosts"]] == ["192.168.1.20"], f"not seen: {[h['ip'] for h in d['missing_hosts']]}")
    moved = [c for c in d["other_changes"] if c["what"] == "IP address"]
    check(len(moved) == 1 and moved[0]["old"] == "192.168.1.40" and moved[0]["new"] == "192.168.1.41",
          "laptop that changed IP is reported as moved, not new+missing")
    macs = [c for c in d["other_changes"] if c["what"].startswith("MAC")]
    check(len(macs) == 1 and macs[0]["ip"] == "192.168.1.30", "different MAC on the printer's IP is reported")
    pc = {c["ip"]: c for c in d["port_changes"]}
    r = pc.get("192.168.1.1", {})
    check([p["port"] for p in r.get("opened", [])] == [8080], "router: 8080 newly open")
    check([p["port"] for p in r.get("closed", [])] == [80], "router: 80 now closed")
    check(r.get("changed") and r["changed"][0]["old"] == "OpenSSH 9.5", "router: SSH version change noticed")
    check("192.168.1.30" not in pc, "printer ports unchanged -> no port change entry")
    check(d["warnings"] == [], f"no warnings ({d['warnings']})")

    print("Warnings")
    ping = make_scan("20261117-100000-cccccc", t + 90000, [host("192.168.1.1")], preset="ping")
    d2 = server.diff_scans(old, ping)
    check(not d2["ports_compared"] and d2["port_changes"] == [], "ping scan: ports not compared")
    check(any("only looked for devices" in w for w in d2["warnings"]), "ping scan: warning shown")
    svc = make_scan("20261117-110000-dddddd", t + 95000, [], preset="services", status="cancelled")
    d3 = server.diff_scans(old, svc)
    check(any("different scan types" in w for w in d3["warnings"]), "different presets: warning")
    check(any("did not finish" in w for w in d3["warnings"]), "cancelled scan: warning")
    same = server.diff_scans(old, make_scan("20261117-120000-eeeeee", t + 99000,
                                            json.loads(json.dumps(old.result["hosts"]))))
    check(not (same["new_hosts"] or same["missing_hosts"] or same["port_changes"] or same["other_changes"]),
          "identical scans: no changes")

    print("Through the web server")
    p = free_port()
    srv = subprocess.Popen([sys.executable, str(ROOT / "server.py"), "--port", str(p), "--no-browser"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                request(p, "GET", "/api/info")
                break
            except OSError:
                time.sleep(0.1)
        st, d = request(p, "GET", f"/api/compare?old={old.id}&new={new.id}")
        check(st == 200 and len(d["new_hosts"]) == 1, f"GET /api/compare works ({st})")
        st, _ = request(p, "GET", f"/api/compare?old={old.id}&new={old.id}")
        check(st == 400, "same scan twice refused")
        st, _ = request(p, "GET", f"/api/compare?old={old.id}&new=nope")
        check(st == 404, "unknown scan -> 404")
        st, _ = request(p, "GET", f"/api/compare?old={old.id}&new={new.id}", host="evil.example.com")
        check(st == 403, "foreign Host refused")
        st, s = request(p, "GET", "/api/settings")
        check(st == 200 and "{new_devices}" in s["settings"]["body"], "default template served")
        st, s = request(p, "POST", "/api/settings", {"recipients": "it@example.com", "subject": "Hi {target}", "body": "B"})
        check(st == 200 and s["settings"]["recipients"] == "it@example.com", "template saved")
        st, s = request(p, "GET", "/api/settings")
        check(s["settings"]["subject"] == "Hi {target}", "saved template read back")
        st, _ = request(p, "POST", "/api/settings", {"body": "x" * 30000})
        check(st == 400, "huge template refused")
        for path in ("/compare.js",):
            st, _ = request(p, "GET", path)
            check(st == 200, f"GET {path}")
    finally:
        srv.terminate()
        srv.wait()
        err = srv.stderr.read().decode()
        if err.strip():
            print("server stderr:\n" + err)

    print("\nRESULT:", "FAILED" if failed else "ALL PASSED")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
