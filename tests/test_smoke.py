#!/usr/bin/env python3
# nmap-gui - a modern browser interface for the nmap network scanner
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
# This program is free software: you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version. It comes WITHOUT ANY WARRANTY.
# See the LICENSE file or <https://www.gnu.org/licenses/>.
"""End-to-end smoke test: starts the server, scans 127.0.0.1, checks results.

Run:  python3 tests/test_smoke.py
Scan history goes to a temporary folder, so your real history is untouched.
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(port, method, path, body=None, host=None, ctype="application/json"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if body is not None:
        headers["Content-Type"] = ctype
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    r = c.getresponse()
    data = r.read()
    try:
        data = json.loads(data)
    except ValueError:
        pass
    return r.status, data


def check(cond, msg):
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        global failed
        failed = True


failed = False


def main():
    port = free_port()
    tmp = tempfile.mkdtemp(prefix="nmap-gui-test-")
    env = {**os.environ, "XDG_DATA_HOME": tmp}
    srv = subprocess.Popen([sys.executable, str(ROOT / "server.py"), "--port", str(port), "--no-browser"],
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                request(port, "GET", "/api/info")
                break
            except OSError:
                time.sleep(0.1)

        print("Pages")
        for path in ("/", "/app.js", "/app.css", "/icon.svg"):
            st, _ = request(port, "GET", path)
            check(st == 200, f"GET {path} -> {st}")

        print("Safety checks")
        st, _ = request(port, "GET", "/api/info", host="evil.example.com")
        check(st == 403, f"foreign Host header refused ({st})")
        st, _ = request(port, "POST", "/api/scans", {"target": "127.0.0.1", "preset": "quick"}, ctype="text/plain")
        check(st == 400, f"non-JSON post refused ({st})")
        for bad in ["-oN /tmp/x 127.0.0.1", "127.0.0.1;rm -rf ~", "$(id)", ""]:
            st, d = request(port, "POST", "/api/scans", {"target": bad, "preset": "quick"})
            check(st == 400, f"bad target {bad!r} refused: {d.get('error') if isinstance(d, dict) else d}")
        st, _ = request(port, "POST", "/api/scans", {"target": "127.0.0.1", "preset": "nope"})
        check(st == 400, "unknown preset refused")

        print("Info")
        st, info = request(port, "GET", "/api/info")
        check(st == 200 and info["nmap"], f"nmap detected: {info.get('nmap')}")
        check(len(info["presets"]) == 10, f"{len(info['presets'])} presets")

        print("Scan 127.0.0.1 (quick)")
        st, s = request(port, "POST", "/api/scans", {"target": "127.0.0.1", "preset": "quick"})
        check(st == 201 and s["status"] == "running", f"scan started ({st})")
        sid = s["id"]

        # Read live events until the scan ends.
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        c.request("GET", f"/api/scans/{sid}/events", headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse()
        events = []
        while True:
            line = r.fp.readline().decode()
            if not line:
                break
            if line.startswith("event: "):
                events.append(line[7:].strip())
                if events[-1] == "end":
                    break
        check("log" in events and "end" in events, f"live events received: {sorted(set(events))}")

        st, full = request(port, "GET", f"/api/scans/{sid}")
        check(full["status"] == "done", f"status done ({full['status']}, error={full.get('error')})")
        res = full["result"] or {}
        check(res.get("hosts_up") == 1, f"1 host up ({res.get('hosts_up')})")
        hosts = res.get("hosts", [])
        check(hosts and hosts[0]["ip"] == "127.0.0.1", "host is 127.0.0.1")
        opened = [p["port"] for h in hosts for p in h["ports"] if p["state"] == "open"]
        print(f"        open ports on this PC: {opened or 'none'}")

        print("History")
        st, lst = request(port, "GET", "/api/scans")
        check(any(x["id"] == sid for x in lst), "scan listed in history")
        check((Path(tmp) / "nmap-gui/scans" / f"{sid}.json").exists(), "saved to disk")

        print("Stop a running scan")
        st, s2 = request(port, "POST", "/api/scans", {"target": "127.0.0.1", "preset": "allports"})
        time.sleep(1)
        request(port, "POST", f"/api/scans/{s2['id']}/cancel", {})
        for _ in range(50):
            _, s2f = request(port, "GET", f"/api/scans/{s2['id']}")
            if s2f["status"] != "running":
                break
            time.sleep(0.1)
        check(s2f["status"] == "cancelled", f"scan stopped ({s2f['status']})")

        print("Delete")
        st, _ = request(port, "DELETE", f"/api/scans/{s2['id']}")
        check(st == 200, "deleted")
        st, _ = request(port, "GET", f"/api/scans/{s2['id']}")
        check(st == 404, "gone afterwards")

        print("History survives restart")
        srv.terminate(); srv.wait()
        srv = subprocess.Popen([sys.executable, str(ROOT / "server.py"), "--port", str(port), "--no-browser"],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(50):
            try:
                st, lst = request(port, "GET", "/api/scans")
                break
            except OSError:
                time.sleep(0.1)
        check(any(x["id"] == sid for x in lst), "old scan still there after restart")
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
