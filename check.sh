#!/bin/sh
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
# Quick health check: syntax + full end-to-end smoke test (scans 127.0.0.1 only).
set -e
cd "$(dirname "$0")"
python3 -m py_compile server.py tests/test_smoke.py tests/test_compare.py
python3 tests/test_smoke.py
python3 tests/test_compare.py
