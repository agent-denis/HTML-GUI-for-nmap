#!/usr/bin/env bash
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
# Remove nmap-gui installed by install.sh.
#
#   ./uninstall.sh            remove the program, command and menu entry (keeps scan history and settings)
#   ./uninstall.sh --purge    also delete scan history and settings
set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
case "$DATA" in /*) ;; *) DATA="$HOME/.local/share" ;; esac
BASE="$DATA/nmap-gui"
MANIFEST="$BASE/installed-files.txt"

# stop it if it is running
command -v nmap-gui >/dev/null 2>&1 && nmap-gui --stop >/dev/null 2>&1 || true

if [ -f "$MANIFEST" ]; then
    while IFS= read -r f; do
        # only remove files inside the home folder that install.sh put there
        case "$f" in "$HOME"/*) rm -f -- "$f" ;; esac
    done < "$MANIFEST"
    rm -f "$MANIFEST"
fi
rm -rf "$BASE/app" "$BASE/app.new"
touch "$DATA/icons/hicolor" 2>/dev/null || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$DATA/applications" 2>/dev/null || true

if [ "$PURGE" -eq 1 ]; then
    rm -rf "$BASE"
    echo "nmap-gui removed, including scan history and settings."
else
    rmdir "$BASE" 2>/dev/null || true
    echo "nmap-gui removed. Scan history and settings are kept in $BASE"
    echo "(delete them with: ./uninstall.sh --purge)"
fi
