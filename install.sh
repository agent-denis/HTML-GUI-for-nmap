#!/usr/bin/env bash
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
# Install nmap-gui for the current user (no root, no sudo needed).
#
#   ./install.sh        install, or upgrade an existing install (scan history and settings are kept)
#
# Puts everything under your home folder:
#   ~/.local/share/nmap-gui/app        the program
#   ~/.local/bin/nmap-gui              the command
#   ~/.local/share/applications/...    app menu entry, plus icons and AppStream metadata
# Undo with ./uninstall.sh
set -euo pipefail

APP_ID=io.github.agent_denis.NmapGui
say()  { printf '  %s\n' "$*"; }
step() { printf '\n>> %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "Don't run the installer as root. nmap-gui installs for your own user only."

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SRC/server.py" ] && [ -d "$SRC/static" ] || die "Run install.sh from the nmap-gui folder."
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/server.py")"

DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
case "$DATA" in /*) ;; *) DATA="$HOME/.local/share" ;; esac
BIN="$HOME/.local/bin"
APPDIR="$DATA/nmap-gui/app"
MANIFEST="$DATA/nmap-gui/installed-files.txt"

echo "nmap-gui $VERSION - installer"

step "Checking what nmap-gui needs"
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install it with: sudo dnf install python3"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "Python 3.8 or newer is needed."
say "Python $(python3 -c 'import platform; print(platform.python_version())')"
if command -v nmap >/dev/null 2>&1; then
    say "$(nmap --version | head -1)"
else
    say "WARNING: nmap is not installed yet. Install it with: sudo dnf install nmap"
fi

step "Installing the program"
NEW="$APPDIR.new"
rm -rf "$NEW"
mkdir -p "$NEW"
cp "$SRC/server.py" "$SRC/README.md" "$SRC/LICENSE" "$NEW/"
cp -R "$SRC/static" "$NEW/static"
rm -rf "$APPDIR"
mv "$NEW" "$APPDIR"
say "$APPDIR"

step "Adding the command and the app menu entry"
: > "$MANIFEST"
put() {   # put SOURCE DEST MODE : copy a file and remember it for uninstall.sh
    install -Dm "$3" "$1" "$2"
    echo "$2" >> "$MANIFEST"
}
TMP="$(mktemp)"
cat > "$TMP" <<EOF
#!/bin/sh
# nmap-gui launcher (installed by install.sh)
exec python3 "$APPDIR/server.py" "\$@"
EOF
put "$TMP" "$BIN/nmap-gui" 755
rm -f "$TMP"
put "$SRC/packaging/$APP_ID.desktop" "$DATA/applications/$APP_ID.desktop" 644
put "$SRC/packaging/$APP_ID.metainfo.xml" "$DATA/metainfo/$APP_ID.metainfo.xml" 644
for f in "$SRC"/packaging/icons/hicolor/*/apps/"$APP_ID".*; do
    rel="${f#"$SRC/packaging/icons/"}"
    put "$f" "$DATA/icons/$rel" 644
done
# Don't create icons/hicolor/icon-theme.cache here: without an index.theme next to it,
# GNOME would show the app without its icon. Just touch the folder so the menu refreshes.
touch "$DATA/icons/hicolor" 2>/dev/null || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$DATA/applications" 2>/dev/null || true
say "command:   $BIN/nmap-gui"
say "menu item: nmap-gui (in your app menu / Activities search)"

case ":$PATH:" in
    *":$BIN:"*) ;;
    *) say "NOTE: $BIN is not on your PATH; the menu item still works." ;;
esac

echo
echo "Done. Open nmap-gui from your app menu, or run: nmap-gui"
echo "For scan types that need sudo (OS detection, UDP, Intense), run in a terminal: sudo nmap-gui"
