#!/usr/bin/env bash
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
# Build the nmap-gui RPM from the files in this folder (committed or not).
# Result: ~/rpmbuild/RPMS/noarch/nmap-gui-<version>-1.<fedora>.noarch.rpm
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' server.py)"
rpmdev-setuptree
git ls-files -co --exclude-standard \
    | tar -czf ~/rpmbuild/SOURCES/nmap-gui-"$VERSION".tar.gz --transform "s,^,nmap-gui-$VERSION/," -T -
rpmbuild -ba packaging/nmap-gui.spec
echo
echo "Built:"
ls -1 ~/rpmbuild/RPMS/noarch/nmap-gui-"$VERSION"-*.rpm
