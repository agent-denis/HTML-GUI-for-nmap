# RPM spec for nmap-gui.
#
# Build locally (needs: sudo dnf install rpm-build rpmdevtools desktop-file-utils appstream):
#
#   ./packaging/build-rpm.sh
#
# nmap-gui uses only the Python standard library and installs outside Python's site-packages,
# so the RPM does not depend on one Python version: the same noarch RPM installs on
# Fedora 44, 45 and newer.

%global app_id  io.github.agent_denis.NmapGui

Name:           nmap-gui
Version:        1.0.0
Release:        1%{?dist}
Summary:        Modern browser interface for the nmap network scanner

License:        GPL-3.0-or-later
URL:            https://github.com/agent-denis/nmap-gui
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3
BuildRequires:  desktop-file-utils
BuildRequires:  appstream

Requires:       python3 >= 3.8
Requires:       nmap
Requires:       xdg-utils
Requires:       hicolor-icon-theme
# desktop notifications when it can't start
Recommends:     libnotify

%description
nmap-gui is a modern, easy interface for the nmap network scanner. It runs a
small server on your own computer (127.0.0.1 only) and opens in your web
browser. It offers ten ready-made scan types, live progress, results as device
cards, a filterable port table and a network map, a saved scan history, and a
comparison between scans that lists new devices and port changes, with a
ready-to-send email note.

%prep
%autosetup -n %{name}-%{version}
# started through /usr/bin/nmap-gui, so the file itself needs no #! line
sed -i '1{/^#!/d}' server.py

%build
# nothing to build: plain Python (standard library only), HTML, CSS and JavaScript

%install
install -Dpm 0644 server.py %{buildroot}%{_datadir}/%{name}/server.py
for f in static/*; do
    install -Dpm 0644 "$f" %{buildroot}%{_datadir}/%{name}/$f
done
install -dm 0755 %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/%{name} <<'EOF'
#!/bin/sh
exec /usr/bin/python3 %{_datadir}/%{name}/server.py "$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/%{name}

desktop-file-install --dir=%{buildroot}%{_datadir}/applications packaging/%{app_id}.desktop
install -Dpm 0644 packaging/%{app_id}.metainfo.xml %{buildroot}%{_metainfodir}/%{app_id}.metainfo.xml
for size in 16 22 24 32 48 64 128 256 512; do
    install -Dpm 0644 packaging/icons/hicolor/${size}x${size}/apps/%{app_id}.png \
        %{buildroot}%{_datadir}/icons/hicolor/${size}x${size}/apps/%{app_id}.png
done
install -Dpm 0644 packaging/icons/hicolor/scalable/apps/%{app_id}.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/%{app_id}.svg

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/%{app_id}.desktop
appstreamcli validate --no-net %{buildroot}%{_metainfodir}/%{app_id}.metainfo.xml
%{__python3} %{buildroot}%{_datadir}/%{name}/server.py --version
# comparison + settings tests (made-up scans, no nmap, localhost only)
%{__python3} tests/test_compare.py

%files
%license LICENSE
%doc README.md CHANGELOG.md PRIVACY.txt
%{_bindir}/%{name}
%{_datadir}/%{name}/
%{_datadir}/applications/%{app_id}.desktop
%{_metainfodir}/%{app_id}.metainfo.xml
%{_datadir}/icons/hicolor/*/apps/%{app_id}.png
%{_datadir}/icons/hicolor/scalable/apps/%{app_id}.svg

%changelog
* Tue Nov 17 2026 Denis <356570572+agent-denis@users.noreply.github.com> - 1.0.0-1
- First release: scan presets, live results, network map, history,
  change reports with email note, desktop launcher
