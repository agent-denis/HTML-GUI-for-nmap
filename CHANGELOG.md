# Changelog

All notable changes to nmap-gui. Dates are in YYYY-MM-DD.

## 1.0.0 – 2026-11-17

The first public release of **nmap-gui**, a modern browser interface for the nmap network scanner.

### Scanning
- Ten ready-made scan types: Find devices, Quick scan, Quick scan without ping, Regular scan, Service
  versions, Versions + safe scripts, All TCP ports, OS detection, UDP scan and Intense scan (the last
  three need sudo). The exact nmap command is shown before you start.
- Live progress bar; devices and open ports appear while the scan runs; Stop and Run again buttons.
- Targets are checked and passed straight to nmap (never through a shell).

### Results
- A card for every device: hostname, MAC address and vendor, OS guess, open ports, software versions
  and script output.
- Port table with a filter, nmap's raw output, and a network map coloured by open ports.
- Scan history, kept between sessions, with delete.

### Changes and email note
- Compare a scan with an earlier one: new devices, devices not seen, opened and closed ports, changed
  software versions, devices that moved to another IP address (same MAC), and a different MAC address
  on a known IP address. Warnings when a comparison could mislead.
- Email note from an editable template with saved default recipients: Send email (opens your email
  program), Copy text and Download report (HTML).

### Desktop
- App menu entry and icon. Clicking it starts nmap-gui and opens the browser, or just opens the page if
  nmap-gui is already running. It stops by itself after 10 idle minutes; Quit button in the page;
  *Stop nmap-gui* in the icon's right-click menu; `--stop`, `--port`, `--no-browser`, `--version`.
- `install.sh` / `uninstall.sh` for a per-user install, and a noarch RPM for Fedora 44 and newer.
- Light and dark theme; works in narrow windows.
