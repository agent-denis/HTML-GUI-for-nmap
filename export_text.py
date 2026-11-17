#!/usr/bin/env python3
# Copyright (C) 2026 Denis (https://github.com/agent-denis)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Plain-text versions of the project for people who prefer (or need) .txt files.

    README.txt                 README.md converted to plain text (committed)
    nmap-gui-source.txt    every source file in one text file (committed; refresh it before a release)

Usage:
    python3 tools/export_text.py            # both
    python3 tools/export_text.py readme     # only README.txt
    python3 tools/export_text.py source     # only nmap-gui-source.txt
"""
import datetime
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIDTH = 80


# --------------------------------------------------------------------------- README.md -> README.txt
def _inline(text: str) -> str:
    text = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", r"[Screenshot: \1 – \2]", text)
    text = re.sub(r"\[([^\]]+)\]\(#[^)]*\)", r"\1", text)                       # links inside the README
    text = re.sub(r"\[`?([^\]`]+)`?\]\(([^)]+)\)",
                  lambda m: m.group(1) if m.group(1) == m.group(2) else f"{m.group(1)} ({m.group(2)})", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text


def _table(rows: list[str]) -> list[str]:
    cells = [[_inline(c.strip()) for c in r.strip().strip("|").split("|")] for r in rows]
    cells = [r for r in cells if not all(re.fullmatch(r":?-+:?", c) for c in r)]
    head, body = cells[0], cells[1:]
    widths = [max(len(r[i]) for r in cells if i < len(r)) for i in range(len(head))]
    if sum(widths) + 3 * len(widths) <= WIDTH:
        line = lambda r: "  " + "   ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip()
        return [line(head), "  " + "   ".join("-" * w for w in widths)] + [line(r) for r in body]
    out = []                                          # too wide for columns: one block per row
    for r in body:
        extra = "; ".join(f"{h.lower()}: {c}" for h, c in zip(head[2:], r[2:]) if c)
        text = f"{r[0]}: {r[1]}" + (f" ({extra})" if extra else "")
        out += textwrap.wrap(text, WIDTH, initial_indent="  - ", subsequent_indent="    ")
    return out


def readme_text(md: str) -> str:
    head, md = md.split("\n", 1)
    title = head.lstrip("# ").strip()
    intro, md = md.strip("\n").split("\n\n", 1)
    out = [title.upper(), "=" * len(title), ""] + textwrap.wrap(_inline(" ".join(intro.split())), WIDTH) + [""]
    lines = md.splitlines()
    i = 0
    para: list[str] = []

    def flush():
        if para:
            text = _inline(" ".join(s.strip() for s in para))
            m = re.match(r"^(\s*)(- |\d+\. )(.*)", para[0])
            if m:
                ind = " " * (2 + len(m.group(2)))
                out.extend(textwrap.wrap(_inline(" ".join([m.group(3)] + [s.strip() for s in para[1:]])), WIDTH,
                                         initial_indent="  " + m.group(2), subsequent_indent=ind))
            else:
                out.extend(textwrap.wrap(text, WIDTH))
            para.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                out.append("    " + lines[i])
                i += 1
            out.append("")
        elif line.startswith("## Contents"):
            flush()
            i += 1
            while i < len(lines) and not lines[i].startswith("## "):   # the link list only makes sense on GitHub
                i += 1
            continue
        elif line.startswith("## "):
            flush()
            head = _inline(line[3:]).upper()
            out += ["", head, "-" * len(head), ""]
        elif line.startswith("### "):
            flush()
            head = _inline(line[4:])
            out += [head, "~" * len(head), ""]
        elif line.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i])
                i += 1
            out += _table(rows) + [""]
            continue
        elif line.startswith(">"):
            flush()
            out.extend(textwrap.wrap(_inline(line.lstrip("> ")), WIDTH, initial_indent="  | ", subsequent_indent="  | "))
        elif not line.strip():
            flush()
            if out and out[-1] != "":
                out.append("")
        elif re.match(r"^\s*(- |\d+\. )", line):
            flush()
            para.append(line)
        else:
            para.append(line)
        i += 1
    flush()
    text = "\n".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"
    return text + "\n(Plain-text version of README.md, made by tools/export_text.py.)\n"


def write_readme():
    (ROOT / "README.txt").write_text(readme_text((ROOT / "README.md").read_text(encoding="utf-8")), encoding="utf-8")
    print("wrote README.txt")


# --------------------------------------------------------------------------- source code export
SKIP = re.compile(r"^(docs/screenshots/|Screenshots/|LICENSE$|README\.txt$)|\.(png|svg)$")


def write_source():
    files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT, capture_output=True,
                           text=True, check=True).stdout.split()
    files = sorted(f for f in files if not SKIP.search(f) and f != "nmap-gui-source.txt" and (ROOT / f).is_file())
    texts = {f: (ROOT / f).read_text(encoding="utf-8") for f in files}
    count = {f: len(t.splitlines()) for f, t in texts.items()}
    version = re.search(r'__version__ = "(.*)"', texts["server.py"]).group(1)
    out = ["NMAP-GUI – SOURCE CODE",
           f"Version {version} · exported {datetime.datetime.now():%Y-%m-%d %H:%M}",
           "Licence: GNU General Public License v3.0 or later (the full text is in LICENSE in the repository)",
           "Homepage: https://github.com/agent-denis/nmap-gui",
           f"{len(files)} files, {sum(count.values())} lines. Not included: the LICENSE text, screenshots and icons.",
           "", "FILES"]
    out += [f"  {f:<64}{count[f]:>7} lines" for f in files]
    out += ["", ""]
    bar = "=" * 100
    for f in files:
        out += [bar, f"FILE: {f}   ({count[f]} lines)", bar, texts[f].rstrip("\n"), "", ""]
    (ROOT / "nmap-gui-source.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote nmap-gui-source.txt ({len(files)} files, {sum(count.values())} lines)")


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("all", "readme"):
        write_readme()
    if what in ("all", "source"):
        write_source()
