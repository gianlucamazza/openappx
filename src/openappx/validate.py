"""Layout validation for Appx/MSIX package roots."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def layout_problems(root: Path) -> list[str]:
    """Return human-readable problems (empty list => ok for pack)."""
    problems: list[str] = []
    root = root.resolve()
    manifest = root / "AppxManifest.xml"
    if not manifest.is_file():
        return ["missing AppxManifest.xml"]

    text = manifest.read_text(encoding="utf-8", errors="replace")

    m = re.search(r'Executable="([^"]+)"', text)
    if m:
        exe = root / m.group(1).replace("\\", "/")
        if not exe.is_file():
            problems.append(f"manifest Executable not found: {m.group(1)}")

    for asset in re.findall(
        r'(?:Logo|Square\d+x\d+Logo|Wide\d+x\d+Logo|Image)="([^"]+)"', text
    ):
        p = root / asset.replace("\\", "/")
        if not p.is_file():
            problems.append(f"manifest asset missing: {asset}")

    if 'Name="' not in text and "Name='" not in text:
        # Identity Name is required; soft check
        if "<Identity" in text and "Name=" not in text:
            problems.append("Identity/@Name missing")

    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate an Appx/MSIX layout directory")
    ap.add_argument("--root", required=True, type=Path)
    args = ap.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    problems = layout_problems(root)
    if not problems:
        print(f"OK: {root}")
        return 0
    print(f"FAIL: {root}", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
