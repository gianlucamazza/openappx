"""Layout validation for Appx/MSIX package roots."""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def layout_problems(root: Path) -> list[str]:
    """Return human-readable problems (empty list => ok for pack)."""
    problems: list[str] = []
    root = root.resolve()
    manifest = root / "AppxManifest.xml"
    if not manifest.is_file():
        return ["missing AppxManifest.xml"]

    raw = manifest.read_text(encoding="utf-8", errors="replace")
    # Everything below greps, so a manifest documenting itself — and these
    # manifests do, the interesting attributes all need explaining — would match
    # its own comments. Well-formedness still looks at the raw text.
    text = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL)

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

    problems += _wellformed_problems(raw)
    problems += _identity_problems(text)
    problems += _capability_problems(text)
    problems += _entry_point_problems(root, text)
    problems += _build_artefact_problems(root)
    return problems


def _wellformed_problems(text: str) -> list[str]:
    """Reject XML a device would reject, while the rest of this module stays lax.

    Everything else here greps deliberately, so a broken manifest can still be
    reported rather than crashing the tool. Well-formedness is different: a
    device answers `0xC00CEE23` with a line and column and no explanation, and
    the rules are stricter than they look — `--` inside a comment is invalid XML,
    for instance, which is easy to introduce while documenting a manifest.
    """
    try:
        ET.fromstring(text)
    except ET.ParseError as e:
        return [f"AppxManifest.xml is not well-formed XML: {e}"]
    return []


def _identity_attribute(text: str, attribute: str) -> str | None:
    """Read one attribute off the <Identity> element, if it is there at all."""
    identity = re.search(r"<Identity\b([^>]*)>", text)
    if not identity:
        return None
    found = re.search(rf'\b{attribute}\s*=\s*"([^"]*)"', identity.group(1))
    return found.group(1) if found else None


def _identity_problems(text: str) -> list[str]:
    if "<Identity" not in text:
        return ["Identity element missing"]
    return [
        f"Identity/@{attribute} missing"
        for attribute in ("Name", "Publisher", "Version")
        if not _identity_attribute(text, attribute)
    ]


def _capability_problems(text: str) -> list[str]:
    """Catch manifest rules a device only reports as an opaque error code.

    `Windows.FullTrustApplication` without the `runFullTrust` capability fails
    at install with 0x80080204, naming a line number and nothing else.
    """
    if "Windows.FullTrustApplication" not in text:
        return []
    if re.search(r'Capability\s+Name="runFullTrust"', text):
        return []
    return [
        'EntryPoint="Windows.FullTrustApplication" needs '
        '<rescap:Capability Name="runFullTrust" /> in <Capabilities>'
    ]


def _entry_point_problems(root: Path, text: str) -> list[str]:
    """A managed EntryPoint is resolved against a .winmd that has to be present.

    `EntryPoint="hello.App"` names an activatable class, which the loader looks
    up in the metadata shipped inside the package. Leave the .winmd out and the
    package installs and then fails to launch, which reads like an application
    bug rather than a packaging one. `Windows.FullTrustApplication` is the
    exception: it names no class.
    """
    problems = []
    for entry in re.findall(r'EntryPoint="([^"]+)"', text):
        if entry == "Windows.FullTrustApplication" or "." not in entry:
            continue
        namespace = entry.split(".")[0]
        if any(root.glob("*.winmd")) and not (root / f"{namespace}.winmd").is_file():
            problems.append(
                f'EntryPoint="{entry}" expects {namespace}.winmd, '
                f"but the layout has {', '.join(p.name for p in root.glob('*.winmd'))}"
            )
        elif not any(root.glob("*.winmd")):
            problems.append(
                f'EntryPoint="{entry}" names an activatable class, but the '
                f"layout carries no .winmd to resolve it against"
            )
    return problems


# Anything in the layout is packed, so a stray build directory ships silently —
# a precompiled header alone is around 190 MB.
_BUILD_ARTEFACTS = ("*.obj", "*.pch", "*.ilk", "*.pdb", "*.lib", "*.exp")


def _build_artefact_problems(root: Path) -> list[str]:
    found = sorted(
        {p.name for pattern in _BUILD_ARTEFACTS for p in root.rglob(pattern)}
    )
    if not found:
        return []
    shown = ", ".join(found[:4]) + (" …" if len(found) > 4 else "")
    return [f"build artefacts in the layout would be packed: {shown}"]


def publisher(root: Path) -> str | None:
    """`Identity/@Publisher`, which must equal the signing certificate subject."""
    manifest = Path(root) / "AppxManifest.xml"
    if not manifest.is_file():
        return None
    return _identity_attribute(
        manifest.read_text(encoding="utf-8", errors="replace"), "Publisher"
    )


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
