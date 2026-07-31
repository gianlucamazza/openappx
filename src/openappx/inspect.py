"""Inspect a packed .msix: contents, blockmap summary, archive consistency.

This is the read side of `pack`: it re-derives every block hash from the bytes
actually stored in the archive and compares them with what AppxBlockMap.xml
claims, so a package that packs cleanly but would be rejected at install time
fails here instead.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from openappx.blockmap import (
    BLOCK_SIZE,
    NS,
    hash_file_blocks,
    package_path,
    read_local_header,
)

MANIFEST = "AppxManifest.xml"
BLOCKMAP = "AppxBlockMap.xml"
CONTENT_TYPES = "[Content_Types].xml"
SIGNATURE = "AppxSignature.p7x"

# Parts the packer generates; they are never listed inside AppxBlockMap.xml.
GENERATED = (BLOCKMAP, CONTENT_TYPES, SIGNATURE)
REQUIRED = (MANIFEST, BLOCKMAP, CONTENT_TYPES)

_METHODS = {zipfile.ZIP_STORED: "store", zipfile.ZIP_DEFLATED: "deflate"}


def _method(compress_type: int) -> str:
    return _METHODS.get(compress_type, f"method-{compress_type}")


def _identity(manifest_text: str) -> dict:
    """Best-effort Identity attributes; tolerant like `validate.layout_problems`."""
    m = re.search(r"<Identity\b([^>]*)>", manifest_text)
    if not m:
        return {}
    attrs = dict(re.findall(r'([\w:]+)\s*=\s*"([^"]*)"', m.group(1)))
    keys = ("Name", "Publisher", "Version", "ProcessorArchitecture")
    return {k: attrs[k] for k in keys if k in attrs}


def _blockmap_entries(data: bytes, problems: list[str]) -> dict[str, ET.Element]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        problems.append(f"{BLOCKMAP} is not well-formed XML: {e}")
        return {}
    entries: dict[str, ET.Element] = {}
    for el in root.findall(f"{{{NS}}}File"):
        name = el.get("Name")
        if not name:
            problems.append(f"{BLOCKMAP}: <File> without a Name attribute")
            continue
        if name in entries:
            problems.append(f"{BLOCKMAP}: duplicate entry for {name}")
        entries[name] = el
    return entries


def _check_blocks(name: str, el: ET.Element, data: bytes, problems: list[str]) -> int:
    """Recompute block hashes from stored bytes; return the declared block count."""
    declared_size = el.get("Size")
    if declared_size is not None and int(declared_size) != len(data):
        problems.append(
            f"{name}: blockmap Size={declared_size} but archive holds {len(data)} bytes"
        )

    blocks = el.findall(f"{{{NS}}}Block")
    hashes, sizes = hash_file_blocks(data)
    if len(blocks) != len(hashes):
        problems.append(
            f"{name}: blockmap declares {len(blocks)} block(s), content needs {len(hashes)}"
        )
        return len(blocks)

    for i, (block, digest, size) in enumerate(zip(blocks, hashes, sizes)):
        expected = base64.b64encode(digest).decode("ascii")
        if block.get("Hash") != expected:
            problems.append(f"{name}: block {i} hash mismatch")
        declared_block_size = int(block.get("Size", BLOCK_SIZE))
        if declared_block_size != size:
            problems.append(
                f"{name}: block {i} Size={declared_block_size}, actual {size}"
            )
    return len(blocks)


def _check_content_types(data: bytes, names: list[str], problems: list[str]) -> None:
    text = data.decode("utf-8", errors="replace")
    defaults = {m.lower() for m in re.findall(r'<Default\s+Extension="([^"]+)"', text)}
    overrides = set(re.findall(r'<Override\s+PartName="([^"]+)"', text))
    for name in names:
        if name == CONTENT_TYPES:  # not an OPC part; describes the others
            continue
        if f"/{name}" in overrides:
            continue
        ext = Path(name).suffix.lstrip(".").lower()
        if not ext:
            problems.append(
                f"{CONTENT_TYPES}: no content type for {name} (no extension)"
            )
        elif ext not in defaults:
            problems.append(
                f"{CONTENT_TYPES}: no Default for extension .{ext} ({name})"
            )


def inspect_package(pkg: Path) -> dict:
    """Return a report dict; `report["problems"]` empty means the package is coherent."""
    pkg = pkg.resolve()
    if not pkg.is_file():
        raise FileNotFoundError(f"no such package: {pkg}")
    if not zipfile.is_zipfile(pkg):
        raise ValueError(f"not a ZIP/MSIX container: {pkg}")

    raw = pkg.read_bytes()
    problems: list[str] = []
    parts: list[dict] = []
    identity: dict = {}

    with zipfile.ZipFile(pkg) as zf:
        infos = zf.infolist()
        names = [i.filename for i in infos]
        for required in REQUIRED:
            if required not in names:
                problems.append(f"missing required part: {required}")

        declared = (
            _blockmap_entries(zf.read(BLOCKMAP), problems) if BLOCKMAP in names else {}
        )
        if MANIFEST in names:
            identity = _identity(zf.read(MANIFEST).decode("utf-8", errors="replace"))
        if CONTENT_TYPES in names:
            _check_content_types(zf.read(CONTENT_TYPES), names, problems)

        seen: set[str] = set()
        for info in infos:
            name = info.filename
            header = read_local_header(raw, info.header_offset)
            if header.name.decode("utf-8", errors="replace") != name:
                problems.append(
                    f"{name}: central directory and local header disagree on the name"
                )

            part = {
                "name": name,
                "size": info.file_size,
                "compressed": info.compress_size,
                "method": _method(info.compress_type),
                "blocks": None,
            }

            if name not in GENERATED:
                key = package_path(Path(name))
                el = declared.get(key)
                if el is None:
                    problems.append(
                        f"{name}: present in archive but absent from {BLOCKMAP}"
                    )
                else:
                    seen.add(key)
                    part["blocks"] = _check_blocks(name, el, zf.read(name), problems)
                    lfh = el.get("LfhSize")
                    if lfh is not None and int(lfh) != header.size:
                        problems.append(
                            f"{name}: blockmap LfhSize={lfh} but the local header is "
                            f"{header.size} bytes"
                            + (
                                f" ({header.extra_len} bytes of extra fields)"
                                if header.extra_len
                                else ""
                            )
                        )
            parts.append(part)

    for missing in sorted(set(declared) - seen):
        problems.append(f"{missing}: listed in {BLOCKMAP} but absent from the archive")

    return {
        "package": str(pkg),
        "size": len(raw),
        "identity": identity,
        "signed": SIGNATURE in [p["name"] for p in parts],
        "parts": parts,
        "problems": problems,
    }


def render(report: dict) -> str:
    lines = [f"Package: {report['package']} ({report['size']} bytes)"]
    if report["identity"]:
        lines.append(
            "Identity: " + "  ".join(f"{k}={v}" for k, v in report["identity"].items())
        )
    lines.append(f"Signature: {'present' if report['signed'] else 'absent'}")
    lines.append("")

    width = max((len(p["name"]) for p in report["parts"]), default=4)
    lines.append(
        f"{'Part'.ljust(width)}  {'Size':>10}  {'Stored':>10}  {'Method':>7}  Blocks"
    )
    for p in report["parts"]:
        blocks = "-" if p["blocks"] is None else str(p["blocks"])
        lines.append(
            f"{p['name'].ljust(width)}  {p['size']:>10}  {p['compressed']:>10}  "
            f"{p['method']:>7}  {blocks:>6}"
        )
    lines.append("")

    if report["problems"]:
        lines.append(f"FAIL: {len(report['problems'])} problem(s)")
        lines += [f"  - {p}" for p in report["problems"]]
    else:
        lines.append("OK: blockmap and content types are consistent with the archive")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Inspect an .msix package and check it against its own blockmap"
    )
    ap.add_argument("--package", required=True, type=Path)
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = ap.parse_args(argv)

    try:
        report = inspect_package(args.package)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        stream = sys.stderr if report["problems"] else sys.stdout
        print(render(report), file=stream)
    return 1 if report["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
