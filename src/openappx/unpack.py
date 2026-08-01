"""Extract a layout from a packed .msix.

The inverse of `pack`, and the operation you need before repackaging someone
else's package: it writes back exactly the payload, dropping the parts a packer
regenerates (`AppxBlockMap.xml`, `[Content_Types].xml`, `AppxSignature.p7x`,
`AppxMetadata/CodeIntegrity.cat`), so the result can be fed straight back to
`openappx pack`.

Archive members are attacker-controlled data: names are checked to stay inside
the destination, so a crafted package cannot write through `..` or an absolute
path.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

from openappx.inspect import GENERATED


def safe_target(destination: Path, name: str) -> Path:
    """Resolve an archive member against `destination`, refusing to escape it."""
    if name.startswith(("/", "\\")) or ":" in name.split("/")[0]:
        raise ValueError(f"absolute path in archive: {name}")
    target = (destination / name.replace("\\", "/")).resolve()
    if not target.is_relative_to(destination.resolve()):
        raise ValueError(f"path escapes the destination: {name}")
    return target


def unpack_package(
    package: Path, destination: Path, *, keep_generated: bool = False
) -> list[Path]:
    """Write the package contents into `destination`; return the files written."""
    package = Path(package)
    destination = Path(destination)
    if not zipfile.is_zipfile(package):
        raise ValueError(f"not a ZIP/MSIX container: {package}")

    written: list[Path] = []
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(package) as zf:
        seen: set[str] = set()
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            if not keep_generated and name in GENERATED:
                continue
            if name in seen:
                raise ValueError(f"duplicate archive member: {name}")
            seen.add(name)
            target = safe_target(destination, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(name))
            written.append(target)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Extract an .msix into a layout directory that `pack` accepts"
    )
    ap.add_argument("--package", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path, help="destination directory")
    ap.add_argument(
        "--keep-generated",
        action="store_true",
        help="also extract blockmap, content types, signature and CodeIntegrity",
    )
    args = ap.parse_args(argv)

    try:
        written = unpack_package(
            args.package, args.out, keep_generated=args.keep_generated
        )
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (ValueError, OSError, zipfile.BadZipFile) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    total = sum(p.stat().st_size for p in written)
    print(f"Extracted {len(written)} file(s), {total} bytes, to {args.out}")
    if not args.keep_generated:
        print("Generated parts were skipped; `openappx pack` rebuilds them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
