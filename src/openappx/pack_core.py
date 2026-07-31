"""Pack backends: pure Python and optional makemsix."""
from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import Optional

from openappx.blockmap import (
    build_file_blocks,
    collect_files,
    content_types_xml,
    package_path,
    render_blockmap_xml,
    zip_local_header_size,
)


def _zip_name(pkg_path: str) -> str:
    return pkg_path.replace("\\", "/")


def pack_python(root: Path, out_msix: Path) -> Path:
    root = root.resolve()
    out_msix = out_msix.resolve()
    if not (root / "AppxManifest.xml").is_file():
        raise FileNotFoundError(f"AppxManifest.xml missing under {root}")

    files = collect_files(root)
    if not files:
        raise RuntimeError(f"No payload files under {root}")

    entries = build_file_blocks(root, files)
    lfh_sizes = {}
    for e in entries:
        name_bytes = _zip_name(e.name).encode("utf-8")
        lfh_sizes[e.name] = zip_local_header_size(name_bytes, b"")

    blockmap = render_blockmap_xml(entries, lfh_sizes)
    content_types = content_types_xml([e.name for e in entries])

    out_msix.parent.mkdir(parents=True, exist_ok=True)
    if out_msix.exists():
        out_msix.unlink()

    with zipfile.ZipFile(
        out_msix, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as zf:
        for p in files:
            arc = _zip_name(package_path(p.relative_to(root)))
            info = zipfile.ZipInfo(arc)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.flag_bits |= 0x800
            zf.writestr(info, p.read_bytes())

        for arc, data in (
            ("[Content_Types].xml", content_types),
            ("AppxBlockMap.xml", blockmap),
        ):
            info = zipfile.ZipInfo(arc)
            info.compress_type = zipfile.ZIP_STORED
            info.flag_bits |= 0x800
            zf.writestr(info, data)

    return out_msix


def pack_makemsix(
    root: Path,
    out_msix: Path,
    makemsix_bin: Path,
    cert: Optional[Path] = None,
    cert_password: Optional[str] = None,
) -> Path:
    root = root.resolve()
    out_msix = out_msix.resolve()
    out_msix.parent.mkdir(parents=True, exist_ok=True)
    if out_msix.exists():
        out_msix.unlink()

    cmd = [str(makemsix_bin), "pack", "-d", str(root), "-p", str(out_msix)]
    if cert:
        cmd += ["-c", str(cert.resolve())]
        if cert_password is not None:
            cmd += ["-b", cert_password]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"makemsix failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
        )
    if not out_msix.is_file():
        raise RuntimeError(f"makemsix reported success but {out_msix} missing")
    return out_msix
