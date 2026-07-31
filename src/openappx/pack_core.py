"""Pack backends: pure Python and optional makemsix."""

from __future__ import annotations

import struct
import subprocess
import zlib
from dataclasses import dataclass
from pathlib import Path

from openappx.blockmap import (
    collect_files,
    content_types_xml,
    package_path,
    prepare_file,
    render_blockmap_xml,
    zip_local_header_size,
)


def _zip_name(pkg_path: str) -> str:
    return pkg_path.replace("\\", "/")


# The archive is written by hand rather than through `zipfile`, because the
# blockmap must report the compressed length of each 64 KiB block: that requires
# feeding a pre-built deflate stream into the entry, which `writestr` cannot do.
# Writing it ourselves also pins LfhSize (no extra fields) and the timestamps.
_LFH_SIGNATURE = 0x04034B50
_CDH_SIGNATURE = 0x02014B50
_EOCD_SIGNATURE = 0x06054B50
_ZIP64_EOCD_SIGNATURE = 0x06064B50
_ZIP64_LOCATOR_SIGNATURE = 0x07064B50

# Appx archives are ZIP64: Windows fails to open the package otherwise
# (0x8007000B at install time). Microsoft's own packages mark every central
# directory entry as made by 4.5 and put the ZIP64 sentinels in the classic
# EOCD, while entries themselves need only 2.0 features.
_VERSION_MADE_BY = 45
_VERSION = 20
_ZIP64_SENTINEL_32 = 0xFFFFFFFF
_ZIP64_SENTINEL_16 = 0xFFFF
_DOS_EPOCH_TIME = 0
_DOS_EPOCH_DATE = 0x0021  # 1980-01-01, so output stays byte-reproducible
_METHOD_STORE = 0
_METHOD_DEFLATE = 8


@dataclass(frozen=True)
class _Entry:
    name: bytes  # UTF-8, forward slashes
    compressed_size: int
    uncompressed_size: int
    method: int
    crc: int
    offset: int


def _write_entry(
    out: bytearray, name: str, payload: bytes, plain: bytes, method: int
) -> _Entry:
    name_bytes = name.encode("utf-8")
    entry = _Entry(
        name=name_bytes,
        compressed_size=len(payload),
        uncompressed_size=len(plain),
        method=method,
        crc=zlib.crc32(plain) & 0xFFFFFFFF,
        offset=len(out),
    )
    out += struct.pack(
        "<IHHHHHIIIHH",
        _LFH_SIGNATURE,
        _VERSION,
        0,  # flags: no UTF-8 bit; CPython strips it for ASCII names anyway
        method,
        _DOS_EPOCH_TIME,
        _DOS_EPOCH_DATE,
        entry.crc,
        len(payload),
        entry.uncompressed_size,
        len(name_bytes),
        0,  # no extra field, so LfhSize == 30 + len(name)
    )
    out += name_bytes
    out += payload
    return entry


def _write_central_directory(out: bytearray, entries: list[_Entry]) -> None:
    start = len(out)
    for e in entries:
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            _CDH_SIGNATURE,
            _VERSION_MADE_BY,
            _VERSION,  # version needed
            0,  # flags
            e.method,
            _DOS_EPOCH_TIME,
            _DOS_EPOCH_DATE,
            e.crc,
            e.compressed_size,
            e.uncompressed_size,
            len(e.name),
            0,  # extra length
            0,  # comment length
            0,  # disk number
            0,  # internal attributes
            0,  # external attributes
            e.offset,
        )
        out += e.name
    size = len(out) - start

    # ZIP64 end of central directory, then its locator, then a classic EOCD whose
    # fields are all sentinels — the layout Microsoft's packages use.
    zip64_eocd = len(out)
    out += struct.pack(
        "<IQHHIIQQQQ",
        _ZIP64_EOCD_SIGNATURE,
        44,  # size of the remainder of this record
        _VERSION_MADE_BY,
        _VERSION_MADE_BY,
        0,  # this disk
        0,  # disk with central directory
        len(entries),
        len(entries),
        size,
        start,
    )
    out += struct.pack(
        "<IIQI",
        _ZIP64_LOCATOR_SIGNATURE,
        0,  # disk with the ZIP64 EOCD
        zip64_eocd,
        1,  # total disks
    )
    out += struct.pack(
        "<IHHHHIIH",
        _EOCD_SIGNATURE,
        0,  # this disk
        0,  # disk with central directory
        _ZIP64_SENTINEL_16,
        _ZIP64_SENTINEL_16,
        _ZIP64_SENTINEL_32,
        _ZIP64_SENTINEL_32,
        0,  # comment length
    )


def pack_python(root: Path, out_msix: Path) -> Path:
    root = root.resolve()
    out_msix = out_msix.resolve()
    if not (root / "AppxManifest.xml").is_file():
        raise FileNotFoundError(f"AppxManifest.xml missing under {root}")

    files = collect_files(root)
    if not files:
        raise RuntimeError(f"No payload files under {root}")

    prepared = [
        prepare_file(package_path(p.relative_to(root)), p.read_bytes()) for p in files
    ]
    entries = [p.blocks for p in prepared]
    lfh_sizes = {
        e.name: zip_local_header_size(_zip_name(e.name).encode("utf-8"))
        for e in entries
    }

    blockmap = render_blockmap_xml(entries, lfh_sizes)
    content_types = content_types_xml([e.name for e in entries])

    archive = bytearray()
    written: list[_Entry] = []
    for item, plain in zip(prepared, (p.read_bytes() for p in files)):
        written.append(
            _write_entry(
                archive,
                _zip_name(item.blocks.name),
                item.payload,
                plain,
                _METHOD_DEFLATE if item.deflated else _METHOD_STORE,
            )
        )
    # Generated parts are stored, so a reader can reach them without inflating.
    for name, data in (
        ("[Content_Types].xml", content_types),
        ("AppxBlockMap.xml", blockmap),
    ):
        written.append(_write_entry(archive, name, data, data, _METHOD_STORE))

    _write_central_directory(archive, written)

    out_msix.parent.mkdir(parents=True, exist_ok=True)
    out_msix.write_bytes(bytes(archive))
    return out_msix


def append_stored_part(archive: bytes, name: str, payload: bytes) -> bytes:
    """Append a stored part and rewrite the central directory.

    Used to insert `AppxSignature.p7x`, which must be the last record: the
    signature covers every byte before its own local header (AXPC) and the
    central directory as it stood beforehand (AXCD), so it can only be added
    after everything else is final.

    Existing local records keep their offsets, so their central directory
    entries are copied through verbatim.
    """
    entries: list[_Entry] = []
    offset = 0
    while archive[offset : offset + 4] == struct.pack("<I", _LFH_SIGNATURE):
        header = struct.unpack("<IHHHHHIIIHH", archive[offset : offset + 30])
        _sig, _ver, flags, method, _t, _d, crc, csize, size, name_len, extra_len = (
            header
        )
        if flags & 0x08:
            raise ValueError(f"{name}: archive uses data descriptors; cannot append")
        entries.append(
            _Entry(
                name=archive[offset + 30 : offset + 30 + name_len],
                compressed_size=csize,
                uncompressed_size=size,
                method=method,
                crc=crc,
                offset=offset,
            )
        )
        offset += 30 + name_len + extra_len + csize

    if not entries:
        raise ValueError("archive has no local file records")

    out = bytearray(archive[:offset])  # file records, central directory dropped
    entries.append(_write_entry(out, name, payload, payload, _METHOD_STORE))
    _write_central_directory(out, entries)
    return bytes(out)


def pack_makemsix(root: Path, out_msix: Path, makemsix_bin: Path) -> Path:
    """Pack via the upstream MSIX SDK CLI.

    `makemsix pack` takes only -d and -p: upstream implements signature
    *validation*, not creation, so this backend produces unsigned packages just
    like the Python one. See docs/signing.md.
    """
    root = root.resolve()
    out_msix = out_msix.resolve()
    out_msix.parent.mkdir(parents=True, exist_ok=True)
    if out_msix.exists():
        out_msix.unlink()

    cmd = [str(makemsix_bin), "pack", "-d", str(root), "-p", str(out_msix)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"makemsix failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
        )
    if not out_msix.is_file():
        raise RuntimeError(f"makemsix reported success but {out_msix} missing")
    return out_msix
