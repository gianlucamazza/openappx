"""Pack backends: pure Python and optional makemsix."""

from __future__ import annotations

import contextlib
import os
import shutil
import struct
import subprocess
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from openappx.blockmap import (
    BLOCK_SIZE,
    collect_files,
    content_types_xml,
    package_path,
    prepare_file_streamed,
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
_VERSION_ZIP64 = 45  # entries that need ZIP64 fields must say so

# Values above this need a ZIP64 extra field. Parameterised so tests can drive
# the ZIP64 path with small files instead of 4 GiB ones.
_ZIP64_THRESHOLD = 0xFFFFFFFF
_ZIP64_EXTRA_TAG = 0x0001
_ZIP64_SENTINEL_32 = 0xFFFFFFFF
_ZIP64_SENTINEL_16 = 0xFFFF
_DOS_EPOCH_TIME = 0
_DOS_EPOCH_DATE = 0x0021  # 1980-01-01, so output stays byte-reproducible
_METHOD_STORE = 0
_METHOD_DEFLATE = 8


# Bit 11 marks the name as UTF-8. Required for anything outside ASCII: without
# it a reader falls back to CP437 and the name comes out as mojibake.
_FLAG_UTF8_NAME = 0x800


def atomic_write_bytes(path: Path, data: bytes) -> Path:
    """Write beside *path*, then replace it — so a failure leaves no half-package.

    Everything here writes a finished archive in one go, and a partial `.msix`
    is worse than none: it is a valid ZIP that fails much later, on a device.
    """
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return path


@contextlib.contextmanager
def atomic_output(path: Path):
    """`atomic_write_bytes` for writers that stream: yields the open file.

    Same discipline — write beside the target, fsync, `os.replace` — so an
    interrupted pack leaves no half-package, just an unlinked temporary.
    """
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


@dataclass(frozen=True)
class _Entry:
    name: bytes  # UTF-8, forward slashes
    compressed_size: int
    uncompressed_size: int
    method: int
    crc: int
    offset: int
    flags: int = 0


def zip64_local_extra(uncompressed_size: int, compressed_size: int) -> bytes:
    """The ZIP64 extra field a local header needs, or empty if it fits in 32 bits.

    Order is fixed by the spec: uncompressed size, then compressed size. Callers
    need its length before writing, because it counts towards `LfhSize` in the
    blockmap.

    **Appx does not accept this.** A package whose entries carry ZIP64 extra
    fields is refused at install with `0x8007000B` — measured on an Xbox One dev
    kit, using a package that installs fine without them. Microsoft's own
    packages have `extraLen=0` on every record. `pack_python` therefore refuses
    oversized files outright rather than emitting an archive no device will open;
    this function stays because the tests pin that behaviour down.
    """
    if max(uncompressed_size, compressed_size) <= _ZIP64_THRESHOLD:
        return b""
    return struct.pack(
        "<HHQQ", _ZIP64_EXTRA_TAG, 16, uncompressed_size, compressed_size
    )


def _local_header_bytes(entry: _Entry) -> bytes:
    """The local file header for `entry`: fixed part, name, ZIP64 extra."""
    extra = zip64_local_extra(entry.uncompressed_size, entry.compressed_size)
    # With a ZIP64 extra field the 32-bit size fields carry sentinels instead.
    sizes = (
        (_ZIP64_SENTINEL_32, _ZIP64_SENTINEL_32)
        if extra
        else (entry.compressed_size, entry.uncompressed_size)
    )
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            _LFH_SIGNATURE,
            _VERSION_ZIP64 if extra else _VERSION,
            entry.flags,
            entry.method,
            _DOS_EPOCH_TIME,
            _DOS_EPOCH_DATE,
            entry.crc,
            *sizes,
            len(entry.name),
            len(extra),
        )
        + entry.name
        + extra
    )


def _write_entry(
    out: bytearray, name: str, payload: bytes, plain: bytes, method: int
) -> _Entry:
    entry = _Entry(
        name=name.encode("utf-8"),
        compressed_size=len(payload),
        uncompressed_size=len(plain),
        method=method,
        crc=zlib.crc32(plain) & 0xFFFFFFFF,
        offset=len(out),
        flags=0 if name.isascii() else _FLAG_UTF8_NAME,
    )
    out += _local_header_bytes(entry)
    out += payload
    return entry


def _zip64_central_extra(entry: _Entry) -> bytes:
    """ZIP64 extra for a central directory entry: sizes first, then the offset.

    Only the fields that overflow are present, in the spec's fixed order, so the
    reader can tell them apart by the record's length alone.
    """
    values = []
    if max(entry.uncompressed_size, entry.compressed_size) > _ZIP64_THRESHOLD:
        values += [entry.uncompressed_size, entry.compressed_size]
    if entry.offset > _ZIP64_THRESHOLD:
        values.append(entry.offset)
    if not values:
        return b""
    body = b"".join(struct.pack("<Q", v) for v in values)
    return struct.pack("<HH", _ZIP64_EXTRA_TAG, len(body)) + body


def _central_directory_bytes(entries: list[_Entry], start: int) -> bytes:
    """Central directory + ZIP64 EOCD + locator + classic EOCD, as one buffer.

    `start` is the archive offset the directory will be written at. The
    directory is bytes-in-memory even on the streaming path: it is a few dozen
    bytes per entry, not payload.
    """
    out = bytearray()
    for e in entries:
        extra = _zip64_central_extra(e)
        big_sizes = max(e.uncompressed_size, e.compressed_size) > _ZIP64_THRESHOLD
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            _CDH_SIGNATURE,
            _VERSION_MADE_BY,
            _VERSION_ZIP64 if extra else _VERSION,
            e.flags,
            e.method,
            _DOS_EPOCH_TIME,
            _DOS_EPOCH_DATE,
            e.crc,
            _ZIP64_SENTINEL_32 if big_sizes else e.compressed_size,
            _ZIP64_SENTINEL_32 if big_sizes else e.uncompressed_size,
            len(e.name),
            len(extra),
            0,  # comment length
            0,  # disk number
            0,  # internal attributes
            0,  # external attributes
            _ZIP64_SENTINEL_32 if e.offset > _ZIP64_THRESHOLD else e.offset,
        )
        out += e.name
        out += extra
    size = len(out)

    # ZIP64 end of central directory, then its locator, then a classic EOCD whose
    # fields are all sentinels — the layout Microsoft's packages use.
    zip64_eocd = start + len(out)
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
    return bytes(out)


def _write_central_directory(out: bytearray, entries: list[_Entry]) -> None:
    out += _central_directory_bytes(entries, len(out))


def pack_python(root: Path, out_msix: Path) -> Path:
    root = root.resolve()
    out_msix = out_msix.resolve()
    if not (root / "AppxManifest.xml").is_file():
        raise FileNotFoundError(f"AppxManifest.xml missing under {root}")

    files = collect_files(root)
    if not files:
        raise RuntimeError(f"No payload files under {root}")

    for path in files:
        size = path.stat().st_size
        if size > _ZIP64_THRESHOLD:
            raise ValueError(
                f"{path.name} is {size} bytes: Appx cannot carry a file above "
                f"{_ZIP64_THRESHOLD} bytes. The ZIP64 record fields that would "
                "describe it make the package unopenable (0x8007000B), so this "
                "fails here instead of producing one."
            )

    # Two passes, nothing payload-sized in memory. Pass 1 reads every file once,
    # hashing and deflating block by block, the deflate streams going to spill
    # files beside the output (same filesystem as the archive they become part
    # of). Pass 2 copies spill or source into the archive in blocks. Data
    # descriptors would allow a single pass, and are exactly what Appx readers
    # here refuse — see append_stored_part and sign/digest.py — so the
    # compressed size must be known before each local header is written.
    out_msix.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{out_msix.name}.spill.", dir=out_msix.parent
    ) as spill_dir:
        streamed = [
            prepare_file_streamed(
                package_path(p.relative_to(root)), p, Path(spill_dir)
            )
            for p in files
        ]
        entries = [s.blocks for s in streamed]
        # LfhSize counts the extra field too, so it has to be known before the
        # blockmap is rendered — hence computing it from the prepared payloads.
        lfh_sizes = {
            s.blocks.name: zip_local_header_size(
                _zip_name(s.blocks.name).encode("utf-8"),
                zip64_local_extra(s.blocks.size, s.payload_size),
            )
            for s in streamed
        }

        blockmap = render_blockmap_xml(entries, lfh_sizes)
        content_types = content_types_xml([e.name for e in entries])

        with atomic_output(out_msix) as stream:
            written: list[_Entry] = []
            for s in streamed:
                name = _zip_name(s.blocks.name)
                entry = _Entry(
                    name=name.encode("utf-8"),
                    compressed_size=s.payload_size,
                    uncompressed_size=s.blocks.size,
                    method=_METHOD_DEFLATE if s.deflated else _METHOD_STORE,
                    crc=s.crc,
                    offset=stream.tell(),
                    flags=0 if name.isascii() else _FLAG_UTF8_NAME,
                )
                stream.write(_local_header_bytes(entry))
                with open(s.spill if s.deflated else s.source, "rb") as payload:
                    shutil.copyfileobj(payload, stream, BLOCK_SIZE)
                written.append(entry)
            # Generated parts are stored, so a reader reaches them without
            # inflating.
            for name, data in (
                ("[Content_Types].xml", content_types),
                ("AppxBlockMap.xml", blockmap),
            ):
                entry = _Entry(
                    name=name.encode("utf-8"),
                    compressed_size=len(data),
                    uncompressed_size=len(data),
                    method=_METHOD_STORE,
                    crc=zlib.crc32(data) & 0xFFFFFFFF,
                    offset=stream.tell(),
                )
                stream.write(_local_header_bytes(entry))
                stream.write(data)
                written.append(entry)
            stream.write(_central_directory_bytes(written, stream.tell()))

    return out_msix


def _read_zip64_extra(extra: bytes) -> tuple[int, int]:
    """Uncompressed and compressed size out of a local header's ZIP64 extra."""
    offset = 0
    while offset + 4 <= len(extra):
        tag, size = struct.unpack("<HH", extra[offset : offset + 4])
        body = extra[offset + 4 : offset + 4 + size]
        if tag == _ZIP64_EXTRA_TAG and len(body) >= 16:
            return struct.unpack("<QQ", body[:16])
        offset += 4 + size
    raise ValueError("ZIP64 sentinel present but no ZIP64 extra field found")


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
        if csize == _ZIP64_SENTINEL_32 or size == _ZIP64_SENTINEL_32:
            extra = archive[
                offset + 30 + name_len : offset + 30 + name_len + extra_len
            ]
            size, csize = _read_zip64_extra(extra)
        entries.append(
            _Entry(
                name=archive[offset + 30 : offset + 30 + name_len],
                compressed_size=csize,
                uncompressed_size=size,
                method=method,
                crc=crc,
                offset=offset,
                flags=flags,
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
    fd, temporary = tempfile.mkstemp(prefix=f".{out_msix.name}.", dir=out_msix.parent)
    os.close(fd)
    os.unlink(temporary)
    try:
        cmd = [str(makemsix_bin), "pack", "-d", str(root), "-p", temporary]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"makemsix failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
            )
        if not Path(temporary).is_file():
            raise RuntimeError(
                f"makemsix reported success but wrote no {out_msix.name}"
            )
        os.replace(temporary, out_msix)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return out_msix
