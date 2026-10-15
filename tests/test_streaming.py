"""The streaming writer must produce the bytes the in-memory writer always has.

`pack_python` streams: one pass hashing and deflating per 64 KiB block into
spill files, a second pass copying them into the archive. The in-memory
primitives — `prepare_file`, `_write_entry`, `_write_central_directory` —
remain the reference implementation (`bundle.py` still writes through them),
and this file holds the two writers to identical output on a layout that
exercises every branch either can take.
"""

from __future__ import annotations

import os
from pathlib import Path

from openappx.blockmap import (
    BLOCK_SIZE,
    collect_files,
    content_types_xml,
    package_path,
    prepare_file,
    prepare_file_streamed,
    render_blockmap_xml,
    zip_local_header_size,
)
from openappx.inspect import inspect_package
from openappx.pack_core import (
    _METHOD_DEFLATE,
    _METHOD_STORE,
    _write_central_directory,
    _write_entry,
    _zip_name,
    pack_python,
    zip64_local_extra,
)


def branchy_layout(tmp_path: Path) -> Path:
    """Every branch the writers can take, in one layout: multi-block deflate,
    incompressible-therefore-stored, empty, exactly-one-block, one byte over a
    block boundary, a nested path, and a name outside ASCII (flag bit 11)."""
    layout = tmp_path / "layout"
    (layout / "Assets").mkdir(parents=True)
    (layout / "AppxManifest.xml").write_bytes(b"<Package/>")
    (layout / "big.txt").write_bytes(b"the same line over and over\r\n" * 9000)
    (layout / "Assets" / "noise.bin").write_bytes(os.urandom(3 * BLOCK_SIZE + 17))
    (layout / "empty.dat").write_bytes(b"")
    (layout / "block.bin").write_bytes(b"\x00" * BLOCK_SIZE)
    (layout / "block-plus.bin").write_bytes(b"\x01" * (BLOCK_SIZE + 1))
    (layout / "Assets" / "Ünïcode.txt").write_bytes(b"non-ascii name")
    return layout


def reference_archive(root: Path) -> bytes:
    """The pre-streaming `pack_python`, byte for byte, from the primitives."""
    files = collect_files(root)
    prepared = [
        prepare_file(package_path(p.relative_to(root)), p.read_bytes()) for p in files
    ]
    lfh_sizes = {
        item.blocks.name: zip_local_header_size(
            _zip_name(item.blocks.name).encode("utf-8"),
            zip64_local_extra(item.blocks.size, len(item.payload)),
        )
        for item in prepared
    }
    blockmap = render_blockmap_xml([p.blocks for p in prepared], lfh_sizes)
    content_types = content_types_xml([p.blocks.name for p in prepared])
    archive = bytearray()
    written = []
    for item, plain in zip(prepared, (p.read_bytes() for p in files), strict=True):
        written.append(
            _write_entry(
                archive,
                _zip_name(item.blocks.name),
                item.payload,
                plain,
                _METHOD_DEFLATE if item.deflated else _METHOD_STORE,
            )
        )
    for name, data in (
        ("[Content_Types].xml", content_types),
        ("AppxBlockMap.xml", blockmap),
    ):
        written.append(_write_entry(archive, name, data, data, _METHOD_STORE))
    _write_central_directory(archive, written)
    return bytes(archive)


def test_streamed_output_is_byte_identical_to_the_reference(tmp_path: Path):
    layout = branchy_layout(tmp_path)
    out = pack_python(layout, tmp_path / "out.msix")
    assert out.read_bytes() == reference_archive(layout)


def test_prepare_file_streamed_matches_prepare_file(tmp_path: Path):
    """Field for field, including the spilled deflate stream's bytes."""
    import zlib

    layout = branchy_layout(tmp_path)
    spill = tmp_path / "spill"
    spill.mkdir()
    for path in collect_files(layout):
        name = package_path(path.relative_to(layout))
        data = path.read_bytes()
        in_memory = prepare_file(name, data)
        streamed = prepare_file_streamed(name, path, spill)
        assert streamed.blocks == in_memory.blocks
        assert streamed.deflated == in_memory.deflated
        assert streamed.payload_size == len(in_memory.payload)
        assert streamed.crc == zlib.crc32(data) & 0xFFFFFFFF
        if streamed.deflated:
            assert streamed.spill.read_bytes() == in_memory.payload
        else:
            assert streamed.spill is None


def test_the_streamed_package_is_coherent(tmp_path: Path):
    out = pack_python(branchy_layout(tmp_path), tmp_path / "out.msix")
    assert inspect_package(out)["problems"] == []


def test_nothing_is_left_beside_the_package(tmp_path: Path):
    """Spill files and the atomic temporary must both be gone afterwards."""
    layout = branchy_layout(tmp_path)
    outdir = tmp_path / "outdir"
    out = pack_python(layout, outdir / "out.msix")
    assert [p.name for p in outdir.iterdir()] == [out.name]


def test_a_failed_pack_leaves_the_target_and_directory_untouched(
    tmp_path: Path, monkeypatch
):
    """A failure in pass 2 must discard spill files and the temporary, and must
    not touch a package already at the target path."""
    import pytest

    from openappx import pack_core

    layout = branchy_layout(tmp_path)
    outdir = tmp_path / "outdir"
    outdir.mkdir()
    target = outdir / "out.msix"
    target.write_bytes(b"previous package")

    def boom(entry):
        raise OSError("disk full")

    monkeypatch.setattr(pack_core, "_local_header_bytes", boom)
    with pytest.raises(OSError, match="disk full"):
        pack_python(layout, target)
    assert [p.name for p in outdir.iterdir()] == [target.name]
    assert target.read_bytes() == b"previous package"


def test_a_source_that_changes_between_passes_is_refused(tmp_path: Path, monkeypatch):
    """Pass 1 fixes sizes and CRCs; a stored part re-read in pass 2 must still
    match them, or the offsets after it would be wrong."""
    import pytest

    from openappx import pack_core

    layout = branchy_layout(tmp_path)
    noise = layout / "Assets" / "noise.bin"  # incompressible, so stored
    prepare = pack_core.prepare_file_streamed

    def prepare_then_grow(name, path, spill_dir, *args, **kwargs):
        part = prepare(name, path, spill_dir, *args, **kwargs)
        if path == noise:
            with open(path, "ab") as f:
                f.write(b"late write")
        return part

    monkeypatch.setattr(pack_core, "prepare_file_streamed", prepare_then_grow)
    outdir = tmp_path / "outdir"
    with pytest.raises(RuntimeError, match="changed while it was being packed"):
        pack_python(layout, outdir / "out.msix")
    assert list(outdir.iterdir()) == []


def test_a_package_past_the_32_bit_range_is_refused(tmp_path: Path, monkeypatch):
    """Each file fits, the archive does not: offsets would need ZIP64 fields."""
    import pytest

    from openappx import pack_core

    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_bytes(b"<Package/>")
    for i in range(3):  # incompressible, so stored at full size
        (layout / f"part{i}.bin").write_bytes(os.urandom(BLOCK_SIZE))
    monkeypatch.setattr(pack_core, "_ZIP64_THRESHOLD", 2 * BLOCK_SIZE)
    with pytest.raises(ValueError, match="ZIP64 fields that are not verified"):
        pack_python(layout, tmp_path / "out.msix")


def test_spill_is_removed_when_prepare_fails(tmp_path: Path, monkeypatch):
    import pytest

    from openappx import blockmap

    layout = branchy_layout(tmp_path)
    spill = tmp_path / "spill"
    spill.mkdir()

    def fail(*args, **kwargs):
        raise OSError("read error")

    monkeypatch.setattr(blockmap.hashlib, "sha256", fail)
    with pytest.raises(OSError, match="read error"):
        prepare_file_streamed("big.txt", layout / "big.txt", spill)
    assert list(spill.iterdir()) == []
