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
