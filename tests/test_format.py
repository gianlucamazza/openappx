"""Format-level invariants: blockmap/ZIP parity and reproducible output.

These guard the subtle rules documented in CLAUDE.md — a break here produces a
package that packs fine but is rejected by the target installer.
"""

from __future__ import annotations

import base64
import hashlib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from openappx.blockmap import NS, hash_file_blocks, package_path, read_local_header
from openappx.pack_core import pack_python

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"

GENERATED_PARTS = ("[Content_Types].xml", "AppxBlockMap.xml")


def blockmap_files(msix: Path) -> dict[str, ET.Element]:
    with zipfile.ZipFile(msix) as zf:
        root = ET.fromstring(zf.read("AppxBlockMap.xml"))
    return {el.get("Name"): el for el in root.findall(f"{{{NS}}}File")}


@pytest.fixture
def packed(tmp_path: Path) -> Path:
    return pack_python(EXAMPLE, tmp_path / "example.msix")


def test_pack_is_byte_reproducible(tmp_path: Path):
    a = pack_python(EXAMPLE, tmp_path / "a.msix").read_bytes()
    b = pack_python(EXAMPLE, tmp_path / "b.msix").read_bytes()
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()


def test_lfh_size_matches_written_headers(packed: Path):
    """LfhSize is computed as 30+len(name), never measured — prove it holds."""
    raw = packed.read_bytes()
    declared = blockmap_files(packed)
    with zipfile.ZipFile(packed) as zf:
        infos = zf.infolist()

    for info in infos:
        header = read_local_header(raw, info.header_offset)
        assert header.name.decode("utf-8") == info.filename
        if info.filename in GENERATED_PARTS:
            continue  # generated parts are not listed in the blockmap
        el = declared[package_path(Path(info.filename))]
        assert int(el.get("LfhSize")) == header.size, (
            f"{info.filename}: blockmap says {el.get('LfhSize')}, "
            f"archive has {header.size} (extra fields present?)"
        )


def test_blockmap_covers_exactly_the_payload(packed: Path):
    with zipfile.ZipFile(packed) as zf:
        payload = {n for n in zf.namelist() if n not in GENERATED_PARTS}
    assert {n.replace("\\", "/") for n in blockmap_files(packed)} == payload


def test_blockmap_hashes_cover_uncompressed_blocks(packed: Path):
    """Hash is over the plain 64 KiB block; File/@Size is the plain file size."""
    with zipfile.ZipFile(packed) as zf:
        for name, el in blockmap_files(packed).items():
            data = zf.read(name.replace("\\", "/"))
            blocks = el.findall(f"{{{NS}}}Block")
            hashes, _ = hash_file_blocks(data)
            assert int(el.get("Size")) == len(data)
            assert len(blocks) == len(hashes)
            for block, digest in zip(blocks, hashes, strict=True):
                assert block.get("Hash") == base64.b64encode(digest).decode()


def test_block_size_is_the_compressed_length(packed: Path):
    """Block/@Size counts compressed bytes, and is absent on stored parts.

    Verified against a Microsoft-signed package — see docs/signing.md.
    """
    with zipfile.ZipFile(packed) as zf:
        for name, el in blockmap_files(packed).items():
            info = zf.getinfo(name.replace("\\", "/"))
            sizes = [b.get("Size") for b in el.findall(f"{{{NS}}}Block")]
            if info.compress_type == zipfile.ZIP_STORED:
                assert all(s is None for s in sizes), name
            else:
                assert all(s is not None for s in sizes), name
                # the deflate end-of-stream marker belongs to no block
                assert sum(int(s) for s in sizes) == info.compress_size - 2, name


def test_generated_parts_are_stored(packed: Path):
    with zipfile.ZipFile(packed) as zf:
        for info in zf.infolist():
            if info.filename in GENERATED_PARTS:
                assert info.compress_type == zipfile.ZIP_STORED, info.filename


def test_payload_is_deflated_only_when_it_pays_off(packed: Path):
    with zipfile.ZipFile(packed) as zf:
        for info in zf.infolist():
            if info.filename in GENERATED_PARTS:
                continue
            if info.compress_type == zipfile.ZIP_DEFLATED:
                assert info.compress_size < info.file_size, info.filename
            else:
                assert info.compress_size == info.file_size, info.filename


def test_preseeded_generated_parts_are_not_packed_as_payload(tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text("<Package/>", encoding="utf-8")
    stale = b"<BlockMap>stale</BlockMap>"
    (layout / "AppxBlockMap.xml").write_bytes(stale)
    (layout / "[Content_Types].xml").write_bytes(b"stale")
    (layout / "AppxSignature.p7x").write_bytes(b"stale")

    out = pack_python(layout, tmp_path / "out.msix")
    with zipfile.ZipFile(out) as zf:
        assert zf.read("AppxBlockMap.xml") != stale
        assert "AppxSignature.p7x" not in zf.namelist()
    assert "AppxBlockMap.xml" not in blockmap_files(out)


def test_empty_file_has_no_blocks(tmp_path: Path):
    """`<File Name="…" Size="0" LfhSize="…"/>`, as Microsoft's packer emits."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text("<Package/>", encoding="utf-8")
    (layout / "empty.bin").write_bytes(b"")

    out = pack_python(layout, tmp_path / "out.msix")
    el = blockmap_files(out)["empty.bin"]
    assert int(el.get("Size")) == 0
    assert el.findall(f"{{{NS}}}Block") == []
    with zipfile.ZipFile(out) as zf:
        assert zf.getinfo("empty.bin").compress_type == zipfile.ZIP_STORED


def test_nested_paths_use_backslash_in_blockmap_slash_in_zip(tmp_path: Path):
    layout = tmp_path / "layout"
    (layout / "Assets" / "sub").mkdir(parents=True)
    (layout / "AppxManifest.xml").write_text("<Package/>", encoding="utf-8")
    (layout / "Assets" / "sub" / "x.png").write_bytes(b"\x89PNG")

    out = pack_python(layout, tmp_path / "out.msix")
    with zipfile.ZipFile(out) as zf:
        assert "Assets/sub/x.png" in zf.namelist()
    assert "Assets\\sub\\x.png" in blockmap_files(out)


def test_unknown_extension_gets_a_content_type(tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text("<Package/>", encoding="utf-8")
    (layout / "data.qwerty").write_bytes(b"payload")

    out = pack_python(layout, tmp_path / "out.msix")
    with zipfile.ZipFile(out) as zf:
        types = zf.read("[Content_Types].xml").decode("utf-8")
    assert 'Extension="qwerty"' in types


def test_pack_rejects_layout_without_manifest(tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "stray.txt").write_bytes(b"x")
    with pytest.raises(FileNotFoundError):
        pack_python(layout, tmp_path / "out.msix")


def test_pack_overwrites_existing_output(tmp_path: Path):
    out = tmp_path / "out.msix"
    out.write_bytes(b"junk")
    pack_python(EXAMPLE, out)
    assert zipfile.is_zipfile(out)


def test_non_ascii_names_set_the_utf8_flag(tmp_path: Path):
    """Without bit 11 a reader falls back to CP437 and mangles the name."""
    layout = tmp_path / "layout"
    (layout / "Assets").mkdir(parents=True)
    (layout / "AppxManifest.xml").write_text("<Package/>", encoding="utf-8")
    (layout / "Assets" / "città-日本.png").write_bytes(b"\x89PNG")

    out = pack_python(layout, tmp_path / "out.msix")
    raw = out.read_bytes()

    with zipfile.ZipFile(out) as zf:
        assert "Assets/città-日本.png" in zf.namelist()
        for info in zf.infolist():
            header = read_local_header(raw, info.header_offset)
            expected = 0 if info.filename.isascii() else 0x800
            assert header.flag_bits & 0x800 == expected, info.filename
            # the central directory must agree with the local header
            assert info.flag_bits & 0x800 == expected, info.filename


def test_ascii_names_do_not_set_the_utf8_flag(packed: Path):
    raw = packed.read_bytes()
    with zipfile.ZipFile(packed) as zf:
        for info in zf.infolist():
            assert info.filename.isascii()
            assert read_local_header(raw, info.header_offset).flag_bits == 0
