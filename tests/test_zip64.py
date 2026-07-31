"""ZIP64 record fields, and why Appx cannot use them.

The important finding here is negative. A package whose entries carry ZIP64
extra fields is refused by a device with `0x8007000B`, while the identical
package without them installs. Standard ZIP readers accept both — `zipfile` and
`unzip` below are perfectly happy — which is precisely why only a device could
reveal it. Microsoft's own packages have `extraLen=0` on every record.

So `pack_python` refuses a file it cannot describe in 32 bits, instead of
emitting an archive no device will open. The encoder is kept and pinned by these
tests: it is correct per the ZIP spec, and whoever revisits this needs to know
that correctness was not the problem.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from openappx import pack_core
from openappx.blockmap import read_local_header
from openappx.pack_core import (
    _read_zip64_extra,
    _write_central_directory,
    _write_entry,
    pack_python,
    zip64_local_extra,
)

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"

SMALL_THRESHOLD = 16


@pytest.fixture
def tiny_threshold(monkeypatch):
    monkeypatch.setattr(pack_core, "_ZIP64_THRESHOLD", SMALL_THRESHOLD)


# --- the encoder ------------------------------------------------------------


def test_no_extra_field_below_the_threshold():
    assert zip64_local_extra(10, 10) == b""


def test_extra_field_carries_both_sizes():
    extra = zip64_local_extra(2**32 + 7, 2**32 + 3)
    tag, size, uncompressed, compressed = struct.unpack("<HHQQ", extra)
    assert (tag, size) == (0x0001, 16)
    assert (uncompressed, compressed) == (2**32 + 7, 2**32 + 3)


def test_extra_field_round_trips():
    extra = zip64_local_extra(2**33, 2**32 + 1)
    assert _read_zip64_extra(extra) == (2**33, 2**32 + 1)


def test_reading_a_missing_extra_field_is_an_error():
    with pytest.raises(ValueError, match="no ZIP64 extra field"):
        _read_zip64_extra(b"")


def test_a_zip64_entry_is_still_a_valid_zip(tiny_threshold, tmp_path: Path):
    """Standard readers accept what Appx rejects — hence the device test."""
    archive = bytearray()
    payload = b"y" * (SMALL_THRESHOLD + 20)
    entry = _write_entry(archive, "big.bin", payload, payload, 0)
    _write_central_directory(archive, [entry])

    out = tmp_path / "z64.zip"
    out.write_bytes(bytes(archive))

    header = read_local_header(bytes(archive), 0)
    assert header.extra_len == 20  # the ZIP64 extra really is there

    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        assert zf.read("big.bin") == payload


@pytest.mark.skipif(shutil.which("unzip") is None, reason="unzip not installed")
def test_unzip_also_accepts_it(tiny_threshold, tmp_path: Path):
    archive = bytearray()
    payload = b"z" * (SMALL_THRESHOLD + 5)
    entry = _write_entry(archive, "big.bin", payload, payload, 0)
    _write_central_directory(archive, [entry])
    out = tmp_path / "z64.zip"
    out.write_bytes(bytes(archive))

    result = subprocess.run(
        ["unzip", "-t", str(out)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --- what the packer actually does -----------------------------------------


def test_pack_refuses_a_file_it_cannot_describe(tiny_threshold, tmp_path: Path):
    """Better a clear error than an archive no device will open."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text("<Package/>", encoding="utf-8")
    (layout / "huge.bin").write_bytes(b"x" * (SMALL_THRESHOLD + 1))

    with pytest.raises(ValueError, match="0x8007000B"):
        pack_python(layout, tmp_path / "out.msix")


def test_the_error_names_the_offending_file(tiny_threshold, tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text("<Package/>", encoding="utf-8")
    (layout / "toobig.bin").write_bytes(b"x" * (SMALL_THRESHOLD + 1))

    with pytest.raises(ValueError, match="toobig.bin"):
        pack_python(layout, tmp_path / "out.msix")


def test_normal_packages_carry_no_extra_fields(tmp_path: Path):
    """The real threshold is 4 GiB, so ordinary packages never take that path."""
    out = pack_python(EXAMPLE, tmp_path / "small.msix")
    raw = out.read_bytes()
    with zipfile.ZipFile(out) as zf:
        for info in zf.infolist():
            assert read_local_header(raw, info.header_offset).extra_len == 0
