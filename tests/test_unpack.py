"""`openappx unpack` — the inverse of pack, and a path that reads hostile input."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from openappx.inspect import inspect_package
from openappx.pack_core import pack_python
from openappx.unpack import main, safe_target, unpack_package

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"


@pytest.fixture
def packed(tmp_path: Path) -> Path:
    return pack_python(EXAMPLE, tmp_path / "x.msix")


def test_round_trips_through_pack(packed: Path, tmp_path: Path):
    """Unpack then pack must produce a coherent package again."""
    layout = tmp_path / "layout"
    unpack_package(packed, layout)
    repacked = pack_python(layout, tmp_path / "again.msix")
    assert inspect_package(repacked)["problems"] == []


def test_round_trip_is_byte_identical(packed: Path, tmp_path: Path):
    """Nothing is lost in the trip: the same layout yields the same bytes."""
    layout = tmp_path / "layout"
    unpack_package(packed, layout)
    repacked = pack_python(layout, tmp_path / "again.msix")
    assert repacked.read_bytes() == packed.read_bytes()


def test_generated_parts_are_skipped(packed: Path, tmp_path: Path):
    layout = tmp_path / "layout"
    written = {p.name for p in unpack_package(packed, layout)}
    assert "AppxManifest.xml" in written
    assert "AppxBlockMap.xml" not in written
    assert "[Content_Types].xml" not in written


def test_generated_parts_can_be_kept(packed: Path, tmp_path: Path):
    layout = tmp_path / "layout"
    written = {p.name for p in unpack_package(packed, layout, keep_generated=True)}
    assert {"AppxBlockMap.xml", "[Content_Types].xml"} <= written


def test_nested_paths_are_recreated(packed: Path, tmp_path: Path):
    layout = tmp_path / "layout"
    unpack_package(packed, layout)
    assert (layout / "Assets" / "StoreLogo.png").is_file()


def test_contents_match_the_archive(packed: Path, tmp_path: Path):
    layout = tmp_path / "layout"
    unpack_package(packed, layout)
    with zipfile.ZipFile(packed) as zf:
        assert (layout / "AppxManifest.xml").read_bytes() == zf.read("AppxManifest.xml")


# --- hostile archives ------------------------------------------------------


def test_refuses_paths_that_escape_the_destination(tmp_path: Path):
    with pytest.raises(ValueError, match="escapes the destination"):
        safe_target(tmp_path, "../../etc/passwd")


def test_refuses_absolute_paths(tmp_path: Path):
    for name in ("/etc/passwd", "\\windows\\system32", "C:/Windows/system.ini"):
        with pytest.raises(ValueError, match="absolute path|escapes"):
            safe_target(tmp_path, name)


def test_a_traversal_entry_is_rejected_end_to_end(tmp_path: Path):
    """A crafted package must not write outside the destination."""
    hostile = tmp_path / "hostile.msix"
    with zipfile.ZipFile(hostile, "w") as zf:
        zf.writestr("AppxManifest.xml", "<Package/>")
        zf.writestr("../escaped.txt", "should never be written")

    with pytest.raises(ValueError, match="escapes the destination"):
        unpack_package(hostile, tmp_path / "out")
    assert not (tmp_path / "escaped.txt").exists()


def test_backslash_names_land_in_subdirectories(tmp_path: Path):
    """Blockmap-style names use backslashes; they are path separators, not literals."""
    archive = tmp_path / "a.msix"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("AppxManifest.xml", "<Package/>")
        zf.writestr("Assets\\logo.png", "x")

    unpack_package(archive, tmp_path / "out")
    assert (tmp_path / "out" / "Assets" / "logo.png").is_file()


def test_rejects_a_non_zip(tmp_path: Path):
    junk = tmp_path / "junk.msix"
    junk.write_bytes(b"not a zip at all")
    with pytest.raises(ValueError, match="not a ZIP/MSIX container"):
        unpack_package(junk, tmp_path / "out")


# --- CLI -------------------------------------------------------------------


def test_cli_extracts_and_reports(packed: Path, tmp_path: Path, capsys):
    code = main(["--package", str(packed), "--out", str(tmp_path / "layout")])
    assert code == 0
    out = capsys.readouterr().out
    assert "Extracted" in out and "rebuilds them" in out


def test_cli_keep_generated(packed: Path, tmp_path: Path, capsys):
    layout = tmp_path / "layout"
    code = main(["--package", str(packed), "--out", str(layout), "--keep-generated"])
    assert code == 0
    assert (layout / "AppxBlockMap.xml").is_file()


def test_cli_reports_a_bad_package(tmp_path: Path, capsys):
    junk = tmp_path / "junk.msix"
    junk.write_bytes(b"nope")
    assert main(["--package", str(junk), "--out", str(tmp_path / "out")]) == 1
    assert "error:" in capsys.readouterr().err
