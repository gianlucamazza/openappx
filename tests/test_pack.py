from __future__ import annotations

import zipfile
from pathlib import Path

from openappx.blockmap import hash_file_blocks, package_path
from openappx.pack_core import pack_python
from openappx.validate import layout_problems

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"


def test_hash_multi_block():
    data = b"x" * (64 * 1024 + 3)
    hashes, sizes = hash_file_blocks(data)
    assert len(hashes) == 2
    assert sizes == [64 * 1024, 3]


def test_package_path():
    assert package_path(Path("Assets/logo.png")) == "Assets\\logo.png"


def test_example_layout_valid():
    assert layout_problems(EXAMPLE) == []


def test_pack_example(tmp_path: Path):
    out = tmp_path / "example.msix"
    pack_python(EXAMPLE, out)
    assert out.is_file()
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert "AppxManifest.xml" in names
        assert "AppxBlockMap.xml" in names
        assert "[Content_Types].xml" in names
        assert "app.exe" in names
        assert "Assets/StoreLogo.png" in names
        bm = zf.read("AppxBlockMap.xml").decode("utf-8")
        assert "BlockMap" in bm
        assert "app.exe" in bm


def test_full_trust_entrypoint_requires_the_capability(tmp_path: Path):
    """A device reports this as 0x80080204 with only a line number."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/>'
        '<Applications><Application Id="x" Executable="a.exe" '
        'EntryPoint="Windows.FullTrustApplication"/></Applications></Package>',
        encoding="utf-8",
    )
    problems = layout_problems(layout)
    assert any("runFullTrust" in p for p in problems)


def test_the_example_layout_declares_that_capability():
    assert layout_problems(EXAMPLE) == []


def test_missing_identity_attributes_are_reported(tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a"/></Package>', encoding="utf-8"
    )
    problems = layout_problems(layout)
    assert any("Identity/@Publisher missing" in p for p in problems)
    assert any("Identity/@Version missing" in p for p in problems)
    assert not any("Identity/@Name missing" in p for p in problems)


RESOURCE_ONLY = REPO / "examples" / "resource-only"


def test_resource_only_example_is_valid():
    """The example the README points at as installable must stay installable."""
    assert layout_problems(RESOURCE_ONLY) == []


def test_resource_only_example_has_no_executable():
    import xml.etree.ElementTree as ET

    ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
    root = ET.parse(RESOURCE_ONLY / "AppxManifest.xml").getroot()
    assert root.find(f"{ns}Applications") is None  # the element, not the comment
    assert root.find(f".//{ns}TargetDeviceFamily").get("Name") == "Windows.Universal"


def test_example_manifests_are_well_formed_xml():
    """XML forbids `--` inside comments; a device reports that as 0xC00CEE23."""
    import xml.etree.ElementTree as ET

    for layout in (EXAMPLE, RESOURCE_ONLY):
        ET.parse(layout / "AppxManifest.xml")


def test_malformed_xml_is_reported(tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<?xml version="1.0"?><!-- a --b --><Package/>', encoding="utf-8"
    )
    assert any("not well-formed" in p for p in layout_problems(layout))
