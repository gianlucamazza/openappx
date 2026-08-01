from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

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


@pytest.mark.parametrize(
    "reference", ["../outside.exe", "/tmp/outside.exe", "C:/outside.exe"]
)
def test_manifest_references_must_stay_inside_layout(tmp_path: Path, reference: str):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/>'
        f'<Applications><Application Id="x" Executable="{reference}"/></Applications>'
        "</Package>",
        encoding="utf-8",
    )
    assert any("Executable not found" in p for p in layout_problems(layout))


def test_symlinks_are_rejected_before_pack(tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/></Package>',
        encoding="utf-8",
    )
    target = tmp_path / "outside.bin"
    target.write_bytes(b"outside")
    (layout / "payload.bin").symlink_to(target)
    assert any("symlink" in p for p in layout_problems(layout))
    with pytest.raises(ValueError, match="symlink"):
        pack_python(layout, tmp_path / "out.msix")


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


def _managed_manifest(entry: str = "hello.App") -> str:
    return (
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/>'
        f'<Applications><Application Id="x" Executable="hello.exe" '
        f'EntryPoint="{entry}"/></Applications></Package>'
    )


def test_managed_entrypoint_needs_a_winmd_in_the_layout(tmp_path: Path):
    """Without it the package installs and then refuses to launch."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(_managed_manifest(), encoding="utf-8")
    (layout / "hello.exe").write_bytes(b"MZ")
    assert any("no .winmd" in p for p in layout_problems(layout))

    (layout / "hello.winmd").write_bytes(b"metadata")
    assert layout_problems(layout) == []


def test_a_winmd_under_the_wrong_name_is_reported(tmp_path: Path):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(_managed_manifest(), encoding="utf-8")
    (layout / "hello.exe").write_bytes(b"MZ")
    (layout / "other.winmd").write_bytes(b"metadata")
    assert any("expects hello.winmd" in p for p in layout_problems(layout))


def test_full_trust_entrypoint_needs_no_winmd(tmp_path: Path):
    """It names no activatable class, so there is nothing to resolve."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        _managed_manifest("Windows.FullTrustApplication").replace(
            "</Applications>",
            '</Applications><Capabilities><Capability Name="runFullTrust"/>'
            "</Capabilities>",
        ),
        encoding="utf-8",
    )
    (layout / "hello.exe").write_bytes(b"MZ")
    assert layout_problems(layout) == []


def test_build_artefacts_in_the_layout_are_reported(tmp_path: Path):
    """Everything in the layout gets packed; a precompiled header alone is ~190 MB."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/></Package>',
        encoding="utf-8",
    )
    assert layout_problems(layout) == []
    (layout / "pch.pch").write_bytes(b"x")
    assert any("build artefacts" in p for p in layout_problems(layout))


def test_comments_are_not_grepped(tmp_path: Path):
    """These manifests document themselves; a comment must not look like markup."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/>'
        '<!-- e.g. Executable="ghost.exe" with Logo="Assets\\Ghost.png" -->'
        "</Package>",
        encoding="utf-8",
    )
    assert layout_problems(layout) == []
