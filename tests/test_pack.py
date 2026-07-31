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
