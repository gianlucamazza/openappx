"""`openappx inspect` must detect packages that pack cleanly but are incoherent."""

from __future__ import annotations

import base64
import hashlib
import zipfile
from pathlib import Path

import pytest

from openappx.inspect import inspect_package, main
from openappx.pack_core import pack_python

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"


def rebuild(
    src: Path,
    dest: Path,
    replace: dict[str, bytes] | None = None,
    drop: set[str] | None = None,
) -> Path:
    """Rewrite an .msix, substituting or dropping parts, preserving compression."""
    replace, drop = replace or {}, drop or set()
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, "w") as zout:
        for info in zin.infolist():
            if info.filename in drop:
                continue
            data = replace.get(info.filename, zin.read(info.filename))
            out = zipfile.ZipInfo(info.filename)
            out.compress_type = info.compress_type
            zout.writestr(out, data)
    return dest


@pytest.fixture
def pkg(tmp_path: Path) -> Path:
    return pack_python(EXAMPLE, tmp_path / "example.msix")


def blockmap_of(pkg: Path) -> str:
    with zipfile.ZipFile(pkg) as zf:
        return zf.read("AppxBlockMap.xml").decode("utf-8")


def problems_after(tmp_path: Path, pkg: Path, **kwargs) -> list[str]:
    return inspect_package(rebuild(pkg, tmp_path / "broken.msix", **kwargs))["problems"]


def test_clean_package_reports_expected_metadata(pkg: Path):
    report = inspect_package(pkg)
    assert report["problems"] == []
    assert report["signed"] is False
    assert report["signature"] is None
    assert report["identity"]["Name"] == "OpenAppx.Example"
    assert {p["name"] for p in report["parts"]} >= {"app.exe", "AppxManifest.xml"}


def test_our_own_packages_are_conformant(pkg: Path):
    """Our output must satisfy the same checks a third-party package does."""
    assert inspect_package(pkg)["problems"] == []


def test_detects_tampered_payload(tmp_path: Path, pkg: Path):
    """Payload changed after packing: block hash no longer matches."""
    problems = problems_after(tmp_path, pkg, replace={"app.exe": b"tampered payload"})
    assert any("hash mismatch" in p for p in problems)
    assert any("blockmap Size=" in p for p in problems)


def test_detects_wrong_lfh_size(tmp_path: Path, pkg: Path):
    bm = blockmap_of(pkg).replace('LfhSize="37"', 'LfhSize="99"')
    problems = problems_after(
        tmp_path, pkg, replace={"AppxBlockMap.xml": bm.encode("utf-8")}
    )
    assert any("LfhSize=99" in p and "local header is 37" in p for p in problems)


def test_detects_part_missing_from_blockmap(tmp_path: Path, pkg: Path):
    bm = blockmap_of(pkg)
    start = bm.index('<File Name="app.exe"')
    end = bm.index("</File>", start) + len("</File>\r\n")
    problems = problems_after(
        tmp_path, pkg, replace={"AppxBlockMap.xml": (bm[:start] + bm[end:]).encode()}
    )
    assert any("absent from AppxBlockMap.xml" in p for p in problems)


def test_detects_blockmap_entry_without_archive_part(tmp_path: Path, pkg: Path):
    problems = problems_after(tmp_path, pkg, drop={"app.exe"})
    assert any("listed in AppxBlockMap.xml but absent" in p for p in problems)


def test_detects_missing_required_parts(tmp_path: Path, pkg: Path):
    problems = problems_after(tmp_path, pkg, drop={"AppxManifest.xml"})
    assert any("missing required part: AppxManifest.xml" in p for p in problems)


def test_detects_malformed_blockmap(tmp_path: Path, pkg: Path):
    problems = problems_after(
        tmp_path, pkg, replace={"AppxBlockMap.xml": b"<BlockMap>truncated"}
    )
    assert any("not well-formed XML" in p for p in problems)


def test_detects_missing_content_type(tmp_path: Path, pkg: Path):
    with zipfile.ZipFile(pkg) as zf:
        ct = zf.read("[Content_Types].xml").decode("utf-8")
    ct = ct.replace(
        '<Default Extension="exe" ContentType="application/x-msdownload"/>', ""
    )
    problems = problems_after(
        tmp_path, pkg, replace={"[Content_Types].xml": ct.encode()}
    )
    assert any("no Default for extension .exe" in p for p in problems)


def test_declared_block_count_mismatch_is_reported(tmp_path: Path, pkg: Path):
    """A blockmap can lie about block count without lying about file size."""
    bm = blockmap_of(pkg)
    extra = f'<Block Hash="{base64.b64encode(hashlib.sha256(b"").digest()).decode()}"/>'
    bm = bm.replace("  </File>", f"    {extra}\r\n  </File>", 1)
    problems = problems_after(tmp_path, pkg, replace={"AppxBlockMap.xml": bm.encode()})
    assert any("block(s), content needs" in p for p in problems)


def test_unparseable_signature_is_reported(tmp_path: Path, pkg: Path):
    out = rebuild(pkg, tmp_path / "signed.msix")
    with zipfile.ZipFile(out, "a") as zf:
        zf.writestr(zipfile.ZipInfo("AppxSignature.p7x"), b"not-a-real-signature")
    report = inspect_package(out)
    assert report["signed"] is True
    assert any("not a p7x signature" in p for p in report["problems"])


def test_rejects_non_zip(tmp_path: Path):
    junk = tmp_path / "junk.msix"
    junk.write_bytes(b"definitely not a zip")
    with pytest.raises(ValueError):
        inspect_package(junk)


def test_rejects_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        inspect_package(tmp_path / "nope.msix")


def test_cli_exit_codes(tmp_path: Path, pkg: Path, capsys):
    assert main(["--package", str(pkg)]) == 0
    broken = rebuild(pkg, tmp_path / "broken.msix", replace={"app.exe": b"tampered"})
    assert main(["--package", str(broken)]) == 1
    assert main(["--package", str(tmp_path / "nope.msix")]) == 2


def test_cli_json_is_parseable(pkg: Path, capsys):
    import json

    assert main(["--package", str(pkg), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["problems"] == []


def pe(dll_characteristics: int, *, plus: bool = True) -> bytes:
    """The smallest PE header carrying a DllCharacteristics field.

    Only the offsets `_appcontainer_problems` reads are real: the MZ signature,
    e_lfanew, the PE signature, the optional-header magic, and the field itself
    at optional-header offset 0x46 (the same in PE32 and PE32+).
    """
    pe_offset = 0x80
    data = bytearray(b"\0" * (pe_offset + 0x18 + 0x48))
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    magic = 0x20B if plus else 0x10B
    data[pe_offset + 0x18 : pe_offset + 0x1A] = magic.to_bytes(2, "little")
    field = pe_offset + 0x18 + 0x46
    data[field : field + 2] = dll_characteristics.to_bytes(2, "little")
    return bytes(data)


def container_problems(tmp_path: Path, pkg: Path, exe: bytes) -> list[str]:
    """Only the app-container verdict: swapping a payload also breaks the blockmap."""
    problems = problems_after(tmp_path, pkg, replace={"app.exe": exe})
    return [p for p in problems if "app container" in p]


def test_executable_without_the_appcontainer_flag_is_reported(
    tmp_path: Path, pkg: Path
):
    """A device refuses to install it; the flag is readable from the archive."""
    assert any("0x8160" in p for p in container_problems(tmp_path, pkg, pe(0x8160)))


def test_executable_with_the_appcontainer_flag_is_accepted(tmp_path: Path, pkg: Path):
    assert container_problems(tmp_path, pkg, pe(0x9160)) == []


def test_pe32_is_read_at_the_same_offset(tmp_path: Path, pkg: Path):
    assert container_problems(tmp_path, pkg, pe(0x9160, plus=False)) == []
    assert container_problems(tmp_path, pkg, pe(0x8160, plus=False))


def test_a_non_pe_executable_is_left_alone(tmp_path: Path, pkg: Path):
    """`inspect` reads real archives: an Executable that is not a PE is not a lie."""
    assert container_problems(tmp_path, pkg, b"MZ" + b"\0" * 200) == []
    assert container_problems(tmp_path, pkg, b"not an exe") == []


def test_a_pe_with_an_unknown_optional_header_is_left_alone(tmp_path: Path, pkg: Path):
    """ROM images and future formats exist; only PE32 and PE32+ are read."""
    data = bytearray(pe(0x8160))
    data[0x80 + 0x18 : 0x80 + 0x1A] = (0x107).to_bytes(2, "little")  # PE32-ROM
    assert container_problems(tmp_path, pkg, bytes(data)) == []


def test_a_pe_truncated_before_the_field_is_left_alone(tmp_path: Path, pkg: Path):
    assert container_problems(tmp_path, pkg, pe(0x8160)[:0x90]) == []
