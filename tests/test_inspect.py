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


# openappx writes Block/@Size uncompressed; the format wants the compressed
# length (verified against a Microsoft-signed package — see docs/signing.md and
# the v0.2 roadmap entry). Until pack_python emits per-block compressed sizes,
# our own packages trip this check, so tests that only care about *other*
# findings filter it out through here.
NONCONFORMANCE = "block sizes total"


def other_problems(problems: list[str]) -> list[str]:
    return [p for p in problems if NONCONFORMANCE not in p]


def test_clean_package_reports_expected_metadata(pkg: Path):
    report = inspect_package(pkg)
    assert other_problems(report["problems"]) == []
    assert report["signed"] is False
    assert report["signature"] is None
    assert report["identity"]["Name"] == "OpenAppx.Example"
    assert {p["name"] for p in report["parts"]} >= {"app.exe", "AppxManifest.xml"}


@pytest.mark.xfail(
    strict=True,
    reason="pack_python writes uncompressed Block/@Size; the format requires the "
    "compressed length, and empty files must have zero blocks",
)
def test_our_own_packages_are_conformant(pkg: Path):
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
    broken = rebuild(pkg, tmp_path / "broken.msix", replace={"app.exe": b"tampered"})
    assert main(["--package", str(broken)]) == 1
    assert main(["--package", str(tmp_path / "nope.msix")]) == 2


def test_cli_json_is_parseable(pkg: Path, capsys):
    import json

    main(["--package", str(pkg), "--json"])
    assert other_problems(json.loads(capsys.readouterr().out)["problems"]) == []
