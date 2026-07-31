"""AppxSignature.p7x digest parsing and verification.

The golden tests run against Microsoft's own signed test packages and are the
only proof that our reading of the format is right; the synthetic tests cover
the error paths those fixtures cannot reach.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

import pytest

from openappx.pack_core import pack_python
from openappx.sign import (
    P7X_MAGIC,
    SIGNATURE_PART,
    compute_digests,
    parse_p7x_digests,
    signature_problems,
)

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"


def make_p7x(digests: dict[str, bytes], preamble: bytes = b"\x30\x82\x01\x00") -> bytes:
    """A minimal stand-in for a real p7x: magic, some DER-ish noise, the APPX blob."""
    blob = b"APPX" + b"".join(name.encode() + h for name, h in digests.items())
    return P7X_MAGIC + preamble + blob


# --- golden: Microsoft-signed packages ------------------------------------


def test_reads_digests_from_a_real_signature(signed_reference: Path):
    with zipfile.ZipFile(signed_reference) as zf:
        declared = parse_p7x_digests(zf.read(SIGNATURE_PART))
    assert set(declared) == {"AXPC", "AXCD", "AXCT", "AXBM"}
    assert all(len(h) == 32 for h in declared.values())


def test_recomputed_digests_match_a_real_signature(signed_reference: Path):
    """AXPC/AXCT/AXBM as we compute them equal what Microsoft signed."""
    with zipfile.ZipFile(signed_reference) as zf:
        declared = parse_p7x_digests(zf.read(SIGNATURE_PART))
    actual = compute_digests(signed_reference)
    for name in ("AXPC", "AXCT", "AXBM"):
        assert actual[name] == declared[name], name
    assert signature_problems(signed_reference) == []


def test_axcd_is_declared_but_not_recomputable(signed_reference: Path):
    """Documents the known limit: the pre-signature central directory is gone."""
    with zipfile.ZipFile(signed_reference) as zf:
        declared = parse_p7x_digests(zf.read(SIGNATURE_PART))
    assert "AXCD" in declared
    assert "AXCD" not in compute_digests(signed_reference)


def test_detects_a_package_tampered_after_signing(tampered_blockmap: Path):
    problems = signature_problems(tampered_blockmap)
    assert any("AXBM digest mismatch" in p for p in problems)


def test_a_microsoft_package_passes_the_same_checks_as_ours(signed_reference: Path):
    """The conformance rules `inspect` enforces are the real ones.

    If this fails, our reading of the format drifted — not Microsoft's packer.
    """
    from openappx.inspect import inspect_package

    assert inspect_package(signed_reference)["problems"] == []


def test_our_packages_and_microsofts_agree_on_block_size_semantics(
    signed_reference: Path, tmp_path: Path
):
    """Block/@Size present iff the part is deflated, in both packers."""
    import xml.etree.ElementTree as ET

    from openappx.blockmap import NS

    for package in (signed_reference, pack_python(EXAMPLE, tmp_path / "ours.msix")):
        with zipfile.ZipFile(package) as zf:
            blockmap = ET.fromstring(zf.read("AppxBlockMap.xml"))
            for el in blockmap.findall(f"{{{NS}}}File"):
                info = zf.getinfo(el.get("Name").replace("\\", "/"))
                deflated = info.compress_type == zipfile.ZIP_DEFLATED
                for block in el.findall(f"{{{NS}}}Block"):
                    assert (block.get("Size") is not None) == deflated, (
                        f"{package.name}: {el.get('Name')}"
                    )


# --- synthetic: error paths ------------------------------------------------


def test_rejects_signature_without_magic():
    with pytest.raises(ValueError, match="not a p7x"):
        parse_p7x_digests(b"\x30\x82APPX" + b"AXPC" + b"\x00" * 32)


def test_rejects_signature_without_digest_header():
    with pytest.raises(ValueError, match="no APPX digest header"):
        parse_p7x_digests(P7X_MAGIC + b"\x30\x82\x01\x00" * 8)


def test_skips_a_stray_appx_marker_in_the_der():
    """A literal 'APPX' in certificate bytes must not be mistaken for the blob."""
    real = {"AXPC": b"\x01" * 32, "AXBM": b"\x02" * 32}
    p7x = P7X_MAGIC + b"APPX" + b"not-a-digest-name" + make_p7x(real)[len(P7X_MAGIC) :]
    assert parse_p7x_digests(p7x) == real


def test_round_trips_computed_digests(tmp_path: Path):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    digests = compute_digests(pkg)
    assert set(digests) == {"AXPC", "AXCD", "AXCT", "AXBM"}
    assert (
        digests["AXBM"]
        == hashlib.sha256(zipfile.ZipFile(pkg).read("AppxBlockMap.xml")).digest()
    )


def test_unsigned_package_has_no_signature_to_check(tmp_path: Path):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    with pytest.raises(ValueError, match="no AppxSignature.p7x"):
        signature_problems(pkg)


def test_reports_mismatch_against_a_forged_signature(tmp_path: Path):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    good = compute_digests(pkg)
    forged = dict(good)
    forged["AXBM"] = b"\xff" * 32
    signed = append_signature(pkg, tmp_path / "signed.msix", make_p7x(forged))

    problems = signature_problems(signed)
    assert any("AXBM digest mismatch" in p for p in problems)
    assert not any("AXCT" in p for p in problems)


def append_signature(src: Path, dest: Path, p7x: bytes) -> Path:
    """Rebuild an archive with AppxSignature.p7x appended as the last part."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, "w") as zout:
        for info in zin.infolist():
            out = zipfile.ZipInfo(info.filename)
            out.compress_type = info.compress_type
            zout.writestr(out, zin.read(info.filename))
        sig = zipfile.ZipInfo(SIGNATURE_PART)
        sig.compress_type = zipfile.ZIP_STORED
        zout.writestr(sig, p7x)
    return dest


def test_axpc_covers_everything_before_the_signature_record(tmp_path: Path):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    signed = append_signature(
        pkg, tmp_path / "signed.msix", make_p7x(compute_digests(pkg))
    )
    raw = signed.read_bytes()
    offset = zipfile.ZipFile(signed).getinfo(SIGNATURE_PART).header_offset
    assert compute_digests(signed)["AXPC"] == hashlib.sha256(raw[:offset]).digest()


def test_rejects_a_signature_that_is_not_the_last_part(tmp_path: Path):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    out = tmp_path / "misplaced.msix"
    with zipfile.ZipFile(pkg) as zin, zipfile.ZipFile(out, "w") as zout:
        zout.writestr(zipfile.ZipInfo(SIGNATURE_PART), b"PKCX")
        for info in zin.infolist():
            zout.writestr(zipfile.ZipInfo(info.filename), zin.read(info.filename))
    with pytest.raises(ValueError, match="not the last part"):
        compute_digests(out)


def test_streamed_entries_are_refused(tmp_path: Path):
    """A data descriptor makes the record length unknowable, so bail out loudly."""
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    raw = bytearray(pkg.read_bytes())
    last = max(zipfile.ZipFile(pkg).infolist(), key=lambda i: i.header_offset)
    name = last.filename.encode("utf-8")

    struct.pack_into("<H", raw, last.header_offset + 6, 0x08)  # local header flags
    entry = raw.rindex(b"PK\x01\x02")  # its central directory entry, last written
    while raw[entry + 46 : entry + 46 + len(name)] != name:
        entry = raw.rindex(b"PK\x01\x02", 0, entry)
    struct.pack_into("<H", raw, entry + 8, 0x08)  # central directory flags

    broken = tmp_path / "streamed.msix"
    broken.write_bytes(raw)
    with pytest.raises(ValueError, match="data descriptor"):
        compute_digests(broken)


def test_code_integrity_is_not_expected_in_the_blockmap(with_code_integrity: Path):
    """CodeIntegrity.cat is covered by AXCI, never listed in AppxBlockMap.xml.

    A real package caught this: `inspect` used to report it as a missing entry.
    """
    from openappx.inspect import inspect_package

    with zipfile.ZipFile(with_code_integrity) as zf:
        assert "AppxMetadata/CodeIntegrity.cat" in zf.namelist()
        assert b"CodeIntegrity" not in zf.read("AppxBlockMap.xml")

    problems = inspect_package(with_code_integrity)["problems"]
    assert not any("CodeIntegrity" in p and "absent from" in p for p in problems)


def test_axci_digest_is_recomputed(with_code_integrity: Path):
    digests = compute_digests(with_code_integrity)
    assert "AXCI" in digests
    with zipfile.ZipFile(with_code_integrity) as zf:
        expected = hashlib.sha256(zf.read("AppxMetadata/CodeIntegrity.cat")).digest()
    assert digests["AXCI"] == expected
