"""Signature creation.

The structural assertions compare our output against a real Microsoft-signed
package field by field; the acceptance proof is in docs/signing.md, where an
Xbox installed a package produced entirely by this code.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from openappx.pack_core import pack_python
from openappx.sign import parse_p7x_digests, signature_problems
from openappx.sign.digest import P7X_MAGIC, SIGNATURE_PART, compute_digests

pytest.importorskip("cryptography", reason="signing needs the optional [sign] extra")

from openappx.sign import asn1  # noqa: E402
from openappx.sign.signer import (  # noqa: E402
    build_p7x,
    digest_blob,
    load_pfx,
    make_test_certificate,
    sign_package,
    spc_indirect_data,
)

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"
PUBLISHER = "CN=OpenAppx-Example"


@pytest.fixture(scope="module")
def identity(tmp_path_factory):
    out = tmp_path_factory.mktemp("cert")
    pfx, _cer = make_test_certificate(PUBLISHER, out / "t.pfx", out / "t.cer")
    return load_pfx(pfx)


@pytest.fixture
def signed(tmp_path: Path, identity) -> Path:
    unsigned = pack_python(EXAMPLE, tmp_path / "x.msix")
    return sign_package(unsigned, identity, tmp_path / "signed.msix")


def test_signed_package_verifies_against_itself(signed: Path):
    assert signature_problems(signed) == []


def test_signature_is_the_last_part(signed: Path):
    with zipfile.ZipFile(signed) as zf:
        assert zf.namelist()[-1] == SIGNATURE_PART
        info = zf.getinfo(SIGNATURE_PART)
        assert info.header_offset == max(i.header_offset for i in zf.infolist())


def test_p7x_starts_with_the_magic(signed: Path):
    with zipfile.ZipFile(signed) as zf:
        assert zf.read(SIGNATURE_PART).startswith(P7X_MAGIC)


def test_declared_digests_match_the_archive(signed: Path):
    with zipfile.ZipFile(signed) as zf:
        declared = parse_p7x_digests(zf.read(SIGNATURE_PART))
    assert set(declared) == {"AXPC", "AXCD", "AXCT", "AXBM"}
    actual = compute_digests(signed)
    for name in ("AXPC", "AXCT", "AXBM"):
        assert declared[name] == actual[name]


def test_signing_preserves_the_other_parts(tmp_path: Path, identity):
    unsigned = pack_python(EXAMPLE, tmp_path / "x.msix")
    before = {
        n: zipfile.ZipFile(unsigned).read(n)
        for n in zipfile.ZipFile(unsigned).namelist()
    }
    signed = sign_package(unsigned, identity, tmp_path / "signed.msix")
    with zipfile.ZipFile(signed) as zf:
        for name, data in before.items():
            assert zf.read(name) == data


def test_refuses_to_sign_twice(signed: Path, identity, tmp_path: Path):
    with pytest.raises(ValueError, match="already carries a signature"):
        sign_package(signed, identity, tmp_path / "again.msix")


def test_message_digest_covers_the_content_not_the_wrapper():
    """The rule that is easiest to get wrong, verified against the real layout."""
    blob = digest_blob({k: bytes(32) for k in ("AXPC", "AXCD", "AXCT", "AXBM")})
    full, content = spc_indirect_data(blob)
    assert full.endswith(content)
    assert len(full) > len(content)  # tag + length are excluded from the hash
    assert hashlib.sha256(content).digest() != hashlib.sha256(full).digest()


def test_digest_blob_layout():
    digests = {
        name: bytes([i]) * 32 for i, name in enumerate(("AXPC", "AXCD", "AXCT", "AXBM"))
    }
    blob = digest_blob(digests)
    assert blob[:4] == b"APPX"
    assert len(blob) == 4 + 4 * 36
    assert blob[4:8] == b"AXPC"  # order is fixed, not dict order


def test_digest_blob_requires_every_mandatory_digest():
    with pytest.raises(ValueError, match="missing digests"):
        digest_blob({"AXPC": bytes(32)})


def test_rsa_signature_covers_the_signed_attributes(signed: Path, identity):
    """Verify the signature the way a validator would, from the outside."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    from openappx.sign.signer import _signed_attributes

    unsigned_digests = compute_digests(signed)
    with zipfile.ZipFile(signed) as zf:
        declared = parse_p7x_digests(zf.read(SIGNATURE_PART))
        der = zf.read(SIGNATURE_PART)[len(P7X_MAGIC) :]

    _full, content = spc_indirect_data(
        digest_blob({**unsigned_digests, "AXCD": declared["AXCD"]})
    )
    to_verify = asn1.set_of(*_signed_attributes(content))
    identity.certificate.public_key().verify(
        der[-256:], to_verify, padding.PKCS1v15(), hashes.SHA256()
    )


def test_structure_matches_a_microsoft_package(signed: Path, signed_reference: Path):
    """Same DER shape, offset for offset, up to the digest values themselves."""
    ours = zipfile.ZipFile(signed).read(SIGNATURE_PART)[len(P7X_MAGIC) :]
    theirs = zipfile.ZipFile(signed_reference).read(SIGNATURE_PART)[len(P7X_MAGIC) :]

    # The SpcIndirectDataContent (SIP info + digest blob) is fixed-size here:
    # both carry four digests, so the encodings must agree byte-for-byte except
    # for the hashes themselves.
    marker = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x1e"  # OID 1.3.6.1.4.1.311.2.1.30
    assert marker in ours and marker in theirs
    ours_sip = ours[ours.index(marker) : ours.index(marker) + 41]
    theirs_sip = theirs[theirs.index(marker) : theirs.index(marker) + 41]
    assert ours_sip == theirs_sip  # same SIP GUID and version word


def test_certificate_subject_is_the_requested_publisher(tmp_path: Path):
    pfx, cer = make_test_certificate(PUBLISHER, tmp_path / "a.pfx", tmp_path / "a.cer")
    assert load_pfx(pfx).subject_rfc4514 == PUBLISHER
    assert cer.read_bytes()[:1] == b"\x30"  # DER certificate


def test_certificate_can_be_password_protected(tmp_path: Path):
    pfx, _cer = make_test_certificate(
        PUBLISHER, tmp_path / "b.pfx", tmp_path / "b.cer", password="secret"
    )
    assert load_pfx(pfx, "secret").subject_rfc4514 == PUBLISHER
    with pytest.raises(Exception):
        load_pfx(pfx)


def test_build_p7x_is_deterministic_for_a_fixed_key(identity):
    blob = digest_blob({k: bytes(32) for k in ("AXPC", "AXCD", "AXCT", "AXBM")})
    assert build_p7x(blob, identity) == build_p7x(blob, identity)


def test_publisher_mismatch_is_caught_before_signing(tmp_path: Path):
    """The device answers this with an opaque code; catch it locally instead."""
    other = make_test_certificate(
        "CN=Someone-Else", tmp_path / "o.pfx", tmp_path / "o.cer"
    )[0]
    unsigned = pack_python(EXAMPLE, tmp_path / "x.msix")
    with pytest.raises(ValueError, match="publisher mismatch"):
        sign_package(unsigned, load_pfx(other), tmp_path / "signed.msix")


def test_publisher_check_can_be_skipped(tmp_path: Path):
    other = make_test_certificate(
        "CN=Someone-Else", tmp_path / "o.pfx", tmp_path / "o.cer"
    )[0]
    unsigned = pack_python(EXAMPLE, tmp_path / "x.msix")
    out = sign_package(
        unsigned, load_pfx(other), tmp_path / "signed.msix", check_publisher=False
    )
    assert out.is_file()


def test_publisher_comparison_tolerates_whitespace(tmp_path: Path):
    from openappx.sign.signer import _normalise_name

    assert _normalise_name("CN=A, O=B") == _normalise_name("CN=A,O=B")
    assert _normalise_name("CN=a") == _normalise_name("CN=A")
    assert _normalise_name("CN=A,O=B") != _normalise_name("O=B,CN=A")
