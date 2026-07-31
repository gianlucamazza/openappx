"""Certificate inspection and RFC 3161 timestamping.

The timestamp tests that need a TSA are skipped without network, like the golden
package tests. What they can prove is that the token is a real RFC 3161 response
covering the right bytes; what no test here can prove is that Windows honours it
after the certificate expires.
"""

from __future__ import annotations

import datetime
import os
import zipfile
from pathlib import Path

import pytest

from openappx.pack_core import pack_python

pytest.importorskip("cryptography", reason="needs the optional [sign] extra")

from openappx.sign.certificate import (  # noqa: E402
    certificate_problems,
    certificates_from_p7x,
    signer_info,
)
from openappx.sign.signer import (  # noqa: E402
    _normalise_name,
    load_pfx,
    make_test_certificate,
    sign_package,
)
from openappx.sign.timestamp import (  # noqa: E402
    DEFAULT_TSA,
    TimestampError,
    build_request,
    parse_response,
    token_from_p7x,
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
    return sign_package(
        pack_python(EXAMPLE, tmp_path / "x.msix"), identity, tmp_path / "signed.msix"
    )


# --- certificate -----------------------------------------------------------


def test_reads_the_signing_certificate(signed: Path):
    info = signer_info(signed)
    assert info.subject == PUBLISHER
    assert info.self_signed is True
    assert not info.expired and not info.not_yet_valid
    assert info.not_valid_after > datetime.datetime.now(datetime.timezone.utc)


def test_unsigned_package_has_no_certificate(tmp_path: Path):
    assert signer_info(pack_python(EXAMPLE, tmp_path / "x.msix")) is None


def test_publisher_agreement_is_checked(signed: Path):
    assert certificate_problems(signed) == []


def test_a_publisher_mismatch_is_reported(tmp_path: Path):
    other = make_test_certificate(
        "CN=Someone-Else", tmp_path / "o.pfx", tmp_path / "o.cer"
    )[0]
    package = sign_package(
        pack_python(EXAMPLE, tmp_path / "x.msix"),
        load_pfx(other),
        tmp_path / "signed.msix",
        check_publisher=False,
    )
    assert any("publisher mismatch" in p for p in certificate_problems(package))


def test_state_abbreviation_is_not_a_mismatch():
    """Appx manifests write `S=`, RFC 4514 writes `ST=`; a real package uses both."""
    manifest = "CN=Microsoft Corporation, O=Microsoft Corporation, S=Washington, C=US"
    certificate = "CN=Microsoft Corporation,O=Microsoft Corporation,ST=Washington,C=US"
    assert _normalise_name(manifest) == _normalise_name(certificate)


def test_reads_certificates_out_of_a_real_signature(signed_reference: Path):
    with zipfile.ZipFile(signed_reference) as zf:
        certificates = certificates_from_p7x(zf.read("AppxSignature.p7x"))
    assert certificates
    assert "Microsoft" in certificates[0].subject.rfc4514_string()


def test_a_microsoft_package_passes_the_publisher_check(signed_reference: Path):
    """The `S=`/`ST=` difference above is exactly what this would trip on."""
    assert certificate_problems(signed_reference) == []


def test_rejects_something_that_is_not_a_signature():
    with pytest.raises(ValueError, match="not a p7x"):
        certificates_from_p7x(b"nope")


# --- timestamp, offline ----------------------------------------------------


def test_request_is_a_well_formed_timestamp_query():
    from openappx.sign import asn1

    request = build_request(b"signature-bytes", nonce=1234)
    tag, body, _end = asn1.read_tlv(request)
    assert tag == asn1.TAG_SEQUENCE
    version_tag, version, _ = asn1.read_tlv(body)
    assert version_tag == asn1.TAG_INTEGER
    assert int.from_bytes(version, "big") == 1


def test_request_covers_the_signature_not_the_content():
    import hashlib

    request = build_request(b"the-signature")
    assert hashlib.sha256(b"the-signature").digest() in request


def test_a_refusal_is_reported(monkeypatch):
    from openappx.sign import asn1

    refusal = asn1.sequence(asn1.sequence(asn1.integer(2)))  # rejection
    with pytest.raises(TimestampError, match="refused"):
        parse_response(refusal)


def test_a_granted_response_without_a_token_is_reported():
    from openappx.sign import asn1

    with pytest.raises(TimestampError, match="no token"):
        parse_response(asn1.sequence(asn1.sequence(asn1.integer(0))))


def test_unreachable_authority_is_reported(tmp_path: Path, identity):
    from openappx.sign.timestamp import fetch_token

    with pytest.raises(TimestampError, match="cannot reach"):
        fetch_token(b"signature", "http://127.0.0.1:1", timeout=2)


def test_untimestamped_signature_reports_no_token(signed: Path):
    with zipfile.ZipFile(signed) as zf:
        assert token_from_p7x(zf.read("AppxSignature.p7x")) is None


# --- timestamp, against a real authority -----------------------------------


@pytest.fixture
def tsa_available():
    if os.environ.get("OPENAPPX_NO_NETWORK"):
        pytest.skip("network tests disabled via OPENAPPX_NO_NETWORK")


def test_timestamping_embeds_a_readable_token(tsa_available, tmp_path: Path, identity):
    from openappx.sign.timestamp import fetch_token

    try:
        token = fetch_token(b"some-signature-bytes", DEFAULT_TSA, timeout=30)
    except TimestampError as e:
        pytest.skip(f"timestamp authority unavailable: {e}")

    assert len(token) > 1000  # a token embeds the TSA certificate chain

    package = sign_package(
        pack_python(EXAMPLE, tmp_path / "x.msix"),
        identity,
        tmp_path / "signed.msix",
        timestamp_url=DEFAULT_TSA,
    )
    with zipfile.ZipFile(package) as zf:
        embedded = token_from_p7x(zf.read("AppxSignature.p7x"))
    assert embedded is not None and len(embedded) > 1000


def test_a_timestamped_package_still_verifies(tsa_available, tmp_path: Path, identity):
    """Adding the countersignature must not disturb the digests."""
    from openappx.inspect import inspect_package

    try:
        package = sign_package(
            pack_python(EXAMPLE, tmp_path / "x.msix"),
            identity,
            tmp_path / "signed.msix",
            timestamp_url=DEFAULT_TSA,
        )
    except TimestampError as e:
        pytest.skip(f"timestamp authority unavailable: {e}")

    report = inspect_package(package)
    assert report["problems"] == []
    assert report["signature"]["timestamped"] is True
