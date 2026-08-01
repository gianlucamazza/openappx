"""Build AppxSignature.p7x and attach it to a package.

Every structure here was copied from a real Microsoft-signed package rather than
derived from the spec — see docs/signing.md for the decoded original. The two
hashing rules that are easy to get silently wrong:

- the signed attributes' `messageDigest` covers the *content* of the
  SpcIndirectDataContent SEQUENCE, without its own tag and length;
- the RSA signature covers those attributes encoded as a SET (tag 0x31), not
  with the [0] IMPLICIT tag they carry inside the SignerInfo.

This module needs the optional `cryptography` extra; nothing else in openappx
does, and the default pack path stays dependency-free.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the optional [sign] extra must stay optional at runtime
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.x509 import Certificate

from openappx.sign import asn1
from openappx.sign.digest import (
    DIGEST_HEAD,
    P7X_MAGIC,
    SIGNATURE_PART,
    compute_digests,
)

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_SPC_SIPINFO = "1.3.6.1.4.1.311.2.1.30"
OID_SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11"
OID_SPC_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12"
OID_INDIVIDUAL_CODE_SIGNING = "1.3.6.1.4.1.311.2.1.21"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"

# The subject-interface-package GUID, verbatim from signed artefacts. A bundle
# uses a different one from a package, and getting it wrong is not a subtle
# failure: the device answers 0x800B0100 "no signature was present in the
# subject" even though the signature is well formed and verifies locally.
# Both read out of Microsoft-signed files, not from documentation.
APPX_SIP_GUID = bytes.fromhex("4BDFC50A07CEE24DB76E23C839A09FD1")
BUNDLE_SIP_GUID = bytes.fromhex("B3585F0FDEAA9A4BA43495742D92ECEB")
SIP_VERSION_WORD = bytes.fromhex("01010000")

# AXCI is only present when the package carries a CodeIntegrity catalogue.
DIGEST_ORDER = ("AXPC", "AXCD", "AXCT", "AXBM", "AXCI")


class SigningUnavailable(RuntimeError):
    """The optional `cryptography` dependency is not installed."""


def _require_cryptography():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError as e:  # pragma: no cover - exercised by the error path only
        raise SigningUnavailable(
            "signing needs the optional dependency: pip install 'openappx[sign]'"
        ) from e
    return hashes, serialization, padding, pkcs12


@dataclass(frozen=True)
class SigningIdentity:
    """A certificate and its private key, as `cryptography` objects."""

    certificate: Certificate
    private_key: RSAPrivateKey

    @property
    def subject_rfc4514(self) -> str:
        return self.certificate.subject.rfc4514_string()


def load_pfx(path: Path, password: str | None = None) -> SigningIdentity:
    _hashes, _serialization, _padding, pkcs12 = _require_cryptography()
    raw = Path(path).read_bytes()
    secret = password.encode("utf-8") if password else None
    key, certificate, _extra = pkcs12.load_key_and_certificates(raw, secret)
    if key is None or certificate is None:
        raise ValueError(f"{path}: no key/certificate pair inside")
    return SigningIdentity(certificate=certificate, private_key=key)


def digest_blob(digests: dict[str, bytes]) -> bytes:
    """`APPX` followed by each present digest, in the order Windows writes them."""
    missing = [name for name in ("AXPC", "AXCD", "AXCT", "AXBM") if name not in digests]
    if missing:
        raise ValueError(f"cannot sign: missing digests {', '.join(missing)}")
    blob = bytearray(DIGEST_HEAD)
    for name in DIGEST_ORDER:
        if name in digests:
            blob += name.encode("ascii") + digests[name]
    return bytes(blob)


def spc_indirect_data(blob: bytes, *, bundle: bool = False) -> tuple[bytes, bytes]:
    """Return (full DER SEQUENCE, its content bytes).

    The content is returned separately because that — not the whole SEQUENCE —
    is what the messageDigest attribute hashes.
    """
    sip_info = asn1.sequence(
        asn1.oid(OID_SPC_SIPINFO),
        asn1.sequence(
            asn1.raw_integer(SIP_VERSION_WORD),
            asn1.octet_string(BUNDLE_SIP_GUID if bundle else APPX_SIP_GUID),
            *(asn1.integer(0) for _ in range(5)),
        ),
    )
    message_digest = asn1.sequence(
        asn1.algorithm(OID_SHA256),
        asn1.octet_string(blob),
    )
    content = sip_info + message_digest
    return asn1.tlv(asn1.TAG_SEQUENCE, content), content


def _signed_attributes(spc_content: bytes) -> list[bytes]:
    return [
        # SpcSpOpusInfo, present but empty — as Microsoft's own packages have it
        asn1.sequence(asn1.oid(OID_SPC_OPUS_INFO), asn1.set_of(asn1.sequence())),
        asn1.sequence(
            asn1.oid(OID_CONTENT_TYPE), asn1.set_of(asn1.oid(OID_SPC_INDIRECT_DATA))
        ),
        asn1.sequence(
            asn1.oid(OID_SPC_STATEMENT_TYPE),
            asn1.set_of(asn1.sequence(asn1.oid(OID_INDIVIDUAL_CODE_SIGNING))),
        ),
        asn1.sequence(
            asn1.oid(OID_MESSAGE_DIGEST),
            asn1.set_of(asn1.octet_string(hashlib.sha256(spc_content).digest())),
        ),
    ]


def build_p7x(
    blob: bytes,
    identity: SigningIdentity,
    timestamp_url: str | None = None,
    *,
    bundle: bool = False,
) -> bytes:
    """Wrap a digest blob into a signed AppxSignature.p7x.

    `bundle` selects the subject-interface-package GUID. It is not cosmetic: a
    bundle signed with the package GUID is rejected as unsigned.

    With `timestamp_url`, the RSA signature is countersigned by that RFC 3161
    authority so it outlives the certificate. That needs network access and makes
    the output non-reproducible — the token carries a nonce and the TSA's clock.
    """
    hashes, serialization, padding, _pkcs12 = _require_cryptography()

    spc_full, spc_content = spc_indirect_data(blob, bundle=bundle)
    attributes = _signed_attributes(spc_content)

    # Signed over a SET; carried in the SignerInfo under [0] IMPLICIT.
    to_sign = asn1.set_of(*attributes)
    signature = identity.private_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())

    certificate_der = identity.certificate.public_bytes(serialization.Encoding.DER)
    issuer_der = identity.certificate.issuer.public_bytes()

    signer_fields = [
        asn1.integer(1),
        asn1.sequence(issuer_der, asn1.integer(identity.certificate.serial_number)),
        asn1.algorithm(OID_SHA256),
        asn1.implicit_set(0, *attributes),
        asn1.algorithm(OID_RSA_ENCRYPTION),
        asn1.octet_string(signature),
    ]
    if timestamp_url:
        from openappx.sign.timestamp import fetch_token, unauthenticated_attributes

        # The timestamp covers the signature itself, not the content.
        token = fetch_token(signature, timestamp_url)
        signer_fields.append(unauthenticated_attributes(token))

    signer_info = asn1.sequence(*signer_fields)

    signed_data = asn1.sequence(
        asn1.integer(1),
        asn1.set_of(asn1.algorithm(OID_SHA256)),
        asn1.sequence(asn1.oid(OID_SPC_INDIRECT_DATA), asn1.explicit(0, spc_full)),
        asn1.explicit(0, certificate_der),  # [0] IMPLICIT certificates
        asn1.set_of(signer_info),
    )

    content_info = asn1.sequence(
        asn1.oid(OID_SIGNED_DATA),
        asn1.explicit(0, signed_data),
    )
    return P7X_MAGIC + content_info


# Appx manifests spell stateOrProvinceName `S=`, RFC 4514 spells it `ST=`, and a
# real Microsoft-signed package uses both — the manifest one way, the certificate
# the other. Comparing them literally reports a mismatch that is not there.
_ATTRIBUTE_ALIASES = {"s": "st", "e": "emailaddress", "email": "emailaddress"}


def _normalise_name(name: str) -> str:
    """Compare X.500 names ignoring whitespace, case and attribute spelling."""
    parts = []
    for part in name.split(","):
        attribute, sep, value = part.strip().partition("=")
        key = attribute.strip().casefold()
        parts.append(f"{_ATTRIBUTE_ALIASES.get(key, key)}{sep}{value.strip()}")
    return ",".join(parts).casefold()


def package_publisher(package: Path) -> str | None:
    """`Identity/@Publisher`, from whichever manifest this container carries.

    A bundle keeps its identity in AppxMetadata/AppxBundleManifest.xml, and it
    is signed the same way a package is — so the publisher check has to look
    there too, or every signed bundle reports a missing publisher.
    """
    import zipfile

    from openappx.validate import _identity_attribute

    with zipfile.ZipFile(package) as zf:
        names = zf.namelist()
        for manifest in ("AppxManifest.xml", "AppxMetadata/AppxBundleManifest.xml"):
            if manifest in names:
                text = zf.read(manifest).decode("utf-8", errors="replace")
                return _identity_attribute(text, "Publisher")
    return None


def sign_package(
    package: Path,
    identity: SigningIdentity,
    out_package: Path | None = None,
    *,
    check_publisher: bool = True,
    timestamp_url: str | None = None,
) -> Path:
    """Sign an unsigned package, writing `AppxSignature.p7x` as its last part.

    The manifest's `Identity/@Publisher` must equal the certificate subject, or
    the device rejects the package however valid the signature is — checked here
    so the failure is legible instead of an opaque install error.
    """
    from openappx.pack_core import (
        append_stored_part,  # avoids a cycle at import time
        atomic_write_bytes,
    )

    package = Path(package)
    out_package = Path(out_package) if out_package else package
    archive = package.read_bytes()

    if check_publisher:
        declared = package_publisher(package)
        subject = identity.subject_rfc4514
        if declared is None:
            raise ValueError(f"{package}: no Identity/@Publisher to check against")
        if _normalise_name(declared) != _normalise_name(subject):
            raise ValueError(
                "publisher mismatch — the device would reject this package:\n"
                f"  manifest Identity/@Publisher: {declared}\n"
                f"  certificate subject:          {subject}"
            )

    digests = compute_digests(package)
    if "AXCD" not in digests:
        raise ValueError(f"{package} already carries a signature")

    import zipfile

    with zipfile.ZipFile(package) as zf:
        is_bundle = "AppxMetadata/AppxBundleManifest.xml" in zf.namelist()
    p7x = build_p7x(digest_blob(digests), identity, timestamp_url, bundle=is_bundle)
    signed = append_stored_part(archive, SIGNATURE_PART, p7x)

    return atomic_write_bytes(out_package, signed)


def make_test_certificate(
    publisher: str, out_pfx: Path, out_cer: Path, password: str | None = None
) -> tuple[Path, Path]:
    """Create a self-signed certificate for sideloading.

    `publisher` must equal `Identity/@Publisher` in the manifest exactly, or the
    device rejects the package however valid the signature is.
    """
    hashes, serialization, _padding, _pkcs12 = _require_cryptography()
    # Fixed validity: these scripts must not depend on wall-clock reproducibility
    # traps, and a dev certificate has no business being long-lived.
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID

    name = x509.Name.from_rfc4514_string(publisher)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    secret = password.encode("utf-8") if password else None
    encryption = (
        serialization.BestAvailableEncryption(secret)
        if secret
        else serialization.NoEncryption()
    )
    out_pfx = Path(out_pfx)
    out_cer = Path(out_cer)
    out_pfx.parent.mkdir(parents=True, exist_ok=True)
    out_pfx.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=b"openappx-test",
            key=key,
            cert=certificate,
            cas=None,
            encryption_algorithm=encryption,
        )
    )
    out_cer.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    return out_pfx, out_cer
