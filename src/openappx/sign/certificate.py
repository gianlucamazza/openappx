"""Read the certificate out of a signature and check it against the manifest.

Digest verification proves a package matches what it claims to cover; it says
nothing about *who* signed it. These checks close part of that gap: the publisher
in the manifest must equal the certificate subject, and an expired certificate is
worth knowing about before a device refuses the install.

What is still not checked: chain of trust and revocation. Both need a trust store
and a policy decision about which roots count, which is the device's job, not
ours. `inspect` says so rather than implying more than it verifies.

Needs the optional `[sign]` extra; callers degrade gracefully when it is absent.
"""

from __future__ import annotations

import datetime
import zipfile
from dataclasses import dataclass
from pathlib import Path

from openappx.sign.digest import P7X_MAGIC, SIGNATURE_PART


class CertificateInspectionUnavailable(RuntimeError):
    """`cryptography` is not installed, so the certificate cannot be read."""


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    issuer: str
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    self_signed: bool

    @property
    def expired(self) -> bool:
        return datetime.datetime.now(datetime.timezone.utc) > self.not_valid_after

    @property
    def not_yet_valid(self) -> bool:
        return datetime.datetime.now(datetime.timezone.utc) < self.not_valid_before


def _load_pkcs7():
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise CertificateInspectionUnavailable(
            "reading certificates needs: pip install 'openappx[sign]'"
        ) from e
    return pkcs7


def certificates_from_p7x(p7x: bytes) -> list:
    """Every certificate embedded in an AppxSignature.p7x."""
    pkcs7 = _load_pkcs7()
    if not p7x.startswith(P7X_MAGIC):
        raise ValueError(f"not a p7x signature: expected {P7X_MAGIC!r} header")

    import warnings

    with warnings.catch_warnings():
        # Real signatures are BER, not strict DER; cryptography copes but warns.
        warnings.simplefilter("ignore")
        return list(pkcs7.load_der_pkcs7_certificates(p7x[len(P7X_MAGIC) :]))


def signer_info(package: Path) -> CertificateInfo | None:
    """Describe the signing certificate, or None if the package is unsigned."""
    with zipfile.ZipFile(package) as zf:
        if SIGNATURE_PART not in zf.namelist():
            return None
        certificates = certificates_from_p7x(zf.read(SIGNATURE_PART))

    if not certificates:
        raise ValueError("signature carries no certificate")

    certificate = certificates[0]
    return CertificateInfo(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
        self_signed=certificate.subject == certificate.issuer,
    )


def certificate_problems(package: Path) -> list[str]:
    """Publisher agreement and validity dates. Never a claim about trust."""
    from openappx.sign.signer import _normalise_name, package_publisher

    info = signer_info(package)
    if info is None:
        return []

    problems: list[str] = []
    declared = package_publisher(package)
    if declared is None:
        problems.append("signed package has no Identity/@Publisher to check")
    elif _normalise_name(declared) != _normalise_name(info.subject):
        problems.append(
            f"publisher mismatch: manifest says {declared}, "
            f"certificate subject is {info.subject}"
        )

    if info.expired:
        problems.append(
            f"signing certificate expired on {info.not_valid_after:%Y-%m-%d}"
        )
    elif info.not_yet_valid:
        problems.append(
            f"signing certificate is not valid until {info.not_valid_before:%Y-%m-%d}"
        )
    return problems
