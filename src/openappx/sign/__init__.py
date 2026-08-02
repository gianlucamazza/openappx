"""Appx signature support.

Reading works with no dependencies:

    parse_p7x_digests(p7x_bytes)  -> declared digests from AppxSignature.p7x
    compute_digests(package)      -> digests recomputed from the archive itself
    signature_problems(package)   -> mismatches between the two

Creating a signature works too — `openappx sign` (signer.py) builds the
CMS/PKCS#7 SignedData around the digest blob and attaches it — but it needs
the optional `[sign]` extra for the RSA/ECDSA primitives. Every structure it
emits was copied from a real Microsoft signature and confirmed by a console
accepting the package; docs/signing.md records the evidence.

Verification proves digest coherence, publisher agreement and validity dates
(certificate.py). Chain of trust and revocation are deliberately not checked:
both need a trust store and a policy about which roots count, which is the
device's job, not ours.
"""

from __future__ import annotations

from openappx.sign.digest import (
    DIGEST_NAMES,
    P7X_MAGIC,
    RECOMPUTABLE,
    SIGNATURE_PART,
    compute_digests,
    parse_p7x_digests,
    signature_problems,
)

__all__ = [
    "DIGEST_NAMES",
    "P7X_MAGIC",
    "RECOMPUTABLE",
    "SIGNATURE_PART",
    "compute_digests",
    "parse_p7x_digests",
    "signature_problems",
]
