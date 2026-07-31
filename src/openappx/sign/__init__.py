"""Appx signature support.

What works today, with no dependencies:

    parse_p7x_digests(p7x_bytes)  -> declared digests from AppxSignature.p7x
    compute_digests(package)      -> digests recomputed from the archive itself
    signature_problems(package)   -> mismatches between the two

What is **not** implemented: creating a signature. That needs a CMS/PKCS#7
SignedData structure wrapped around the digest blob, which means ASN.1 encoding
and RSA/ECDSA signing — neither is in the standard library, and the upstream
MSIX SDK cannot do it either (`makemsix` validates signatures, it does not
create them). docs/signing.md records what a signer would have to produce.

Verification here is limited to digest coherence: it proves the package matches
what its signature covers, not that the certificate is trusted, unexpired, or
that Identity/@Publisher matches the certificate subject.
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
