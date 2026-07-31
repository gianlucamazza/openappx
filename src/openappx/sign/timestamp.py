"""RFC 3161 timestamping, so a signature outlives its certificate.

A signature without a countersignature stops being accepted the day the
certificate expires. A timestamp records that the signing happened while the
certificate was valid, which lets a verifier keep trusting it afterwards.

The token goes into the SignerInfo's **unauthenticated** attributes under
`1.3.6.1.4.1.311.3.3.1`, and its message imprint is the hash of the RSA
signature itself (`encryptedDigest`) — not the content. That is Authenticode's
arrangement, shared with PE signing.

**What is verified here, and what is not.** Neither Microsoft reference package
available to this project is timestamped, so unlike everything else in
`docs/format.md`, this structure was not copied from a working example. What has
been checked: the token is a valid RFC 3161 response accepted by `openssl ts`,
the resulting package still installs on a device, and the token can be read back
out. What has *not* been checked: that Windows honours it once the certificate
expires — that would take an expired certificate and a time machine.

Timestamping needs network access and makes the signature non-reproducible: the
token carries a nonce and the TSA's clock.
"""

from __future__ import annotations

import hashlib
import secrets
import urllib.error
import urllib.request

from openappx.sign import asn1

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RFC3161_TIMESTAMP = "1.3.6.1.4.1.311.3.3.1"

# Public TSAs that speak RFC 3161 over HTTP.
DEFAULT_TSA = "http://timestamp.digicert.com"

_STATUS_GRANTED = (0, 1)  # granted, grantedWithMods


class TimestampError(RuntimeError):
    """The timestamp authority refused, or could not be reached."""


def build_request(signature: bytes, *, nonce: int | None = None) -> bytes:
    """A TimeStampReq over the signature bytes.

    `certReq` is true so the response embeds the TSA certificate; without it a
    verifier has nothing to check the token against.
    """
    imprint = asn1.sequence(
        asn1.algorithm(OID_SHA256),
        asn1.octet_string(hashlib.sha256(signature).digest()),
    )
    return asn1.sequence(
        asn1.integer(1),  # version
        imprint,
        asn1.integer(secrets.randbits(64) if nonce is None else nonce),
        asn1.boolean(True),  # certReq
    )


def parse_response(response: bytes) -> bytes:
    """Pull the TimeStampToken out of a TimeStampResp, or explain the refusal.

    TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }
    """
    tag, body, _end = asn1.read_tlv(response)
    if tag != asn1.TAG_SEQUENCE:
        raise TimestampError("malformed response: not a SEQUENCE")

    status_tag, status_body, offset = asn1.read_tlv(body)
    if status_tag != asn1.TAG_SEQUENCE:
        raise TimestampError("malformed response: status is not a SEQUENCE")

    value_tag, value, _ = asn1.read_tlv(status_body)
    status = int.from_bytes(value, "big") if value_tag == asn1.TAG_INTEGER else -1
    if status not in _STATUS_GRANTED:
        raise TimestampError(
            f"timestamp authority refused the request (status {status})"
        )

    if offset >= len(body):
        raise TimestampError("authority granted the request but returned no token")
    return body[offset:]


def fetch_token(signature: bytes, url: str = DEFAULT_TSA, timeout: int = 30) -> bytes:
    """Ask a TSA to timestamp `signature`; return the raw TimeStampToken."""
    request = urllib.request.Request(
        url,
        data=build_request(signature),
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise TimestampError(f"cannot reach the timestamp authority {url}: {e}") from e
    return parse_response(body)


def unauthenticated_attributes(token: bytes) -> bytes:
    """`[1] IMPLICIT SET OF Attribute` carrying the timestamp token."""
    attribute = asn1.sequence(
        asn1.oid(OID_RFC3161_TIMESTAMP),
        asn1.set_of(token),
    )
    return asn1.tlv(0xA1, attribute)


def token_from_p7x(p7x: bytes) -> bytes | None:
    """Find the timestamp token in a signature, if it carries one.

    Located by scanning for the attribute OID, in the same spirit as the digest
    blob: no full ASN.1 parse, and a stray match yields nothing usable.
    """
    marker = asn1.oid(OID_RFC3161_TIMESTAMP)
    index = p7x.find(marker)
    if index < 0:
        return None
    tag, value, _end = asn1.read_tlv(p7x, index + len(marker))
    if tag != asn1.TAG_SET:
        return None
    return value
