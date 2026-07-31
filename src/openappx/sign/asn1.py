"""A DER encoder with just enough coverage to build an Appx signature.

Only the constructs `AppxSignature.p7x` needs, written against the structure of a
real Microsoft-signed package (see docs/signing.md). Nothing here parses DER —
reading is done by scanning for the `APPX` marker, as upstream does.
"""

from __future__ import annotations

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def sequence(*parts: bytes) -> bytes:
    return tlv(TAG_SEQUENCE, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    """DER SET OF: elements are sorted by their encoding."""
    return tlv(TAG_SET, b"".join(sorted(parts)))


def explicit(number: int, *parts: bytes) -> bytes:
    """Context-specific constructed tag [n]."""
    return tlv(0xA0 | number, b"".join(parts))


def implicit_set(number: int, *parts: bytes) -> bytes:
    """[n] IMPLICIT SET OF — the encoding signed attributes use."""
    return tlv(0xA0 | number, b"".join(sorted(parts)))


def boolean(value: bool) -> bytes:
    return tlv(TAG_BOOLEAN, b"\xff" if value else b"\x00")


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Return (tag, value, end offset) for the TLV at `offset`.

    The only decoding this module does: enough to pull a timestamp token out of
    a TSA response, which is a two-element SEQUENCE.
    """
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        length, start = first, offset + 2
    else:
        count = first & 0x7F
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        start = offset + 2 + count
    return tag, data[start : start + length], start + length


def null() -> bytes:
    return bytes([TAG_NULL, 0x00])


def octet_string(value: bytes) -> bytes:
    return tlv(TAG_OCTET_STRING, value)


def integer(value: int) -> bytes:
    if value == 0:
        return tlv(TAG_INTEGER, b"\x00")
    if value < 0:
        raise ValueError("negative integers are not needed here")
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:  # keep it positive
        body = b"\x00" + body
    return tlv(TAG_INTEGER, body)


def raw_integer(body: bytes) -> bytes:
    """An INTEGER whose exact content bytes matter (e.g. the SIP version word)."""
    return tlv(TAG_INTEGER, body)


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2:
        raise ValueError(f"not an OID: {dotted}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = bytearray([part & 0x7F])
        part >>= 7
        while part:
            chunk.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        body += chunk
    return tlv(TAG_OID, bytes(body))


def algorithm(oid_value: str) -> bytes:
    """AlgorithmIdentifier with an explicit NULL parameter, as Windows emits."""
    return sequence(oid(oid_value), null())
