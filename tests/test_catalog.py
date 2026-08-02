"""What `AppxMetadata/CodeIntegrity.cat` actually is, pinned off a real one.

Everything asserted here was read from Microsoft's own
`SignedTamperedCodeIntegrity-TRUST_E_BAD_DIGEST.appx` — the package the
`with_code_integrity` fixture downloads — not derived from a specification.
This is the research spike for generating the catalogue: a writer would have
to reproduce exactly these facts, and the hardest of them (members are PE
Authenticode digests, acceptance judged only by enforced Device Guard) is why
no writer exists yet. See docs/signing.md, "CodeIntegrity catalogues".
"""

from __future__ import annotations

import hashlib
import struct
import zipfile

# --- Minimal DER reading, enough to walk a catalogue ------------------------

OID_TAG = 0x06
OCTETS_TAG = 0x04
SEQUENCE_TAG = 0x30


def der(data: bytes) -> list[tuple[int, object]]:
    """[(tag, children-or-body), …]; constructed nodes parse recursively."""
    items: list[tuple[int, object]] = []
    i = 0
    while i < len(data):
        tag = data[i]
        length = data[i + 1]
        j = i + 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[j : j + n], "big")
            j += n
        body = data[j : j + length]
        items.append((tag, der(body) if tag & 0x20 else body))
        i = j + length
    return items


def oid(text: str) -> bytes:
    parts = [int(p) for p in text.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        encoded = [value & 0x7F]
        value >>= 7
        while value:
            encoded.append((value & 0x7F) | 0x80)
            value >>= 7
        body += bytes(reversed(encoded))
    return bytes(body)


SIGNED_DATA = oid("1.2.840.113549.1.7.2")
CTL = oid("1.3.6.1.4.1.311.10.1")  # szOID_CTL: the content is a trust list
CATALOG_LIST = oid("1.3.6.1.4.1.311.12.1.1")
CATALOG_MEMBER_V2 = oid("1.3.6.1.4.1.311.12.1.3")
SHA256 = oid("2.16.840.1.101.3.4.2.1")
SPC_PE_IMAGE_DATA = oid("1.3.6.1.4.1.311.2.1.15")

CODE_INTEGRITY = "AppxMetadata/CodeIntegrity.cat"


def authenticode_digest(pe: bytes, algorithm: str) -> str:
    """The Authenticode hash of a PE with no embedded certificate table:
    every byte except the 4-byte CheckSum and the 8-byte security data
    directory entry. Reproduces all four member tags of the real catalogue."""
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    optional = e_lfanew + 4 + 20
    magic = struct.unpack_from("<H", pe, optional)[0]
    checksum = optional + 64
    security_dir = optional + (128 if magic == 0x10B else 144)  # PE32 / PE32+
    digest = hashlib.new(algorithm)
    digest.update(pe[:checksum])
    digest.update(pe[checksum + 4 : security_dir])
    digest.update(pe[security_dir + 8 :])
    return digest.hexdigest()


def catalog_and_parts(package):
    with zipfile.ZipFile(package) as zf:
        return zf.read(CODE_INTEGRITY), {n: zf.read(n) for n in zf.namelist()}


def ctl_content(cat: bytes) -> list:
    """The CertificateTrustList SEQUENCE inside the signed content."""
    top = der(cat)[0][1]  # ContentInfo children
    assert top[0] == (OID_TAG, SIGNED_DATA)
    signed_data = top[1][1][0][1]  # [0] EXPLICIT -> SignedData children
    content_info = signed_data[2][1]
    assert content_info[0] == (OID_TAG, CTL)
    return content_info[1][1][0][1]  # [0] EXPLICIT -> CTL children


def test_the_catalogue_is_signeddata_around_a_certificate_trust_list(
    with_code_integrity,
):
    cat, _ = catalog_and_parts(with_code_integrity)
    ctl = ctl_content(cat)
    # SubjectUsage: this trust list is a catalogue.
    assert ctl[0][1][0] == (OID_TAG, CATALOG_LIST)
    # A 16-byte list identifier and a UTCTIME follow; then the subject
    # algorithm says members are keyed the V2 way (hash as identifier).
    assert len(ctl[1][1]) == 16
    assert ctl[3][1][0] == (OID_TAG, CATALOG_MEMBER_V2)


def test_signeddata_digests_with_sha256(with_code_integrity):
    cat, _ = catalog_and_parts(with_code_integrity)
    top = der(cat)[0][1]
    signed_data = top[1][1][0][1]
    digest_algorithms = signed_data[1][1]
    assert digest_algorithms[0][1][0] == (OID_TAG, SHA256)


def member_tags(cat: bytes) -> set[str]:
    ctl = ctl_content(cat)
    members = ctl[4][1]  # SEQUENCE OF CatalogListMember
    tags = set()
    for _, member in members:
        tag_kind, body = member[0]
        assert tag_kind == OCTETS_TAG
        tags.add(body.hex())
    return tags


def test_members_are_pe_authenticode_digests_and_nothing_else(with_code_integrity):
    """The decisive fact, and the reason no writer exists: each PE payload
    appears twice — once keyed by its SHA-1 and once by its SHA-256
    *Authenticode* digest (CheckSum and security directory excluded) — and
    non-PE payloads are not members at all. Flat hashes match nothing."""
    cat, parts = catalog_and_parts(with_code_integrity)
    tags = member_tags(cat)

    pe_parts = {n: d for n, d in parts.items() if d[:2] == b"MZ"}
    assert pe_parts, "the fixture is expected to carry PE payloads"
    assert len(tags) == 2 * len(pe_parts)

    for data in pe_parts.values():
        assert authenticode_digest(data, "sha1") in tags
        assert authenticode_digest(data, "sha256") in tags

    for name, data in parts.items():
        assert hashlib.sha1(data).hexdigest() not in tags, name
        assert hashlib.sha256(data).hexdigest() not in tags, name


def test_sha256_members_carry_spc_pe_image_data(with_code_integrity):
    """The V2 (SHA-256) members carry an SPC_INDIRECT_DATA attribute whose
    data is SPC_PE_IMAGE_DATA — the catalogue says out loud that the digest
    is over a PE image, not over a flat file."""
    cat, _ = catalog_and_parts(with_code_integrity)
    flattened = cat  # attribute is easiest to assert by encoded presence
    assert (bytes([OID_TAG, len(SPC_PE_IMAGE_DATA)]) + SPC_PE_IMAGE_DATA) in flattened


def test_the_catalogue_entry_sits_before_the_signature_and_is_deflated(
    with_code_integrity,
):
    """Placement and compression, read off the archive: after every payload
    and [Content_Types].xml, immediately before AppxSignature.p7x — and
    deflated, unlike our always-stored generated parts."""
    with zipfile.ZipFile(with_code_integrity) as zf:
        infos = sorted(zf.infolist(), key=lambda i: i.header_offset)
        names = [i.filename for i in infos]
        assert names[-2:] == [CODE_INTEGRITY, "AppxSignature.p7x"]
        cat_info = infos[-2]
        assert cat_info.compress_type == zipfile.ZIP_DEFLATED


def test_the_content_type_is_an_override_not_a_default(with_code_integrity):
    """Microsoft declares the part with an Override — there is no
    Default Extension="cat" — so a writer must do the same."""
    with zipfile.ZipFile(with_code_integrity) as zf:
        content_types = zf.read("[Content_Types].xml").decode("utf-8")
    assert (
        '<Override PartName="/AppxMetadata/CodeIntegrity.cat" '
        'ContentType="application/vnd.ms-pkiseccat"/>' in content_types
    )
    assert 'Extension="cat"' not in content_types
