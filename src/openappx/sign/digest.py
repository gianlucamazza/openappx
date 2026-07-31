"""Appx signature digests: the `APPX` blob inside AppxSignature.p7x.

Layout, as implemented by microsoft/msix-packaging (`src/inc/internal/AppxSignature.hpp`,
`src/msix/PAL/Signature/OpenSSL/SignatureValidator.cpp`):

    AppxSignature.p7x = b"PKCX" + PKCS#7 SignedData (DER)

and somewhere inside the signed SpcIndirectDataContent:

    b"APPX" + N * (4-byte digest name + 32-byte SHA-256)

    AXPC  every byte of the archive before the AppxSignature.p7x record
    AXCD  the central directory, as it was *before* the signature was inserted
    AXCT  [Content_Types].xml, uncompressed
    AXBM  AppxBlockMap.xml, uncompressed
    AXCI  AppxMetadata/CodeIntegrity.cat, uncompressed (optional)

Upstream locates the blob by scanning the DER for the `APPX` marker rather than
parsing ASN.1; this module does the same, which is why it needs no ASN.1 support.

AXPC/AXCT/AXBM are checked against a real Microsoft-signed package in the test
suite. AXCD is **not verifiable after the fact**: inserting the signature rewrites
the central directory and the end-of-central-directory records, and the pre-signature
bytes cannot be reconstructed from the signed file. Upstream does not verify it
either (`AppxSignature.cpp`: "TODO: unnamed stream for central directory?").
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

from openappx.blockmap import read_local_header

P7X_MAGIC = b"PKCX"
DIGEST_HEAD = b"APPX"
HASH_BYTES = 32
ENTRY_SIZE = 4 + HASH_BYTES

AXPC, AXCD, AXCT, AXBM, AXCI = b"AXPC", b"AXCD", b"AXCT", b"AXBM", b"AXCI"
DIGEST_NAMES = (AXPC, AXCD, AXCT, AXBM, AXCI)

SIGNATURE_PART = "AppxSignature.p7x"
CONTENT_TYPES_PART = "[Content_Types].xml"
BLOCKMAP_PART = "AppxBlockMap.xml"
CODE_INTEGRITY_PART = "AppxMetadata/CodeIntegrity.cat"

# Digests this module can recompute from a finished archive; see module docstring.
RECOMPUTABLE = ("AXPC", "AXCT", "AXBM", "AXCI")

_FLAG_DATA_DESCRIPTOR = 0x08


def parse_p7x_digests(p7x: bytes) -> dict[str, bytes]:
    """Extract the declared digests from an AppxSignature.p7x blob."""
    if not p7x.startswith(P7X_MAGIC):
        raise ValueError(f"not a p7x signature: expected {P7X_MAGIC!r} header")

    start = 4
    while True:
        head = p7x.find(DIGEST_HEAD, start)
        if head < 0:
            raise ValueError("no APPX digest header found in the signature")
        digests = _read_entries(p7x, head + len(DIGEST_HEAD))
        if digests:  # a stray "APPX" in the DER would yield nothing
            return digests
        start = head + 1


def _read_entries(blob: bytes, offset: int) -> dict[str, bytes]:
    digests: dict[str, bytes] = {}
    while offset + ENTRY_SIZE <= len(blob):
        name = blob[offset : offset + 4]
        if name not in DIGEST_NAMES:
            break
        digests[name.decode("ascii")] = blob[offset + 4 : offset + ENTRY_SIZE]
        offset += ENTRY_SIZE
    return digests


def central_directory_offset(raw: bytes, infos: list[zipfile.ZipInfo]) -> int:
    """Offset where the central directory starts, i.e. the end of the last record.

    Derived from the last local record rather than the EOCD, which stores
    0xFFFFFFFF placeholders in ZIP64 archives.
    """
    if not infos:
        raise ValueError("archive has no entries")
    last = max(infos, key=lambda i: i.header_offset)
    if last.flag_bits & _FLAG_DATA_DESCRIPTOR:
        raise ValueError(
            f"{last.filename}: streamed entry (data descriptor); "
            "record length cannot be determined"
        )
    header = read_local_header(raw, last.header_offset)
    return last.header_offset + header.size + last.compress_size


def compute_digests(package: Path) -> dict[str, bytes]:
    """Recompute the digests that can be derived from a finished package.

    For an unsigned package this includes AXCD, and the result is exactly what a
    signer must cover. For a signed package AXCD is omitted (see module docstring).
    """
    raw = Path(package).read_bytes()
    digests: dict[str, bytes] = {}

    with zipfile.ZipFile(package) as zf:
        infos = zf.infolist()
        names = {i.filename for i in infos}
        signature = next((i for i in infos if i.filename == SIGNATURE_PART), None)

        cd_offset = central_directory_offset(raw, infos)
        if signature is None:
            digests["AXPC"] = hashlib.sha256(raw[:cd_offset]).digest()
            digests["AXCD"] = hashlib.sha256(raw[cd_offset:]).digest()
        else:
            # The signature must be the last record for AXPC to mean anything.
            if signature.header_offset != max(i.header_offset for i in infos):
                raise ValueError(
                    f"{SIGNATURE_PART} is not the last part of the archive"
                )
            digests["AXPC"] = hashlib.sha256(raw[: signature.header_offset]).digest()

        for part, key in (
            (CONTENT_TYPES_PART, "AXCT"),
            (BLOCKMAP_PART, "AXBM"),
            (CODE_INTEGRITY_PART, "AXCI"),
        ):
            if part in names:
                digests[key] = hashlib.sha256(zf.read(part)).digest()

    return digests


def signature_problems(package: Path) -> list[str]:
    """Compare a package against the digests declared in its own signature.

    Empty list means every recomputable digest matches. Raises if the package
    carries no signature.
    """
    with zipfile.ZipFile(package) as zf:
        if SIGNATURE_PART not in zf.namelist():
            raise ValueError(f"package has no {SIGNATURE_PART}")
        declared = parse_p7x_digests(zf.read(SIGNATURE_PART))

    actual = compute_digests(package)
    problems: list[str] = []

    for required in ("AXPC", "AXCT", "AXBM"):
        if required not in declared:
            problems.append(f"signature declares no {required} digest")

    for name, value in declared.items():
        if name not in RECOMPUTABLE:
            continue  # AXCD: cannot be recomputed from a signed archive
        expected = actual.get(name)
        if expected is None:
            problems.append(
                f"signature declares {name} but the package has no such part"
            )
        elif expected != value:
            problems.append(
                f"{name} digest mismatch: signature says {value.hex()[:16]}…, "
                f"package hashes to {expected.hex()[:16]}…"
            )

    for name in actual:
        if name not in declared and name != "AXCD":
            problems.append(f"package has {name} content not covered by the signature")

    return problems
