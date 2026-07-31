"""Shared fixtures, including opt-in golden packages fetched from upstream."""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

CACHE = Path(__file__).parent / ".cache"
UPSTREAM = (
    "https://raw.githubusercontent.com/microsoft/msix-packaging/master"
    "/src/test/testData/unpack/"
)


def fetch_upstream(name: str) -> Path:
    """Download a signed reference package, or skip the test.

    These are Microsoft's own test packages (MIT licensed). They are cached, not
    committed: the repo keeps no third-party binaries. Set OPENAPPX_NO_NETWORK=1
    to skip without attempting a download.
    """
    target = CACHE / name
    if target.is_file():
        return target
    if os.environ.get("OPENAPPX_NO_NETWORK"):
        pytest.skip("network tests disabled via OPENAPPX_NO_NETWORK")
    CACHE.mkdir(exist_ok=True)
    try:
        with urllib.request.urlopen(UPSTREAM + name, timeout=30) as response:
            data = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"cannot fetch {name}: {e}")
    target.write_bytes(data)
    return target


@pytest.fixture(scope="session")
def signed_reference() -> Path:
    """A genuinely Microsoft-signed package (its cert chain is untrusted, digests are valid)."""
    return fetch_upstream("SignedUntrustedCert-CERT_E_CHAINING.appx")


@pytest.fixture(scope="session")
def tampered_blockmap() -> Path:
    """Same package with AppxBlockMap.xml altered after signing."""
    return fetch_upstream("SignedTamperedBlockMap-TRUST_E_BAD_DIGEST.appx")


@pytest.fixture(scope="session")
def with_code_integrity() -> Path:
    """A package carrying AppxMetadata/CodeIntegrity.cat, i.e. an AXCI digest."""
    return fetch_upstream("SignedTamperedCodeIntegrity-TRUST_E_BAD_DIGEST.appx")
