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
    # `name` may name a subdirectory (bundles/…), so create the whole path.
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(UPSTREAM + name, timeout=30) as response:
            data = response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"cannot fetch {name}: {e}")
    target.write_bytes(data)
    return target


@pytest.fixture(scope="session")
def signed_reference() -> Path:
    """Microsoft-signed: the cert chain is untrusted, but the digests are valid."""
    return fetch_upstream("SignedUntrustedCert-CERT_E_CHAINING.appx")


@pytest.fixture(scope="session")
def tampered_blockmap() -> Path:
    """Same package with AppxBlockMap.xml altered after signing."""
    return fetch_upstream("SignedTamperedBlockMap-TRUST_E_BAD_DIGEST.appx")


@pytest.fixture(scope="session")
def with_code_integrity() -> Path:
    """A package carrying AppxMetadata/CodeIntegrity.cat, i.e. an AXCI digest."""
    return fetch_upstream("SignedTamperedCodeIntegrity-TRUST_E_BAD_DIGEST.appx")


@pytest.fixture(scope="session")
def reference_bundle() -> Path:
    """A well-formed Microsoft bundle: two application packages, no signature."""
    return fetch_upstream("bundles/ContainsNeutralAndX86AppPackages.appxbundle")


@pytest.fixture(scope="session")
def signed_reference_bundle() -> Path:
    """The same container shape, signed — the signature format does not change."""
    return fetch_upstream("bundles/SignedUntrustedCert-CERT_E_CHAINING.appxbundle")


@pytest.fixture(scope="session")
def bundle_with_wrong_offset() -> Path:
    """Upstream's deliberately-broken bundle: a Package/@Offset that is off."""
    return fetch_upstream("bundles/ManifestPackageHasInvalidOffset.appxbundle")


@pytest.fixture(scope="session")
def bundle_with_wrong_size() -> Path:
    return fetch_upstream("bundles/ManifestPackageHasIncorrectSize.appxbundle")


@pytest.fixture(scope="session")
def bundle_with_compressed_payload() -> Path:
    return fetch_upstream("bundles/PayloadPackageIsCompressed.appxbundle")


@pytest.fixture(scope="session")
def bundle_with_unlisted_payload() -> Path:
    return fetch_upstream("bundles/PayloadPackageNotListedInManifest.appxbundle")
