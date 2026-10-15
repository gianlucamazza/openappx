"""`.msixbundle` support, checked against Microsoft's own reference bundles.

The format facts asserted here were read off those bundles, not the schema: the
blockmap covers only the bundle manifest, payload packages are stored, and each
`Offset` points at the payload's data rather than its local header.
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from openappx.blockmap import read_local_header
from openappx.bundle import (
    BUNDLE_MANIFEST,
    build_bundle,
    bundle_problems,
    bundle_version,
    read_package,
)
from openappx.inspect import inspect_package
from openappx.pack_core import pack_python

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"


_COUNTER = iter(range(1000))


def package_for(tmp_path: Path, architecture: str, name: str | None = None) -> Path:
    """Pack the example under a different architecture, or a different identity."""
    tag = next(_COUNTER)
    layout = tmp_path / f"layout-{tag}"
    shutil.copytree(EXAMPLE, layout)
    manifest = layout / "AppxManifest.xml"
    text = manifest.read_text().replace(
        'ProcessorArchitecture="x64"', f'ProcessorArchitecture="{architecture}"'
    )
    if name:
        text = text.replace('Name="OpenAppx.Example"', f'Name="{name}"')
    manifest.write_text(text)
    return pack_python(layout, tmp_path / f"app-{architecture}-{tag}.msix")


@pytest.fixture
def two_packages(tmp_path: Path) -> list[Path]:
    return [package_for(tmp_path, "x64"), package_for(tmp_path, "x86")]


def test_a_bundle_holds_the_packages_and_the_generated_parts(
    tmp_path: Path, two_packages: list[Path]
):
    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
    assert BUNDLE_MANIFEST in names
    assert "AppxManifest.xml" not in names  # a bundle has no package manifest
    assert {p.name for p in two_packages} <= set(names)


def test_a_fresh_bundle_inspects_clean(tmp_path: Path, two_packages: list[Path]):
    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    assert inspect_package(out)["problems"] == []


def test_the_blockmap_covers_only_the_bundle_manifest(
    tmp_path: Path, two_packages: list[Path]
):
    """A package blockmap hashes every payload; a bundle blockmap has one File."""
    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    with zipfile.ZipFile(out) as zf:
        blockmap = zf.read("AppxBlockMap.xml").decode()
    assert blockmap.count("<File ") == 1
    assert "AppxMetadata\\AppxBundleManifest.xml" in blockmap
    for package in two_packages:
        assert package.name not in blockmap


def test_payload_packages_are_stored(tmp_path: Path, two_packages: list[Path]):
    """Deflating one would make the Offset and Size in the manifest meaningless."""
    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    with zipfile.ZipFile(out) as zf:
        for package in two_packages:
            assert zf.getinfo(package.name).compress_type == zipfile.ZIP_STORED


def test_offset_points_at_the_data_not_the_header(
    tmp_path: Path, two_packages: list[Path]
):
    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    raw = out.read_bytes()
    with zipfile.ZipFile(out) as zf:
        manifest = zf.read(BUNDLE_MANIFEST).decode()
        for package in two_packages:
            info = zf.getinfo(package.name)
            header = read_local_header(raw, info.header_offset)
            expected = info.header_offset + header.size
            assert f'FileName="{package.name}" Offset="{expected}"' in manifest
            assert raw[expected : expected + 4] == package.read_bytes()[:4]


def test_the_bundle_is_byte_reproducible(tmp_path: Path, two_packages: list[Path]):
    first = build_bundle(two_packages, tmp_path / "a.msixbundle").read_bytes()
    second = build_bundle(two_packages, tmp_path / "b.msixbundle").read_bytes()
    assert first == second


def test_packages_with_different_identities_are_refused(tmp_path: Path):
    """One bundle names one application; a device resolves against that identity."""
    packages = [
        package_for(tmp_path, "x64"),
        package_for(tmp_path, "x86", name="OpenAppx.Other"),
    ]
    with pytest.raises(ValueError, match="disagree on Identity/@Name"):
        build_bundle(packages, tmp_path / "app.msixbundle")


def test_two_packages_for_the_same_architecture_are_refused(tmp_path: Path):
    packages = [package_for(tmp_path, "x64"), package_for(tmp_path, "x64")]
    with pytest.raises(ValueError, match="same architecture"):
        build_bundle(packages, tmp_path / "app.msixbundle")


def resource_package(tmp_path: Path, resource_id: str, language: str) -> Path:
    """A real resource package: Identity/@ResourceId and no architecture."""
    tag = next(_COUNTER)
    layout = tmp_path / f"res-{tag}"
    shutil.copytree(REPO / "examples" / "resource-only", layout)
    manifest = layout / "AppxManifest.xml"
    text = manifest.read_text().replace(
        'ProcessorArchitecture="x64" />', f'ResourceId="{resource_id}" />'
    )
    text = text.replace(
        "<PublisherDisplayName>openappx</PublisherDisplayName>",
        "<PublisherDisplayName>openappx</PublisherDisplayName>"
        "<ResourcePackage>true</ResourcePackage>",
    ).replace('<Resource Language="en-US" />', f'<Resource Language="{language}" />')
    manifest.write_text(text)
    return pack_python(layout, tmp_path / f"res-{tag}.msix")


def test_a_resource_only_bundle_is_allowed(tmp_path: Path):
    """Upstream ships ContainsOnlyResourcePackages: language packs look like this."""
    packages = [
        resource_package(tmp_path, "language-en", "en-US"),
        resource_package(tmp_path, "language-it", "it-IT"),
    ]
    out = build_bundle(packages, tmp_path / "res.msixbundle")
    assert inspect_package(out)["problems"] == []


def test_a_resource_package_is_recognised_by_its_resource_id(tmp_path: Path):
    """Not by the absence of <Applications>, which the device disagreed with."""
    entry = read_package(resource_package(tmp_path, "language-it", "it-IT"))
    assert entry.kind == "resource"
    assert entry.resource_id == "language-it"
    assert entry.architecture is None


def test_a_package_without_a_resource_id_is_an_application(tmp_path: Path):
    entry = read_package(package_for(tmp_path, "x64"))
    assert entry.kind == "application"
    assert entry.architecture == "x64"


def test_the_resource_language_example_bundles_beside_minimal_layout(tmp_path: Path):
    """The checked-in example, not a synthesised package: what the README's
    bundle walkthrough packs must classify as a resource package and bundle
    cleanly beside minimal-layout, whose identity it deliberately shares."""
    app = pack_python(EXAMPLE, tmp_path / "app.msix")
    res = pack_python(
        REPO / "examples" / "resource-language", tmp_path / "lang-de.msix"
    )
    entry = read_package(res)
    assert entry.kind == "resource"
    assert entry.resource_id == "language-de"
    assert entry.architecture is None
    assert entry.languages == ("de-DE",)
    out = build_bundle([app, res], tmp_path / "app.msixbundle")
    assert inspect_package(out)["problems"] == []


def test_the_bundle_version_zeroes_the_revision():
    """What MakeAppx does when not told otherwise."""

    class Fake:
        def __init__(self, version):
            self.version = version

    assert bundle_version([Fake("1.5.2.789"), Fake("1.5.1.4")]) == "1.5.2.0"
    assert bundle_version([Fake("not a version")]) == "1.0.0.0"


def test_problems_are_reported_together(tmp_path: Path):
    """Like the other checkers here, it returns a list rather than raising."""
    entries = [
        read_package(package_for(tmp_path, "x64", name="OpenAppx.A")),
        read_package(package_for(tmp_path, "x64", name="OpenAppx.B")),
    ]
    problems = bundle_problems(entries)
    assert any("Identity/@Name" in p for p in problems)
    assert any("same architecture" in p for p in problems)


def test_a_signed_bundle_verifies_against_its_own_signature(
    tmp_path: Path, two_packages: list[Path]
):
    """The signer needs no bundle-specific code: it signs the container."""
    pytest.importorskip("cryptography")
    from openappx.sign.signer import load_pfx, make_test_certificate, sign_package

    pfx, _cer = make_test_certificate(
        "CN=OpenAppx-Example", tmp_path / "t.pfx", tmp_path / "t.cer"
    )
    identity = load_pfx(pfx)
    # A signed bundle needs signed payloads: signing only the container is
    # answered as if the container were unsigned.
    for package in two_packages:
        sign_package(package, identity)
    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    sign_package(out, identity)
    report = inspect_package(out)
    assert report["problems"] == []
    assert report["signed"] is True


def test_a_signed_bundle_with_unsigned_payloads_is_reported(
    tmp_path: Path, two_packages: list[Path]
):
    """The device blames the bundle for it, so inspect has to name the payload."""
    pytest.importorskip("cryptography")
    from openappx.sign.signer import load_pfx, make_test_certificate, sign_package

    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    pfx, _cer = make_test_certificate(
        "CN=OpenAppx-Example", tmp_path / "t.pfx", tmp_path / "t.cer"
    )
    sign_package(out, load_pfx(pfx))
    problems = inspect_package(out)["problems"]
    assert all("payload package is not signed" in p for p in problems)
    assert len(problems) == len(two_packages)


def test_a_bundle_signature_uses_its_own_sip_guid(
    tmp_path: Path, two_packages: list[Path]
):
    """A bundle signed with the package GUID is rejected as unsigned."""
    pytest.importorskip("cryptography")
    from openappx.sign.signer import (
        APPX_SIP_GUID,
        BUNDLE_SIP_GUID,
        load_pfx,
        make_test_certificate,
        sign_package,
    )

    out = build_bundle(two_packages, tmp_path / "app.msixbundle")
    pfx, _cer = make_test_certificate(
        "CN=OpenAppx-Example", tmp_path / "t.pfx", tmp_path / "t.cer"
    )
    sign_package(out, load_pfx(pfx))
    with zipfile.ZipFile(out) as zf:
        signature = zf.read("AppxSignature.p7x")
    assert BUNDLE_SIP_GUID in signature
    assert APPX_SIP_GUID not in signature


# --- against Microsoft's own bundles -----------------------------------------
# Same reasoning as tests/test_signature.py: the format is checked against real
# artefacts, so a drift in our reading fails here rather than on a device.


def test_a_microsoft_bundle_inspects_clean(reference_bundle: Path):
    report = inspect_package(reference_bundle)
    assert report["problems"] == []
    assert report["identity"]["Name"] == "Test"


def test_a_signed_microsoft_bundle_verifies(signed_reference_bundle: Path):
    """Bundle and package signatures are the same structure over the same digests."""
    report = inspect_package(signed_reference_bundle)
    assert report["problems"] == []
    assert report["signed"] is True
    assert "AXBM" in report["signature"]["verified"]


def test_microsoft_bundles_use_data_descriptors_and_still_read(
    reference_bundle: Path,
):
    """Ours emits none; theirs does. Both are valid, so inspect must accept both."""
    raw = reference_bundle.read_bytes()
    assert b"PK\x07\x08" in raw
    assert inspect_package(reference_bundle)["problems"] == []


def test_a_wrong_offset_is_caught(bundle_with_wrong_offset: Path):
    problems = inspect_package(bundle_with_wrong_offset)["problems"]
    assert any("Offset=" in p and "data starts at" in p for p in problems)


def test_a_wrong_size_is_caught(bundle_with_wrong_size: Path):
    problems = inspect_package(bundle_with_wrong_size)["problems"]
    assert any("Size=" in p and "archive holds" in p for p in problems)


def test_a_compressed_payload_is_caught(bundle_with_compressed_payload: Path):
    problems = inspect_package(bundle_with_compressed_payload)["problems"]
    assert any("must be stored" in p for p in problems)


def test_a_payload_missing_from_the_manifest_is_caught(
    bundle_with_unlisted_payload: Path,
):
    problems = inspect_package(bundle_with_unlisted_payload)["problems"]
    assert any("not listed in the bundle manifest" in p for p in problems)


# --- the command line ---------------------------------------------------------


def test_the_cli_builds_a_bundle(tmp_path: Path, two_packages: list[Path], capsys):
    from openappx.cli import main as cli_main

    out = tmp_path / "app.msixbundle"
    argv = ["bundle", "--out", str(out)]
    for package in two_packages:
        argv += ["--package", str(package)]
    assert cli_main(argv) == 0
    assert "Wrote" in capsys.readouterr().out
    assert inspect_package(out)["problems"] == []


def test_the_cli_reports_a_missing_package(tmp_path: Path, capsys):
    from openappx.cli import main as cli_main

    absent = str(tmp_path / "absent.msix")
    code = cli_main(["bundle", "--package", absent, "--out", str(tmp_path / "b")])
    assert code == 2
    assert "no such package" in capsys.readouterr().err


def test_the_cli_reports_incompatible_packages(tmp_path: Path, capsys):
    """Exit 2, like every other usage or layout failure here."""
    from openappx.cli import main as cli_main

    packages = [
        package_for(tmp_path, "x64"),
        package_for(tmp_path, "x86", name="OpenAppx.Other"),
    ]
    argv = ["bundle", "--out", str(tmp_path / "app.msixbundle")]
    for package in packages:
        argv += ["--package", str(package)]
    assert cli_main(argv) == 2
    assert "disagree on Identity/@Name" in capsys.readouterr().err


def test_bundle_appears_in_the_cli_usage(capsys):
    from openappx.cli import main as cli_main

    cli_main(["--help"])
    assert "openappx bundle" in capsys.readouterr().out
