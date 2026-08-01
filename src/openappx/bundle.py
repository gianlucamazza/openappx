"""Build an `.msixbundle` from finished `.msix` packages.

A bundle is the same OPC ZIP container as a package, and this module reuses the
writer in `pack_core` unchanged. What differs is what goes inside, and every
point below was read off Microsoft's own reference bundles
(`src/test/testData/unpack/bundles` upstream), not derived from the schema:

- The manifest is `AppxMetadata/AppxBundleManifest.xml`, root element `<Bundle>`
  in the 2013 namespace — not `AppxManifest.xml`.
- **`AppxBlockMap.xml` covers only that manifest.** A package blockmap hashes
  every payload file; a bundle blockmap has exactly one `<File>`. The payload
  packages carry their own blockmaps and their own signatures.
- Payload packages are **stored**, never deflated. Their `Offset` in the bundle
  manifest points at the file *data* — the local header offset plus `LfhSize` —
  so it can only be filled in after the archive is laid out.
- `[Content_Types].xml` maps `appx` and declares the `xml` default as
  `bundlemanifest+xml`, where a package says `manifest+xml`.

Deliberately not copied: the reference bundles write data descriptors after each
entry (24 bytes, `PK\\x07\\x08`). They are optional, our writer emits none, and
`pack_core.append_stored_part` refuses archives that have them.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from openappx.blockmap import (
    _xml_escape,
    prepare_file,
    render_blockmap_xml,
    zip_local_header_size,
)
from openappx.pack_core import (
    _METHOD_DEFLATE,
    _METHOD_STORE,
    _Entry,
    _write_central_directory,
    _write_entry,
    atomic_write_bytes,
    zip64_local_extra,
)

BUNDLE_MANIFEST = "AppxMetadata/AppxBundleManifest.xml"
BUNDLE_NS = "http://schemas.microsoft.com/appx/2013/bundle"
BLOCKMAP = "AppxBlockMap.xml"
CONTENT_TYPES = "[Content_Types].xml"

# The bundle version is the packages' version with the revision zeroed, which is
# what MakeAppx does when it is not told otherwise.
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$")


@dataclass(frozen=True)
class PackageEntry:
    """One `.msix` about to go into a bundle, as its own manifest describes it."""

    path: Path
    name: str
    publisher: str
    version: str
    architecture: str | None  # absent for a resource package
    languages: tuple[str, ...]
    resource_id: str
    kind: str  # "application" or "resource"
    signed: bool


def _identity(manifest: str, attribute: str) -> str | None:
    element = re.search(r"<Identity\b([^>]*)>", manifest)
    if not element:
        return None
    found = re.search(rf'\b{attribute}\s*=\s*"([^"]*)"', element.group(1))
    return found.group(1) if found else None


def read_package(path: Path) -> PackageEntry:
    """Describe a packed `.msix` well enough to list it in a bundle manifest."""
    path = Path(path).resolve()
    if not zipfile.is_zipfile(path):
        raise ValueError(f"not a ZIP/MSIX container: {path}")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        if "AppxManifest.xml" not in names:
            raise ValueError(f"{path.name} has no AppxManifest.xml")
        manifest = zf.read("AppxManifest.xml").decode("utf-8", errors="replace")
        signed = "AppxSignature.p7x" in names
    # Comments in these manifests describe the very attributes being read.
    manifest = re.sub(r"<!--.*?-->", "", manifest, flags=re.DOTALL)

    missing = [
        attribute
        for attribute in ("Name", "Publisher", "Version")
        if not _identity(manifest, attribute)
    ]
    if missing:
        raise ValueError(f"{path.name}: Identity/@{', @'.join(missing)} missing")

    languages = tuple(re.findall(r'<Resource\b[^>]*Language="([^"]+)"', manifest))
    # `Identity/@ResourceId` is what makes a package a resource package — not the
    # absence of <Applications>, which was the obvious guess and is wrong: a
    # device answers 0x80080204 "its package type doesn't match the value found
    # in the bundle manifest". Microsoft's own resource packages pair it with
    # <Properties><ResourcePackage>true, and carry no ProcessorArchitecture.
    resource_id = _identity(manifest, "ResourceId")
    kind = "resource" if resource_id else "application"
    architecture = _identity(manifest, "ProcessorArchitecture")
    return PackageEntry(
        path=path,
        name=_identity(manifest, "Name") or "",
        publisher=_identity(manifest, "Publisher") or "",
        version=_identity(manifest, "Version") or "",
        architecture=None if kind == "resource" else (architecture or "neutral"),
        languages=languages or ("en-us",),
        resource_id=resource_id or "",
        kind=kind,
        signed=signed,
    )


def bundle_version(packages: list[PackageEntry]) -> str:
    """Highest package version with the revision zeroed, as MakeAppx does."""
    parsed = [
        tuple(int(n) for n in m.groups())
        for m in (_VERSION_RE.match(p.version) for p in packages)
        if m
    ]
    if not parsed:
        return "1.0.0.0"
    major, minor, build, _ = max(parsed)
    return f"{major}.{minor}.{build}.0"


def bundle_problems(packages: list[PackageEntry]) -> list[str]:
    """Reasons these packages cannot go in one bundle (empty list => they can).

    Identity has to agree: the bundle names one application, and a device
    resolves the packages inside it against that single identity. Two packages
    claiming the same architecture and resource are a mistake for the same
    reason — nothing could choose between them.

    Deliberately not required: an application package. A bundle of nothing but
    resource packages is legal — upstream ships one as `ContainsOnlyResourcePackages`
    — and is how language packs are distributed.
    """
    problems = []
    names = {p.name for p in packages}
    if len(names) > 1:
        problems.append(
            f"packages disagree on Identity/@Name: {', '.join(sorted(names))}"
        )
    publishers = {p.publisher for p in packages}
    if len(publishers) > 1:
        problems.append(
            f"packages disagree on Identity/@Publisher: {', '.join(sorted(publishers))}"
        )
    seen: dict[tuple, Path] = {}
    for p in packages:
        key = (p.kind, p.architecture, p.resource_id)
        if key in seen:
            problems.append(
                f"{p.path.name} and {seen[key].name} describe the same "
                f"architecture and resource: "
                f"{p.architecture or 'neutral'}/{p.resource_id}"
            )
        seen[key] = p.path
    if not packages:
        problems.append("a bundle needs at least one package")
    return problems


def unsigned_payloads(packages: list[PackageEntry]) -> list[str]:
    """Payload packages carrying no signature of their own.

    Not a `bundle_problems` entry, on purpose. Signing needs the optional
    `[sign]` extra, and bundling must keep working without it — assembling the
    container is mechanical. It is still a certain install failure, so the CLI
    warns and `inspect` reports it on the finished bundle, which is where this
    codebase puts checks that need the artefact to exist.

    Signing the bundle is not enough: a device answers 0x800B0100 against the
    *bundle*, which reads as if the bundle itself were unsigned. Measured by
    signing one and not the other.
    """
    return sorted(p.path.name for p in packages if not p.signed)


def render_bundle_manifest(
    packages: list[PackageEntry], offsets: dict[str, int], version: str
) -> bytes:
    """The `<Bundle>` document, with each package's offset inside the archive.

    Rendered as bytes for the same reason the blockmap is: reference tooling
    compares byte for byte, and a serialiser would reorder attributes.
    """
    first = packages[0]
    lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
        f'<Bundle SchemaVersion="2.0" xmlns="{BUNDLE_NS}">',
        f'  <Identity Name="{_xml_escape(first.name)}" '
        f'Publisher="{_xml_escape(first.publisher)}" Version="{version}"/>',
        "  <Packages>",
    ]
    for p in packages:
        attributes = [f'Type="{p.kind}"', f'Version="{p.version}"']
        if p.architecture:
            attributes.append(f'Architecture="{p.architecture}"')
        # Only resource packages carry a ResourceId. A real Store bundle omits it
        # on application packages, and a device that finds one there stops
        # matching them by architecture — reporting that the bundle "does not
        # have an appropriate application package for x64", measured.
        if p.kind == "resource":
            attributes.append(f'ResourceId="{_xml_escape(p.resource_id)}"')
        attributes += [
            f'FileName="{_xml_escape(p.path.name)}"',
            f'Offset="{offsets[p.path.name]}"',
            f'Size="{p.path.stat().st_size}"',
        ]
        lines.append(f"    <Package {' '.join(attributes)}>")
        lines.append("      <Resources>")
        for language in p.languages:
            lines.append(f'        <Resource Language="{_xml_escape(language)}"/>')
        lines.append("      </Resources>")
        lines.append("    </Package>")
    lines += ["  </Packages>", "</Bundle>"]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def bundle_content_types() -> bytes:
    """`xml` defaults to bundlemanifest+xml here, where a package says manifest+xml."""
    return (
        "\r\n".join(
            [
                '<?xml version="1.0" encoding="utf-8"?>',
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
                'content-types">',
                '  <Default Extension="appx" ContentType="application/vnd.ms-appx"/>',
                '  <Default Extension="msix" ContentType="application/vnd.ms-appx"/>',
                '  <Default Extension="xml" '
                'ContentType="application/vnd.ms-appx.bundlemanifest+xml"/>',
                '  <Override PartName="/AppxBlockMap.xml" '
                'ContentType="application/vnd.ms-appx.blockmap+xml"/>',
                '  <Override PartName="/AppxSignature.p7x" '
                'ContentType="application/vnd.ms-appx.signature"/>',
                "</Types>",
            ]
        )
        + "\r\n"
    ).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="openappx bundle",
        description="Combine .msix packages into one .msixbundle",
    )
    ap.add_argument(
        "--package",
        action="append",
        required=True,
        type=Path,
        dest="packages",
        help="a packed .msix to include; repeat for each architecture",
    )
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    missing = [p for p in args.packages if not p.is_file()]
    if missing:
        for p in missing:
            print(f"error: no such package: {p}", file=sys.stderr)
        return 2
    try:
        entries = [read_package(p) for p in args.packages]
        unsigned = unsigned_payloads(entries)
        if unsigned:
            print(
                "warning: these payload packages are unsigned, and a device will "
                "refuse the bundle: " + ", ".join(unsigned),
                file=sys.stderr,
            )
        out = build_bundle(args.packages, args.out)
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(
        f"Wrote {out} ({out.stat().st_size} bytes) from {len(args.packages)} packages"
    )
    print("Reminder: sign the bundle itself — the packages inside are not enough.")
    return 0


def build_bundle(packages: list[Path], out: Path) -> Path:
    """Write `out` as a bundle carrying `packages`, each stored verbatim."""
    entries = [read_package(p) for p in packages]
    problems = bundle_problems(entries)
    if problems:
        raise ValueError("; ".join(problems))

    archive = bytearray()
    written: list[_Entry] = []
    offsets: dict[str, int] = {}
    for entry in entries:
        data = entry.path.read_bytes()
        header_offset = len(archive)
        written.append(
            _write_entry(archive, entry.path.name, data, data, _METHOD_STORE)
        )
        # Offset is where the data starts, not where the record does.
        offsets[entry.path.name] = header_offset + zip_local_header_size(
            entry.path.name.encode("utf-8"), zip64_local_extra(len(data), len(data))
        )

    version = bundle_version(entries)
    manifest = render_bundle_manifest(entries, offsets, version)
    prepared = prepare_file(BUNDLE_MANIFEST.replace("/", "\\"), manifest)
    lfh_size = zip_local_header_size(
        BUNDLE_MANIFEST.encode("utf-8"),
        zip64_local_extra(len(manifest), len(prepared.payload)),
    )
    # The blockmap covers this one file, so the package renderer does the job
    # unchanged — the difference between a bundle and a package here is what is
    # in the list, not how it is written.
    blockmap = render_blockmap_xml([prepared.blocks], {prepared.blocks.name: lfh_size})

    written.append(
        _write_entry(
            archive,
            BUNDLE_MANIFEST,
            prepared.payload,
            manifest,
            _METHOD_DEFLATE if prepared.deflated else _METHOD_STORE,
        )
    )
    for name, data in ((CONTENT_TYPES, bundle_content_types()), (BLOCKMAP, blockmap)):
        written.append(_write_entry(archive, name, data, data, _METHOD_STORE))

    _write_central_directory(archive, written)
    out = Path(out).resolve()
    return atomic_write_bytes(out, bytes(archive))
